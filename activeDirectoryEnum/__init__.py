#!/usr/bin/python3
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, LEVEL, SUBTREE, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPKeyError
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout, NetBIOSError
from getpass import getpass
from termcolor import colored
from impacket import smbconnection
from impacket.dcerpc.v5 import srvs
import contextlib, argparse, textwrap, errno, sys, socket, json, re, os, base64

from dns.resolver import NXDOMAIN

from .bloodhound import BloodHound, resolve_collection_methods
from .bloodhound.ad.domain import AD
from .bloodhound.ad.authentication import ADAuthentication


class EnumAD():

    def __init__(self, domainController, ldaps, output, enumsmb, bhout, kpre, spnEnum, sysvol, domuser=None, computer=None):
        self.server = domainController
        self.domuser = domuser
        self.ldaps = ldaps
        self.output = output
        self.bhout = bhout
        self.kpre = kpre
        self.spnEnum = spnEnum
        self.enumsmb = enumsmb
        self.enumSYSVOL = sysvol

        self.ou_structure = domainController.split('.')
        self.dc_string=''
        for element in self.ou_structure:
            self.dc_string += 'dc={},'.format(element)
        
        # LDAP properties
        # At the moment we just want everything
        self.ldapProps = ["*"]


        # Setting lists containing elements we want from the domain controller
        self.computers = []
        self.people = []
        self.groups = []
        self.spn = []
        self.acl = []
        self.gpo = []
        self.domains = []
        self.ous = []
        self.deletedUsers = []
        self.passwd = False

        if domuser is not False:
            self.runWithCreds()
        else:
            self.runWithoutCreds()
       

    def runWithCreds(self):
        self.CREDS = True
        if not self.passwd:
            self.passwd = str(getpass())
        self.bind()
        self.search()

        if self.output:
            self.write_file()
       
        self.checkForPW()
        self.checkOS()
        if self.enumSYSVOL:
            from . enumeration.sysvol import EnumSYSVOL
            enumSYSVOL = EnumSYSVOL(self.server, self.domuser, self.passwd)

        if self.bhout:
            self.outputToBloodhoundJson()
    
        if self.kpre:
            from . attack.ASREPRoasting import ASREPRoasting
            asrep = ASREPRoasting(self.dc_string, self.server, self.conn)
    
        if self.spnEnum:
            from . attack.kerberoasting import Kerberoasting
            kerb = Kerberoasting(self.server, self.domuser, self.passwd, self.spn)
        
        self.conn.unbind()
        
        if self.enumsmb:
            # Setting variables for further testing and analysis
            from . enumeration.smb import EnumSMB
            enumSMB = EnumSMB(self.computers, self.domuser, self.passwd, self.server)

        # Lets clear variable now
        self.passwd = None


    def runWithoutCreds(self):
        self.CREDS = False
        print('[ ' + colored('INFO', 'green') +' ] Attempting to get objects without credentials'.format(self.server))           
        self.passwd = ''
        self.domuser = ''
        print('')

        self.bind()
        self.search()

        if self.output:
            self.write_file()
       
        self.checkForPW()
        self.checkOS()

        self.enumForCreds(self.people)

        print('[ ' + colored('WARN', 'yellow') +' ] Didn\'t find useable info as anonymous user, please gather credentials and run again')
        exit(0)

    
    @contextlib.contextmanager
    def suppressOutput(self):
        with open(os.devnull, 'w') as devnull:
            with contextlib.redirect_stderr(devnull) as err, contextlib.redirect_stdout(devnull) as out:
                yield (err, out)


    def bind(self): 
        try:
            if self.ldaps:
                self.dc_conn = Server(self.server, port=636, use_ssl=True, get_info='ALL')
                self.conn = Connection(self.dc_conn, user=self.domuser, password=self.passwd)
                self.conn.bind()
                self.conn.start_tls()
                # Validate the login (bind) request
                if int(self.conn.result['result']) != 0:
                    print('\033[1A\r[ ' + colored('ERROR', 'red') +' ] Failed to bind to LDAPS server: {0}'.format(self.conn.result['description']))
                    sys.exit(1)
                else:
                    print('\033[1A\r[ ' + colored('OK', 'green') +' ] Bound to LDAPS server: {0}'.format(self.server))           
            else:
                self.dc_conn = Server(self.server, get_info=ALL)
                self.conn = Connection(self.dc_conn, user=self.domuser, password=self.passwd)
                self.conn.bind()
                # Validate the login (bind) request
                if int(self.conn.result['result']) != 0:
                    print('\033[1A\r[ ' + colored('ERROR', 'red') +' ] Failed to bind to LDAP server: {0}'.format(self.conn.result['description']))
                    sys.exit(1)
                else:
                    print('\033[1A\r[ ' + colored('OK', 'green') +' ] Bound to LDAP server: {0}'.format(self.server))
        # TODO: Catch individual exceptions instead
        except Exception as e:
            if self.ldaps:
                print('\033[1A\r[ ' + colored('ERROR', 'red') +' ] Failed to bind to LDAPS server: {0}'.format(self.server))
            else:
                print('\033[1A\r[ ' + colored('ERROR', 'red') +' ] Failed to bind to LDAP server: {0}'.format(self.server))
            sys.exit(1)


    def search(self):
        # Get computer objects
        self.conn.search(self.dc_string[:-1], '(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.computers.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all Computer objects')

        # Get person objects
        self.conn.search(self.dc_string[:-1], '(objectCategory=person)', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.people.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all Person objects')
        
        # Get group objects
        self.conn.search(self.dc_string[:-1], '(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(primarygroupid=*))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.groups.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all Group objects')

        # Get SPN objects
        self.conn.search(self.dc_string[:-1], '(&(samaccounttype=805306368)(serviceprincipalname=*))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.spn.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all SPN objects')

        # Get ACL objects
        self.conn.search(self.dc_string[:-1], '(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*))(objectcategory=organizationalUnit))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.acl.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all ACL objects')

        # Get GPO objects
        self.conn.search(self.dc_string[:-1], '(|(&(&(objectcategory=groupPolicyContainer)(flags=*))(name=*)(gpcfilesyspath=*))(objectcategory=organizationalUnit)(objectClass=domain))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.gpo.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all GPO objects')

        # Get Domain
        self.conn.search(self.dc_string[:-1], '(objectclass=domain)', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.domains.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all Domains')

        # Get OUs
        self.conn.search(self.dc_string[:-1], '(objectclass=organizationalUnit)', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.ous.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all OUs')

        # Get deleted users
        self.conn.search(self.dc_string[:-1], '(objectclass=user)', attributes=self.ldapProps, search_scope=SUBTREE, controls=[('1.2.840.113556.1.4.417', True, None)])
        for entry in self.conn.entries:
            self.deletedUsers.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all deleted users')
        if len(self.deletedUsers) > 0:
            print('[ ' + colored('INFO', 'green') +' ] Searching for juicy info in deleted users')
            self.enumForCreds(self.deletedUsers)
        

    '''
        Since it sometimes is real that the property 'userPassword:' is set
        we test for it and dump the passwords
    '''
    def checkForPW(self):
        passwords = {}
        idx = 0
        for entry in self.people:
            user = json.loads(self.people[idx].entry_to_json())
            idx += 1    
            if user['attributes'].get('userPassword') is not None:
                passwords[user['attributes']['name']] = user['attributes']['userPassword']
        if len(passwords.keys()) > 0:
            with open('{0}-clearpw'.format(self.server), 'w') as f:
                json.dump(passwords, f, sort_keys=False) 

        if len(passwords.keys()) == 1:
            print('[ ' + colored('WARN', 'yellow') +' ] Found {0} clear text password'.format(len(passwords.keys())))
        elif len(passwords.keys()) == 0:
            print('[ ' + colored('OK', 'green') +' ] Found {0} clear text password'.format(len(passwords.keys())))
        else:
            print('[ ' + colored('OK', 'green') +' ] Found {0} clear text passwords'.format(len(passwords.keys())))


    '''
        While it is not unusual to find EOL servers hidden or forgotten these 
        often makes easier targets for lateral movemen, and because of that 
        we'll dump the lowest registered OS and the respective hosts for easier 
        enumeration afterwards
    '''
    def checkOS(self):

        os_json = {
                # Should perhaps include older version
                "Windows XP": [],
                "Windows Server 2008": [],
                "Windows 7": [],
                "Windows Server 2012": [],
                "Windows 10": [],
                "Windows Server 2016": [],
                "Windows Server 2019": []
        }
        idx = 0
        for entry in self.computers:
            computer = json.loads(self.computers[idx].entry_to_json())
            idx += 1    

            for os_version in os_json.keys():
                try:
                    if os_version in computer['attributes'].get('operatingSystem'):
                        os_json[os_version].append(computer['attributes']['dNSHostName'])
                except TypeError:
                    # computer['attributes'].get('operatingSystem') is of NoneType, just continue
                    continue

        for key, value in os_json.items():
            if len(value) == 0:
                continue
            with open('{0}-oldest-OS'.format(self.server), 'w') as f:
                for item in value:
                    f.write('{0}: {1}\n'.format(key, item))
                break

        print('[ ' + colored('OK', 'green') +' ] Wrote hosts with oldest OS to {0}-oldest-OS'.format(self.server))
    
    def outputToBloodhoundJson(self):
        
        print('[ ' + colored('OK', 'green') +' ] Generating BloodHound output - this may take time...')
        try:
            with self.suppressOutput():
                opts = argparse.Namespace(dns_tcp=False, global_catalog=self.server)
                auth = ADAuthentication(username=self.domuser, password=self.passwd, domain=self.server)
            try:
                ad = AD(auth=auth, domain=self.server, nameserver=None, dns_tcp=False)
                ad.dns_resolve(kerberos=False, domain=self.server, options=opts)
            except (NXDOMAIN) as e:
                # So we didnt succeed with DNS lookup. Most likely an internal, so lets try to point to the DC
                print('[ ' + colored('WARN', 'yellow') +' ] DNS lookup of Domain Controller failed - attempting to set the DC as Nameserver')
                try:
                    ns = socket.gethostbyname(self.server)
                    opts = argparse.Namespace(dns_tcp=False, global_catalog=self.server, nameserver=ns)
                    ad = AD(auth=auth, domain=self.server, nameserver=ns, dns_tcp=False)
                    ad.dns_resolve(kerberos=False, domain=self.server, options=opts)
                except (NXDOMAIN) as e:
                    # I'm all out of luck
                    print('[ ' + colored('ERROR', 'red') +' ] DNS lookup of Domain Controller failed with DC as nameserver')
                    exit(1)
            with self.suppressOutput():
                bloodhound = BloodHound(ad)
                bloodhound.connect()
                collection = resolve_collection_methods('Session,Trusts,ACL,DCOM,RDP,PSRemote')
                bloodhound.run(collect=collection, num_workers=40, disable_pooling=False)
            print('[ ' + colored('OK', 'green') +' ] BloodHound output generated')
        except Exception as e:
            print(e)
            print('[ ' + colored('ERROR', 'red') +' ] Generating BloodHound output failed')


    def write_file(self):
        with open(str(self.output) + '-computers', 'w') as f:
            for item in self.computers:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-people', 'w') as f:
            for item in self.people:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-groups', 'w') as f:
            for item in self.groups:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-spn', 'w') as f:
            for item in self.spn:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-acl', 'w') as f:
            for item in self.acl:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-gpo', 'w') as f:
            for item in self.gpo:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-domains', 'w') as f:
            for item in self.domains:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-ous', 'w') as f:
            for item in self.ous:
                f.write(str(item))
                f.write("\n")

        print('[ ' + colored('OK', 'green') +' ] Wrote all files to {0}-obj_name'.format(self.output))


    def enumForCreds(self, ldapdump):
        searchTerms = [
                'legacy', 'pass', 'password', 'pwd', 'passcode'
        ]
        excludeTerms = [
                'badPasswordTime', 'badPwdCount', 'pwdLastSet'
        ]
        possiblePass = {}
        idx = 0
        for entry in ldapdump:
            user = json.loads(ldapdump[idx].entry_to_json())
            for prop, value in user['attributes'].items():
                if any(term in prop.lower() for term in searchTerms) and not any(ex in prop for ex in excludeTerms):
                    possiblePass[user['attributes']['userPrincipalName'][0]] = value[0]
            idx += 1
        if len(possiblePass) > 0:
            print('[ ' + colored('INFO', 'green') +' ] Found possible password in properties')
            print('[ ' + colored('INFO', 'green') +' ] Attempting to determine if it is a password')

            for user, password in possiblePass.items():
                try:
                    usr, passwd = self.entroPass(user, password)
                except TypeError:
                    # None returned, just continue
                    continue
            if not self.CREDS:
                self.domuser = usr
                self.passwd = passwd
                self.runWithCreds()
                exit(0)


    def entroPass(self, user, password):
        # First check if it is a clear text
        dc_test_conn = Server(self.server, get_info=ALL)
        test_conn = Connection(dc_test_conn, user=user, password=password)
        test_conn.bind()
        # Validate the login (bind) request
        if int(test_conn.result['result']) != 0:
            if self.CREDS:
                print('[ ' + colored('INFO', 'yellow') +' ] User: "{0}" with: "{1}" as possible clear text password'.format(user, password))
            else:
                print('[ ' + colored('INFO', 'green') +' ] User: "{0}" with: "{1}" was not cleartext'.format(user, password))
        else:
            if self.CREDS:
                print('[ ' + colored('INFO', 'yellow') +' ] User: "{0}" had cleartext password of: "{1}" in a property'.format(user, password))
            else:
                print('[ ' + colored('OK', 'yellow') +' ] User: "{0}" had cleartext password of: "{1}" in a property - continuing with these creds'.format(user, password))
                print('')
                return user, password

        test_conn.unbind()

        # Attempt for base64
        # Could be base64, lets try
        pw = base64.b64decode(bytes(password, encoding='utf-8')).decode('utf-8')
    
        # Attempt decoded PW
        dc_test_conn = Server(self.server, get_info=ALL)
        test_conn = Connection(dc_test_conn, user=user, password=pw)
        test_conn.bind()
        # Validate the login (bind) request
        if int(test_conn.result['result']) != 0:
            if self.CREDS:
                print('[ ' + colored('INFO', 'yellow') +' ] User: "{0}" with: "{1}" as possible base64 decoded password'.format(user, pw))
            else:
                print('[ ' + colored('INFO', 'green') +' ] User: "{0}" with: "{1}" was not base64 encoded'.format(user, pw))
        else:
            if self.CREDS:
                print('[ ' + colored('INFO', 'yellow') +' ] User: "{0}" had base64 encoded password of: "{1}" in a property'.format(user, pw))
            else:
                print('[ ' + colored('OK', 'yellow') +' ] User: "{0}" had base64 encoded password of: "{1}" in a property - continuing with these creds'.format(user, pw))
                print('')
                return user, pw


