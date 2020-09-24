# -*- coding: utf-8 -*-

import json
import ldap3
from ldap3.core.exceptions import LDAPBindError
from impacket.dcerpc.v5 import epm
from termcolor import colored

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