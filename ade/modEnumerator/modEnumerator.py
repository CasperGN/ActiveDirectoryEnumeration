# -*- coding: utf-8 -*-

import json
import ldap3
from ldap3.core.exceptions import LDAPBindError

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