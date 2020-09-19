# -*- coding: utf-8 -*-

import json
import ldap3

class ModEnumerator():

    def __init__(self, ):
        pass


    def enumerate_server_names(self, computerobjects: ldap3.Entry) -> dict:
        '''Return a dict of key(dNSHostName) and value(fingerprinted servertype)
        
        '''
        self.wordlist = {
            "mssql": ["mssql", "sqlserver"],
            "ftp": ["ftp"], 
            "smtp": ["exchange", "smtp"],
            "ad": ["dc", "domaincontroller", "msol", "domain controller"]
        }
        self.computerobjects = computerobjects
        self.results = {}

        for key, value in self.wordlist.items():
            for fingerprint in value:
                for obj in self.computerobjects:
                    if fingerprint in str(obj["name"]).lower():
                        self.results[str(obj["dNSHostName"])] = key
                    elif fingerprint in str(obj["dNSHostName"]).lower():
                        self.results[str(obj["dNSHostName"])] = key
                    elif fingerprint in str(obj["distinguishedName"]).lower():
                        self.results[str(obj["dNSHostName"])] = key
                    elif fingerprint in str(obj["dNSHostName"]).lower():
                        self.results[str(obj["dNSHostName"])] = key

        return self.results