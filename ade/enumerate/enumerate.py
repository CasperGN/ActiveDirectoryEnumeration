import json

class Enumerate():

    def __init__(self, computerobjects):
        self.wordlist = {
            "mssql": ["mssql", "sqlserver"],
            "ftp": ["ftp"], 
            "smtp": ["exchange", "smtp"],
            "ad": ["dc", "domaincontroller", "msol", "domain controller"]
        }
        self.results = {}
        self.computerobjects = computerobjects


    def enumerate_server_names(self):
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