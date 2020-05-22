import socket, json
from termcolor import colored
from progressbar import Bar, Percentage, ProgressBar, ETA
from impacket.smbconnection import SessionError
from ldap3.core.exceptions import LDAPKeyError
from impacket.nmb import NetBIOSTimeout, NetBIOSError
from impacket import smbconnection

class EnumSMB():

    def __init__(self, computers, user, passwd, server):
        self.computers = computers
        self.domuser = user
        self.passwd = passwd
        self.server = server

        self.smbShareCandidates = []
        self.smbBrowseable = {}
        self.sortComputers()
        self.enumSMB()


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
                json.dump(self.smbBrowseable, f, indent=4, sort_keys=False)
            print('[ ' + colored('OK', 'green') + ' ] Wrote browseable shares to {0}-open-smb'.format(self.server))