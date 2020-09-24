# LDAP connection
import ldap3
from ldap3.core.exceptions import LDAPBindError
# SMB connection
from impacket import smbconnection
from impacket.smbconnection import SessionError
from impacket.nmb import NetBIOSTimeout, NetBIOSError
# RPC connection
from impacket.dcerpc.v5 import transport
# For when impacket releases the feature as a release
#from impacket.http import AUTH_NTLM
from socket import gaierror
# Generic imports
import sys
from termcolor import colored

class Connectors():


    def __init__(self):
        pass


    def ldap_connector(self, server: str, ldaps: bool, domuser: str, passwd: str, level='ALL') -> ldap3.Connection:
        '''Returns an ldap3.Connection object that is bound to the supplied domain controller

        Raise LDAPBindError on bind() errors.

        '''
        if ldaps:
            dc_conn = ldap3.Server(server, port=636, use_ssl=True, get_info=level)
            conn = ldap3.Connection(dc_conn, user=domuser, password=passwd)
            conn.bind()
            conn.start_tls()
            # Validate the login (bind) request
            if int(conn.result['result']) != 0:
                raise LDAPBindError
        else:
            dc_conn = ldap3.Server(server, get_info=level)
            conn = ldap3.Connection(dc_conn, user=domuser, password=passwd)
            conn.bind()
            # Validate the login (bind) request
            if int(conn.result['result']) != 0:
                raise LDAPBindError
        
        return conn

    
    def winrm_connector(self):
        pass


    def rpc_connector(self, server: str, domuser: str, passwd: str):
        rpc_protocols = {
            135: 'ncacn_ip_tcp:{}[135]',
            139: 'ncacn_np:{}[\pipe\epmapper]',
            443: 'ncacn_http:[593,RpcProxy={}:443]',
            #445: 'ncacn_np:{}[\pipe\epmapper]',
        }
        dce = False

        for port, protocol in rpc_protocols.items():
            transporter = transport.DCERPCTransportFactory(protocol.format(server))

            transporter.set_credentials(domuser, passwd, server, '', '')

            if port == 139 or port == 445:
                transporter.setRemoteHost(server)
                transporter.set_dport(port)
            #elif [443] in protocol:
            #    transporter.set_auth_type(AUTH_NTLM)
            try:
                dce = transporter.get_dce_rpc()
                dce.connect()
                # We can break to return since the connection did not raise an error
                break
            except (NetBIOSError, gaierror):
                # Something was off
                continue
        return dce


    def smb_connector(self, server: str, domuser: str, passwd: str) -> smbconnection:
        try:
            smbconn = smbconnection.SMBConnection(f'\\\\{server}\\', server, timeout=5)
            smbconn.login(domuser, passwd)
        except (SessionError, UnicodeEncodeError, NetBIOSError):
            smbconn.close()
            return False
        return smbconn

    
    def ftp_connector(self):
        pass


    def smtp_connector(self):
        pass
        