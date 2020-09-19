import ldap3
from ldap3.core.exceptions import LDAPBindError
import sys
from termcolor import colored

class Connectors():


    def __init__(self):
        pass


    def ldap_connector(self, server: str, ldaps: bool, domuser: str, passwd: str, level='ALL') -> ldap3.Connection:
        '''Returns an ldap3.Connection object that is bound to the supplied domain controller

        Raise ldap3.core.exceptions.LDAPBindError on bind() errors.

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
                print('\033[1A\r[ ' + colored('ERROR', 'red') +' ] Failed to bind to LDAP server: {0}'.format(conn.result['description']))
                raise LDAPBindError
        
        return conn