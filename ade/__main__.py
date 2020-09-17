from ade import EnumAD
from termcolor import colored
import argparse
import textwrap
import sys
import re
import os

parser = argparse.ArgumentParser(prog='activeDirectoryEnum', formatter_class=argparse.RawDescriptionHelpFormatter, description=textwrap.dedent('''
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
parser.add_argument('-u', '--user', type=str, help='Username of the domain user to query with. The username has to be domain name as `user@domain.org`')
parser.add_argument('-s', '--secure', help='Try to estalish connection through LDAPS', action='store_true')
parser.add_argument('-smb', '--smb', help='Force enumeration of SMB shares on all computer objects fetched', action='store_true')
parser.add_argument('-kp', '--kerberos_preauth', help='Attempt to gather users that does not require Kerberos preauthentication', action='store_true')
parser.add_argument('-bh', '--bloodhound', help='Output data in the format expected by BloodHound', action='store_true')
parser.add_argument('-spn', help='Attempt to get all SPNs and perform Kerberoasting', action='store_true')
parser.add_argument('-sysvol', help='Search sysvol for GPOs with cpassword and decrypt it', action='store_true')
parser.add_argument('--all', help='Run all checks', action='store_true')
parser.add_argument('--no-creds', help='Start without credentials', action='store_true')

if len(sys.argv) == 1:
    parser.print_help(sys.stderr)
    sys.exit(1)

args = parser.parse_args()

# If theres more than 4 sub'ed (test.test.domain.local) - tough luck sunny boy
domainRE = re.compile(r'^((?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z]+)$')
userRE = re.compile(r'^([a-zA-Z0-9-\.]+@(?:[a-zA-Z0-9-.]+)?(?:[a-zA-Z0-9-.]+)?[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)$')

domainMatch = domainRE.findall(args.dc)

if not domainMatch:
    print('[ ' + colored('ERROR', 'red') +' ] Domain flag has to be in the form "domain.local"')
    sys.exit(1)

if args.all:
    args.smb = True
    args.kerberos_preauth = True
    args.bloodhound = True
    args.spn = True
if args.no_creds:
    args.user = False
else:
    userMatch = userRE.findall(args.user)
    if not userMatch:
        print('[ ' + colored('ERROR', 'red') +' ] User flag has to be in the form "user@domain.local"')
        sys.exit(1)


# Boolean flow control flags
file_to_write = None
if args.out_file:
    file_to_write = args.out_file

enumAD = EnumAD(args.dc, args.secure, file_to_write, args.smb, args.bloodhound, args.kerberos_preauth, args.spn, args.sysvol, args.user)

# Just print a blank line for output sake
print('')
