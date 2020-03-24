## ADE - ActiveDirectoryEnum
```
usage: activeDirectoryEnum [-h] [-o OUT_FILE] [-s] [-smb] [-kp] [-bh] [-spn]
                       dc user

        ___        __  _            ____  _                __                   ______                    
       /   | _____/ /_(_)   _____  / __ \(_)_______  _____/ /_____  _______  __/ ____/___  __  ______ ___ 
      / /| |/ ___/ __/ / | / / _ \/ / / / / ___/ _ \/ ___/ __/ __ \/ ___/ / / / __/ / __ \/ / / / __ `__ \
     / ___ / /__/ /_/ /| |/ /  __/ /_/ / / /  /  __/ /__/ /_/ /_/ / /  / /_/ / /___/ / / / /_/ / / / / / /
    /_/  |_\___/\__/_/ |___/\___/_____/_/_/   \___/\___/\__/\____/_/   \__, /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                      /____/                             

|*----------------------------------------------------------------------------------------------------------*|

positional arguments:
  dc                    Hostname of the Domain Controller
  user                  Username of the domain user to query with. The
                        username has to be domain name as `user@domain.org`

optional arguments:
  -h, --help            show this help message and exit
  -o OUT_FILE, --out-file OUT_FILE
                        Path to output file. If no path, CWD is assumed
                        (default: None)
  -s, --secure          Try to estalish connection through LDAPS
  -smb, --smb           Force enumeration of SMB shares on all computer objects
                        fetched
  -kp, --kerberos_preauth
                        Attempt to gather users that does not require Kerberos
                        preauthentication
  -bh, --bloodhound     Output data in the format expected by BloodHound
  -spn                  Attempt to get all SPNs and perform Kerberoasting
  --all                 Run all checks

```

## Install

Run installation through pip3:
```
pip3 install .
```
Since it is not yet distributed through pip packages yet this is the way, for now.
The script can now be called as a module or be imported:

```
python3 -m activeDirectoryEnum 
```

## Included attacks

- [X] ASREPRoasting
- [X] Kerberoasting
- [X] Dump AD as BloodHound JSON files 

## Features list and status

- [X] Found external module to handle Bloodhound json files 
- [X] Enumerate all SPNs for Kerberoasting  
  - [X] Get TGT for supplied user (requires testing on non-skew'ed machine)
  - [X] Request TGS for each SPN gathered
  - [X] Dump all tickets for offline cracking
- [ ] Check servername for service indication (e.g. FTP, MSSQL, Other DB, Exhange etc) to map technical landscape  
- [ ] Based upon above, enumerate the service indication for default login  
- [X] Dump lowest Major OS servers (can we find Win2003, Win2008?) -> Fixed in [75bc987](https://github.com/CasperGN/ActiveDirectoryEnumeration/commit/75bc98798df623c5488ea9447e5335f4dcdfb873)
- [X] Connect through LDAPS
- [X] Bruteforce enumeration of SMB shares on all computer objects
- [X] Output SMB Bruteforce enumeration properly -> Fixed in [9434920](https://github.com/CasperGN/ActiveDirectoryEnumeration/commit/9434920fbb729710ebf4034394b69643d445115a)
- [X] Get all users with `Kerberos preauthentication` not required and dump hashes
- [X] Write AD Object dump to raw file
- [X] Fix [requirements.txt](requirements.txt) file, since not all the contained libs can be needed -> Fixed in [ad3e180](https://github.com/CasperGN/ActiveDirectoryEnumeration/commit/ad3e18076b91d0c081502d72fd75d3b284f2e707)
- [X] Test SMB connection for encryption [see here](https://github.com/CasperGN/ActiveDirectoryEnumeration/blob/2585a91661ed8e344df8ea2ad95b5233c072fe38/activeDirectoryEnum.py#L395)
- [X] Query all users with an actual password set in the property `userPassword:` -> Fixed in [f05308b](https://github.com/CasperGN/ActiveDirectoryEnumeration/commit/f05308ba4db0d2abda86e15a5145d2ce44c5c889)
  - [ ] Check if password is encrypted/hashed and if so, dump in JTR format
- [X] Search SYSVOL share for any passwords in GPOs and crack them [see](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#passwords-in-sysvol--group-policy-preferences)
- [ ] Try to get SilverTicket
- [ ] Try to get GoldenTicket
- [X] Make `--all` flag that runs all checks
- [X] Move smb enum to be the last check
- [ ] Make validation of password before proceeding with ldap connection + querries 
- [ ] Create better validation of input format to ensure that domain flag is of `domain.local` type and user is `user@domain.local`
- [ ] Test for RPC and SMB Null sessions
- [ ] Get accounts with passwords set long time ago
- [ ] NTLM vs. LM hashes - Search for old accounts
- [ ] Extract hashes and brute against fx. rockyou / SecList etc.


## Collaboration

While this project is developed to fit my need, any collaboration is appriciated. Please feel free to fork the project, make changes according to the License agreements and make a Pull Request.
I only ask that:
- Keep equivilent naming standard as the base project
- Keep equivilent syntaxing
- Test your code
- Error handling is incorporated
- Document the feature - both in code but also for potential Wiki page

## Thanks & Acknowledgements

Big thanks to the creators of:
`Impacket`
`BloodHound`
`BloodHound.py`

Without the above this wrapper was not possible.
