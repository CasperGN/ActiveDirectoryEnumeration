## ADE - ActiveDirectoryEnum
```
usage: activeDirectoryEnum [-h] [-o OUT_FILE] [-u USER] [-c COMPUTER] [-s] [-smb]
                       [-kp] [-bh]
                       dc

        ___        __  _            ____  _                __                   ______                    
       /   | _____/ /_(_)   _____  / __ \(_)_______  _____/ /_____  _______  __/ ____/___  __  ______ ___ 
      / /| |/ ___/ __/ / | / / _ \/ / / / / ___/ _ \/ ___/ __/ __ \/ ___/ / / / __/ / __ \/ / / / __ `__ \
     / ___ / /__/ /_/ /| |/ /  __/ /_/ / / /  /  __/ /__/ /_/ /_/ / /  / /_/ / /___/ / / / /_/ / / / / / /
    /_/  |_\___/\__/_/ |___/\___/_____/_/_/   \___/\___/\__/\____/_/   \__, /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                      /____/                             

|*----------------------------------------------------------------------------------------------------------*|

positional arguments:
  dc                    Hostname of the Domain Controller

optional arguments:
  -h, --help            show this help message and exit
  -o OUT_FILE, --out-file OUT_FILE
                        Path to output file. If no path, CWD is assumed
                        (default: Prints to stdout)
  -u USER, --user USER  Username of the domainuser to query with. The username
                        has to be domain name either by domain\user og
                        user@domain.org
  -c COMPUTER, --computer COMPUTER
                        Query specific computer (default: None)
  -s, --secure          Try to estalish connection through LDAPS
  -smb, --smb           Force enumeration of SMB shares onall computer objects
                        fetched
  -kp, --kerberos_preauth
                        Attempt to gather users that does not require Kerberos
                        preauthentication
  -bh, --bloodhound     Output data in the format expected by BloodHound
```

## Included attacks

- [x] ASREPRoasting
- [ ] Kerberoasting

## Be advised

- I haven't fully tested if SMB connection with `-smb` flag runs encrypted. Use at own risk
- The output harvested from AD is not yet mapped correctly to th BloodHound format. See code with `TODO's`

## Features list and status

- [ ] Finish mapping of JSON output to SharpHound3 format  
- [ ] Enumerate all SPNs for Kerberoasting  
- [ ] Check servername for service indication (e.g. FTP, MSSQL, Other DB, Exhange etc) to map technical landscape  
- [ ] Based upon above, enumerate the service indication for default login  
- [ ] Dump lowest Major OS servers (can we find Win2003, Win2008?)  
- [X] Connect through LDAPS
- [X] Bruteforce enumeration of SMB shares on all computer objects
- [ ] Output SMB Bruteforce enumetaion properly [see here](https://github.com/CasperGN/ActiveDirectoryEnumeration/blob/2585a91661ed8e344df8ea2ad95b5233c072fe38/activeDirectoryEnum.py#L421)
- [X] Get all users with `Kerberos preauthentication` not required and dump hashes
- [X] Write AD Object dump to raw file
- [ ] Fix [requirements.txt](requirements.txt) file, since not all the contained libs can be needed
- [ ] Test SMB connection for encryption [see here](https://github.com/CasperGN/ActiveDirectoryEnumeration/blob/2585a91661ed8e344df8ea2ad95b5233c072fe38/activeDirectoryEnum.py#L395)
- [ ] Query all users with an actual password set in the property `userPassword:`


## Collaboration

While this project is developed to fit my need, any collaboration is appriciated. Please feel free to fork the project, make changes according to the License agreements and make a Pull Request.
I only ask that:
- Keep equivilent naming standard as the base project
- Keep equivilent syntaxing
- Test your code
- Error handling is incorporated
- Document the feature - both in code but also for potential Wiki page

## Thanks & Acknowledgements

Big thanks to the creators of `Impacket` and `BloodHound`.
