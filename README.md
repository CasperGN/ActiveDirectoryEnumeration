## ADE - ActiveDirectoryEnum
```
usage: getAD-Computers [-h] [-o OUT_FILE] [-u USER] [-c COMPUTER] [-s] [-smb]
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
## Be advised

- I haven't fully tested if SMB connection with `-smb` flag runs encrypted. Use at own risk
- The output harvested from AD is not yet mapped correctly to th BloodHound format. See code with TODO's
