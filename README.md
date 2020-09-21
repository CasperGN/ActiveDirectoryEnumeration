[![GitHub stars](https://img.shields.io/github/stars/CasperGN/ActiveDirectoryEnumeration)](https://github.com/CasperGN/ActiveDirectoryEnumeration/stargazers) [![GitHub forks](https://img.shields.io/github/forks/CasperGN/ActiveDirectoryEnumeration)](https://github.com/CasperGN/ActiveDirectoryEnumeration/network) [![GitHub license](https://img.shields.io/github/license/CasperGN/ActiveDirectoryEnumeration)](https://github.com/CasperGN/ActiveDirectoryEnumeration/blob/master/LICENSE) [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FCasperGN%2FActiveDirectoryEnumeration.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FCasperGN%2FActiveDirectoryEnumeration?ref=badge_shield) [![Total alerts](https://img.shields.io/lgtm/alerts/g/CasperGN/ActiveDirectoryEnumeration.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/CasperGN/ActiveDirectoryEnumeration/alerts/) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/CasperGN/ActiveDirectoryEnumeration.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/CasperGN/ActiveDirectoryEnumeration/context:python) [![Pypi version](https://img.shields.io/pypi/v/activedirectoryenum.svg)](https://img.shields.io/pypi/v/activedirectoryenum.svg) [![PyPI downloads](https://img.shields.io/pypi/dm/activedirectoryenum.svg)](https://img.shields.io/pypi/dm/activedirectoryenum)
  
[![Packaging status](https://repology.org/badge/vertical-allrepos/activedirectoryenum.svg)](https://repology.org/project/activedirectoryenum/versions)  

## ADE - ActiveDirectoryEnum
```
 python -m ade
usage: ade [-h] [--dc DC] [-o OUT_FILE] [-u USER] [-s] [-smb] [-kp] [-bh] [-spn] [-sysvol] [--all] [--no-creds] [--dry-run]
           [--exploit EXPLOIT]

        ___        __  _            ____  _                __                   ______                    
       /   | _____/ /_(_)   _____  / __ \(_)_______  _____/ /_____  _______  __/ ____/___  __  ______ ___ 
      / /| |/ ___/ __/ / | / / _ \/ / / / / ___/ _ \/ ___/ __/ __ \/ ___/ / / / __/ / __ \/ / / / __ `__ \
     / ___ / /__/ /_/ /| |/ /  __/ /_/ / / /  /  __/ /__/ /_/ /_/ / /  / /_/ / /___/ / / / /_/ / / / / / /
    /_/  |_\___/\__/_/ |___/\___/_____/_/_/   \___/\___/\__/\____/_/   \__, /_____/_/ /_/\__,_/_/ /_/ /_/ 
                                                                      /____/                             

/*----------------------------------------------------------------------------------------------------------*/

optional arguments:
  -h, --help            show this help message and exit
  --dc DC               Hostname of the Domain Controller
  -o OUT_FILE, --out-file OUT_FILE
                        Path to output file. If no path, CWD is assumed (default: None)
  -u USER, --user USER  Username of the domain user to query with. The username has to be domain name as `user@domain.org`
  -s, --secure          Try to estalish connection through LDAPS
  -smb, --smb           Force enumeration of SMB shares on all computer objects fetched
  -kp, --kerberos_preauth
                        Attempt to gather users that does not require Kerberos preauthentication
  -bh, --bloodhound     Output data in the format expected by BloodHound
  -spn                  Attempt to get all SPNs and perform Kerberoasting
  -sysvol               Search sysvol for GPOs with cpassword and decrypt it
  --all                 Run all checks
  --no-creds            Start without credentials
  --dry-run             Don't execute a test but run as if. Used for testing params etc.
  --exploit EXPLOIT     Show path to PoC exploit code

```

The new inclusion of imbedded exploits can yield results such as:
```
...
[ WARN ] DC may be vulnerable to: [ cve-2020-1472 ]
...
```

To query an exploit do for PoC code:
```
$ python -m ade --exploit cve-2020-1472
Exploit for: cve-2020-1472 can be found at: https://github.com/dirkjanm/CVE-2020-1472
```

## Install

Run installation through pip3:
```
pip3 install ActiveDirectoryEnum
python -m ade
```
  
If you run BlackArch, ActiveDirectoryEnum is available through `pacman` as such:  
```
pacman -S activedirectoryenum
```  

## Included attacks/vectors

- [X] ASREPRoasting
- [X] Kerberoasting
- [X] Dump AD as BloodHound JSON files 
- [X] Searching GPOs in SYSVOL for cpassword and decrypting  
- [X] Run without creds and attempt to gather for further enumeration during the run
- [X] Sample exploits included:
 - CVE-2020-1472

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
`Impacket` [@github](https://github.com/SecureAuthCorp/impacket)
`BloodHound` [@github](https://github.com/BloodHoundAD/BloodHound)
`BloodHound.py` [@github](https://github.com/fox-it/BloodHound.py)
`CVE-2020-1472` by Tom Tervoort of [Secura](https://github.com/SecuraBV/CVE-2020-1472)

Without the above this wrapper was not possible.


## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FCasperGN%2FActiveDirectoryEnumeration.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FCasperGN%2FActiveDirectoryEnumeration?ref=badge_large)