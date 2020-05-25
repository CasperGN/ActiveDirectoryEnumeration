[![GitHub stars](https://img.shields.io/github/stars/CasperGN/ActiveDirectoryEnumeration)](https://github.com/CasperGN/ActiveDirectoryEnumeration/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/CasperGN/ActiveDirectoryEnumeration)](https://github.com/CasperGN/ActiveDirectoryEnumeration/network)
[![Rawsec's CyberSecurity Inventory](https://inventory.rawsec.ml/img/badges/Rawsec-inventoried-FF5050_flat.svg)](https://inventory.rawsec.ml/tools.html#ActiveDirectoryEnumeration)
[![GitHub license](https://img.shields.io/github/license/CasperGN/ActiveDirectoryEnumeration)](https://github.com/CasperGN/ActiveDirectoryEnumeration/blob/master/LICENSE)
  
[![Packaging status](https://repology.org/badge/vertical-allrepos/activedirectoryenum.svg)](https://repology.org/project/activedirectoryenum/versions)  

## ADE - ActiveDirectoryEnum
```
usage: activeDirectoryEnum [-h] [-o OUT_FILE] [-u USER] [-s] [-smb] [-kp]
                           [-bh] [-spn] [--all] [--no-creds]
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
                        (default: None)
  -u USER, --user USER  Username of the domain user to query with. The
                        username has to be domain name as `user@domain.org`
  -s, --secure          Try to estalish connection through LDAPS
  -smb, --smb           Force enumeration of SMB shares on all computer
                        objects fetched
  -kp, --kerberos_preauth
                        Attempt to gather users that does not require Kerberos
                        preauthentication
  -bh, --bloodhound     Output data in the format expected by BloodHound
  -spn                  Attempt to get all SPNs and perform Kerberoasting
  -sysvol               Search sysvol for GPOs with cpassword and decrypt it
  --all                 Run all checks
  --no-creds            Start without credentials

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
