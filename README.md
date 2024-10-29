# RShellGen
#### rshellgen is a simple python reverse shell  generator that have most of the famous reverse shells out there.
___
## Note:
#### All the reverse shells are from:
https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/

---
## Usage:
```console
[+] Usage: rshellgen.py -lh <LHOST IP> -lp <LPORT> -t <reverse shell type> [-options]

        options:
                -h                  help for this script
                -o string           output to file to write result to
                -e <base64, url>    encode the payload in base64 OR URL encoding

                -t <shell type>

    _______________________
   (_O_O_O_O_O_O_O_O_O_O_O_)         ___________________________________________________
    \/___________________\/         |                                                   |
    |_____________________|         |                   Avalible Types                  |
    | |                 | |         |___________________________________________________|
    | | rshellgen By:   | |         |               |                   |               |
    | |                 | |         |   powershell  |   php-system      |   py3-win     |
    | |_MuhammadMuazen__| |         |   perl-win    |   php-popen       |   py2-win     |
    |/___________________\|         |   perl-lin    |   php-exec (php)  |   py3-lin     |
                                    |   bash-tcp    |   php-passthru    |   ruby-win    |
                                    |   bash-udp    |   php-shellexec   |   ruby-lin    |
                                    |   rust        |   java-thread-win |   java-win    |
                                    |   dart        |   java-thread-lin |   java-lin    |
                                    |   awk         |   nodejs-win      |   lua-win     |
                                    |   go          |   nodejs-lin      |   lua-lin     |
                                    |   c           |                   |               |
                                    |_______________|___________________|_______________|

[+] Example: rshellgen.py -lh 192.168.1.2 -lp 4444 -t bash-tcp -e base64 -o reverse-shell.sh
```
---


