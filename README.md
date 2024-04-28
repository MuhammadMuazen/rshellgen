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
   (_O_O_O_O_O_O_O_O_O_O_O_)         _______________________________
    \/___________________\/         |                               |
    |_____________________|         |        avalible types         |
    | |                 | |         |_______________________________|
    | | rshellgen By:   | |         |               |               |
    | |                 | |         | bash-tcp      | bash-udp      |
    | |_MuhammadMuazen__| |         | perl-linux    | perl-win      |
    |/___________________\|         | py3-win       | py2-win       |
                                    | py3-linux     | php-exec (php)|
                                    | php-shellexec | php-system    |
                                    | php-passthru  | php-popen     |
                                    | ruby-linux    | ruby-win      |
                                    | rust          | go            |
                                    | powershell    | awk           |
                                    | java-linux    |java-thread-lin|
                                    | java-win      |java-thread-win|
                                    | lua-linux     | lua-win       |
                                    | nodejs-win    | nodejs-linux  |
                                    | c             | dart          |
                                    |_______________|_______________|

[+] Example: rshellgen.py -lh 192.168.1.2 -lp 4444 -t bash-tcp -e base64 -o reverse-shell.sh
```
---


