---
title: "CyberTalents Injector Machine Writeup"
date: "2020-12-13"
layout: single
---
![logo](https://k.top4top.io/p_18081y31k1.png)

Injector machine is an easy box with some good ideas.

By the way, I could not solve the machine through the vpn because of some problems, but I solved the machine through it's public IP which is 3.127.234.70

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
┌─[root@kali]─[~]
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
2020/12/13 16:51:38 Finished
===============================================================
```
