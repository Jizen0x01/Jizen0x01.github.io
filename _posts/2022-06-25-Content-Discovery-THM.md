---
title: "Content Discovery - THM"
date: "2022-06-25"
layout: single
---
Learn the various ways of discovering hidden or private content on a webserver that could lead to new vulnerabilities.

# Task 1: What Is Content Discovery?

Firstly, we should ask, in the context of web application security, what is content? Content can be many things, a file, video, picture, backup, a website feature. When we talk about content discovery, we're not talking about the obvious things we can see on a website; it's the things that aren't immediately presented to us and that weren't always intended for public access.

## What is the Content Discovery method that begins with M? 

- Manually

## What is the Content Discovery method that begins with A?

- Automated

## What is the Content Discovery method that begins with O?

- OSINT

***

# Task 2: Manual Discovery - Robots.txt

Open the link that gives u which is : (http://10.10.160.158/robots.txt)

We discoverd the "staff-portal" can't authorized to this page.

## What is the directory in the robots.txt that isn't allowed to be viewed by web crawlers?

- /staff-portal

***

# Task 3: Manual Discovery - Favicon

### favicon 
The favicon is a small icon displayed in the browser's address bar or tab used for branding a website.

` if the website developer doesn't replace this with a custom one, this can give us a clue on what framework is in use. `

Open this link in your browser : [https://static-labs.tryhackme.cloud/sites/favicon/](https://static-labs.tryhackme.cloud/sites/favicon/)

Now open the source code page of this website by hitting CTRL + U
We can see

```html

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Welcome to my webpage!</title>
    <link rel="shortcut icon" type="image/jpg" href="images/favicon.ico"/>
</head>
<body>
Website coming soon....
</body>
</html>
```

At line 7 we can see the favicon of this webpage
we can download the favicon by this line so we can find the md5 hash vlaue

```
curl https://static-labs.tryhackme.cloud/sites/favicon/images/favicon.ico | md5sum
```

Now we got the hash f276b19aabcb4ae8cda4d22625c6735f 
to find the framework that the website working with

visit this website [https://wiki.owasp.org/index.php/OWASP_favicon_database](https://wiki.owasp.org/index.php/OWASP_favicon_database)
then put the hash in the search bar.

Woop!! The result is **cgiirc**

## What framework did the favicon belong to?

- cgiirc

***

# Task 4: Manual Discovery - Sitemap.xml

the sitemap.xml file gives a list of every file the website owner wishes to be listed on a search engine.

Now we should take a look at sitemap.xml file on the Acme IT Support on link

[http://10.10.160.158/sitemap.xml](http://10.10.160.158/sitemap.xml)

we found this secret one **/s3cr3t-area**

What is the path of the secret area that can be found in the sitemap.xml file?

- /s3cr3t-area

***

# Task 5: Manual Discovery - HTTP Headers

When we make requests to the web server, the server returns various HTTP headers. These headers can sometimes contain useful information such as the webserver software and possibly the programming/scripting language in use

So we can Type the CURL Command to find the flag

```
curl http://10.10.160.158 -v
```

## What is the flag value from the X-FLAG header?

- THM{HEADER_FLAG}

***

# Task 6: Manual Discovery - Framework Stack

By looking for clues in the page source such as comments, copyright notices or credits, you can then locate the framework's website.

Open the page source so we can find a comment at the end of every page with a page load time and also a link to the framework's website, which is [https://static-labs.tryhackme.cloud/sites/thm-web-framework](https://static-labs.tryhackme.cloud/sites/thm-web-framework). Let's take a look at that website.

Once you opened the link click on the documentation page so you can find something useful ** /thm/framework**

so Now go to this page[http://10.10.160.158/thm-framework-login](http://10.10.160.158/thm-framework-login) and try this default credential

We found the flag!! 

## What is the flag from the framework's administration portal?

- THM{CHANGE_DEFAULT_CREDENTIALS}

***

# Task 7: OSINT - Google Hacking / Dorking

Google hacking / Dorking utilizes Google's advanced search engine features, which allow you to pick out custom content. 

## What Google dork operator can be used to only show results from a particular site?

- site:

***

# Task 8: OSINT - Wappalyzer

Wappalyzer [https://www.wappalyzer.com/](https://www.wappalyzer.com/) is an online tool and browser extension that helps identify what technologies a website uses, such as frameworks, Content Management Systems (CMS), payment processors and much more, and it can even find version numbers as well.

> try solve it :)

***

# Task: 10 OSINT - GitHub

> same as above :"

***

# Task 11: OSINT - S3 Buckets

S3 Buckets are a storage service provided by Amazon AWS, allowing people to save files and even static website content in the cloud accessible over HTTP and HTTPS.
The format of the S3 buckets is http(s)://{name}.s3.amazonaws.com where {name} is decided by the owner, such as tryhackme-assets.s3.amazonaws.com.

> do some research :)

***

# Task 12 Automated Discovery

We can fuzz the web app by many ways Choose your suitable way from these

### FFuF

```
ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://10.10.160.158/FUZZ
```

### DiRB

```
dirb http://10.10.160.158/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```

### GoBuster

```
gobuster dir --url http://10.10.160.158/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
```

## What is the name of the directory beginning "/mo...." that was discovered?

- /monthly

## What is the name of the log file that was discovered?

- /development.log


![We done here](https://media.giphy.com/media/3ofT5yFjWxh15lsl0s/giphy.gif)
