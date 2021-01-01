---
title: "New Year CTF - Mess Me Writeup"
date: "2021-1-1"
layout: single
---

![messme](https://j.top4top.io/p_1827enp1i1.png)

| Details |                     |
| ------------- |:-------------:|
| Points        | 200           |
| Level         | hard     |
| Category      | Digital Forensics     |

# Mess Me


* Mess me is a Digital Forensics challenge was in New Year CTF which is an encrypted zip file with a password and had 2 files called flag.jpg and oracle.vdi 

* first i used john and alot of tools to crack the password but nothing worked but it was a Plaintext-Based Attack

# What is Plaintext-Based Attacks?

*  it's an attack model for cryptanalysis where the attacker has access to both the plaintext, and its encrypted version.

# Attacking the zip file

*i used bkcrack tool to start this attack but the attack requires at least 12 bytes of known plaintext. At least 8 of them must be contiguous. The larger the contiguous known plaintext, the faster attack.

so we have flag.jpg and oracle.vdi and we should get a known plaintext for them 

btw we can get a plaintext for the .vdi file using another vdi file so i already had a file called andro.vdi and i tried to read it

we got the first 20 bytes of "andro.vdi" 

![plaintextsucks](https://h.top4top.io/p_1827p1ph11.png)

* note : 12-byte encryption header in prepended to the data in the archive.
The last byte of the encryption header is the most significant byte of the file's CRC.

and we can get the CRC using this command

```bash
unzip -Z -v Challange.zip oracle.vdi | grep CRC
```

and the result was "f63e7666"

* now putting them together
```bash
echo -n -e "\xf6<<< Oracle VM VirtualBox Disk Image >>>" > plain.txt
```
and now let's run the attack
```bash
./bkcrack -C Challange.zip -c oracle.vdi -p plain.txt -o -1
```
after the tool finished i got this

![awesomebkcrack](https://e.top4top.io/p_1827rxm1v1.png)

now we have the keys, we can decipher the files

```bash
./bkcrack -C Challange.zip -c oracle.vdi -k be17a2b4 30cbf569 8b83cb3a  -d oracle.vdi
```

![lol](https://b.top4top.io/p_1827yn54t1.png)

we got the oracle.vdi finally now let's get the flag.jpg


![flag](https://c.top4top.io/p_1827dkqxy1.png)

* The file flag.jpg was compressed with the deflate algorithm in the zip file, so we now have to uncompressed it and we can use inflate.py that comes with bkcrack

```bash
python3 tools/inflate.py < flag.deflate > flag.png
```

and we got the flag :)

![flag](https://f.top4top.io/p_1827gegyz1.png)

* cheers!



