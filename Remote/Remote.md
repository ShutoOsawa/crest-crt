#crest-crt #windows 

# Enumeration
## Nmap portscan

### Normal service scanning
```
nmap -sC -sV remote.htb 
Nmap scan report for remote.htb (10.129.79.142)
Host is up (0.18s latency).
Not shown: 993 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-13T04:33:07
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 185.12 seconds
                                                                
```

### Quick full scanning
```
nmap -p- --min-rate 10000 remote.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-13 00:00 EST
Warning: 10.129.79.142 giving up on port because retransmission cap hit (10).
Nmap scan report for remote.htb (10.129.79.142)
Host is up (0.18s latency).
Not shown: 63364 closed tcp ports (conn-refused), 2155 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
2049/tcp  open  nfs
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49678/tcp open  unknown
49679/tcp open  unknown
49680/tcp open  unknown
```

## Feroxbuster

`feroxbuster -u http://remote.htb -k`
```
200      GET      187l      490w     6693c http://remote.htb/
302      GET        3l        8w      126c http://remote.htb/install => http://remote.htb/umbraco/
200      GET      187l      490w     6703c http://remote.htb/home
302      GET        3l        8w      126c http://remote.htb/Install => http://remote.htb/umbraco/
500      GET       80l      276w     3420c http://remote.htb/product
200      GET      187l      490w     6703c http://remote.htb/Home
200      GET      129l      302w     5338c http://remote.htb/products
200      GET       95l      189w     4040c http://remote.htb/umbraco
200      GET      129l      302w     5338c http://remote.htb/Products
200      GET      137l      338w     5011c http://remote.htb/Blog
500      GET       80l      276w     3420c http://remote.htb/master
500      GET       80l      276w     3420c http://remote.htb/Product
200      GET      124l      331w     7880c http://remote.htb/Contact
302      GET        3l        8w      126c http://remote.htb/INSTALL => http://remote.htb/umbraco/
200      GET       81l      198w     2741c http://remote.htb/person
500      GET       80l      276w     3420c http://remote.htb/Master
200      GET      116l      222w     3313c http://remote.htb/Intranet
200      GET      167l      330w     6739c http://remote.htb/People
200      GET       81l      198w     2741c http://remote.htb/Person
200      GET      187l      490w     6693c http://remote.htb/%E2%80%8E
200      GET      187l      490w     6703c http://remote.htb/HOME
200      GET      137l      338w     5011c http://remote.htb/BLOG
200      GET      161l      428w     5451c http://remote.htb/About-Us
200      GET      123l      305w     4206c http://remote.htb/1111
200      GET      124l      331w     7890c http://remote.htb/CONTACT
200      GET      116l      222w     3323c http://remote.htb/INTRANET
200      GET      129l      302w     5338c http://remote.htb/PRODUCTS
500      GET       80l      276w     3420c http://remote.htb/PRODUCT
200      GET      167l      330w     6739c http://remote.htb/1116
200      GET       81l      201w     2752c http://remote.htb/1118
200      GET      116l      222w     3313c http://remote.htb/1148
200      GET       81l      201w     2750c http://remote.htb/1117
```

## Check the website - TCP port 80

Nothing interesting other than umbraco several places.

### Login page
`http://remote.htb/umbraco` takes us to the login page.
![[Pasted image 20230213135505.png]]

## Check ftp - TCP port 21

### connect to ftp
```
ftp remote.htb                                                  
Connected to remote.htb.
220 Microsoft FTP Service
Name (remote.htb:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
```
No data under root

## SMB - TCP port 445
### smbmap
```
smbmap -H remote.htb
[!] Authentication error on remote.htb
```

### smbclient
```
smbclient -N -L remote.htb
session setup failed: NT_STATUS_ACCESS_DENIED
```

## NFS - TCP port 2049
```
showmount -e remote.htb   
Export list for remote.htb:
/site_backups (everyone)
```

### Mount /site_backups on local machine
mount it on the kali machine so that we can enumerate it locally.
```
sudo mount -t nfs remote.htb:/site_backups /mnt/
```


### Check files
#### /mnt
web.config
```
cat Web.config | grep umbraco
                <sectionGroup name="umbracoConfiguration">
        <umbracoConfiguration>
                <settings configSource="config\umbracoSettings.config" />
        </umbracoConfiguration>
      https://our.umbraco.com/documentation/using-umbraco/config-files/#webconfig
                <add key="umbracoConfigurationStatus" value="7.12.4" />
                <add key="umbracoReservedUrls" value="~/config/splashes/booting.aspx,~/install/default.aspx,~/config/splashes/noNodes.aspx,~/VSEnterpriseHelper.axd,~/.well-known" />
                <add key="umbracoReservedPaths" value="~/umbraco,~/install/" />
                <add key="umbracoPath" value="~/umbraco" />
                <add key="umbracoHideTopLevelNodeFromPath" value="true" />
                <add key="umbracoUseDirectoryUrls" value="true" />
                <add key="umbracoTimeOutInMinutes" value="20" />
                <add key="umbracoDefaultUILanguage" value="en-US" />
                <add key="umbracoUseSSL" value="false" />
                <remove name="umbracoDbDSN" />
                <add name="umbracoDbDSN" connectionString="Data Source=|DataDirectory|\Umbraco.sdf;Flush Interval=1;" providerName="System.Data.SqlServerCe.4.0" />
                                <add tagPrefix="umbraco" namespace="umbraco.presentation.templateControls" assembly="umbraco" />
                        <add name="UmbracoModule" type="Umbraco.Web.UmbracoModule,umbraco" />
                                <add extension=".cshtml" type="umbraco.MacroEngines.RazorBuildProvider, umbraco.MacroEngines" />
                                <add extension=".vbhtml" type="umbraco.MacroEngines.RazorBuildProvider, umbraco.MacroEngines" />
                                <add extension=".razor" type="umbraco.MacroEngines.RazorBuildProvider, umbraco.MacroEngines" />
                        <add name="UmbracoModule" type="Umbraco.Web.UmbracoModule,umbraco" />
                  https://our.umbraco.com/documentation/Reference/Routing/IISRewriteRules
        <location path="umbraco">
```

Umbraco version 7.12.4

#### /mnt/App_Data

SDF is SQL Server Compact Database File, so it is interesting.
Umbraco.sdf
```
strings Umbraco.sdf                   
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
@{pv
qpkaj
dAc0^A\pW
(1&a$
"q!Q
umbracoDomains
domainDefaultLanguage
umbracoDomains
domainRootStructureID
umbracoDomains
domainName
umbracoDomains
PK_umbracoDomains
PK_umbracoDomains
umbracoDomains
PK_umbracoDomains
umbracoDomains
```

### Passwords

```
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
smithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749-a054-27463ae58b8e
ssmithsmith@htb.localjxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts={"hashAlgorithm":"HMACSHA256"}smith@htb.localen-US7e39df83-5e64-4b93-9702-ae257a9b9749
ssmithssmith@htb.local8+xXICbPe7m5NQ22HfcGlg==RF9OLinww9rd2PmaKUpLteR6vesD2MtFaBKe1zL5SXA={"hashAlgorithm":"HMACSHA256"}ssmith@htb.localen-US3628acfb-a62c-4ab0-93f7-5ee9724c8d32
```

```
admin:SHA1:b8be16afba8c314ad33d812f22a04991b90e2aaa
smith:HMACSHA256:jxDUCcruzN8rSRlqnfmvqw==AIKYyl6Fyy29KA3htB/ERiyJUAdpTtFeTpnIk9CiHts=
```

## Crack the hash

```
cat adminpass                                                     
b8be16afba8c314ad33d812f22a04991b90e2aaa
```

```
hashcat -m 100 adminpass /usr/share/wordlists/rockyou.txt --force
Dictionary cache building /usr/share/wordlists/rockyou.txt: 33553434 bytes (2Dictionary cache building /usr/share/wordlists/rockyou.txt: 100660302 bytes (Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

b8be16afba8c314ad33d812f22a04991b90e2aaa:baconandcheese   
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: b8be16afba8c314ad33d812f22a04991b90e2aaa
Time.Started.....: Mon Feb 13 00:26:55 2023, (2 secs)
Time.Estimated...: Mon Feb 13 00:26:57 2023, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3962.2 kH/s (0.08ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 9824256/14344385 (68.49%)
Rejected.........: 0/9824256 (0.00%)
Restore.Point....: 9823232/14344385 (68.48%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: bad_boy101 -> bacninh_kc
Hardware.Mon.#1..: Util: 67%

Started: Mon Feb 13 00:26:30 2023
Stopped: Mon Feb 13 00:26:58 2023
```

`baconandcheese` is the password.

# Foothold

## Login to the website as Admin

username admin does not work, but email address admin@local.htb works.

We can find the version under help after login as well.

## Searchsploit
We know the version, so we look for potential vulns.
```
searchsploit Umbraco 7.12.4
------------------------------------------- ---------------------------------
 Exploit Title                             |  Path
------------------------------------------- ---------------------------------
Umbraco CMS 7.12.4 - (Authenticated) Remot | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution | aspx/webapps/49488.py
------------------------------------------- ---------------------------------
Shellcodes: No Results
                            
```

Potential RCE.

### Save the exploits
`searchsploit -m 49488`
`searchsploit -m 46153`


