| Attack Types        | Description                                                    |
|---------------------|----------------------------------------------------------------|
| OS                  | Attacks that target default operating system settings         |
| App level           | Attacks that target application code                          |
| Shrink Wrap         | Attacks that target off-the-shelf scripts and code             |
| Misconfiguration    | Attacks that exploit poorly configured systems or applications |

| Penetration Phases    | Description                                                                                |
|-----------------------|--------------------------------------------------------------------------------------------|
| Reconnaissance         | The process of gathering information about the target system                              |
| Scanning & Enumeration | The process of identifying open ports, services, and vulnerabilities on the target system |
| Gaining Access         | The process of exploiting vulnerabilities to gain access to the target system             |
| Maintaining Access     | The process of maintaining access to the target system once access has been gained        |
| Covering Tracks        | The process of hiding evidence of the attack to avoid detection or attribution            |

# Legal
### 18 U.S.C 1029 & 1030
| Name | description |
| --- | --- |
| [RFC 1918 – Private IP Standard](https://en.wikipedia.org/wiki/Private_network) | SOX – Corporate Finance Processes |
| RFC 3227 – Collecting andstoring data | GLBA – Personal Finance Data |
| ISO 27002 – InfoSec Guideline | FERPA – Education Records
| CAN-SPAM – email marketing | FISMA – Gov Networks Security Std |
| SPY-Act – License Enforcement | CVSS – Common Vuln Scoring System |
| DMCA – Intellectual Property | CVE – Common Vulns and Exposure |

## Cryptography
| Type of Encryption | Description |
| --- | --- |
| Symmetric Encryption | Only one key is used to encrypt and decrypt |
| Asymmetric Encryption | Public key is used to encrypt, Private key is used to decrypt |

### Symmetric Algorithms
| Algorithm | Key Size | Block Size |
| --- | --- | --- |
| DES | 56-bit (8-bit parity) | Fixed block |
| 3DES | 168-bit | Keys ≤ 3 |
| AES | 128, 192, or 256 | Replaced DES |
| IDEA | 128-bit | - |
| Twofish | Block cipher key size ≤ 256-bit | - |
| Blowfish | Replaced by AES; 64-bit block | - |
| RC | Including RC2 -› RC6. 2,040 key, RC6 (128-bit block) | - |

### Asymmetric Algorithms
| Algorithm | Description |
| --- | --- |
| Diffie-Hellman | Key Exchange, used in SSL/IPSec |
| ECC | Elliptical Curve. Low process power/Mobile |
| EI Gamal | !=Primes, log problem to encrypt/sign |
| RSA | 2 x Prime 4,096-bit. Modern standard |

## Hash Algorithms
| Algorithm | Description |
| --- | --- |
| MD5 | 128-bit hash, expressed as 32-bit hex |
| SHA1 | 160-bit hash, widely used in US applications |
| SHA2 | Four separate hash algorithms with key sizes of 224, 256, 384, and 512 bits |

## Trust Models
| Model | Description |
| --- | --- |
| Web of Trust | Entities sign certs for each other |
| Single Authority | CA at top. Trust based on CA itself |
| Hierarchical | CA at top. RA’s under to manage certs |
| XMKS – XML PKI System | - |

## Cryptography Attacks
| Attack Type | Description |
| --- | --- |
| Known Plain-text | Search plaintext for repeatable sequences. Compare to t versions. |
| Ciphertext-only | Obtain several messages with the same algorithm. Analyze to reveal repeating code. |
| Replay | Performed in MITM. Repeat exchange to fool system in setting up a comms channel. |

## Digital Certificate
| Field | Description |
| --- | --- |
| Used to verify user identity | Nonrepudiation |
| Valid from/to | Certificate good through dates |
| Version | Identifies format. Common = V1 |
| Key usage | Shows for what purpose cert was made |
| Serial | Uniquely identify the certificate |
| Subject’s public key | Self-explanatory |
| Subject | Whoever/whatever being identified by cert |
| Optional fields | e.g., Issuer ID, Subject Alt Name... |
| Algorithm ID | Algorithm used |
| Issuer | Entity that verifies authenticity of certificate |

## Reconnaissance
| Term | Description |
| --- | --- |
| Reconnaissance | Gathering information on targets, whereas foot-printing is mapping out at a high level. These are interchangeable in C|EH. |
| Google Hacking | Operator: keyword additional search items. site: Search only within domain. ext: File Extension. loc: Maps Location. intitle: keywords in title tag of page. allintitle: any keywords can be in title. inurl: keywords anywhere in url. allinurl: any of the keywords can be in url. incache: search Google cache only. |
| DNS Record Types | Service (SRV): hostname & port # of servers. Start of Authority (SOA): Primary name server. Pointer (PTR): IP to Hostname; for reverse

# Reconnaissance
**Definition:** Gathering information on targets, whereas foot-printing is mapping out at a high level. These are interchangeable in C|EH.

## Google Hacking
| Operator | Keyword additional search items |
| --- | --- |
| `site:` | Search only within domain |
| `ext:` | File Extension |
| `loc:` | Maps Location |
| `intitle:` | Keywords in title tag of page |
| `allintitle:` | Any keywords can be in title |
| `inurl:` | Keywords anywhere in URL |
| `allinurl:` | Any of the keywords can be in URL |
| `incache:` | Search Google cache only |

## DNS Record Types
| Record Type | Description |
| --- | --- |
| Service (SRV) | Hostname & port # of servers |
| Start of Authority (SOA) | Primary name server |
| Pointer (PTR) | IP to hostname; for reverse DNS |
| Name Server (NS) | NameServers with namespace |
| Mail Exchange (MX) | E-mail servers |
| CNAME | Aliases in zone, lists multi services in DNS |
| Address (A) | IP to hostname; for DNS lookup |
| DNS footprinting | whois, nslookup, dig |

## TCP Header Flags

| Flag | Description |
| --- | --- |
| URG | Indicates data being sent out of band |
| ACK | Ack to, and after SYN |
| PSH | Forces delivery without concern for buffering |
| RST | Forces comms termination in both directions |
| SYN | Initial comms. Parameters and sequence #’s |
| FIN | Ordered close to communications |

## DNS
| Protocol/Port | Description |
| --- | --- |
| UDP Port 53 | nslookup |
| TCP Port 53 | Zone transfer |

## DHCP
| Step | Description |
| --- | --- |
| Client -> Discover -> Server | Client sends a broadcast message to discover available DHCP servers |
| Client <- Offers --- Server | DHCP server responds with an offer of configuration parameters |
| Client -> Request -> Server | Client sends a request to a chosen DHCP server |
| Client <- Acknowledgment (ACK) <- Server | DHCP server sends an acknowledgment to the client that the IP is reserved |
| IP is removed from pool | The IP address that was assigned to the client is removed from the pool of available addresses |

# Scanning & Enumeration

## ICMP Message Types
| Type | Description |
| --- | --- |
| 0 | Echo Reply: Answer to type 8 Echo Request |
| 3 | Destination Unreachable: No host/network codes |
| 4 | Source Quench: Congestion control message |
| 5 | Redirect: 2+ gateways for sender to use or the best route not the configured default gateway |
| 8 | Echo Request: Ping message requesting echo |
| 11 | Time Exceeded: Packet too long to be routed |

## CIDR
Method of representing IP addresses.

| IPv4 Notation | Subnet Mask       | # of Hosts |
|---------------|--------------------|------------|
| /30           | 255.255.255.252    | 4          |
| /28           | 255.255.255.240    | 16         |
| /26           | 255.255.255.192    | 64         |
| /24           | 255.255.255.0      | 256        |
| /22           | 255.255.252.0      | 1024       |
| /20           | 255.255.240.0      | 4096       |
| /16           | 255.255.0.0        | 65,536     |
| /14           | 255.252.0.0        | 262,144    |
| /12           | 255.240.0.0        | 1,048,576  |
| /10           | 255.192.0.0        | 4,194,304  |
| /8            | 255.0.0.0          | 16,777,216 |

To calculate a subnet mask for a given IPv4 address and prefix length, you can use the following formula: 
> subnet mask = 2^(32 - prefix length) - 1


## Port Numbers
| Range | Description |
| --- | --- |
| 0-1023 | Well-known |
| 1024-49151 | Registered |
| 49152-65535 | Dynamic |

## HTTP Error Codes
| Code | Name | Description |
|------|------|-------------|
| 100  | Continue | The server has received the request headers and the client should proceed to send the request body. |
| 200  | OK | The request was successful and the server has returned the requested data. |
| 302  | Found | The requested resource has been temporarily moved to a new URL. |
| 400  | Bad Request | The server could not understand the request due to invalid syntax or other client-side errors. |
| 404  | Not Found | The requested resource could not be found on the server. |
| 500  | Internal Server Error | The server encountered an unexpected error and could not fulfill the request. |


## Important Port Numbers
| Service | Port(s) |
| --- | --- |
| FTP | 20/21 |
| NetBIOS/SMB | 137-139 |
| SSH | 22 |
| IMAP | 143 |
| Telnet | 23 |
| SNMP | 161/162 |
| SMTP | 25 |
| LDAP | 389 |
| WINS | 42 |
| HTTPS | 443 |
| TACACS | 49 |
| CIFS | 445 |
| DNS | 53 |
| RADIUS | 1812 |
| HTTP | 80/8080 |
| RDP | 3389 |
| Kerberos | 88 |
| IRC | 6667 |
| POP3 | 110 |
| Printer | 515, 631, 9100 |
| Portmapper (Linux) | 111 |
| Tini | 7777 |
| NNTP | 119 |
| NetBus | 12345 |
| NTP | 123 |
| Back Orifice | 27374 |
| RPC-DCOM | 135 |
| Sub7 | 31337 |

# NMAP
Nmap is the de-facto tool for this pen-test phase.

## Nmap Scan Types
| Scan Type | Description | Open | Closed |
| --- | --- | --- | --- |
| TCP | 3-way handshake on all ports | SYN/ACK | RST/ACK |
| SYN | SYN packets to ports (incomplete handshake) | SYN/ACK | RST/ACK |
| FIN | Packet with FIN flag set | No response | RST |
| XMAS | Multiple flags set (FIN, URG, and PSH) Binary Header: 00101001 | No response | RST |
| ACK | Used for Linux/Unix systems | RST | No response |
| IDLE | Spoofed IP, SYN flag, designed for stealth | SYN/ACK | RST/ACK |
| NULL | No flags set. Responses vary by OS. Designed for Linux/Unix machines | N/A | N/A |

## Nmap Scan Options
| Option | Description |
| --- | --- |
| -sA | ACK scan |
| -sF | FIN scan |
| -sS | SYN scan |
| -sT | TCP scan |
| -sI | IDLE scan |
| -sn | PING sweep |
| -sN | NULL scan |
| -sS | Stealth scan |
| -sR | RPC scan |
| -Po | No ping |
| -sW | Window scan |
| -sX | XMAS tree scan |
| -PI | ICMP ping |
| -PS | SYN ping |
| -PT | TCP ping |
| -oN | Normal output |
| -oX | XML output |
| -A | OS/Vers/Script |
| -T<0-4> | Slow - Fast |

## SNMP
Uses a community string for PW. SNMPv3 encrypts the community strings.

## NETBIOS
| Command | Description |
| --- | --- |
| nbstat | |
| nbtstat -a COMPUTER | Shows details about the computer |
| nbtstat -S 10 -display ses stats every 10 sec | Displays session statistics |
| nbtstat -A 192.168.10.12 | Displays the remote table |
| nbtstat -n | Displays the local name table |
| nbtstat -c | Displays the local name cache |
| nbtstat -r -purge | Purges the name cache |

- 1B = master browser for the subnet
- 1C = domain controller
- 1D = domain master browser

# Sniffing and Evasion
## IPv4 and IPv6
- IPv4 = unicast, multicast, and broadcast
- IPv6 = unicast, multicast, and anycast
- IPv6 unicast and multicast scope includes link local, site local, and global.

## MAC Address
- First half = 3 bytes (24 bits) = Org UID
- Second half = unique number

## NAT (Network Address Translation)
- Basic NAT is a one-to-one mapping where each internal IP equals a unique public IP.
- NAT overload (PAT) = port address translation. Typically used as the cheaper option.

## Stateful Inspection
- Concerned with the connections.
- Doesn’t sniff every packet, it just verifies if it’s a known connection, then passes it along.

## HTTP Tunnelling
- Crafting of wrapped segments through a port rarely filtered by the Firewall (e.g., 80) to carry payloads that may otherwise be blocked.

## IDS Evasion Tactics
- Slow down or flood the network (and sneak through in the mix) or fragmentation.

## TCPDUMP Syntax
- `tcpdump flag(s) interface`

## Snort IDS
- It has three modes: Sniffer/Packet logger/Network IDS.
- Config file: /etc/snort or c:snortetc
- Example: `alert tcp!HOME_NET any ->$HOME_NET 31337 (msg : "BACKDOOR ATTEMPT-Back-orifice.")`
  - Any packet from any address != home network.
  - Using any source port, intended for an address in home network on port 31337, send msg.
- Span port = port mirroring
- False Negative: IDS incorrectly reports stream clean

## LM Hashing
- 7 spaces hashed: AAD3B435B51404EE

## SAM File
- `C:Windowssystem32config`

# Attacking a System
## C|EH Rules for Passwords
- Must not contain user’s name.
- Minimum of 8 characters.
- At least 3 of 4 complexity components (e.g., special characters, numbers, uppercase letters, lowercase letters).

## Attack Types
- Passive Online: Sniffing wire, intercept clean text password/replay/MITM
- Active Online: Password guessing.
- Offline: Steal copy of password i.e., SAM file. Cracking efforts on a separate system.
- Non-electronic: Social Engineering.

## Sidejacking
- Steal cookies exchanged between systems and use them to perform a replay-style attack.

## Session Hijacking
- Refers to the active attempt to steal an entire established session from a target.
1. Sniff traffic between client and server.
2. Monitor traffic and predict sequence.
3. Desynchronise session with client.
4. Predict session token and take over session.
5. Inject packets to the target server.

## Authentication Types
- Type 1: Something you know.
- Type 2: Something you have.
- Type 3: Something you are.

## Kerberos
- Kerberos makes use of symmetric and asymmetric encryption technologies and involves:
  - KDC: Key Distribution Centre.
  - AS: Authentication Service.
  - TGS: Ticket Granting Service.
  - TGT: Ticket Granting Ticket.
- Process:
1. Client asks KDC (who has AS and TGS) for ticket to authenticate throughout the network. This request is in clear text.
2. Server responds with secret key. Hashed by the password copy kept on AD server (TGT).
3. TGT sent back to server requesting TGS if user decrypts.
4. Server responds with ticket, and client can log on and access network resources.

# Registry
- Two elements make a registry setting: a key (location pointer) and value (define the key setting).
- Root-level keys include:
  - HKEY_LOCAL_MACHINE - Info on hard/software.
  - HKEY_CLASSES_ROOT - Info on file associations and Object Linking and Embedding (OLE) classes.
  - HKEY_CURRENT_USER - Profile info on current user.
  - HKEY_USERS - User config info for all active users.
  - HKEY_CURRENT-CONFIG - Pointer to hardware profiles.
  - HKEY_LOCAL-MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
  - HKEY_LOCAL-MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices
  - HKEY_LOCAL-MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
  - HKEY_LOCAL-MACHINE\Software\Microsoft\Windows\CurrentVersion\Run

# Social Engineering
## Human-Based Attacks
- Dumpster diving
- Impersonation
- Technical support
- Shoulder surfing
- Tailgating/piggybacking

## Computer-Based Attacks
| Threat                         | Description                                                                                                           |
|--------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| Phishing                       | Email scam that tricks users into divulging personal information or clicking on malicious links.                      |
| Whaling                        | Phishing attack that specifically targets high-ranking executives or other individuals with access to valuable data.  |
| Pharming                       | Malicious technique that redirects users to a fake website that looks like the real one.                               |
| Spear Phishing                 | Targeted phishing attack that focuses on a specific individual or organization.                                       |
| Vishing                        | Phone scam in which attackers impersonate legitimate organizations to obtain sensitive information.                    |
| Smishing                       | Phishing attack that uses SMS text messages instead of email.                                                          |
| Malware                        | Malicious software, including viruses, trojans, and ransomware, that can be spread through various channels.           |
| Denial-of-Service (DoS) attacks | Attack that overwhelms a server or network with traffic, making it unavailable to legitimate users.                    |
| Man-in-the-Middle (MITM) attacks | Attack that intercepts communication between two parties and can eavesdrop, modify, or inject messages.                 |
| SQL Injection                  | Attack that injects malicious SQL code into a vulnerable application to gain access to sensitive data or perform actions. |
| Cross-Site Scripting (XSS)     | Attack that injects malicious scripts into a web page, enabling an attacker to steal data or execute code on a victim's system. |
| DNS Spoofing                   | Attack that poisons the DNS cache to redirect traffic to a malicious website or server.                                |
| Watering Hole Attacks          | Attack that targets a specific group of users by infecting websites they frequently visit.                              |
| Advanced Persistent Threats (APTs) | Attack that gains unauthorized access to a network and stays undetected for a long time to steal sensitive data or perform malicious actions. |

## Types of Social Engineers
| Type of Social Engineer | Description |
|-------------------------|-------------|
| Insider associates      | Limited authorized access. |
| Insider affiliates      | Insiders by virtue of affiliation that spoof the identity of the insider. |
| Outsider affiliates     | Non-trusted outsider that use an access point that was left open. |
| Pretexters              | Uses a pretext to obtain information or access. Often poses as an authority figure or a trusted individual. |
| Phishers                | Use fraudulent emails, websites or other communications to trick individuals into divulging sensitive information. |
| Baiters                 | Leave a malware-infected device or piece of media in a public place, hoping someone will take the bait and plug it into their device. |
| Quid pro quo            | Offers a service or benefit in exchange for access to sensitive information. |
| Scareware artists       | Trick users into thinking their device is infected with malware, and then sell them a bogus security solution. |
| Human hackers           | Skilled social engineers who use a combination of tactics to gain access to sensitive information or systems. |

# Physical Security
| Category | Description |
| --- | --- |
| Physical measures | Things you can touch, taste, or smell that provide physical security, such as locks, fences, walls, and barriers. |
| Technical measures | Electronic systems and devices that provide security, such as access control systems, smart cards, and biometric scanners. |
| Operational measures | Policies, procedures, and training that ensure proper security protocols are followed, such as visitor management policies, security awareness training, and incident response plans. |
| Access control systems | Devices that restrict entry to physical spaces based on credentials like access cards, PINs, or biometrics. |
| CCTV | Closed circuit television systems that can monitor and record activity in physical spaces. |
| Locks and barriers | Physical locks, fences, walls, and other barriers that can help prevent unauthorized access to areas. |
| Lighting | Proper lighting that can deter intruders and help identify potential security threats. |
| Alarms | Security alarms that can alert staff or law enforcement of security breaches or other security threats. |
| Fire suppression | Fire suppression systems like sprinklers and fire alarms that can help prevent damage and loss from fires. |
| Backup power | Backup power systems like generators or uninterruptible power supplies that can help ensure that critical systems remain operational during power outages or other disruptions. |


# Web-Based Hacking
| Attack Technique | Description |
| --- | --- |
| Cross-Site Scripting (XSS) | Injecting malicious code into a web page that is then executed by unsuspecting users who visit the page. This can allow the attacker to steal sensitive information or take control of the victim's browser. |
| SQL Injection | Exploiting vulnerabilities in web applications that allow attackers to execute arbitrary SQL code against a database. This can allow the attacker to access, modify, or delete sensitive data. |
| Cross-Site Request Forgery (CSRF) | Forcing a user to perform actions on a web application without their knowledge or consent by exploiting their active session. This can allow the attacker to perform actions such as changing the user's password or making unauthorized transactions. |
| File Inclusion | Exploiting vulnerabilities in web applications that allow attackers to include and execute malicious code from remote servers. This can allow the attacker to execute arbitrary code on the server or steal sensitive information. |
| Directory Traversal | Exploiting vulnerabilities in web applications that allow attackers to access files or directories outside of the web root directory. This can allow the attacker to access sensitive files or execute arbitrary code on the server. |
| Clickjacking | Tricking a user into clicking on a button or link that performs an unintended action. This can allow the attacker to perform actions such as posting messages on the victim's social media account or making unauthorized purchases. |
| Remote Code Execution | Exploiting vulnerabilities in web applications that allow attackers to execute arbitrary code on the server. This can allow the attacker to take control of the server or steal sensitive information. |
| Variant of Unicode or un-validated input attack | Techniques that exploit the way web applications handle input data, such as using Unicode encoding or input validation bypass. |


## SQL INJECTION ATTACK TYPES
| Attack Type              | Description                                                                                                          |
|--------------------------|----------------------------------------------------------------------------------------------------------------------|
| Union Query              | Use the UNION command to return the union of the target database with a crafted database.                                     |
| Tautology                | Term used to describe the behavior of a database when deciding if a statement is true.                                        |
| Blind SQL Injection      | Trial and error with no responses or prompts.                                                                                 |
| Error-based SQL Injection| Enumeration technique. Inject poorly constructed commands to have the database respond with table names and other information.|


## BUFFER OVERFLOW
| Type              | Description                                                                                                          |
|-------------------|----------------------------------------------------------------------------------------------------------------------|
| Buffer Overflow   | A condition that occurs when more data is written to a buffer than it has space to store, resulting in data corruption. It is caused by insufficient bounds checking, a bug, or poor configuration in the program code. |
| Stack             | The premise is that all program calls are kept in a stack and performed in order. Attackers try to change a function pointer or variable to allow code execution. |
| Heap              | Takes advantage of memory "on top of" the application (dynamically allocated). Attackers use a program to overwrite function pointers. |
| NOP Sled          | Takes advantage of an instruction called "no-op." Attackers send a large number of NOP instructions into the buffer. Most IDS protect from this attack. |
| Dangerous SQL functions | The following do not check the size of destination buffers: gets(), strcpy(), strcat(), printf(). |


# Wireless Network Hacking
## WIRELESS SNIFFING
You need a Compatible wireless adapter with promiscuous mode is required, but otherwise pretty much the same as sniffing wired.
| 802.11 SPECIFICATIONS       | Description                                      |
|-----------------------------|--------------------------------------------------|
| WEP                         | RC4 with 24-bit vector. Keys are 40 or 104 bits. |
| WPA                         | RC4 supports longer keys; 48-bit IV.             |
| WPA/TKIP                    | Changes IV each frame and key mixing.            |
| WPA2                        | AES + TKIP features; 48-bit IV.                  |


| Spec | Distance | Speed | freq |
| --- | --- | --- | --- |
| 802.11a | 30m | 54 Mbps | 5GHz |
| 802.11b | 100m | 11 Mbps | 2.4 GHz |
| 802.11g | 100m | 54 Mbps | 2.4 GHz |
| 802.11n | 125m | 100 Mbps+ | 2.4/5GHz |

## BLUETOOTH ATTACKS
| Attack Type    | Description                                    |
|----------------|------------------------------------------------|
| Bluesmacking   | DoS against a device                           |
| Bluejacking    | Sending messages to/from devices               |
| Bluesniffing   | Sniffs for Bluetooth                           |
| Bluesnarfing   | Actual theft of data from a device             |


# Trojans and Other Attacks
## VIRUS TYPES
| Virus Type          | Description                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------------|
| Boot                | Moves boot sector to another location and is almost impossible to remove.                     |
| Camo                | Disguises itself as legitimate files to avoid detection.                                      |
| Cavity              | Hides in empty areas in an executable file.                                                   |
| Macro (or Script)   | Written in MS Office Macro Language and is embedded in documents like Word, Excel, or PPT.    |
| Multipartite        | Attempts to infect files and boot sector at the same time.                                    |
| Metamorphic         | Rewrites itself when it infects a new file, making it hard to detect.                         |
| Network             | Spreads via network shares and can infect other computers on the same network.                |
| Polymorphic         | Constantly changes its signature, making it hard to detect.                                   |
| Shell               | Like boot sector but wrapped around application code and run on application start.            |
| Stealth             | Hides in files and copies itself to deliver a payload                                         |


## DOS TYPES
| Attack Type    | Description                                                                                                                                           |
|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| SYN Attack     | Sends thousands of SYN packets with a false IP address, causing the target machine to attempt SYN/ACK response and engage all machine resources.          |
| SYN Flood      | Sends thousands of SYN packets but never responds to any of the returned SYN/ACK packets, causing the target machine to run out of available connections. |
| ICMP Flood     | Sends ICMP Echo packets with a fake source address, causing the target machine to attempt to respond but reach a limit of packets sent per second.        |
| Application-level | Sends "legitimate" traffic to a web application than it can handle, causing the target machine to become overwhelmed and unresponsive.                  |
| Smurf          | Sends a large number of pings to the broadcast address of the subnet with source IP spoofed to the target, causing the subnet to send ping responses to the target.   |
| Fraggle Attack | Similar to Smurf, but uses UDP instead of ICMP.                                                                                                       |
| Ping of Death  | Attacker fragments an ICMP message to send to the target, and when the fragments are reassembled, the resultant ICMP packet is larger than the max size and crashes the system. |

# Linux Commands
## LINUX FILE SYSTEM
| Path | Description |
| --- | --- |
| / | -Root |
| /var | -Variable Data / Log Files |
| /bin | -Biniaries / User Commands |
| /sbin | -Sys Binaries / Admin Commands |
| /root | -Home dir for root user |
| /boot | -Store kernel /proc -Direct access to kernel |
| /dev | -Hardware storage devices |
| /mnt | -Mount devices | 

## IDENTIFYING USERS AND PROCESSES
- INIT process ID 1
- Root UID, GID 0
- Accounts of Services 1-999
- All other users Above 1000

## PERMISSIONS
- 4 – Read
- 2 – Write
- 1 – Execute
- User/Group/Others
- 764 – User>RWX, Grp>RW, Other>R

## SNORT
- action protocol address port -> address port (option:value;option:value) 
- alert tcp 10.0.0.1 25 -> 10.0.0.2 25
- (msg:”Sample Alert”; sid:1000;)

# Command Line Tools
- **NMAP:** `nmap -ST -T5 -N -P 1-100 10.0.0.1`
- **Netcat:** `nc -v -z -w 2 10.0.0.1`
- **TCPdump:** `tcpdump -i eth0 -v -X ip proto 1`
- **Snort:** `snort -vde -c my.rules 1`
- **hping:** `hping3 -I -eth0 -c 10 -a 2.2.2.2 -t 100 10.0.0.1`
- **iptables:** `iptables -A FORWARD -j ACCEPT -p tcp ―dport 80`




# CEH Tools
## VULNERABILITY RESEARCH
| Tool               | Webpage                                                        | Category              | License          | OS Support                   | Language         | Release Date | Description                                                                                                                                                                                                                                                                                                     |
|--------------------|----------------------------------------------------------------|-----------------------|------------------|----------------------------|------------------|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Eccouncil.org      | https://www.eccouncil.org/                                     | Vulnerability Research | -                | -                            | -                | -            | The International Council of Electronic Commerce Consultants (EC-Council) is a global leader in cybersecurity education, training, and certification. Their website includes a variety of resources related to vulnerability research, including news, articles, and research papers.                                         |
| Exploit Database   | https://vulndb.cyberriskanalytics.com/                         | Vulnerability Research | Proprietary      | Web-based                    | -                | -            | The Exploit Database is a web-based tool that provides information on software vulnerabilities and exploits. It includes a searchable database of known vulnerabilities, as well as details on known exploits and proof-of-concept code. It is maintained by CyberRisk Analytics, a provider of cybersecurity risk intelligence services. |
| Metasploit         | https://www.metasploit.com/                                    | Penetration Testing   | BSD              | Linux, macOS, Windows, BSD | Ruby, C, C++, Lua | 2003         | Metasploit is a popular penetration testing framework that allows users to find vulnerabilities and test for exploits. It includes a database of known vulnerabilities and a suite of tools for conducting penetration tests.                                                                    |
| National Vuln Db   | https://nvd.nist.gov/                                          | Vulnerability Research | Public Domain    | Web-based                    | -                | -            | The National Vulnerability Database (NVD) is a comprehensive database of security vulnerabilities maintained by the National Institute of Standards and Technology (NIST). It includes information on known vulnerabilities, including severity ratings and recommended mitigation strategies.                                       |
| Nessus             | https://www.tenable.com/products/nessus-vulnerability-scanner | Vulnerability Scanning | Proprietary      | Linux, macOS, Windows       | -                | 1998         | Nessus is a popular vulnerability scanning tool that allows users to scan networks for vulnerabilities and assess their security posture. It includes a database of known vulnerabilities and a suite of tools for conducting vulnerability assessments.                                                        |
| Savvius            | https://www.savvius.com/                                       | Network Monitoring    | Proprietary      | Windows, macOS, Linux       | C++, Python       | -            | Savvius provides network performance and security solutions, including network monitoring and packet analysis tools. Its network monitoring tool, Omnipeek, includes features for troubleshooting and analyzing network traffic, detecting network security threats, and optimizing network performance.           |


## FOOT-PRINTING
### Website Research Tools
| Tool           | Webpage                                            | Category              | Description                                                                                                                                                                                                                                                                                                     |
|----------------|----------------------------------------------------|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Nslookup       | https://www.nslookup.io/                           | DNS and Whois Tool    | Nslookup is a command-line tool that can be used to query DNS servers for information such as IP addresses, domain names, and other DNS records.                                                                                                                                                                 |
| Sam Spacde     | https://samlabs.com/whois                          | DNS and Whois Tool    | Sam Spacde is a web-based tool that can be used to perform Whois lookups to get information about domain names, including registration details, IP addresses, and other DNS records.                                                                                                                           |
| ARIN           | https://www.arin.net/whois/                        | DNS and Whois Tool    | ARIN is a web-based tool that can be used to perform Whois lookups to get information about IP addresses and other network resources, including registration details, ownership information, and other DNS records.                                                                                                 |
| WhereisIP      | https://whatismyipaddress.com/ip-lookup            | DNS and Whois Tool    | WhereisIP is a web-based tool that can be used to perform IP address lookups to get information such as geolocation, ISP details, and other DNS records.                                                                                                                                                       |
| DNSstuff       | https://www.dnsstuff.com/                          | DNS and Whois Tool    | DNSstuff is a web-based tool that can be used to perform various DNS and network diagnostic tests, including DNS lookups, traceroutes, ping tests, and email verification. It includes both free and paid features, and is designed for both novice and advanced users.                                           |
| DNS-Digger     | https://www.epideme.com/digger/                    | DNS and Whois Tool    | DNS-Digger is a web-based tool that can be used to perform DNS lookups for a variety of record types, including A, AAAA, MX, NS, TXT, and more. It includes features such as query batching, wildcard support, and multiple DNS server selection.                                                              |
| MXtoolbox      | https://mxtoolbox.com/SuperTool.aspx                | DNS and Whois Tool    | MXtoolbox is a web-based tool that can be used to perform a variety of DNS and network diagnostic tests, including DNS lookups, blacklist checks, email verification, and more. It includes both free and paid features, and is designed for both novice and advanced users.                                  |
| Netcraft       | https://www.netcraft.com/                          | DNS and Whois Tool    | Netcraft is a web-based tool that can be used to perform various DNS and website-related diagnostic tests, including DNS lookups, website uptime monitoring, and phishing site detection. It includes both free and paid features, and is designed for both novice and advanced users.                  |
| Webmaster      | https://developers.google.com/search                | DNS and Whois Tool    | Webmaster is a web-based tool that can be used to perform various website-related diagnostic tests, including website indexing, search engine optimization, and security scanning. It includes both free and paid features, and is designed for both novice and advanced users.                     |
| Archive        | https://archive.org/                               | Website Mirroring Tool | Archive is a free and open-source website mirroring tool that can be used to download entire websites, including all files and subdirectories. It includes features for recursive downloads and automatic indexing of downloaded files.                                                                              |

### DNS and Whois Tools
| Tool           | Webpage | Category              | Description                                                                                                                                                                                                                                                                                                     |
|----------------|-------------|-----------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Nslookup       |             | DNS and Whois Tool    | Nslookup is a command-line tool that can be used to query DNS servers for information such as IP addresses, domain names, and other DNS records.                                                                                                                                                                 |
| Sam Spacde     | https://samlabs.com/whois       | DNS and Whois Tool    | Sam Spacde is a web-based tool that can be used to perform Whois lookups to get information about domain names, including registration details, IP addresses, and other DNS records.                                                                                                                           |
| ARIN           | https://www.arin.net/whois/     | DNS and Whois Tool    | ARIN is a web-based tool that can be used to perform Whois lookups to get information about IP addresses and other network resources, including registration details, ownership information, and other DNS records.                                                                                                 |
| WhereisIP      | https://whatismyipaddress.com/ip-lookup | DNS and Whois Tool    | WhereisIP is a web-based tool that can be used to perform IP address lookups to get information such as geolocation, ISP details, and other DNS records.                                                                                                                                                       |
| DNSstuff       |             | DNS and Whois Tool    | DNSstuff is a web-based tool that can be used to perform various DNS and network diagnostic tests, including DNS lookups, traceroutes, ping tests, and email verification. It includes both free and paid features, and is designed for both novice and advanced users.                                           |
| DNS-Digger     | https://www.epideme.com/digger/ | DNS and Whois Tool    | DNS-Digger is a web-based tool that can be used to perform DNS lookups for a variety of record types, including A, AAAA, MX, NS, TXT, and more. It includes features such as query batching, wildcard support, and multiple DNS server selection.                                                              |
| MXtoolbox      | https://mxtoolbox.com/SuperTool.aspx | DNS and Whois Tool    | MXtoolbox is a web-based tool that can be used to perform a variety of DNS and network diagnostic tests, including DNS lookups, blacklist checks, email verification, and more. It includes both free and paid features, and is designed for both novice and advanced users.                                  |

### Website Mirroring
| Tool          | GitHub page                                | Category              | Description                                                                                                                                                                                                                        |
|---------------|--------------------------------------------|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Wget          | https://github.com/mirror/wget             | Website Mirroring Tool | Wget is a free and open-source website mirroring tool that can be used to download entire websites, including all files and subdirectories. It includes features for recursive downloads, FTP/SSL support, and bandwidth throttling. |
| Archive       | https://web.archive.org/         | Website Mirroring Tool | Archive is a free and open-source website mirroring tool that can be used to download entire websites, including all files and subdirectories. It includes features for recursive downloads and automatic indexing of downloaded files.    |
| GoogleCache   |                                            | Website Mirroring Tool | GoogleCache is a website mirroring tool that can be used to access cached versions of websites stored by Google. It can be useful for accessing websites that are currently down or unavailable.                                           |


# SCANNING AND ENUMERATION
### Ping Sweep
| Tool                              | GitHub page                                | Category         | Description                                                                                                                                                                                                                          |
|-----------------------------------|--------------------------------------------|------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Angry IP Scanner                  | https://github.com/angryip/ipscan          | Ping Sweep Tool   | Angry IP Scanner is an open-source ping sweep tool that can be used to scan networks and identify live hosts. It includes features for both manual and automated testing, as well as reporting and exporting.                               |
| MegaPing                          | https://github.com/LanTricks/MegaPing      | Ping Sweep Tool   | MegaPing is a commercial ping sweep tool that can be used to scan networks and identify live hosts, as well as perform other network diagnostics such as port scanning and DNS resolution.                                           |
| Fping                             | https://github.com/schweikert/fping        | Ping Sweep Tool   | Fping is an open-source ping sweep tool that can be used to scan networks and identify live hosts. It includes features for both manual and automated testing, as well as reporting and exporting.                                        |
| Masscan                           | https://github.com/robertdavidgraham/masscan | Ping Sweep Tool   | Masscan is an open-source port scanner that can also be used for ping sweeps to identify live hosts on a network. It is optimized for high-speed scanning and can scan millions of IP addresses per hour.                              |
| SolarWinds Ping Sweep Tool        | https://www.solarwinds.com/free-tools/ping-sweep | Ping Sweep Tool   | SolarWinds Ping Sweep Tool is a free ping sweep tool that can be used to scan networks and identify live hosts. It includes features for both manual and automated testing, as well as reporting and exporting.                      |
| Advanced IP Scanner               | https://www.advanced-ip-scanner.com/        | Ping Sweep Tool   | Advanced IP Scanner is a free ping sweep tool that can be used to scan networks and identify live hosts. It includes features for both manual and automated testing, as well as reporting and exporting.                                 |

### Scanning Tools
| Tool               | Webpage                                                        | Category              | License     | OS Support    | Language   | Release Date | Description                                                                                                                                                                                                                                                           |
|--------------------|----------------------------------------------------------------|-----------------------|-------------|---------------|------------|--------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Nmap               | https://nmap.org/                                              | Network Scanning      | Open Source | Windows, Linux, macOS | C          | 2022-01-07   | Nmap is a powerful open-source network scanning tool that can be used to discover hosts and services on a network, as well as identify vulnerabilities and perform other security-related tasks.                                                                          |
| Nessus             | https://www.tenable.com/products/nessus                       | Vulnerability Scanning | Commercial  | Windows, Linux, macOS | C          | 2022-02-15   | Nessus is a popular commercial vulnerability scanner that can detect security vulnerabilities in systems and networks. It includes a variety of scanning options and features for reporting and analysis.                                                                    |
| Burp Suite         | https://portswigger.net/burp                                | Web Application Scanning | Commercial | Windows, Linux, macOS | Java       | 2022-02-09   | Burp Suite is a commercial web application scanning tool that can be used to test web applications for security vulnerabilities. It includes a variety of scanning and testing options, as well as features for reporting and analysis.                                       |
| Metasploit         | https://www.metasploit.com/                                    | Exploitation          | Open Source | Windows, Linux, macOS | Ruby       | 2022-01-12   | Metasploit is a popular open-source exploitation framework that can be used to test and exploit vulnerabilities in systems and networks. It includes a variety of payloads and modules for customizing and automating exploitation tasks.                                  |
| Shodan             | https://www.shodan.io/                                         | Search Engine         | Commercial  | Web-Based            | Python     | N/A          | Shodan is a commercial search engine that can be used to find internet-connected devices and services. It includes a variety of search filters and features for analyzing and reporting on search results.                                                                  |
| Wireshark          | https://www.wireshark.org/                                     | Packet Analysis       | Open Source | Windows, Linux, macOS | C, C++     | 2022-02-16   | Wireshark is a popular open-source packet analysis tool that can be used to capture, analyze, and troubleshoot network traffic. It includes a variety of filters and features for dissecting and interpreting network packets.                                             |
| OpenVAS            | http://www.openvas.org/                                        | Vulnerability Scanning | Open Source | Linux                 | C          | 2022-02-21   | OpenVAS is an open-source vulnerability scanner that can detect security vulnerabilities in systems and networks. It includes a variety of scanning options and features for reporting and analysis.                                                                      |
| John the Ripper    | https://www.openwall.com/john/                                 | Password Cracking     | Open Source | Windows, Linux, macOS | C          | 2022-01-18   | John the Ripper is an open-source password cracking tool that can be used to test and crack password hashes. It includes a variety of cracking modes and options for customizing and optimizing cracking tasks.                                                          |
| SQLMap             | http://sqlmap.org/                                             | SQL Injection         | Open Source | Windows, Linux, macOS | Python     | 2022-02-17   | SQLMap is an open-source SQL injection tool that can be used to test web applications



### War Dialing
| Tool          | GitHub page                                           | Category         | Description                                                                                                                                                                                                                                      |
|---------------|-------------------------------------------------------|------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| THC-Scan      | https://github.com/vanhauser-thc/thc-scan              | War Dialing Tool | THC-Scan is an open-source war dialing tool that can be used to scan phone numbers and identify those that are connected to modems, fax machines, or other devices that can be exploited for unauthorized access.                                        |
| TeleSweep     | https://github.com/hackerspider1/TeleSweep             | War Dialing Tool | TeleSweep is an open-source war dialing tool that can be used to scan phone numbers and identify those that are connected to voice mailboxes or other automated systems that can be exploited for unauthorized access.                                |
| ToneLoc       | https://github.com/crmulliner/toneloc                  | War Dialing Tool | ToneLoc is an open-source war dialing tool that can be used to scan phone numbers and identify those that are connected to modems or other devices that can be exploited for unauthorized access.                                                       |
| WarVox        | https://github.com/rapid7/warvox                      | War Dialing Tool | WarVox is an open-source war dialing tool that can be used to scan phone numbers and identify those that are connected to voice mailboxes or other automated systems that can be exploited for unauthorized access. It can also perform audio analysis. |
| Banner Grabbing |                                                     | Information Gathering Tool | Banner grabbing tools can be used to gather information about networked services, including the software version, operating system, and other identifying information.                                                                                |
| Telnet        | https://github.com/willsteel/telnet-iot-scanner        | Banner Grabbing Tool | Telnet is a protocol used for remote access to command-line interfaces on networked devices. Telnet banner grabbing tools can be used to gather information about networked devices that support Telnet, including the software version and other identifying information. |
| ID Serve      | https://github.com/nowsecure/id-serve                  | Banner Grabbing Tool | ID Serve is an open-source banner grabbing tool that can be used to gather information about networked services, including the software version, operating system, and other identifying information.                                                   |
| Netcraft      |                                                     | Banner Grabbing Tool | Netcraft is a commercial banner grabbing tool that can be used to gather information about networked services, including the software version, operating system, and other identifying information.                                                |
| Xprobe        | https://github.com/neuroo/xprobe2                      | Banner Grabbing Tool | Xprobe is an open-source banner grabbing tool that can be used to gather information about networked services, including the software version, operating system, and other identifying information.                                                  |


### Vulnerability Scanning
| Tool              | GitHub page                                               | Category              | Description                                                                                                                                                                                                                                                         |
|-------------------|-----------------------------------------------------------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Nessus            | https://github.com/tenable/nessus-core                      | Vulnerability Scanner  | Nessus is a commercial vulnerability scanner that can detect security vulnerabilities in systems and networks.                                                                                                                                                      |
| SAINT             | https://github.com/securestate/saint                        | Vulnerability Scanner  | SAINT is a commercial vulnerability scanner that can detect security vulnerabilities in systems and networks.                                                                                                                                                        |
| Retina            | https://github.com/BeyondTrust/RetinaNetworkCommunity       | Vulnerability Scanner  | Retina is a commercial vulnerability scanner that can detect security vulnerabilities in systems and networks.                                                                                                                                                       |
| Core Impact       |                                                           | Exploitation Tool      | Core Impact is a commercial penetration testing tool that can exploit vulnerabilities in systems and networks.                                                                                                                                                       |
| Nikto             | https://github.com/sullo/nikto                             | Web Application Scanner | Nikto is an open-source web server scanner that can detect security vulnerabilities in web servers and applications.                                                                                                                                                |
| Network Mapping   |                                                           | Network Mapping Tool   | Network mapping tools can scan and map networks, including the devices and hosts connected to them.                                                                                                                                                                   |
| NetMapper         | https://github.com/bryanb/netmapper                        | Network Mapping Tool   | NetMapper is an open-source network mapping tool that can scan and map networks, including the devices and hosts connected to them.                                                                                                                                    |
| LANState          |                                                           | Network Mapping Tool   | LANState is a commercial network mapping tool that can scan and map networks, including the devices and hosts connected to them.                                                                                                                                      |
| IPSonar           | https://github.com/justaguysecurity/IPSonar                 | Network Mapping Tool   | IPSonar is an open-source network mapping tool that can scan and map networks, including the devices and hosts connected to them.                                                                                                                                     |
| Proxy, Anonymizer, and Tunneling |                                        | Proxy and Tunneling Tool | Proxy, anonymizer, and tunneling tools can be used to bypass firewalls and access blocked content by hiding the user's IP address and/or encrypting their traffic.                                                                                                     |
| Tor               | https://github.com/torproject/tor                           | Anonymizer Tool        | Tor is a free and open-source anonymizer tool that can be used to browse the internet anonymously by routing traffic through a series of servers.                                                                                                                         |
| ProxySwitcher     | https://github.com/proxyswitcher/proxyswitcher              | Proxy Tool             | ProxySwitcher is a commercial proxy tool that can be used to manage and switch between multiple proxies.                                                                                                                                                               |
| ProxyChains       | https://github.com/haad/proxychains-ng                      | Proxy Tool             | ProxyChains is an open-source proxy tool that can be used to tunnel any application through one or more proxy servers.                                                                                                                                                 |
| SoftCab           | https://github.com/SoftCab/SoftCab.ProxyClient              | Proxy Tool             | SoftCab is a commercial proxy tool that can be used to manage and switch between multiple proxies.                                                                                                                                                                      |
| HTTP Tunnel       |                                                           | Tunneling Tool         | HTTP Tunnel is an open-source tunneling tool that can be used to tunnel any application through an HTTP proxy.                                                                                                                                                       |
| Anonymouse        |                                                           | Anonymizer Tool        | Anonymouse is a free web-based anonymizer tool that can be used to browse the internet anonymously by hiding the user's IP address.                                                                                                                                    
| Enumeration       |                                                           | Enumeration Tool       | Enumeration tools are used to gather information about systems, networks, or applications, often for the purpose of penetration testing.                                                                                                                             |
| SuperScan         | https://github.com/nettitude/Nettitude_SuperScan            | Network Scanning Tool  | SuperScan is a free and open-source network scanning tool that can scan networks and identify open ports and services on target systems.                                                                                                                              |
| User2Sid/Sid2User | https://github.com/SecureAuthCorp/impacket                  | Enumeration Tool       | User2Sid/Sid2User is an open-source enumeration tool that can be used to convert between usernames and security identifiers (SIDs) in Windows Active Directory environments.                                                                                        |
| LDAP Admin        |                                                           | Enumeration Tool       | LDAP Admin is a free and open-source tool for managing Lightweight Directory Access Protocol (LDAP) directories. It can be used to browse, search, and modify LDAP directories.                                                                                      |
| Xprobe            | https://github.com/neuroo/xprobe2                          | Enumeration Tool       | Xprobe is an open-source enumeration tool that can be used to fingerprint target systems and identify the operating system, applications, and services running on them.                                                                                                 |
| Hyena             |                                                           | Enumeration Tool       | Hyena is a commercial tool for managing Windows systems and Active Directory domains. It includes features for system administration, management, and reporting.                                                                                                     |
| SNMP Enumeration  |                                                           | Enumeration Tool       | SNMP enumeration tools can be used to gather information about devices on a network that support the Simple Network Management Protocol (SNMP).                                                                                                                        |
| SolarWinds        |                                                           | Enumeration Tool       | SolarWinds is a suite of commercial tools for managing IT infrastructure, including network and system monitoring, configuration management, and security management.                                                                                               |
| SNMPUtil          | https://github.com/mdlayher/snmp                           | Enumeration Tool       | SNMPUtil is an open-source tool for querying devices on a network that support the Simple Network Management Protocol (SNMP). It can be used to gather information about system configurations, performance, and other statistics.                                        |
| SNMPScanner       | https://github.com/10se1ucgo/snmpscan                      | Enumeration Tool       | SNMPScanner is an open-source tool for scanning networks for devices that support the Simple Network Management Protocol (SNMP). It can be used to gather information about system configurations, performance, and other statistics.                                    |

## SYSTEM HACKING TOOLS
### Password Hacking
| Tool Name              | Website                              | CLI Examples                                | Input File            |
| -----------------------|---------------------------------------|--------------------------------------------|-----------------------|
| Cain                   | http://www.oxid.it/cain.html          | cain.exe -r capturefile.cap                | capturefile.cap       |
| John the Ripper        | https://www.openwall.com/john/         | john --wordlist=password.txt hashfile.txt | password.txt, hashfile.txt |
| LCP                    | https://www.lcpsoft.com/              | lcp.exe -dumpsam                              | None                  |
| THC-Hydra              | https://github.com/vanhauser-thc/thc-hydra | hydra -l username -P passwordlist.txt -vV -e ns targetIP http-get /admin | passwordlist.txt       |
| ElcomSoft              | https://www.elcomsoft.com/            | elcomsoft.exe -p passwordfile.txt hashfile.txt | passwordfile.txt, hashfile.txt |
| Aircrack               | https://www.aircrack-ng.org/          | aircrack-ng -w wordlist -b BSSID capturefile.cap | wordlist, capturefile.cap |
| Rainbow Crack          | https://project-rainbowcrack.com/     | rainbowcrack.exe LM_hash.txt rainbow_table.rt | LM_hash.txt, rainbow_table.rt |
| Brutus                 | https://www.hoobie.net/brutus/        | brutus.exe -u username -p passwordfile.txt -x service -s port | passwordfile.txt       |
| KerbCrack              | https://www.tarlogic.com/en/tools/kerbcrack/ | kerbcrack.exe -d targetdomain -u username -p passwordfile.txt | passwordfile.txt       |
| CUPP - Common User Passwords Profiler | https://github.com/Mebus/cupp  | python3 cupp.py -i                | None                  |
| Mentalist              | https://github.com/sc0tfree/mentalist | python3 mentalist.py -i passwordlist.txt -b md5 | passwordlist.txt |
| Hashcat                | https://hashcat.net/hashcat/          | hashcat -m 0 -a 0 hashfile.txt wordlist.txt | hashfile.txt, wordlist.txt |
| Kali linux             | https://www.kali.org/                | john --wordlist=/usr/share/wordlists/rockyou.txt.gz hashfile.txt | /usr/share/wordlists/rockyou.txt.gz, hashfile.txt |

### Sniffing
| Tool Name   | Website                            | CLI Examples                            | Description                                        |
|-------------|------------------------------------|-----------------------------------------|----------------------------------------------------|
| Wireshark   | https://www.wireshark.org/         | wireshark -i eth0                       | Network protocol analyzer and packet sniffer       |
| Ace         | https://github.com/ustayready/ace  | ace --iface eth0 --pcap-file capture.pcap | Sniffs for passwords on the local network           |
| KerbSniff   | https://www.tarlogic.com/en/tools/kerbsniff/ | kerbsniff.exe -i interface_name          | Kerberos packet sniffer and password harvesting tool |
| Ettercap    | https://ettercap.github.io/ettercap/ | ettercap -T -q -i eth0                  | Comprehensive suite for man-in-the-middle attacks   |

### Keyloggers and Screen Capture
| Tool Name          | Website                            | Description                                                  |
|--------------------|------------------------------------|--------------------------------------------------------------|
| KeyProwler         | https://www.keyprowler.com/        | Keylogger and activity monitoring software for Windows       |
| Ultimate Keylogger | https://ultimatekeylogger.com/     | Keylogger and activity monitoring software for Windows       |
| All in one Keylogger | https://www.relytec.com/          | Keylogger and activity monitoring software for Windows       |
| Actual Spy         | https://www.actualspy.com/         | Keylogger and screen capture software for Windows            |
| Ghost              | https://www.ghostmonitor.com/      | Keylogger and activity monitoring software for Windows       |
| Hidden Recorder    | https://hiddenrecorder.net/        | Keylogger and screen capture software for Windows            |
| Desktop Spy        | https://www.spyarsenal.com/desktop-spy/ | Keylogger and screen capture software for Windows            |
| USB Grabber        | https://www.usbgrabber.com/        | Keylogger and USB activity monitoring software for Windows   |


### Privilege Escalation
#### Password Recovery Boot Disk
| Tool Name          | Website                            | Description                                                  |
|--------------------|------------------------------------|--------------------------------------------------------------|
| Offline NT Password & Registry Editor | http://pogostick.net/~pnh/ntpasswd/ | Bootable utility to reset Windows passwords                     |
| Trinity Rescue Kit | https://trinityhome.org/           | Bootable Linux distribution for system rescue, password resetting and file recovery |
| Ophcrack           | https://ophcrack.sourceforge.io/  | Bootable utility for recovering Windows passwords using rainbow tables |

#### Password Reset
| Tool Name          | Website                            | Description                                                  |
|--------------------|------------------------------------|--------------------------------------------------------------|
| PCUnlocker         | https://www.top-password.com/      | Windows password reset tool with bootable CD/DVD/USB option  |
| Password Resetter  | https://www.passwordresetter.com/  | Windows password reset tool with bootable CD/DVD option       |
| PassMoz LabWin     | https://www.passmoz.com/           | Windows password reset tool with bootable USB option          |

#### Password Recovery
| Tool Name          | Website                            | Description                                                  |
|--------------------|------------------------------------|--------------------------------------------------------------|
| PassFab            | https://www.passfab.com/           | Password recovery software for Windows, Office and other programs |
| LCP                | https://www.lcpsoft.com/           | Windows password recovery tool with local and remote password hash retrieval |
| Cain and Abel      | http://www.oxid.it/cain.html       | Password recovery and auditing tool for Windows |

#### System Recovery
| Tool Name          | Website                            | Description                                                  |
|--------------------|------------------------------------|--------------------------------------------------------------|
| SystemRescueCD     | https://www.system-rescue-cd.org/  | Bootable Linux distribution for system rescue and recovery    |
| Acronis True Image | https://www.acronis.com/en-us/home/ | Backup and recovery software with system imaging and cloning |
| Clonezilla         | https://clonezilla.org/            | Bootable partition and disk imaging/cloning program           |

### Executing Applications
| Tool Name   | Website                            | Description                                                  |
|-------------|------------------------------------|--------------------------------------------------------------|
| PDQ Deploy  | https://www.pdq.com/pdq-deploy/   | Software deployment tool for Windows                           |
| RemoteExec  | https://www.isdecisions.com/remoteexec/ | Remote execution tool for Windows                         |
| Dameware    | https://www.dameware.com/          | Remote administration tool for Windows                         |

### Spyware
| Tool Name           | Website                            | Description                                                  |
|---------------------|------------------------------------|--------------------------------------------------------------|
| Remote Desktop Spy  | https://www.spytech-web.com/remote-desktop-spy.shtml | Spyware that allows remote viewing of desktop activity |
| Activity Monitor    | https://www.softactivity.com/      | Monitoring software that records all user activities         |
| OSMonitor           | https://www.os-monitor.com/        | Employee monitoring and surveillance software for Windows     |
| SSPro               | https://www.sspro.com/             | Computer monitoring software for Windows and Mac             |
| Spector Pro         | https://spectorsoft.com/           | Computer monitoring and surveillance software for Windows     |

### Covering Tracks
| Tool Name            | Website                            | Description                                                  |
|----------------------|------------------------------------|--------------------------------------------------------------|
| ELsave               | http://www.theonespy.com/elsave/   | Tool that hides files and folders on a Windows system         |
| Cleaner              | https://www.stevengould.org/       | Utility to clean temporary and unused files from a Windows system |
| EraserPro            | https://www.heidi.ie/eraser/       | Open source secure data removal tool for Windows              |
| Evidence Eliminator  | N/A                                | Tool for removing sensitive files and data from a Windows system |

### Packet Craftin/Spoofing
| Tool Name     | Website                            | Description                                                  |
|---------------|------------------------------------|--------------------------------------------------------------|
| Komodia       | http://www.komodia.com/            | Tool for intercepting and modifying network traffic           |
| Hping2        | https://github.com/antirez/hping   | Command-line packet crafting tool for network testing         |
| PackEth       | https://sourceforge.net/projects/packeth/ | GUI-based packet crafting tool for Windows and Linux   |
| Packet Generator | https://github.com/saminiir/packet-generator | Command-line packet crafting tool for Linux and macOS |
| Netscan       | https://www.softperfect.com/products/networkscanner/ | Network scanner and packet crafting tool for Windows |
| Scapy         | https://scapy.net/                 | Interactive packet crafting tool for Python                   |
| Nemesis       | https://github.com/libnet/nemesis  | Command-line packet crafting and injection tool for Linux     |

### Session Hijacking
| Tool Name    | Website                            | Description                                                  |
|--------------|------------------------------------|--------------------------------------------------------------|
| Paros Proxy  | http://www.parosproxy.org/         | Java-based web application security assessment tool           |
| Burp Suite   | https://portswigger.net/burp       | Comprehensive web application security assessment tool        |
| Firesheep    | https://github.com/codebutler/firesheep | Firefox extension for session hijacking attacks          |
| Hamster/Ferret | https://www.bytepioneers.com/hamster/ | Session hijacking tools for Linux and Windows           |
| Ettercap     | https://www.ettercap-project.org/   | Comprehensive suite for man-in-the-middle attacks and packet sniffing |
| Hunt         | https://github.com/bugcrowd/HUNT | Command-line tool for web application reconnaissance and vulnerability scanning |


## API Research Sites
| Google Search Query                                | Description                                                                                                           |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `inurl:"/wp-json/wp/v2/users"`                     | Finds all publicly available WordPress API user directories.                                                          |
| `intitle:"index.of" intext:"api.txt"`              | Finds publicly available API key files.                                                                               |
| `inurl:"/api/v1" intext:"index of /"`              | Finds potentially interesting API directories.                                                                        |
| `ext:php inurl:"api.php?action="`                  | Finds all sites with a XenAPI SQL injection vulnerability.                                                            |
| `intitle:"index of" api_key OR "api key" OR apiKey -pool` | Lists potentially exposed API keys.                                                                                   |

- [apis.guru](https://apis.guru)
- [Github](https://github.com) // Try using parameters such as:filename:swagger.json or extension:.json

## CRYPTOGRAPHY AND ENCRYPTION
| Tool Name      | Website                            | Description                                                  |
|----------------|------------------------------------|--------------------------------------------------------------|
| Encryption     | N/A                                | Built-in encryption functionality in various operating systems |
| TrueCrypt      | https://www.truecrypt71a.com/      | Open source disk encryption software for Windows, Linux and macOS |
| BitLocker      | https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-overview | Built-in disk encryption feature in Windows operating systems |
| DriveCrypt     | https://www.securstar.com/en/home/products/drivecrypt/overview/ | Commercial disk encryption software for Windows              |
| EZStego        | https://sourceforge.net/projects/ezstego/ | Steganography tool for hiding data inside image files        |
| OmniHidePro    | https://www.omnihil.com/omnihidepro.html | Steganography tool for hiding data inside image and audio files |
| Cryptanalysis  | N/A                                | Techniques for deciphering encrypted messages without knowing the key |
| Cryptobench    | https://www.cryptobench.com/       | Tool for benchmarking encryption algorithms and ciphers       |

### Hash Tools
| Tool Name         | Website                            | Description                                                  |
|-------------------|------------------------------------|--------------------------------------------------------------|
| MD5 Hash          | N/A                                | Hash function commonly used for data integrity verification   |
| Hash Calc         | https://github.com/mkaring/HashCalc | Windows-based hash calculation utility                       |
| Steganography     | N/A                                | Techniques for hiding data within images, audio, or other files |
| XPTools           | N/A                                | Collection of Windows security tools                           |
| ImageHide         | http://www.mnhinc.com/ImageHide.htm | Steganography tool for hiding data within image files         |
| Merge Streams     | https://github.com/stefano-m/lwsm | Tool for merging multiple data streams                          |
| StegParty         | https://github.com/abeluck/stegparty | Command-line steganography tool for Linux and macOS          |
| gifShuffle        | https://github.com/quiet/gifshuffle | Command-line tool for steganography in GIF files              |
| QuickStego        | https://www.quickcrypto.com/quickstego/ | Steganography tool for hiding data within image and audio files |
| InvisibleSecrets  | https://www.invisiblesecrets.com/  | Steganography and encryption software for Windows             |


## SNIFFING
### Packet Capture
| Tool Name  | Website                          | Description                                                      |
|------------|----------------------------------|------------------------------------------------------------------|
| Wireshark  | https://www.wireshark.org/      | Popular network protocol analyzer and packet sniffer             |
| CACE       | https://www.winpcap.org/windump/ | Windows-based packet analyzer and capture utility                |
| tcpdump    | https://www.tcpdump.org/         | Command-line network protocol analyzer and packet sniffer        |
| Capsa      | https://www.colasoft.com/capsa/  | Network analyzer and packet sniffer for Windows-based networks   |
| OmniPeek   | https://www.liveaction.com/      | Comprehensive network analyzer and packet sniffer for Windows    |
| Windump    | https://www.winpcap.org/windump/ | Command-line network protocol analyzer and packet sniffer        |
| dnsstuff   | https://www.dnsstuff.com/       | Online network tool suite for DNS analysis and troubleshooting  |
| EtherApe   | https://etherape.sourceforge.io/ | Graphical network monitor and protocol analyzer for Unix-based systems |
| Wireless   | https://www.aircrack-ng.org/     | Wireless network security auditing and cracking tools            |
| Kismet     | https://www.kismetwireless.net/ | Wireless network detector, sniffer, and intrusion detection system |
| Netstumbler | N/A                             | Windows-based wireless network discovery and mapping tool        |

### MAC Flooding/Spoofing
| Tool Name          | Website                                | Description                                                  |
|--------------------|----------------------------------------|--------------------------------------------------------------|
| Macof              | N/A                                    | Tool for flooding switches with fake MAC addresses            |
| SMAC               | https://www.klcconsulting.net/smac/    | MAC address spoofing utility for Windows                      |
| ARP Poisoning      | N/A                                    | Technique for redirecting traffic to a malicious endpoint     |
| Cain               | https://www.oxid.it/cain.html          | Network security tool for Windows                             |
| UfaSoft            | http://www.ufasoft.com/sniffer/        | Network protocol analyzer and packet sniffer for Windows      |
| WinARP Attacker    | https://www.download32.com/winarpattacker-i32561.html | ARP spoofing tool for Windows                  |

## WEB ATTACKS
| Tool Name           | Website                                  | Description                                                  |
|---------------------|------------------------------------------|--------------------------------------------------------------|
| Wfetch              | N/A                                      | Command-line HTTP client for Windows                          |
| Httprecon           | https://sourceforge.net/projects/httprecon/ | Web server fingerprinting tool for Linux and macOS         |
| ID Serve            | N/A                                      | Tool for detecting web server software and version           |
| WebSleuth           | http://www.metasploit.com/                | Web application fingerprinting and mapping tool              |
| Black Widow         | https://www.softpedia.com/get/Internet/Tools/Misc-Networking-Tools/Black-Widow.shtml | Web site scanner and vulnerability assessment tool |
| CookieDigger       | https://www.allacronyms.com/CookieDigger | Tool for analyzing and extracting cookies from web traffic   |
| Nstalker            | https://www.nstalker.com/products/       | Web application security scanner for Windows and Linux       |
| NetBrute            | N/A                                      | Windows-based web server security testing tool                |
| SQL Injection       | N/A                                      | Attack technique for exploiting web application vulnerabilities |
| BSQL Hacker         | https://www.sqlhacker.com/               | Automated SQL injection and database exploitation tool       |
| Marathon            | https://www.marathontesting.com/          | Web application testing tool for Windows                      |
| SQL Injection Brute | N/A                                      | Tool for brute forcing SQL injection vulnerabilities           |
| SQL Brute           | https://www.securitysoftware.cc/sql-brute/ | Brute force tool for guessing SQL Server account credentials |
| SQLNinja            | https://sqlninja.sourceforge.net/        | SQL Server injection and exploitation tool for Linux          |
| SQLGET              | N/A                                      | Windows-based SQL injection and database exploitation tool    |


## WIRELESS
| Tool Name     | Website                            | Description                                                  |
|---------------|------------------------------------|--------------------------------------------------------------|
| Discovery     | https://www.discoverywifi.com/     | Wireless network discovery and mapping tool                  |
| Kismet        | https://www.kismetwireless.net/    | Wireless network detector, sniffer, and intrusion detection system |
| NetStumbler   | N/A                                | Windows-based wireless network discovery and mapping tool     |
| insider       | https://github.com/0x90/wifi-arsenal | Wireless network security toolkit for Linux and macOS     |
| NetSurveyor   | https://www.nutsaboutnets.com/netsurveyor/ | Windows-based wireless network discovery and mapping tool |
| Packet Sniffing | N/A                              | Technique for intercepting and analyzing wireless network traffic |
| Cascade Pilot | https://www.riverbed.com/products/cascade/ | Network performance management and packet analysis tool |
| Omnipeek      | https://www.liveaction.com/        | Comprehensive network analyzer and packet sniffer for Windows |
| Comm View     | https://www.tamos.com/products/commwifi/ | Windows-based network protocol analyzer and packet sniffer |
| Capsa         | https://www.colasoft.com/capsa/    | Network analyzer and packet sniffer for Windows-based networks |
| WEP/WPA Cracking | N/A                            | Techniques for cracking WEP/WPA encryption on wireless networks |
| Aircrack      | https://www.aircrack-ng.org/      | Wireless network security auditing and cracking tools         |
| KisMac        | https://github.com/IGRSoft/KisMAC2 | Wireless network discovery and mapping tool for macOS         |

### Wireless Security Auditor
| Tool Name            | Website                            | Description                                                  |
|----------------------|------------------------------------|--------------------------------------------------------------|
| WepAttack            | https://sourceforge.net/projects/wepattack/ | Wireless network key cracking tool for Linux        |
| WepCrack             | N/A                                | Windows-based wireless network key cracking tool             |
| coWPatty             | N/A                                | Brute force tool for guessing WPA passwords on wireless networks |
| Bluetooth            | N/A                                | Short-range wireless communication technology                |
| BTBrowser            | N/A                                | Windows-based Bluetooth device discovery tool                 |
| BH Bluejack          | https://www.bluejackingtools.com/  | Windows-based Bluetooth device discovery and hacking tool     |
| BTScanner            | https://www.bluescan.org/          | Linux-based Bluetooth device discovery tool                   |
| Bluesnarfer          | https://www.alighieri.org/tools/bluesnarfer.html | Linux-based Bluetooth device hacking tool         |
| Mobile Device Tracking | N/A                            | Technique for locating and tracking mobile devices            |
| Wheres My Droid      | https://www.wheresmydroid.com/    | Android app for locating and remotely controlling lost or stolen devices |
| Find My Phone        | https://www.apple.com/icloud/find-my/ | Apple's built-in feature for locating lost or stolen devices |
| GadgetTrack          | https://www.gadgettrak.com/       | Cross-platform app for locating and remotely controlling lost or stolen devices |
| iHound               | https://www.ihoundsoftware.com/   | iOS app for tracking and remotely controlling lost or stolen devices |


## TROJANS AND MALWARE
| Tool Name      | Website                            | Description                                                  |
|----------------|------------------------------------|--------------------------------------------------------------|
| Wrappers        | N/A                                | Programs that encapsulate other programs for stealth or other purposes |
| Elite Wrap      | N/A                                | Wrapping tool for creating undetectable backdoors or Trojans  |
| Monitoring Tools | N/A                              | Tools for monitoring system activity or network traffic       |
| HiJackThis      | https://sourceforge.net/projects/hjt/ | Windows-based tool for detecting and removing malware and spyware |
| CurrPorts       | https://www.nirsoft.net/utils/cports.html | Windows-based tool for monitoring open ports and active network connections |
| Fport           | https://www.majorgeeks.com/files/details/fport.html | Windows-based tool for identifying and killing processes using specific ports |

## Attack Tools
| Tool Name  | Website                            | Description                                                  |
|------------|------------------------------------|--------------------------------------------------------------|
| Netcat     | https://eternallybored.org/misc/netcat/ | Swiss Army Knife of networking utilities for TCP/IP protocols |
| Nemesis    | https://github.com/libnet/nemesis  | Command-line network packet crafting and injection tool      |
| IDS        | N/A                                | Intrusion detection systems for monitoring and analyzing network traffic |
| Snort      | https://www.snort.org/            | Open-source intrusion detection and prevention system for networks |

## Evasion Tools
| Tool Name  | Website                            | Description                                                  |
|------------|------------------------------------|--------------------------------------------------------------|
| ADMutate   | https://www.packetfactory.net/projects/admutate/ | Tool for generating a large number of network probes for testing IDS/IPS systems |
| NIDSBench  | https://sourceforge.net/projects/nidsbench/ | Tool for benchmarking and testing network intrusion detection systems |
| IDSInformer | https://sourceforge.net/projects/idsinformer/ | Tool for monitoring network intrusion detection systems and generating alerts |
| Inundator  | https://inundator.sourceforge.net/#download | Network packet generator for testing intrusion detection and prevention systems |


The information in this cheat sheet is not only useful for passing the Certified Ethical Hacker Exam, but can act as a useful reference for penetration testers and those pursuing other Security certifications. However you choose to use it, we hope you’ve found it a helpful resource to keep around. wanna see more ? [visit here](https://drive.google.com/drive/u/0/folders/132ptAPFrhVZAV5dMMK6Jk9HSA4UJl7Du)
