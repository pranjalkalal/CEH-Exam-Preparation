# Enumeration
The goal of performing enumeration on a network is to gather as much information about the network as possible. This process typically looks at hosts and the services that they provide.

***Enumeration vs Scanning***:
- Scanning: Identifies active hosts, open ports, and services running on those ports.
- Enumeration: Gathers detailed information about the services and resources discovered during scanning.
- Relationship: Scanning precedes enumeration and provides the initial data for further investigation.
- Purpose: Scanning is focused on discovery, while enumeration is focused on detailed reconnaissance and information gathering.

# NetBIOS & SMB
## Purpose
- NetBIOS is a networking protocol used for communication between devices on a local area network (LAN). It facilitates the establishment of sessions between devices for communication and data exchange.
- SMB (Server Message Block) is a network file sharing protocol used for accessing files, printers, and other resources on a network. It supports features such as file and print sharing, directory browsing, file access control, and authentication.
  
## Relationship
- Historical Connection: NetBIOS was originally developed by IBM in the 1980s and later adopted by Microsoft. SMB was built on top of NetBIOS to provide file and printer sharing capabilities.
- Modern Evolution: While SMB initially relied on NetBIOS for name resolution and session establishment, modern versions of SMB (e.g., SMB2 and SMB3) have moved away from NetBIOS and use other protocols and mechanisms for these functions.
  
## NetBIOS Enumeration:
1. nbtstat (Windows):
- Command-line tool for querying NetBIOS information on Windows systems.
- Usage: nbtstat -A target_IP
2. enum4linux (Linux):
- A popular tool for enumerating information from Windows and Samba systems.
- Usage: enum4linux -a target_IP
3. 
## SMB Enumeration:
1. SMBClient (Linux):
- Command-line tool for interacting with SMB shares on Windows and Samba systems.
- Usage: smbclient -L //target_IP
2. SMBMap (Linux):
- A tool for enumerating SMB shares on both Windows and Samba systems.
- Usage: smbmap -H target_IP
Metasploit (Windows/Linux):
- It includes modules for SMB enumeration.
- Usage: use auxiliary/scanner/smb/smb_enumshares

# SNMP
Simple Network Management Protocol (SNMP) is a widely used network management protocol for monitoring and managing network devices such as routers, switches, servers, printers, and more. Its primary purpose is to allow network administrators to remotely monitor and control network devices, gather performance data, and detect network issues.

## How it works?
### Components:
- SNMP Agent: Software component running on network devices that collects and stores management information.
- Management Information Base (MIB): Database containing hierarchical data structures that define the parameters managed by SNMP.
- SNMP Manager: Management system that communicates with SNMP agents to retrieve and manipulate management information.
  
### Operations:
- SNMP uses a client-server model, where SNMP managers (clients) communicate with SNMP agents (servers) using UDP protocol.
- SNMP managers send requests to SNMP agents to retrieve or set specific management information.
- SNMP agents respond to requests from SNMP managers and may also send unsolicited notifications (traps) to SNMP managers based on predefined events.

## Enumeration Tools 
> Note: we query the SNMP-enabled devices (Agents). </br>
> community_strings are some sort of authentication between snmp clients and servers.

1. onesixtyone:
- A fast and simple SNMP scanner for discovering SNMP-enabled devices and enumerating information.
- Usage: `onesixtyone -c community_string target_IP`
2. snmp-check:
- A Perl script for enumerating SNMP information from devices, including system information, running processes, network interfaces, and more.
- Usage: `snmp-check -t target_IP -c community_string`
3. Nmap:
- It includes SNMP enumeration capabilities using the --script=snmp* NSE scripts.
- Usage: `nmap -sU -p 161 --script=snmp* target_IP`
4. snmpwalk:
- A command-line tool for walking the SNMP tree and retrieving information from SNMP-enabled devices.
- Usage: `snmpwalk -v 2c -c community_string target_IP`

# LDAP
LDAP (Lightweight Directory Access Protocol) is a network protocol used to store and retrieve information from a directory service. It's often used for managing users, groups, and other network resources in a centralized way. LDAP directories are organized in a hierarchical structure and can store various types of information about network entities. In simple terms, it is like a phonebook. 

AD utilizes LDAP to provide access to directory information, perform authentication, and support directory-based operations.

***Features of LDAP***:
1. Directory Services: LDAP provides a centralized directory service for storing and managing information about network resources.
2. Authentication: LDAP supports user authentication, allowing users to access network resources using a single set of credentials stored in the LDAP directory.
3. Authorization: LDAP directories can store access control lists (ACLs) and permissions to control access to resources based on user roles and groups.
4. Replication: LDAP supports replication, allowing directory information to be replicated across multiple LDAP servers for redundancy and scalability.
## LDAP Enumeration
1. ldapsearch (Command-line tool):
- A command-line utility for querying LDAP directories and retrieving information such as user accounts, groups, organizational units, and attributes.
- Usage: `ldapsearch -x -H ldap://ldap_server -b base_dn -D bind_dn -W`
2. LDAP Browser/Editor (Graphical tool):
- Graphical tools such as Apache Directory Studio, JXplorer, and Softerra LDAP Browser provide a user-friendly interface for browsing and querying LDAP directories.
3. enum4linux:
- While primarily used for SMB enumeration, enum4linux also includes functionality for querying LDAP directories. It can be used to extract information about users, groups, and other objects from LDAP directories during enumeration.
- Usage: `enum4linux -U -G -M -l -d target_IP`

# NTP
NTP (Network Time Protocol) is a networking protocol used to synchronize the clocks of computers and other networked devices to a common time reference. It enables accurate timekeeping and ensures that all devices within a network have synchronized timestamps for logging, authentication, and other time-sensitive operations. NTP operates over UDP and relies on hierarchical servers called NTP servers to distribute time information across the network.

## NTP Enumeration
1. ntpq (NTP Query Program):
- ntpq is another command-line utility for querying and monitoring NTP servers. It provides information about server status, peer associations, and synchronization statistics.
- Usage: `ntpq -p target_IP`
2. Nmap:
- Nmap includes NSE (Nmap Scripting Engine) scripts for querying NTP servers and enumerating information such as server status, version information, and monlist entries.
- Usage: `nmap -p 123 --script ntp-info target_IP`
3. ntpdate:
- ntpdate is a command-line utility used to set the system's time from an NTP server. While primarily used for time synchronization, it can also be used for basic NTP enumeration by querying NTP servers for time information.
- Usage: `ntpdate -q target_IP`
4. ntptrace:
- ntptrace is a command-line utility that traces the path that an NTP packet takes from the local host to a remote NTP server.
- Usage: `ntptrace target_IP`

# NFS Enumeration

## What is NFS?
- **NFS (Network File System)** allows file systems to be shared between systems over a network.
- Common in UNIX/Linux systems, operating on **port 2049**.
- Versions: **NFSv2**, **NFSv3**, **NFSv4**.

## Tools for NFS Enumeration

1. **Nmap**
   - Scans for open ports (2049) and discovers NFS shares.
   - Command: `sudo nmap -sV -p 2049 --script=nfs-showmount <target-ip>`

2. **rpcinfo**
   - Queries RPC services, including NFS.
   - Command: `rpcinfo -p <target-ip>`

3. **showmount**
   - Lists NFS exports (shared directories).
   - Command: `showmount -e <target-ip>`

4. **rpc_scan**
   - Python tool to discover RPC services.
   - Command: `./rpc_scan.py <target-ip>`

5. **NFSClient** (Optional)
   - Mount NFS shares manually.
   - Command: `nfsclient <target-ip>:/<exported-dir> <mount-point>`

## Mounting NFS Shares
- Command: `sudo mount -t nfs <target-ip>:/<nfs-export> <mount-point>`
- Command: `sudo mount -t nfs <IP>:<sharename> <Directory to mount to: /tmp/mount/> -nolock`.
- - Example: `sudo mount -t nfs 192.168.1.10:/ /mnt/nfs`

## Security Risks
- Misconfigured exports: Allows unauthorized access.
- Exposed sensitive files: `/etc/passwd`, `.ssh/authorized_keys`.
- Attackers can mount shares and explore files.

## Hardening NFS
- Restrict access by IP.
- Use **NFSv4** for better security.
- Apply **Kerberos** authentication.
- Set correct file permissions on NFS shares.


# SMTP Enumeration

**SMTP (Simple Mail Transfer Protocol)** is used for sending emails, but it can also be leveraged for enumeration, such as identifying users or email addresses on a system.

## Key Commands for Enumeration
- **VRFY**: Verifies if an email or username exists.
- **EXPN**: Expands a mailing list or alias to show actual recipients.
- **RCPT TO**: Verifies recipient information.

## Enumeration Process
1. **Port 25** is typically used for SMTP. Scan with Nmap to check if it's open.
2. Tools like **Telnet** or **Netcat** can be used to connect to the SMTP server.
3. Use **EHLO** or **HELO** to start a session.
4. Use **VRFY** followed by a username to check if it exists.
5. If the username exists, the server will return a success message (e.g., `252 User exists`); if not, a failure message (e.g., `550 Unknown recipient`).

## Example Enumeration Tool: `SMTP-user-enum`
- Automates user enumeration through various methods (VRFY, EXPN, RCPT TO).
- Supports lists of usernames from sources like **SecLists**.

### Example Command:
```bash
smtp-user-enum -M VRFY -U /path/to/usernames.txt -T target_ip
```

```bash
   nmap -p 25 target_ip
```
