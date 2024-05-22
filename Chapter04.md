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

# NFS
NFS (Network File System) is a distributed file system protocol used for sharing files and directories across a network. It allows clients to access files on remote servers as if they were stored locally.

The server running the NFS service acts as the central point for managing shared files and directories. Clients connect to this server over the network to access the shared resources.

## NFS Enumeration
- we can use tools like rpcscan, rpcinfo, and showmount.
- we can use `showmount -e [IP]` to list the NFS shares.
- Now we know a a sharename on the server, we follow these steps to get it on our machine:
  1. we create a directory for example mkdir /tmp/mount to mount the share to.
  2. use the command `sudo mount -t nfs <IP>:<sharename> <Directory to mount to: /tmp/mount/> -nolock`.

# SMTP
SMTP (Simple Mail Transfer Protocol) is a standard protocol used for sending and receiving email messages over the Internet.

## SMTP Enumeration
The SMTP service has two internal commands that allow the enumeration of users:
  - VRFY (confirming the names of valid users) and
  - EXPN (which reveals the actual address of user’s aliases and lists of e-mail (mailing lists).

Using these SMTP commands, we can reveal a list of valid users. We can do this manually, over a telnet connection- however Metasploit provides a module called "smtp_enum". Using the module is simple, we provide a list of usernames and the host IP and it returns the valid usernames found. Another tool is "smtp-user-enum" and can be used as in the example `smtp-user-enum -M VRFY -U {users_file} -t {target_IP}`. And of course, nmap, using the script `smtp-enum-users`.

We can then bruteforcing these usernames with Hydra for example to crack the password.
