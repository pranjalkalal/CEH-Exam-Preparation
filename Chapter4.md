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
> Note: we query the SNMP-enabled devices (Agents).
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
