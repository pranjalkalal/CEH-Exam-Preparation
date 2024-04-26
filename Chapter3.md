# Network Scanning Types
Network scanning is the active process of utilizing networking technologies to gather information about your targets network like What is out there? What's it running? What's it doing? Is there anything wrong with it that I or maybe I can discover.

1. Port Scanning: Port scanning involves probing a computer system or network to discover open ports and services available on target systems. It helps identify potential entry points and vulnerabilities that attackers could exploit.
  > Examples of port scanning techniques include [1] TCP SYN/Stealth scanning, [2] TCP connect scanning, [3] and UDP scanning.

2. Vulnerability Scanning: Vulnerability scanning is the process of identifying security vulnerabilities and weaknesses in computer systems, networks, or applications. It involves automated tools scanning for known vulnerabilities in software, configurations, or missing patches. Vulnerability scanning helps organizations prioritize and remediate security issues before they can be exploited by attackers. It is kinda including 1 and 3.

3. Network Scanning/Mapping: Network mapping involves creating a visual representation or map of a computer network to identify its structure, layout, and interconnected devices. It helps administrators understand the network topology, identify potential security risks, and plan for network management and security measures. Network mapping tools use techniques such as ICMP echo requests, traceroute, and SNMP queries to gather information about network devices and connections.
   - Host Discovery: Host discovery involves identifying active hosts (devices) on a network. It typically involves sending probe packets to IP addresses within a specified range and analyzing responses to determine which hosts are reachable and responsive. Host discovery techniques include ICMP echo requests (ping), ARP requests, TCP SYN scans, and UDP scans. The goal of host discovery is to determine the presence and availability of hosts on a network.
  
# Networ Scanning Tools
Tools to use: nmap, hping3, masscan, metasploit

# Scans
## TCP Connect Scans
TCP connect scan is a port scanning technique that establishes a full TCP connection with the target system to determine the state of TCP ports. It initiates a TCP handshake by sending a SYN packet to the target port and analyzes the responses received during the handshake process to determine if the port is open, closed, or filtered:
- If the target responds with a SYN-ACK packet, the port is considered open.
- If the target responds with a RST (reset) packet, the port is considered closed.
- If the target does not respond at all, the port may be filtered by a firewall or other network device.

While TCP connect scan is more reliable, it's also more easily detectable by security systems due to the complete TCP connection establishment process.

> `nmap -sT {Target's IP}`.

## Stealth Scanning
Stealth scanning refers to a set of port scanning techniques designed to avoid detection by intrusion detection systems (IDS), firewalls, and other security measures. Stealth scanning typically involves sending specially crafted packets or manipulating network traffic to minimize the footprint of the scanning activity and evade detection. 
  > Examples of stealth scanning techniques include TCP SYN scanning, NULL scanning, FIN scanning, and XMAS scanning.

### TCP SYN 
TCP SYN scanning, also known as SYN scan or half-open scanning, sends TCP SYN packets to target ports and analyzes responses to determine if ports are open, closed, or filtered. SYN scanning is stealthy, fast, and efficient.

> ``
### XMAS/Christmas
