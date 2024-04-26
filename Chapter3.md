# Network Scanning Types
Network scanning is the active process of utilizing networking technologies to gather information about your targets network like What is out there? What's it running? What's it doing? Is there anything wrong with it that I or maybe I can discover.

1. Port Scanning: Port scanning involves probing a computer system or network to discover open ports and services available on target systems. It helps identify potential entry points and vulnerabilities that attackers could exploit.
     > Examples of port scanning techniques include [1] TCP SYN/Stealth scanning, [2] TCP connect scanning, [3] and UDP scanning.

3. Vulnerability Scanning: Vulnerability scanning is the process of identifying security vulnerabilities and weaknesses in computer systems, networks, or applications. It involves automated tools scanning for known vulnerabilities in software, configurations, or missing patches. Vulnerability scanning helps organizations prioritize and remediate security issues before they can be exploited by attackers. It is kinda including 1 and 3.

4. Network Scanning/Mapping: Network mapping involves creating a visual representation or map of a computer network to identify its structure, layout, and interconnected devices. It helps administrators understand the network topology, identify potential security risks, and plan for network management and security measures. Network mapping tools use techniques such as ICMP echo requests, traceroute, and SNMP queries to gather information about network devices and connections.
   - Host Discovery: Host discovery involves identifying active hosts (devices) on a network. It typically involves sending probe packets to IP addresses within a specified range and analyzing responses to determine which hosts are reachable and responsive. Host discovery techniques include ICMP echo requests (ping), ARP requests, TCP SYN scans, and UDP scans. The goal of host discovery is to determine the presence and availability of hosts on a network.
  
# Networ Scanning Tools
Tools to use: nmap, hping3, masscan, metasploit

# Scans Examples/Types
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
TCP SYN scanning, also known as half-open scanning, sends TCP SYN packets to target ports and analyzes responses to determine if ports are open, closed, or filtered. SYN scanning is stealthy, fast, and efficient. This is the default for nmap.

> `nmap -sS {Target's IP}`.

### Inverse Scanning
Inverse scans, also known as reverse scans, are techniques where the scanning tool reverses the logic of traditional port scanning to identify open ports. Instead of sending probes to determine if ports are open, inverse scans rely on analyzing responses to determine if ports are closed.

#### XMAS/Christmas
A Xmas tree scan exploits the behavior of compliant systems to not respond to unexpected flag combinations (ACK, RST, SYN, URG, PSH, and FIN).

It works by sending a combination of FIN, URG, and PSH flags to the target port:
- If the port is open, the target system will not respond, indicating it's "confused" by the unexpected flags.
- If the port is closed, the target system will respond with a TCP RST packet.

Xmas tree scans are effective against systems compliant with RFC 793 but may not work on Windows systems due to differences in TCP/IP implementation.

> `nmap -sX {Target's IP}`.

#### FIN
In this scan, I hit them with a FIN, meaning, I'm done talking to you! The target machine will go, Well, I don't even know how to respond to that because we haven't even started talking yet. So, no response tells me that the port is open. Again, if I want to see if the port is closed, I send my FIN, and if I just get an RST/ACK, then the port is closed.

> `nmap -sF {Target's IP}`.
> `hping3 -8 0-65535 -F {Target's IP}`.

#### NULL
A NULL scan is kind of unique because it typically works on UNIX and Linux systems. Again, it does not work on the Microsoft platform.

Same as FIN scan, but here we send no flags at all. When the target receives that packet, it responds with nothing, which means that you're sending me information I have no idea how to handle. And because it doesn't respond, we know that the port is open. 

The opposite of that is true. The kernel will send an RST/ACK back to the attacker's machine if the port is closed.

> `nmap -sN {Target's IP}`.

#### Maimon Scan
The Maimon scan is a technique used to determine firewall filtering rules by sending TCP SYN packets with the FIN and SYN flags set. The purpose is to bypass certain types of firewall configurations that may only filter based on specific flag combinations.

> `nmap -sM {Target's IP}`.
