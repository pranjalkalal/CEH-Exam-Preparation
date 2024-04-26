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
> Just a little note: we will encounter two scenarios when scanning ports:
> - if port is open then we receive response and we know it's open, or if closed then we don't and we are unsure if it's closed or filtered by firewall. (as in TCP Connect Scans).
> - if port is closed then we receive response like an error or RST and we know it's closed, or if port is open then we don't receive response and we are unsure if it's open or filtered by firewall (as in inverse TCP scans and UDP scan).

## TCP Connect Scans
TCP connect scan is a port scanning technique that establishes a full TCP connection with the target system to determine the state of TCP ports. It initiates a TCP handshake by sending a SYN packet to the target port and analyzes the responses received during the handshake process to determine if the port is open, closed, or filtered:
- If the target responds with a SYN-ACK packet, the port is considered open.
- If the target responds with a RST (reset) packet, the port is considered closed.
- If the target does not respond at all, the port may be filtered by a firewall or other network device.

While TCP connect scan is more reliable, it's also more easily detectable by security systems due to the complete TCP connection establishment process.

> `nmap -sT {Target's IP}`.

## Stealth Scanning
Stealth scanning refers to a set of port scanning techniques designed to avoid detection by intrusion detection systems (IDS), firewalls, and other security measures. Stealth scanning typically involves sending specially crafted packets or manipulating network traffic to minimize the footprint of the scanning activity and evade detection. Examples are mentioned below.

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

### IDLE IPID Scan
***Scenario***:
You want to check if a server at IP address 192.168.1.100 has any open ports, but you want to do it stealthily, without directly scanning from your own IP address. You know there's another computer on the network at 192.168.1.200 that is usually quiet and not doing much, so you decide to use it as your "idle host" or "zombie."

***How it Works***:
1. Selection of Idle Host: Instead of scanning directly from the attacker's IP address, the idle scan relies on a third-party "idle" host, also known as the "zombie host." This idle host must meet specific criteria: it should have an IP ID counter that increments predictably for each packet sent, and it should not send any traffic during the scanning period.
2. Sending Probe Packets: You use Nmap to send spoofed packets to the target server (192.168.1.100), pretending they're from your idle host (192.168.1.200). These packets typically include SYN flags and are sent to various ports on the target server.
3. Observing IP ID Changes: While your scanning tool sends these packets, you monitor the IP ID counter of your idle host (192.168.1.200). If the IP ID counter increases after sending a packet, it indicates that the target server responded to the spoofed packet, meaning the probed port might be open.
4. Interpreting Results: Based on the observed IP ID changes on your idle host, you can infer the state of specific ports on the target server. For example, if the IP ID counter increases after sending a packet to port 80, it suggests that port 80 might be open on the target server.

##### Friendly Conclusion
- I am sending a SYN packet to the zombie, then from the response (RST) I receive, I will find the IPID which let's say is 2000.
- I will send a SYN packet to the target but with spoofing the zombie's IP (to hide from detection), then the target will send the response (RST) to the zombie.
- If the port is open, then IPID of the zombie is already incremented to 2001, however if closed then the target will simply drop or send RST with no change to the IPID as if nothing happened.
- Now I am going to send a SYN packet to the Zombie again, and if the IPID I find is 2002 then I will know the port is open, however if it comes 2001 then I will know that the port is closed|filtered.

> `nmap -sI zombie_IP target_IP`.

### ACK scans

## UDP Scan
UDP scans are used to identify open UDP ports on a target system. Since UDP is a connectionless protocol and no need to establish a connection first, so:
- when sending a packet to an open port, we don't get response.
- However if a port is closed, then we receive an ICMP error that the port is unreachable.
  
> `nmap -sU target_IP`

> `hping3 -2 -p <port> target_IP`

## SCTP INIT/Cookie-Echo Scans
SCTP (Stream Control Transmission Protocol) is a marry of TCP for accuracy and UDP for speed. 

### SCTP INIT Scan
- ***How it Works***: This scan sends an SCTP INIT chunk to the target port:
     + If the port is open, the target system responds with an SCTP INIT-ACK chunk.
     + If the port is closed, the target system responds with an SCTP ABORT.
- ***Characteristics***:
     + Provides information about open SCTP ports on the target system.
     + It's stealthier than other scanning techniques as it doesn't complete the full SCTP handshake.
### SCTP Cookie-Echo Scan
- ***How it Works***: This scan sends an SCTP COOKIE_ECHO chunk to the target port:
     + if the port is open, then we receive no response at all.
     + If the port is closed, the target system responds with an SCTP ABORT.
