# Network Scanning Types
Network scanning is the active process of utilizing networking technologies to gather information about your targets network like What is out there? What's it running? What's it doing? Is there anything wrong with it that I or maybe I can discover.

1. Port Scanning: Port scanning involves probing a computer system or network to discover open ports and services available on target systems. It helps identify potential entry points and vulnerabilities that attackers could exploit.
     > Examples of port scanning techniques include [1] TCP SYN/Stealth scanning, [2] TCP connect scanning, [3] and UDP scanning.

3. Vulnerability Scanning: Vulnerability scanning is the process of identifying security vulnerabilities and weaknesses in computer systems, networks, or applications. It involves automated tools scanning for known vulnerabilities in software, configurations, or missing patches. Vulnerability scanning helps organizations prioritize and remediate security issues before they can be exploited by attackers. It is kinda including 1 and 3.

4. Network Scanning/Mapping: Network mapping involves creating a visual representation or map of a computer network to identify its structure, layout, and interconnected devices. It helps administrators understand the network topology, identify potential security risks, and plan for network management and security measures. Network mapping tools use techniques such as ICMP echo requests, traceroute, and SNMP queries to gather information about network devices and connections.
   - Host Discovery: Host discovery involves identifying active hosts (devices) on a network. It typically involves sending probe packets to IP addresses within a specified range and analyzing responses to determine which hosts are reachable and responsive. Host discovery techniques include ICMP echo requests (ping), ARP requests, TCP SYN scans, and UDP scans. The goal of host discovery is to determine the presence and availability of hosts on a network.
  
# Network Scanning Tools

Network scanning is a fundamental skill for ethical hacking, used to identify and analyze hosts, services, and open ports within a network. This guide provides an overview of essential network scanning tools and techniques.

## 1. **Nmap**
   - **Overview**: Known as the "king" of network scanning tools, Nmap is versatile and widely used for host discovery, service versioning, and vulnerability detection.
   - **Basic Usage**: Run `nmap [target]` to get started.
   - **Key Features**:
     - **Host Discovery**: Identifies live hosts.
     - **Port Scanning**: Customizable scans for specific port ranges.
     - **Service Detection**: Recognizes running services and their versions.
     - **Scripting Engine (NSE)**: Provides scripts for vulnerability detection.
     - **Timing/Performance Adjustments**: Adjust scan speed to avoid IDS/IPS detection.
     - **Output Options**: Saves results in various formats (e.g., XML, grepable).
   - **Documentation**: [Nmap.org](https://nmap.org) has extensive resources, including a free portion of the Nmap book.

## 2. **Unicornscan**
   - **Overview**: A fast, high-performance network scanner, particularly suited for scanning large networks or the internet.
   - **Usage**: Simple commands, e.g., `unicornscan [target]`.
   - **Limitations**: Generally requires IP address input, sometimes not as thorough as Nmap.

## 3. **Masscan**
   - **Overview**: Known for its speed, Masscan is ideal for large-scale internet scans.
   - **Key Features**:
     - **Internet-Scale Scanning**: Efficient for identifying open ports across many hosts.
     - **Compatible with Nmap Syntax**: Can use similar options for familiarity.
   - **Usage Example**: `masscan -p80 --rate=1000 [target network]`.

## 4. **Hping3**
   - **Overview**: A packet crafting tool, excellent for sending custom packets, ideal for testing network responses.
   - **Key Features**:
     - **Packet Crafting**: Supports ICMP, TCP, and UDP packet creation.
     - **Scanning Modes**: Offers SYN scans, ICMP mode, etc.
   - **Example**: `hping3 -S -p 80 -c 1 [target]` to send a single SYN packet to port 80.

## 5. **Metasploit**
   - **Overview**: Primarily an exploitation framework but includes network scanning capabilities.
   - **Usage**: `msfconsole` > `search scanner` to locate available scanners.
   - **Key Features**: Provides various scanner modules (e.g., HTTP scanners, ARP sweep for host discovery).

## 6. **Additional Scanning Tools**
   - **SolarWinds**: Common in network administration, includes tools for port scanning and host discovery.
   - **PRTG Network Monitor**: Offers network monitoring with host discovery features.
   - **Omnipeek & NetScan Tools Pro**: Provides advanced scanning and monitoring, often paid.

## Summary
While **Nmap** remains the go-to for comprehensive network scanning, tools like **Masscan** and **Unicornscan** offer speed, and **Hping3** enables detailed packet customization. For additional functionality, Metasploit, SolarWinds, and other network monitoring solutions provide supplementary scanning features.

# Host Discovery Techniques

Host discovery is essential for identifying connected devices on a network, often forming the first phase in network reconnaissance. Host discovery can be performed both **externally** and **internally** to map devices, understand network structure, and prepare for further testing.

## Key Techniques

### 1. **ICMP (Ping)**
   - **ICMP Echo Request (ICMP Type 8)**: Sends a ping to a target to check if it’s alive. Common, but often blocked on Windows networks for security.
   - **Timestamp & Address Mask**: Alternatives to ICMP Echo, useful if ICMP Echo requests are blocked. Executed with flags like `-PP` (timestamp) or `-PM` (address mask) in Nmap.
   - **Tool Example**: `ping [IP address]`.

### 2. **ARP (Address Resolution Protocol)**
   - Primarily used for discovering devices on a local subnet.
   - **Tool Example**: `arping [IP address]`, useful for internal scans.

### 3. **UDP (User Datagram Protocol)**
   - Although slower, UDP can sometimes discover hosts where ICMP and TCP are blocked.
   - **Tool Example**: `nmap -sU [target IP or range]`.

### 4. **TCP SYN Scan**
   - Sends SYN packets to initiate a TCP connection, checking if devices respond.
   - **Tool Example**: `nmap -PS [IP address]`.

## Common Tools

### 1. **Ping and Automated Scripting**
   - Simple command to check individual hosts or scripts to scan entire IP ranges.
   - Example Bash Script: `sweeper.sh` that automates ping sweeps over a range.

### 2. **Nmap**
   - A versatile network scanner.
   - Useful commands:
     - `nmap -sn [network]` for a ping sweep.
     - `nmap -PE`, `nmap -PP`, `nmap -PM` to customize ICMP request types.
   - **King of Host Discovery Tools** due to its flexibility and comprehensive options.

### 3. **Angry IP Scanner**
   - User-friendly, fast tool for quick host discovery.

### 4. **Traceroute**
   - Helps map the route packets take to reach a destination, identifying intermediary devices.
   - **Command Example**: `traceroute [target domain]`.

## Advanced Techniques

### Protocol Ping in Nmap
   - Sends IP packets across multiple protocols like ICMP, IGMP, and IP-in-IP to test for responses.
   - Command: `nmap -PO [IP address]`.

### Combining Techniques
   - Mix different pings and scan types for comprehensive results, especially when some protocols are blocked.

## Testing Contexts

- **Black Box**: No prior knowledge of the network; requires complete discovery.
- **Gray Box**: Limited access or knowledge; may include partial credentials.
- **White Box**: Full access and network details provided by the client.

## Tips for Effective Host Discovery

- Use a mix of **ICMP**, **ARP**, and **TCP SYN** scans.
- Check responses for any blocked protocols and adapt.
- Ensure **multiple tools** are tried for verification and completeness.

## References and Further Learning
- **Nmap Book**: For in-depth command usage and options.
- **Additional Tools**: Path Analyzer Pro, VisualRoute.

Host discovery is about identifying live systems on a network, often requiring adjustments based on network structure and security policies. Keep experimenting with different tools and flags to maximize visibility!

# Port and Service Scanning

1. **Port vs. Service Scanning**:
   - **Port Scanning**: Identifies open TCP ports on a target. An open port may or may not have a service running on it, but knowing it’s open can reveal potential vulnerabilities.
   - **Service Scanning**: After identifying open ports, a service scan can determine the specific application or service type running, if any, on that port.

2. **Common Ports and Services**:
   - Ports like 80 (HTTP) and 443 (HTTPS) have commonly agreed-upon uses but are not restricted to these services. For example, a service can run on any available port, though defaults exist for ease of identification (e.g., 8080 often for proxies).
   - Recognizing service types on open ports helps identify potential targets for vulnerabilities, especially by comparing version details to known exploits.

3. **Nmap Scanning Techniques**:
   - **Basic Port Scan**: Simply detects open ports.
   - **Service and Version Detection (`-sV` flag)**: Probes each open port to detect the specific application and version, allowing for vulnerability research.
   - **Example**: The scan found ports like 8080 and 9001 open, identifying a version of Nginx on one and a JDBC-related service on another.

4. **Practical Usage and Output Handling**:
   - Saving Nmap outputs (`-o` option) is useful for later analysis, especially when looking through numerous open ports.
   - Nmap's service file, located in `/usr/share/nmap/nmap-services`, lists well-known ports and services, acting as a reference for commonly open ports and their associated services.

5. **Takeaways**:
   - Port and service scanning is foundational in ethical hacking, assisting in identifying vulnerable points in a network.
   - Familiarity with common ports, along with using tools like Nmap for detailed scanning, is essential for effective vulnerability assessment.


# Scans types
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

# Scan Optimization
Scan optimization refers to the process of fine-tuning your port scanning activities to achieve better efficiency, accuracy, and speed.

Here are some techniques to optimize scans in Nmap:
1. Target Specification (narrowing down):
- Use IP addresses instead of hostnames to avoid DNS resolution delays. (-n in nmap)
- Specify individual hosts or small IP ranges instead of scanning entire subnets to reduce scan time and network load.
2. Timing and Performance:
- Adjust timing options (-T) to balance speed and stealthiness. Options range from 0 (paranoid), 1 (sneaky), 2 (polite), 3 (normal), 4 (agressive) to 5 (insane).
- Increase parallelism (-T4 or -T5) to speed up scans by sending multiple probes simultaneously.
3. Port Specification (narrowing down):
- Scan specific ports or port ranges instead of scanning all 65,535 ports. For example, specify -p 1-1000 to scan the first 1000 ports, or -F for first 100 ports.
- Use service-specific ports (-p- with -sV) to scan only ports associated with common services for faster scans.
4. Scripting Engine:
- Utilize Nmap Scripting Engine (NSE) scripts (-sC) to automate additional tasks such as vulnerability scanning, service enumeration, or brute-force attacks.
5. Avoid the unnessecary:
- For example, usually nmap will ping the host to check if it is alive, however if we already know it is, then we can skip that by using (-Pn).

# Target OS Identification
1. Packet TTL (Time-to-Live) Analysis:
- Nmap analyzes the TTL values in packets returned by the target system to estimate the distance (number of hops) to the target.
- Different operating systems may set TTL values differently, which can help identify the OS.
2. Nmap Scripting Engine (NSE):
- Nmap comes with a collection of scripts (NSE scripts) that can probe target systems for additional information, including OS detection.
- Scripts like http-os-discovery, smb-os-discovery, and ssh-hostkey can provide OS information based on specific service responses.
3. Service Version Detection:
- By identifying the versions of services running on the target system (using -sV option), Nmap can infer the underlying OS based on the known OS-service version correlations.
- Certain services and versions are more commonly associated with specific operating systems.
4. TCP/IP Stack Fingerprinting:
- Nmap compares the responses to its probes with a database of known OS fingerprints to determine the closest match.
- Techniques like TCP Initial Sequence Number (ISN) sampling and TCP Timestamps can reveal subtle differences in how different OSs implement these features.

## Countermeasures
1. Disable or Modify Banners:
- Disable or modify banners in the configuration of services running on the target systems to conceal information about the operating system and software versions.
- For example, in web servers like Apache HTTP Server, disable the ServerSignature and ServerTokens directives to prevent the server from disclosing its identity.
2. Regularly Update and Patch Systems:
- Keep systems up-to-date with security patches and software updates to address known vulnerabilities that could be exploited for OS identification.
- Regularly monitor and apply security advisories from vendors to ensure that vulnerabilities are promptly addressed.
3. Harden Operating Systems:
- For example: Disable unnecessary services, close unused ports, and configure strict access controls to limit exposure to potential attackers.
4. Network Segmentation:
- Segment networks to isolate critical systems and limit the visibility of potential targets to attackers.
- Implement network segmentation using firewalls, VLANs, or subnetting to restrict access to sensitive systems and information.
5. Intrusion Detection and Prevention Systems (IDS/IPS):
- Configure IDS/IPS rules to detect and block suspicious activities associated with OS identification techniques.
6. Traffic Encryption:
- Use encryption (e.g., SSL/TLS) for network communication to obfuscate packet contents and prevent passive OS fingerprinting.
- Encrypt sensitive data to protect it from interception and analysis by attackers.

# IDS/Firewall Evasion
1. Fragmentation:
- Technique: Fragmenting packets into smaller pieces to evade packet inspection and reassembly by IDS and firewalls.
- Example: Use Nmap's -f option to fragment packets during scanning: `nmap -f target_IP`
2. Timing Manipulation:
- Technique: Adjusting timing options to slow down or speed up scans to evade IDS thresholds.
- Example: Use Nmap's timing options (-T0 to -T5) to control scan speed: `nmap -T5 target_IP`
3. Source IP Spoofing:
- Technique: Spoofing the source IP address to disguise the origin of the scan traffic and bypass firewall rules.
- Example: Use Nmap's -S option to specify a spoofed IP address: `nmap -S spoofed_IP target_IP`
  > For this one especially, when spoofing the IP then the response will be sent to this IP which means it is not that useful (later to see what is the point then!).
4. Decoy Scanning:
- Technique: Sending scan packets from multiple decoy IP addresses to confuse IDS and conceal the true source of the scan.
- Example: Use Nmap's -D option to specify decoy IP addresses: `nmap -D decoy_IPs target_IP`
5. Randomizing Target Order:
- Technique: Randomizing the order in which targets are scanned to bypass IDS rule sets that detect sequential scanning patterns.
- Example: Use Nmap's -r option to randomize target order: `nmap --randomize-hosts target_IPs`
6. Packet Manipulation:
- Technique: Manipulating packet headers or payloads to evade signature-based detection by IDS.
- Example: Use Nmap's --data-length option to vary packet size: `nmap --data-length size target_IP`
7. Encoding and Encryption:
- Technique: Encoding or encrypting scan packets to obfuscate their content and evade detection by IDS and firewalls.
- Example: Use tools like Nmap Scripting Engine (NSE) to implement custom encryption or encoding of scan packets.
8. Stealth Scan Techniques:
Technique: Leveraging stealthy scanning techniques like SYN scan (-sS) to minimize the footprint and avoid triggering IDS alerts.
9. Source Port Modification:
- Technique: Modifying the source port of scan packets to bypass firewall rules or evade detection by signature-based IDS. As we know there are ports like DNS 53 which is necessary to be open, so we do benefit from that.
- Example: Use Nmap's --source-port option to specify a custom source port: `nmap --source-port port_number target_IP`
10. SSRF (Server-Side Request Forgery) Attacks:
- Technique: Exploiting SSRF vulnerabilities to force the target server to make requests on behalf of the attacker, potentially bypassing firewall restrictions.
- Example: Use tools like Burp Suite or ZAP to craft HTTP requests with manipulated parameters to exploit SSRF vulnerabilities.
11. Proxy and Anonymizer:
- Technique: Routing scan traffic through proxy servers or anonymization services like TOR OS/browsers (Tails, TOR, Whonix) to hide the true source of the scan and bypass firewall rules.
- Example: Use tools like ProxyChains to route Nmap scan traffic through proxy servers: `proxychains nmap target_IP`
