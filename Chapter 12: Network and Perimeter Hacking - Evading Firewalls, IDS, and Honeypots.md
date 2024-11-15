# IDS and IPS: An Overview

## Introduction
**IDS (Intrusion Detection System)** and **IPS (Intrusion Prevention System)** are critical tools in network security.  
- **IDS** detects suspicious activities and generates alerts.  
- **IPS** detects and actively prevents threats by blocking malicious traffic.  


## Key Differences Between IDS and IPS
| Feature                     | IDS                                            | IPS                                     |
|-----------------------------|------------------------------------------------|-----------------------------------------|
| **Functionality**           | Detects intrusions and generates alerts.       | Detects and actively blocks threats.    |
| **Action**                  | Passive (alert only).                          | Active (blocks malicious traffic).      |
| **Placement**               | Monitors network or host traffic.              | Directly in the traffic flow (inline).  |


## Types of IDS/IPS
1. **Network-Based (NIDS/NIPS)**  
   - Monitors all network traffic.  
   - Deployed at network entry/exit points.  

2. **Host-Based (HIDS/HIPS)**  
   - Monitors traffic on individual systems.  
   - Installed on operating systems (e.g., servers).  


## Alert Types
IDS/IPS generate different alerts based on activity:
- **True Positive**: Real attack detected, alert sent.
- **False Positive**: Alert triggered, but no attack occurred.
- **True Negative**: No attack, no alert.
- **False Negative**: Real attack occurred, but no alert was triggered.

### Key Consideration:
Frequent **false positives** may require tuning of rules to minimize noise without missing critical threats.


## Popular IDS/IPS Tools
1. **Snort**  
   - Open-source IDS/IPS with customizable rules.
   - Monitors network traffic for known patterns (e.g., scans, exploits).
   - Example Rules:
     - Detect scans (e.g., Xmas scan, FIN scan).
     - Alert format specifies traffic patterns (e.g., external to internal).

2. **Zeek (formerly Bro)**  
   - Network security monitoring tool.  
   - Focuses on traffic analysis and anomaly detection.  

3. **Suricata**  
   - Advanced IDS/IPS that supports multi-threading.  
   - Often used with Snort rules for simplicity.  

4. **YARA**  
   - Detects malware by matching files against custom rules.  
   - Useful for identifying IOCs (Indicators of Compromise).  

## Evasion Techniques
Attackers may attempt to bypass IDS/IPS using methods like:
- **Packet Fragmentation**: Splitting attack payloads into smaller packets.  
- **Session Splicing**: Breaking payloads across multiple packets.  
- **Decoys**: Using multiple sources to obscure the attacker’s identity.  
- **Obfuscation**: Encoding payloads (e.g., Base64, Unicode).  
- **DoS Attacks**: Overloading IDS/IPS to force failure (e.g., fail open).  
- **Insertion Attacks**: Sending malformed packets to bypass detection.  

### Example: TTL Attacks
1. Fragmented packets have varying TTL (Time to Live) values.
2. Low TTL fragments get dropped by the network.
3. Reassembled fragments bypass detection systems.


## Defense Strategies
- **Baseline Behavior**: Understand normal activity to detect anomalies.  
- **Patch Management**: Regularly update and patch IDS/IPS systems.  
- **Rule Tuning**: Adjust rules to minimize false positives.  
- **Disallow Lists**: Block known malicious behaviors and payloads.  


## Conclusion
IDS and IPS are foundational to network defense.  
- IDS provides awareness of potential threats.  
- IPS actively defends by preventing attacks.  

With proper configuration and maintenance, these systems significantly enhance security resilience.


# Firewalls: Overview and Best Practices

## Introduction
A **firewall** is a network security tool used to filter and control incoming and outgoing traffic based on predefined rules.  
- **Types**: Can be hardware, software, or both.  
- **Function**: Acts as a "bouncer," determining which traffic to allow or deny based on rules.


## Firewall Basics
### Key Features:
- Filters traffic using **allow/deny lists** (whitelisting/blacklisting).
- **Implicit Deny**: A common security practice to block all traffic except explicitly allowed connections.

### Types of Lists:
1. **Allow List**: Allows specific trusted traffic and blocks all others.
2. **Deny List**: Blocks specific untrusted traffic and allows all others.  
   - Used when you can't identify all trusted sources but know certain threats.


## Deployment Strategies
1. **Gateway Firewalls**: Deployed on routers to control access at the network perimeter.  
2. **Bastion Hosts**: Hardened devices that act as entry points into a network.  
3. **DMZ (Demilitarized Zone)**:  
   - A network segment that isolates public-facing servers (e.g., web servers) from internal networks.  
   - Prevents direct access to internal systems from the internet.


## Types of Firewalls
1. **Packet Filtering Firewalls**  
   - Operates at OSI Layer 3 (Network layer).  
   - Filters based on IP addresses, protocols, and port numbers.

2. **Circuit-Level Gateways**  
   - Operates at OSI Layer 5 (Session layer).  
   - Verifies legitimate sessions before allowing traffic.

3. **Application Layer Firewalls**  
   - Operates at OSI Layer 7 (Application layer).  
   - Filters traffic for specific applications like HTTP or FTP.  
   - Example: Web Application Firewalls (WAFs) block SQL injection attacks.

4. **Stateful Firewalls**  
   - Tracks the state of active connections.  
   - Only allows traffic that is part of an established session.

5. **Next-Generation Firewalls (NGFWs)**  
   - Combines traditional firewall capabilities with advanced features like SSL inspection and intrusion prevention.

6. **Other Types**:
   - **Proxy Firewalls**: Filter traffic by acting as an intermediary between clients and servers.
   - **VPNs**: Provide encrypted tunnels that block unauthorized access.


## Evasion Techniques
Attackers may attempt to bypass firewalls using methods like:
- **Firewalking**: Testing TTL values to probe firewall rules.
- **IP Spoofing**: Faking source IP addresses to bypass rules.  
- **Packet Fragmentation**: Breaking packets into small fragments to evade detection.  
- **Denial of Service (DoS)**: Overwhelming the firewall to make it fail open, allowing all traffic.  
- **Tunneling Traffic**: Hiding malicious data within legitimate traffic (e.g., HTTPS, DNS).  
- **Proxies**: Using a proxy server to bypass IP-based filtering.


## Defense Strategies
1. **Implicit Deny**: Block all traffic by default unless explicitly allowed.  
2. **Ingress and Egress Rules**: Ensure traffic is filtered both entering and exiting the network.  
3. **Regular Updates**: Apply security patches to prevent exploitation of vulnerabilities.  
4. **Testing and Review**: Periodically test and refine rules to ensure they are effective.  
5. **Logging and Monitoring**: Use SIEM solutions to monitor firewall activity and detect anomalies.


## Conclusion
Firewalls are a critical layer of network defense, helping to control access and reduce risks.  
- Combine various types of firewalls and strategies to strengthen security.  
- Regular maintenance and monitoring are essential to ensure effectiveness.


## Implementing Firewalls
**Layers for Firewall Implementation:**
- **Network Layer (Layer 3):** Controls traffic based on IP addresses, protocols, and ports. Common in routers and standalone firewalls.
- **Transport Layer (Layer 4):** Filters traffic based on TCP/UDP port numbers and connection states. Used in stateful firewalls.
- **Application Layer (Layer 7):** Inspects the contents of packets for specific applications (e.g., HTTP, FTP). Used in application firewalls and web application firewalls (WAFs).

### Evading Firewalls
**Firewalking:**
Firewalking is a technique used to determine the rules of a firewall by sending packets with varying TTL values and analyzing the responses. It helps attackers map the firewall rules and identify open ports.

**IP Spoofing:**
IP spoofing involves altering the source IP address of packets to impersonate a trusted host. This can bypass IP-based access controls and make malicious traffic appear to come from a legitimate source.

**Fragmentation:**
Fragmentation involves breaking a packet into smaller fragments to evade detection by firewalls that do not reassemble fragmented packets before inspection. This can bypass filters that detect specific patterns in larger packets.

**Tunneling:**
Tunneling encapsulates one type of traffic within another protocol to bypass firewalls. Common examples include using HTTP or DNS to tunnel other types of traffic, making it appear as normal web or DNS traffic to evade firewall rules.

## Honeypots 
**Honeypots** are environments that attract and trap attackers by mimicking real systems or data. They allow administrators to monitor and analyze attacker behavior without risking real systems.

### Interaction Levels
**Low Interaction:**
- **Description:** Simulates only basic services and interactions. Minimal engagement with attackers.
- **Example:** A simple web server that logs attempted connections and basic interactions.

**Medium Interaction:**
- **Description:** Provides more realistic services and interactions. Engages attackers longer but still does not mimic a full operating system.
- **Example:** A virtual machine that simulates a range of services like FTP, SSH, and HTTP, allowing attackers to perform more extensive actions.

**High Interaction:**
- **Description:** Fully functional systems that mimic real production environments. Engages attackers for extended periods, providing deep insights.
- **Example:** A complete operating system set up with real applications and data to observe complex attack patterns.

**Pure Interaction:**
- **Description:** Real systems used as honeypots. No simulation; attackers interact with actual operating systems and services.
- **Example:** A real server with a standard OS and applications deployed as a honeypot to gather comprehensive data on attacker methods.

### Varieties of Honeypots
**Client Honeypots:**
- **Description:** Simulate client-side applications to detect malicious servers.
- **Example:** A web browser honeypot that visits websites to identify drive-by downloads and other client-side attacks.

**Database Honeypots:**
- **Description:** Mimic database systems to attract attackers targeting database services.
- **Example:** A fake MySQL server designed to log SQL injection attempts and unauthorized access attempts.

**Spam Honeypots:**
- **Description:** Designed to attract and collect spam messages for analysis.
- **Example:** An email server that accepts all incoming messages to gather spam for studying spammer tactics and origins.

**Malware Honeypots:**
- **Description:** Attract and capture malware to study its behavior and propagation.
- **Example:** A virtual environment that allows malware to infect it, recording the malware's actions and analyzing its impact and communication patterns.
