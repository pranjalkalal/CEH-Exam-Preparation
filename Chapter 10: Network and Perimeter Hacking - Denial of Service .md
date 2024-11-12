# DOS vs DDoS

## Introduction
- **DOS (Denial of Service)** and **DDoS (Distributed Denial of Service)** attacks aim to prevent services from being accessible.
- **Difference**: 
  - **DOS**: Single attacker.
  - **DDoS**: Multiple attackers.

## What is a DOS Attack?
- A **Denial of Service** (DOS) attack makes a service (e.g., web server, FTP) inaccessible to legitimate users.
- The attacker overwhelms the service, preventing users from interacting with it.
  
## What is a DDoS Attack?
- A **Distributed Denial of Service** (DDoS) attack involves multiple attack points (botnets) targeting the same service.
- **Key Difference**: DDoS uses multiple attackers, making it harder to defend against compared to DOS.

## Techniques Used in DOS/DDoS Attacks

### 1. **Volumetric Attacks**
   - Depletes the bandwidth of the target by flooding it with large amounts of data.
   - **Amplification attacks**: Attack data grows larger than the original request.
     - Examples: UDP flooding, ICMP flooding, Ping of Death, Smurf attacks.
   - **Pulse Wave Attacks**: Particularly effective in hybrid cloud environments.

### 2. **Protocol Attacks**
   - Targets the protocols themselves (e.g., TCP).
   - **SIN Flood**: Floods with SYN packets, exploiting the three-way handshake in TCP.
   - **ACK Flood**: Sends ACK packets, overwhelming the target.
   - **Fragmentation attacks**: Breaks packets into smaller pieces to exhaust the system.

### 3. **Application Layer Attacks**
   - Aimed at the application layer (e.g., web servers).
   - Example: **Slowloris Attack**: Keeps the connection open, consuming server resources without closing it.
   - **UDP Application Layer Flood**: Utilizes UDP protocol to flood application layers with requests, causing resource starvation.

### 4. **Multi-Vector Attacks**
   - Combines multiple attack vectors (e.g., volumetric + protocol attacks) to increase complexity.
   - Harder to mitigate as it requires defense on multiple fronts simultaneously.

## Permanent Denial of Service
- Some attacks cause permanent damage:
  - **Malware**: Can destroy the hardware or data, making the service permanently unavailable (e.g., bricking a device by corrupting BIOS).

## Reflective Denial of Service Attacks
- In **Reflective DOS**:
  - Attacker uses a third party (e.g., a server) to attack the victim, making it appear that the attack is coming from someone else.
  - Example: Attacker sends a request to a third-party server (Sophia), spoofing the source to make it appear as though the request is from the victim (you).
  - The third-party server responds with a larger packet, amplifying the attack.
  - Commonly seen with **DNS** amplification attacks.

## Tools
- **LOIC (Low Orbit Ion Cannon)**:
  - **Purpose**: Open-source network stress testing and DoS attack tool.
  - **Use**: Generates high traffic to target services.

- **HOIC (High Orbit Ion Cannon)**:
  - **Purpose**: Advanced version of LOIC, used for DDoS attacks.
  - **Features**: Can target multiple URLs simultaneously.

- **Hping3**:
  - **Purpose**: Network packet generator and analyzer.
  - **Use**: Can craft custom packets for security testing, including DoS attacks.

## Example Attacks
### Phlashing (Permanent Denial-of-Service)
- **Definition**: A destructive type of attack that damages hardware firmware.
- **Mechanism**:
  - **Firmware Corruption**: The attacker sends a malicious update to the device's firmware.
  - **Irreparable Damage**: The malicious update corrupts the firmware, rendering the device permanently unusable.
- **Impact**: Often results in irreversible damage, requiring hardware replacement.

### DRDoS (Distributed Reflection Denial-of-Service)
- **Definition**: A DDoS attack that amplifies traffic by exploiting legitimate services to reflect and amplify attack traffic towards the target.
- **Example**: DNS amplification attacks.

***DNS Amplification Attack***:
- **Definition**: A type of DDoS attack that exploits the DNS system to amplify the attack traffic.
- **Mechanism**:
  - **Exploiting DNS Servers**: The attacker sends DNS queries with a spoofed IP address (the target's IP) to open DNS resolvers.
  - **Amplification**: The DNS servers respond to the queries with large DNS responses, which are sent to the target's IP address.
  - **Traffic Volume**: The size of the response is much larger than the request, amplifying the volume of traffic directed at the target.
- **Impact**: Overwhelms the target with a large volume of DNS response traffic, causing a denial of service.
- Example using hping3:  `hping3 --flood --spoof {target's IP} --udp -p 53 {DNS server}`.

### Ping of Death
- **Definition**: A type of DoS attack that involves sending oversized ICMP packets to a target.
- **Mechanism**:
  - **Oversized Packets**: The attacker sends an ICMP echo request (ping) packet that exceeds the maximum allowable size of 65,535 bytes.
  - **Buffer Overflow**: The target system cannot handle the oversized packet, leading to a buffer overflow.
- **Impact**: Causes crashes, reboots, or instability in the target system due to the inability to process the oversized packets.

## Conclusion
- **DOS/DDoS attacks** are designed to disrupt services by overwhelming them with traffic.
- Different techniques, such as volumetric, protocol, and application layer attacks, can be used in isolation or combined for more effective attacks.
- **Reflective attacks** leverage third-party servers to amplify the traffic and mask the attack source.



# Volumetric Attacks

Volumetric attacks are a category of Denial of Service (DoS) attacks that focus on overwhelming the bandwidth or resources of a network, application, or server. These attacks generate massive traffic to flood and exhaust the resources, causing legitimate requests to be denied.

## Key Characteristics:
- **High Traffic Volume**: The attack aims to generate a massive volume of traffic, often in the form of requests or data packets, to overwhelm a target.
- **Network or Application-Level Impact**: These attacks can affect both network infrastructure and application performance.
- **Resource Exhaustion**: The goal is to consume all available resources (e.g., bandwidth, CPU, memory), rendering the service unavailable.

## Types of Volumetric Attacks:
- **UDP Flood**: Sends large volumes of UDP packets to random ports on a target server, consuming bandwidth and resources.
- **ICMP Flood (Ping Flood)**: Floods the target with ICMP Echo Request packets, consuming the network bandwidth.
- **DNS Amplification**: Exploits DNS servers to amplify the attack traffic, sending a small query that generates a large response, overwhelming the target.
- **NTP Amplification**: Similar to DNS amplification but uses NTP servers to flood the target with responses.
- **HTTP Flood**: Sends a large number of HTTP requests to a web server, attempting to exhaust its resources or overload the network.
- **Smurf Attack**: Exploits the ICMP protocol by sending a small ping request to a network's broadcast address, with the source address spoofed to that of the target. All devices in the network reply to the spoofed address, flooding the target with traffic.
- **Fraggle Attack**: Similar to the Smurf attack, but it uses **UDP packets** (typically to port 7 or 19, which are associated with **echo** and **chargen** services). The attacker sends a request to a broadcast address with the source address spoofed to the target, and all devices on the network respond, amplifying the traffic directed at the target.

**Example:**
Using `hping3` to execute a UDP flood attack: `hping3 --udp -p 80 -i u1 192.168.1.1`

This command sends UDP packets to port 80 of the target IP address (192.168.1.1) at a rate of one packet per microsecond.

**Example:**
Using `hping3` for an ICMP flood attack: `hping3 --icmp -i u1 192.168.1.1`

This command sends ICMP Echo Request packets to the target IP address (192.168.1.1) at a rapid rate.

### Smurf vs Fraggle Attacks
**Description:**
Smurf attacks involve spoofing the victim's IP address and sending ICMP Echo Request packets to broadcast addresses, causing amplification. Fraggle attacks are similar but use UDP instead of ICMP, targeting network services like echo (port 7) or chargen (port 19).

So in brief, the ICMP Echo Request packets broadcasted will appear to originate from the spoofed IP causing all devices on the network to respond to the victim. As a result, the victim's system gets overwhelmed with ICMP Echo Reply packets, leading to a denial-of-service condition.

**Example Smurf Attack:**
Using `hping3` to simulate a Smurf attack: `hping3 --icmp -a 192.168.1.1 --broadcast 192.168.1.255`

This command sends ICMP packets with a spoofed source IP (192.168.1.1) to the broadcast address of the network.

**Example Fraggle Attack:**
Using `hping3` to execute a Fraggle attack: `hping3 --udp -a 192.168.1.1 --broadcast -p 7 192.168.1.255`

This command sends UDP packets with a spoofed source IP (192.168.1.1) to the broadcast address, targeting port 7 (echo) of devices on the network.

### Pulse Wave Attack
**Description:**
A Pulse Wave attack involves sending short bursts or pulses of high traffic at regular intervals to overwhelm a target's defenses. This type of attack aims to bypass traditional DDoS defenses by rapidly fluctuating the intensity of the attack.

**Example:**
While not directly supported by `hping3`, a Pulse Wave attack could involve sending bursts of packets at intervals: `hping3 --flood -p 80 192.168.1.1 -i u100`

## Mitigation Strategies:
- **Traffic Filtering**: Implement filtering solutions such as rate limiting and blocking suspicious traffic.
- **Content Delivery Networks (CDNs)**: CDNs can absorb high volumes of traffic, distributing the load across multiple servers.
- **Intrusion Prevention Systems (IPS)**: Use IPS to detect and block attack traffic before it reaches critical systems.
- **Anti-DDoS Solutions**: Dedicated services or appliances designed to detect and mitigate DoS/DDoS attacks.
- **Rate Limiting**: Restrict the number of requests a client can make to a server within a certain time frame to reduce the attack's effectiveness.
  
## Challenges in Defense:
- **Volume and Complexity**: The sheer scale of the attack can overwhelm defenses, especially without prior detection and mitigation plans.
- **Botnets**: Volumetric attacks often use large botnets to generate traffic, making it difficult to distinguish malicious traffic from legitimate traffic.
- **Increased Latency**: While mitigating these attacks, organizations may experience increased latency or degraded performance for legitimate users.

## Detection:
- **Traffic Anomalies**: Monitoring for sudden spikes in traffic volume or unusual patterns can help detect volumetric attacks early.
- **Behavioral Analysis**: Analyzing baseline traffic patterns and looking for deviations from normal behavior can be an effective detection method.
- **Rate of Requests**: Unusual increases in the rate of requests to a particular service or endpoint may indicate an ongoing volumetric attack.

Volumetric attacks are common in the landscape of cyberattacks and are designed to disrupt services by flooding systems with traffic. Effective defense and mitigation require robust network monitoring, traffic filtering, and specialized anti-DDoS solutions.


## Protocol Attacks

### SYN, PUSH, ACK Flood
***Description:***
SYN, PUSH, and ACK floods are types of TCP flood attacks that exploit the TCP handshake process. In a SYN flood, the attacker sends a large number of TCP SYN packets to the target, exhausting its resources by forcing it to allocate resources for half-open connections. PUSH and ACK floods involve sending excessive TCP packets with the PSH and ACK flags set, respectively, to consume target resources and degrade performance.

***Example:*** In this example we are denying RDP service on that TARGET_IP server.
```
hping3 --flood --rand-source -S -p 3389 TARGET_IP
hping3 --flood --rand-source -A -p 3389 TARGET_IP
hping3 --flood --rand-source -P -p 3389 TARGET_IP
```

### TCP Fragmentation Attack
- **Definition**: Exploits IP fragmentation to overwhelm a target.
- **Example**: Teardrop Attack.

***Teardrop Attack***:
- **Definition**: A type of DoS attack that involves sending fragmented packets to a target.
- **Mechanism**:
  - **Fragmented Packets**: The attacker sends malformed IP fragments that cannot be reassembled properly.
  - **Reassembly Issue**: The target system attempts to reassemble the fragments, but the offset values are incorrect, causing the system to crash or become unstable.
- **Impact**: Causes crashes or reboots in vulnerable operating systems due to the inability to handle malformed fragments.
- **Example**: `hping3 --flood --frag --flood -d 2000 TARGET_IP`.

## 3. Application Layer Attacks

### Slowloris
- **Definition**: Slowloris is a type of denial-of-service (DoS) attack tool that targets web servers by opening multiple connections and keeping them open for as long as possible.
- **Mechanism**:
  - **Partial HTTP Requests**: Slowloris sends partial HTTP requests to the target web server and continues to send headers periodically to keep the connections open but incomplete.
  - **Resource Exhaustion**: By keeping many connections open without completing them, Slowloris exhausts the server's resources, leading to denial of service for legitimate users.
- Can be done with slowloris module in Metasploit.

# Botnets
A botnet is a network of compromised computers or "bots" that are controlled by a central command-and-control (C&C) server operated by an attacker or botmaster. These bots are typically infected with malware that allows the attacker to remotely control them without the knowledge of their owners. Botnets are commonly used for various malicious activities, including distributed denial-of-service (DDoS) attacks, spam email dissemination, information theft, and spreading further malware infections.

# Countermeasures for DoS Attacks
**Active Profiling:**
Active profiling involves continuously monitoring network traffic patterns and system behavior to identify anomalies indicative of a potential DoS attack. By establishing baseline behavior profiles and comparing them in real-time, active profiling can help detect deviations that may signal an ongoing attack.

**Sequential Change Point Detection (Cumulative Sum Algorithm):**
Sequential change point detection algorithms, such as the Cumulative Sum (CUSUM) algorithm, analyze incoming data streams to detect sudden changes or shifts in patterns. These algorithms are effective in identifying anomalies in network traffic that could indicate the onset of a DoS attack.

**Wavelet Signal-Based Analysis:**
Wavelet signal-based analysis involves using wavelet transformations to analyze network traffic and identify patterns associated with DoS attacks. By decomposing signals into different frequency components, wavelet analysis can detect subtle changes in traffic patterns that may indicate an attack.

**Mitigation Techniques:**
- **Rate Limiting:** Implementing rate-limiting measures can help mitigate the impact of DoS attacks by limiting the rate of incoming traffic to a manageable level, preventing network resources from being overwhelmed.
- **Black and Sinkholing:** Blackholing involves redirecting malicious traffic to a designated sinkhole or null route, effectively isolating it from the rest of the network and minimizing its impact on legitimate traffic.
- **Deflections:** Deflection techniques redirect incoming attack traffic away from the target server or network, mitigating the impact of the attack while allowing legitimate traffic to pass through unaffected.
- **Hardware Enhancements:** Hardware-based mitigation techniques, such as deploying specialized hardware appliances or employing dedicated hardware components with built-in DoS protection mechanisms, can provide robust defense against DoS.
