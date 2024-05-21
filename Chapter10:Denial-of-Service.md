# DoS/DDoS
## Classification
- **Application Layer Attack**:
  - **Definition**: Targets the application layer (Layer 7) of the OSI model.
  - **Examples**: Slowloris, HTTP Flood.
  - **Impact**: Exhausts the application's resources, causing downtime.

- **Protocol Attack**:
  - **Definition**: Exploits weaknesses in the network protocols.
  - **Examples**: SYN Flood, Ping of Death.
  - **Impact**: Consumes server resources or network infrastructure.

- **Volumetric Attack**:
  - **Definition**: Generates massive amounts of traffic to overwhelm bandwidth.
  - **Examples**: UDP Flood, ICMP Floods, DNS Amplification.
  - **Impact**: Saturates the target's internet connection.

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

### TCP Fragmentation Attack
- **Definition**: Exploits IP fragmentation to overwhelm a target.
- **Example**: Teardrop Attack.

***Teardrop Attack***:
- **Definition**: A type of DoS attack that involves sending fragmented packets to a target.
- **Mechanism**:
  - **Fragmented Packets**: The attacker sends malformed IP fragments that cannot be reassembled properly.
  - **Reassembly Issue**: The target system attempts to reassemble the fragments, but the offset values are incorrect, causing the system to crash or become unstable.
- **Impact**: Causes crashes or reboots in vulnerable operating systems due to the inability to handle malformed fragments.

### Ping of Death
- **Definition**: A type of DoS attack that involves sending oversized ICMP packets to a target.
- **Mechanism**:
  - **Oversized Packets**: The attacker sends an ICMP echo request (ping) packet that exceeds the maximum allowable size of 65,535 bytes.
  - **Buffer Overflow**: The target system cannot handle the oversized packet, leading to a buffer overflow.
- **Impact**: Causes crashes, reboots, or instability in the target system due to the inability to process the oversized packets.

### Slowloris
- **Definition**: Slowloris is a type of denial-of-service (DoS) attack tool that targets web servers by opening multiple connections and keeping them open for as long as possible.
- **Mechanism**:
  - **Partial HTTP Requests**: Slowloris sends partial HTTP requests to the target web server and continues to send headers periodically to keep the connections open but incomplete.
  - **Resource Exhaustion**: By keeping many connections open without completing them, Slowloris exhausts the server's resources, leading to denial of service for legitimate users.

# Now let's dive in more details

## 1. Volumetric Attack

### UDP Flooding
**Description:**
UDP (User Datagram Protocol) flooding is a type of DoS attack where an attacker inundates a target server with a high volume of UDP packets. Since UDP is connectionless, the server must process each packet individually, potentially exhausting its resources.

**Example:**
Using `hping3` to execute a UDP flood attack: `hping3 --udp -p 80 -i u1 192.168.1.1`

This command sends UDP packets to port 80 of the target IP address (192.168.1.1) at a rate of one packet per microsecond.

### ICMP Flooding
**Description:**
ICMP (Internet Control Message Protocol) flooding, or ping flooding, overwhelms a target system with ICMP Echo Request packets. The target's responses to these requests can saturate its network bandwidth and processing capabilities.

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

## 2. 
