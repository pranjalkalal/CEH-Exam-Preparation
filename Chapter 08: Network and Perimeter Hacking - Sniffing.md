# Important Sniffing Concepts
### Hub vs Switch
- **Hub**:
  - **Function**: Broadcasts data to all devices on the network.
  - **Speed**: Slower, as it creates more network collisions.
  - **Layer**: Operates at Layer 1 (Physical Layer) of the OSI model.
  - **Intelligence**: No intelligence; cannot filter data.

- **Switch**:
  - **Function**: Sends data only to the specific device intended.
  - **Speed**: Faster, as it reduces network collisions.
  - **Layer**: Operates at Layer 2 (Data Link Layer) of the OSI model.
  - **Intelligence**: Can filter and forward data based on MAC addresses.

### Sniffing Methods
- **Port Mirroring**:
  - **Definition**: A network switch feature that copies traffic from one port to another for monitoring.
  - **Use**: Commonly used for network troubleshooting and security analysis.

- **LAN Taps**:
  - **Definition**: A physical device inserted between network devices to capture traffic.
  - **Use**: Allows passive monitoring of network traffic without altering it.

### CAM Attack
- **Definition**: An attack that floods a switch’s CAM (Content Addressable Memory) table with fake MAC addresses.
- **Effect**: Causes the switch to enter a fail-open mode, acting like a hub and broadcasting traffic to all ports, enabling packet sniffing.

### VLAN Hopping
- **Definition**: An attack that allows a device on one VLAN to gain access to traffic on another VLAN.
- **Methods**:
  - **Switch Spoofing**: Attacker configures their device to act like a switch.
  - **Double Tagging**: Attacker sends packets with two VLAN tags; the first tag is removed by the first switch, allowing the second switch to forward the packet to the target VLAN.

### Switch Port Stealing
- **Definition**: An attack where an attacker floods a switch with bogus MAC addresses.
- **Effect**: Overloads the switch's MAC table, causing it to fail and broadcast traffic to all ports, making it easier to intercept data.
- **Also Known As**: MAC Flooding or Switch Poisoning.

### What is STP?
- **STP (Spanning Tree Protocol)**:
  - **Definition**: A network protocol that ensures a loop-free topology in Ethernet networks by prevents network loops that can occur in redundant switch configurations.
  - **Function**: STP disables redundant paths by placing some switch ports in a blocking state while keeping the most efficient path active.
  - **Operation**: Uses BPDU (Bridge Protocol Data Units) to communicate between switches and select a root bridge, determining the shortest path and disabling redundant links.

- ***STP Attack***:
  - **Definition**: An attack on the Spanning Tree Protocol (STP) to manipulate the network topology.
  - **Method**: An attacker sends spoofed STP BPDUs (Bridge Protocol Data Units) to become the root bridge.
  - **Effect**: Can reroute traffic through the attacker’s device, enabling data interception and network disruption.

# DHCP Sniffing Attacks
#### DORA
DORA process refers to the 4 step communication for a device to get IP assigned from a DHCP server which are DISCOVER, OFFER, REQUEST, ACKNOWLEDGE.

### DHCP Sniffing Attacks
#### 1. DHCP Starvation Attack
- **Definition**: An attacker sends numerous DHCP requests with spoofed MAC addresses to exhaust the DHCP server's pool of IP addresses.
- **Effect**: Legitimate clients cannot obtain IP addresses, leading to denial of service.
- **Method**: The attacker uses tools like `dhcpstarv` to automate the process of sending fake DHCP requests.

#### 2. DHCP Spoofing Attack
- **Definition**: An attacker sets up a rogue DHCP server on the network to respond to DHCP requests from clients.
- **Effect**: The rogue server can assign malicious IP addresses, gateways, or DNS servers, redirecting traffic and intercepting data.
- **Method**: The attacker listens for DHCP requests and responds faster than the legitimate DHCP server.

#### 3. DHCP Lease Hijacking
- **Definition**: An attacker monitors the network for DHCP requests and responses, then sends a DHCP request to lease an IP address intended for a legitimate client.
- **Effect**: The attacker can impersonate the legitimate client, intercepting their traffic and gaining unauthorized access.
- **Method**: The attacker needs to be quick to send the request before the legitimate client.

### Tools Used in DHCP Sniffing Attacks
- **dhcpstarv**: Automates DHCP starvation attacks.
- **Yersinia**: A network tool that can launch various DHCP attacks, including spoofing and starvation.
- **dhcpxflood**: Another tool for flooding a network with DHCP requests.

### Mitigation Techniques
1. **DHCP Snooping**:
   - **Definition**: A security feature that filters DHCP messages and tracks IP-to-MAC bindings.
   - **Function**: Allows only legitimate DHCP responses from trusted ports, preventing rogue DHCP servers.

2. **Port Security**:
   - **Definition**: Configures switch ports to limit the number of MAC addresses and detect suspicious activity.
   - **Function**: Prevents MAC address spoofing and limits the impact of DHCP starvation attacks.

3. **Rate Limiting**:
   - **Definition**: Limits the rate of DHCP requests on a port.
   - **Function**: Reduces the risk of DHCP starvation by controlling the traffic load.

4. **VLAN Segmentation**:
   - **Definition**: Segregates network traffic into different VLANs.
   - **Function**: Isolates DHCP traffic, reducing the impact of a compromised segment.

5. **Monitoring and Alerts**:
   - **Definition**: Continuously monitors DHCP traffic for anomalies.
   - **Function**: Detects unusual patterns indicative of attacks and triggers alerts.

# ARP Poisoning
**ARP (Address Resolution Protocol) poisoning**, also known as ARP spoofing, is a technique used to intercept network traffic by sending falsified ARP (Address Resolution Protocol) messages. 

### Key Mechanism
- **Manipulation**: The attacker sends fake ARP messages to the network.
- **Objective**: Associate the attacker's MAC address with the IP address of a legitimate device on the network.

### Steps in ARP Poisoning
1. **Send Fake ARP Replies**:
   - The attacker sends spoofed ARP responses that contain the attacker's MAC address and the IP address of the target device (e.g., the gateway or another host).
2. **Update ARP Tables**:
   - The devices on the network receive these spoofed ARP messages and update their ARP tables, associating the attacker's MAC address with the target IP address.
3. **Intercept Traffic**:
   - Once the ARP tables are poisoned, network traffic intended for the target IP address is sent to the attacker's MAC address instead.
4. **Relay Traffic**:
   - The attacker can choose to intercept, modify, or simply forward the traffic to the legitimate recipient, making the attack stealthy.

### Key Points
- **Target**: Changes the MAC address in the ARP table to the attacker's MAC address. The IP address remains unchanged; the attacker is spoofing the MAC address associated with the IP address.

### Example
- **Legitimate ARP Entry**: `192.168.1.1` is mapped to `00:11:22:33:44:55`.
- **Spoofed ARP Entry**: The attacker sends an ARP reply mapping `192.168.1.1` to the attacker's MAC address `66:77:88:99:AA:BB`.
- **Result**: Devices update their ARP tables, associating `192.168.1.1` with `66:77:88:99:AA:BB`, causing traffic to be directed to the attacker.

# DNS Poisoning 

## Overview
DNS Poisoning, also known as DNS Cache Poisoning, is an attack technique used to redirect traffic from a legitimate domain to a malicious IP address. This allows attackers to capture sensitive information or perform phishing attacks. It exploits the DNS resolution process, manipulating DNS cache or settings.

## DNS Resolution Process
1. **Local Check**: The machine checks if it is the requested domain.
2. **Resolver Cache**: Checks the cached DNS entries stored locally.
3. **Host File**: Checks entries in the host file (e.g., `/etc/hosts`).
4. **DNS Server**: If not found locally, the query is sent to the configured DNS server, which may query higher-level authoritative servers.

## Attack Techniques
1. **Host File Modification**: Malware or an attacker may edit the local host file to redirect domains.
2. **Malicious DNS Server Configuration**: Attackers configure malicious DNS servers using DHCP responses, setting a malicious IP for DNS queries.
3. **Cache Poisoning**: Injects fake DNS records into the resolver cache, causing repeated redirections to attacker-controlled sites.

## DNS Cache Poisoning Demo
Using `Ettercap`, the attacker can perform DNS poisoning by configuring a fake DNS response within a local network:
1. Clear the resolver cache using `ipconfig /flushdns` (on Windows).
2. Use `Ettercap` to configure a fake DNS response, setting `twitter.com` to the attacker’s IP.
3. Run `Ettercap` to capture and manipulate DNS requests. Redirected traffic will now resolve to the attacker’s IP.

## Tools for DNS Poisoning
- **Ettercap**: Commonly used for man-in-the-middle attacks, DNS spoofing, and other network-based attacks.
- **DerpNSpoof**: A lightweight command-line tool for DNS spoofing and poisoning.
- **Bettercap**: An alternative to Ettercap, providing DNS spoofing features.

## Mitigations
- **Use DNSSEC**: Prevents unauthorized changes to DNS records by authenticating responses.
- **Enable DNS Security Features**: Such as DNS filtering and validation checks.
- **Secure DNS Settings**: Ensure DNS configurations are secure, preventing unauthorized modifications.


### Example Command in Ettercap
1. Edit `etter.dns` file to set malicious DNS responses.
2. Run `Ettercap` with plugins enabled for DNS spoofing:
    ```bash
    sudo ettercap -T -q -i <interface> -P dns_spoof -M arp // //
    ```

### Additional Resources
- [DerpNSpoof GitHub](https://github.com/path/to/derpNSpoof)
- [Ettercap Documentation](https://www.ettercap-project.org/)



# Sniffing Defenses
#### 1. Use Encrypted Protocols
- **TLS/SSL**: Use HTTPS instead of HTTP for secure web communications.
- **SSH**: Use SSH instead of Telnet for secure remote login.
- **VPN**: Implement Virtual Private Networks (VPNs) for secure communication over untrusted networks.

#### 2. Implement Strong Network Security
- **Switches Over Hubs**: Use switches instead of hubs, as switches reduce the likelihood of traffic being sniffed.
- **Port Security**: Configure port security on switches to limit the number of MAC addresses that can be learned on a port.
- **VLAN Segmentation**: Use VLANs to segment network traffic and isolate sensitive data.

#### 3. Use Secure Authentication
- **MFA (Multi-Factor Authentication)**: Require multi-factor authentication to add an extra layer of security.
- **Encrypted Passwords**: Ensure that passwords are hashed and stored securely, and transmitted over encrypted channels.

#### 4. Network Monitoring and IDS/IPS
- **Intrusion Detection Systems (IDS)**: Deploy IDS to monitor network traffic for signs of sniffing attacks.
- **Intrusion Prevention Systems (IPS)**: Use IPS to actively block suspicious traffic.

#### 5. Implement ARP Security
- **ARP Spoofing Detection**: Use tools and techniques to detect ARP spoofing.
- **Static ARP Entries**: Configure static ARP entries for critical devices to prevent ARP spoofing.

#### 6. Use DHCP Snooping
- **DHCP Snooping**: Enable DHCP snooping on switches to prevent rogue DHCP servers and mitigate DHCP-based sniffing attacks.

#### 7. Enable Port Mirroring Restrictions
- **Controlled Port Mirroring**: Restrict port mirroring to authorized devices and personnel only.

#### 8. Wireless Network Security
- **WPA3**: Use WPA3 for stronger wireless encryption.
- **Hidden SSIDs**: Hide SSIDs to reduce visibility to unauthorized users.
- **MAC Filtering**: Use MAC address filtering to control which devices can connect to the wireless network.

#### 9. Port-Based NAC (Network Access Control)
- **Definition**: Controls access to a network based on the security policies assigned to each port on a switch.
- **Function**: Requires devices to authenticate before granting network access.
- **Benefits**:
  - Enhances security by ensuring only authorized devices can connect.
  - Can enforce different levels of access based on user roles or device types.
- **Example**: IEEE 802.1X is a standard for port-based NAC, providing authenticated access to network resources.

#### 10. Dynamic ARP Inspection (DAI)
- **Definition**: A security feature that validates ARP packets in a network to prevent ARP spoofing and ARP poisoning attacks.
- **Function**:
  - Inspects ARP requests and responses.
  - Ensures that only valid ARP traffic is allowed.
  - Relies on DHCP snooping to build a database of trusted IP-MAC address pairs.
- **Benefits**:
  - Protects against man-in-the-middle attacks.
  - Ensures the integrity of ARP traffic on the network.

#### 11. Disabling Trunk Auto Negotiation
- **Definition**: A feature that allows network devices to automatically negotiate trunking parameters such as VLANs to be carried over a trunk link.
- **Function**:
  - Uses protocols like DTP (Dynamic Trunking Protocol) to dynamically configure trunk links.
  - Negotiates trunk mode (on, off, auto, desirable).
- **Why Disable?**:
  - Trunk auto negotiations are risky because they can inadvertently create unauthorized trunk links, potentially allowing VLAN hopping attacks. It's advisable to disable auto negotiations and manually configure trunk links to ensure only intended VLANs are allowed.

#### 12. BPDU Guard
- **Definition**: A security feature that protects the Spanning Tree Protocol (STP) by disabling ports that receive unexpected BPDUs (Bridge Protocol Data Units).
- **Function**:
  - Monitors network ports for incoming BPDUs.
  - If a BPDU is received on a port with BPDU Guard enabled, the port is immediately placed in an error-disabled state.
- **Benefits**:
  - Prevents rogue switches from affecting the network topology.
  - Enhances the stability and security of the STP domain.

#### 13. DNSSEC (Domain Name System Security Extensions)
- **Definition**: A suite of extensions that add security to the DNS protocol by enabling DNS responses to be verified.
- **Function**:
  - Uses digital signatures to ensure the authenticity and integrity of DNS data.
  - Protects against attacks such as DNS spoofing and cache poisoning.
- **Benefits**:
  - Ensures that DNS responses are authentic and have not been tampered with.
  - Provides a higher level of trust in DNS operations.
