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
