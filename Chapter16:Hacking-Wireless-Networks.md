# Wireless Basics

## Wireless Features
1. **Access Points (APs):**
   - Devices that provide wireless connectivity.
2. **Wireless LAN (WLAN):**
   - Local Area Network using wireless connections.
3. **BSSID (Basic Service Set Identifier):**
   - MAC address of the access point.
4. **SSID (Service Set Identifier):**
   - Name of the wireless network.
5. **Association:**
   - Connecting to an AP. Disassociation needed to connect to a different AP.

## Wireless Standards (802.11)
1. **802.11a:**
   - Frequency: 5 GHz
   - Distance: 35-100 meters
   - Speed: 54 Mbps
2. **802.11b:**
   - Frequency: 2.4 GHz
   - Distance: 35-140 meters
   - Speed: 11 Mbps
3. **802.11g:**
   - Frequency: 2.4 GHz
   - Distance: 38-140 meters
   - Speed: 54 Mbps
4. **802.11n:**
   - Frequency: 2.4 GHz and 5 GHz
   - Distance: 70-250 meters
   - Speed: 54-600 Mbps
5. **802.11ac:**
   - Frequency: 5 GHz
   - Distance: 46-92 meters
   - Speed: 433-6,933 Mbps
6. **802.11ax:**
   - Frequency: 2.4 GHz, 5 GHz, and 6 GHz
   - Distance: Up to 9.1 meters
   - Speed: 574-9,608 Mbps

## Authentication Types
1. **Open WiFi:**
   - No authentication required.
2. **Pre-Shared Key (PSK):**
   - Common password-based authentication.
3. **Centralized Authentication (e.g., RADIUS):**
   - Used in corporate environments.

## Types of Antennas
1. **Yagi Antennas:**
   - Directional, common for TV antennas.
2. **Omnidirectional Antennas:**
   - Radiates signal in all directions.
3. **Parabolic Grid Antennas:**
   - Used for long-distance, looks like a grid.
4. **Reflectors:**
   - Enhance signal by concentrating EM radiation.

## Wireless Encryption Types
1. **WEP (Wired Equivalent Privacy):**
   - 24-bit IV, RC4 algorithm, weak security.
2. **WPA (Wi-Fi Protected Access):**
   - 48-bit IV, RC4 with TKIP, improved but still vulnerable.
3. **WPA2:**
   - 48-bit IV, AES CCMP, 128-bit encryption, secure but crackable.
4. **WPA3:**
   - AES-GCMP-256, 192-bit encryption, personal and enterprise modes, currently robust.

# Wireless Threats and Attacks

## Authentication Attacks
- **Definition:** Attacks aimed at the authentication mechanisms of a wireless network.
- **Method:** Typically involve brute-forcing the pre-shared key (PSK) or password.
- **Impact:** Allows attackers to gain unauthorized access by repeatedly attempting to guess the correct authentication credentials.

## Rogue Access Points
- **Definition:** Unauthorized access points installed within a network.
- **Purpose:** Provides attackers with backdoor access to the internal network.
- **Example:** An employee might install an access point for convenience, inadvertently creating a security vulnerability.

## Evil Twin Attack
- **Definition:** An attack where a malicious access point is set up to mimic a legitimate one.
- **Method:** Attackers use the same SSID as the legitimate network to trick users into connecting.
- **Impact:** Users unknowingly connect to the attacker’s access point, exposing their data to interception.

## Honeypot AP
- **Definition:** An access point set up to lure attackers.
- **Purpose:** Attracts and traps attackers by posing as a legitimate, trusted network.
- **Impact:** Helps to identify and analyze malicious activities.

## Soft AP (Software Access Point)
- **Definition:** An access point created through software rather than hardware.
- **Method:** Malware turns a compromised device into an access point.
- **Impact:** Allows attackers to connect to the infected device and access internal network resources.

## Denial of Service (DoS) Attacks
- **Definition:** Attacks aimed at disrupting the availability of the wireless network.
- **Methods:**
  - **Deauthentication Attacks:** Sending deauthentication frames to disconnect users repeatedly.
  - **Disassociation Attacks:** Sending disassociation frames to force users to disconnect.
  - **Jamming:** Emitting signals that interfere with the wireless communication.

## Crack (Key Reinstallation Attack)
- **Definition:** An attack on WPA and WPA2 protocols.
- **Method:** Blocking message 3 of the four-way handshake, causing the access point to resend it with the same nonce.
- **Impact:** Allows attackers to decipher the encryption keys by exploiting the reuse of nonces.

## MAC Spoofing
- **Definition:** Changing the MAC address of a device to bypass MAC filtering.
- **Method:** Attackers sniff for allowed MAC addresses and change their device’s MAC address to match.
- **Impact:** Grants unauthorized access to the network by appearing as a trusted device.

# Wireless Hacking Tools

## Wi-Fi Discovery Tools
1. **Insider (SSID-er)**
   - Displays statistics about wireless networks.
   - Shows SSIDs, BSSIDs, signal strengths, and channels.
   - Helps identify less congested channels for setting up wireless networks.

2. **NetSurveyor**
   - Provides information on SSIDs, BSSIDs, channels, and signal strengths.
   - Indicates encryption types and beacon strength.

3. **Mobile Tools**
   - **Fing**: Popular network analysis tool for mobile devices.
   - **Network Analyzer**: Another tool for discovering and analyzing wireless networks on mobile.

## GPS Mapping Tools
1. **Wiggle (wigle.net)**
   - Displays a map of detected wireless networks.
   - Provides detailed information about the physical locations of networks.

2. **Wi-Fi Map (wifimap.io)**
   - Shows wireless networks along with passwords if available.
   - Useful for mapping and locating specific networks.

## Traffic Analysis Tools
- **Wireshark**
  - Captures and analyzes network traffic.
  - Useful for seeing unencrypted data transmitted over wireless networks.

## Wireless Attack Tools
1. **Aircrack-ng Suite**
   - Comprehensive suite of tools for wireless network security testing.
   - Includes tools like Airbase-ng, Aircrack-ng, Airdecap-ng, and others.

2. **Fern Wi-Fi Cracker**
   - GUI-based tool for wireless security auditing.
   - Automates the process of network discovery and attacking.

3. **WiFite**
   - Automates wireless auditing and penetration testing.
   - Scans for networks and attempts to crack WEP/WPA keys.

# Wireless Hacking

**MAC Spoofing:**
MAC spoofing is a technique used to impersonate a trusted device on a network by spoofing its MAC address. The process is as follows:
1. Enable monitor mode on the wireless interface: 
   `sudo airmon-ng start wlan0`
2. Begin capturing packets to find the SSIDs available:
   `sudo airodump-ng wlan0mon`
3. Once we have the BSSID of the AP, filter the captured packets to focus on a specific channel and BSSID (AP's MAC address) to identify allowed devices' MAC addresses:
   `sudo airodump-ng -c <channel> --bssid <BSSID> -w output wlan0mon`
4. Use `MAC Changer` to spoof the MAC address and connect to the AP bypassing the mac filtering.

**Deauthentication Attacks:**
Deauthentication attacks disrupt the connection between a client and an access point by sending deauthentication frames. The procedure involves:
1. Use `aireplay-ng` to send deauthentication packets to the target client: (we need to follow the first 3 steps again to get client mac address)
   `sudo aireplay-ng --deauth 25 -a <AP-BSSID> -c <Client-MAC> wlan0mon`

**WPA Cracking:**
WPA cracking aims to capture a WPA handshake and then crack the passphrase. The hosts outlined the steps as follows:
1. If necessary, use `Aireplay-ng` to force a handshake by deauthenticating clients.
1. Capture the WPA handshake by sniffing network traffic on a specific channel and BSSID:
   `sudo airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon`
2. Once the handshake is captured, attempt to crack the WPA password using `aircrack-ng`:
   `sudo aircrack-ng -a2 -b <BSSID> -w /path/to/wordlist capture.cap`

# Wireless Hacking Countermeasures

This document outlines key countermeasures to protect against wireless hacking, emphasizing actionable steps to enhance security.

## Wireless Security Controls
- **Definition**: Measures to improve system security, including:
  - **Technical controls**: Patches, updates, encryption protocols.
  - **Administrative controls**: Audits, policy enforcement.
  - **Procedural controls**: Incident response and change management.


## Patches and Updates
- Regularly update:
  - **Client devices** (e.g., laptops, mobile phones).
  - **Firmware** and **software** for Access Points (APs).
- Importance:
  - Fixes bugs and vulnerabilities.
  - Enhances device security.
- Example: TP-Link updates include security enhancements and bug fixes.


## Changing Default Configurations
- **Default settings** are predictable and exploitable:
  - Default SSIDs (e.g., "Linksys").
  - Default admin passwords.
  - Standard DHCP configurations.
- **Recommendations**:
  - Modify SSID to non-identifiable names.
  - Change admin credentials.
  - Avoid broadcasting SSID (security through obscurity).
  - Use strong, randomly generated passphrases.


## Enable Strong Encryption
- Use at least **WPA2-Personal** for encryption.
- Enterprise environments should consider **WPA2-Enterprise**:
  - Employs RADIUS and certificate-based authentication for added security.
- Avoid deprecated protocols like WEP.


## Limit Remote Access
- Disable remote login unless absolutely necessary.
- If enabled:
  - Use HTTPS to secure connections.
  - Employ strong authentication mechanisms.
  

## Network Access Control (NAC) and Segmentation
- **NAC Tools**:
  - Example: PacketFence (open-source NAC solution).
  - Enforce strict access policies for devices connecting to the network.
- **Network Segmentation**:
  - Divide networks into segments.
  - Restrict access between segments to prevent lateral movement.
  

## Additional Measures
- **VPN Usage**:
  - Encrypts data over untrusted networks.
  - Ideal for remote workers or public WiFi scenarios.
- **Firewalls, IDS, IPS**:
  - Example: Cisco Adaptive Wireless IPS for enterprise wireless security.
  - Detect and prevent intrusions or anomalies.


## Physical Security
- Protect access points and devices:
  - Secure in locked areas.
  - Limit access to authorized personnel.
- Prevent tampering or theft, especially in IoT deployments.


## Scheduled Audits and Baselines
- Conduct regular **WiFi surveys** and **heat maps**:
  - Identify signal bleed into untrusted areas.
  - Optimize signal strength and placement.
- Compare current configurations to established baselines.
- Update baselines after approved changes.


## Public WiFi Guidelines
- Avoid connecting enterprise devices to public WiFi.
- Educate users on risks and enforce policies against usage.


### Summary
Effective wireless security requires a combination of regular updates, strong configurations, physical protection, and continuous auditing. By implementing these countermeasures, organizations can significantly reduce vulnerabilities and mitigate wireless threats.
