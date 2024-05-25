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

# Common Wireless Attacks

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
