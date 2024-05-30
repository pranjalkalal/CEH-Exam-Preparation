# IoT Overview
#### Definition
  - Connecting everyday objects and systems to networks to make them globally available and interactive.

## Components of IoT
1. **Things:**
   - Everyday devices like refrigerators, washing machines, sensors, cameras, and network devices connected to the internet.
2. **Gateway:**
   - Connects IoT devices to each other, end users, or the cloud.
3. **Cloud Server:**
   - Stores and processes IoT data, making it available for consumption.
4. **Remote Apps:**
   - Interface for users to connect and manage IoT devices, often via smartphones or laptops.

## Types of IoT
- **Consumer IoT:**
  - Devices like smart refrigerators, washing machines, IP cameras, and routers.
- **Industrial IoT:**
  - Sensors for monitoring industrial processes, pressure, heat, fluid flow, etc.

## IoT Architecture
1. **Edge Technology:**
   - IoT hardware components.
2. **Access Gateway:**
   - Allows communication between different IoT technologies.
3. **Internet Layer:**
   - IP-based communication for IoT devices.
4. **Middleware:**
   - Services running in the background to support the application layer.
5. **Application Layer:**
   - End-user interface for interacting with IoT devices.

## IoT Applications
- **Healthcare:** Heart monitors, medical sensors.
- **Military:** Monitoring and control systems for military equipment.
- **IT:** Environmental monitoring of server rooms.
- **Transportation:** Tire pressure sensors, traffic monitoring.
- **Energy:** Monitoring and control in power plants, solar, hydroelectric.

## Communication Technologies and Protocols
- **Common Technologies:**
  - Wi-Fi, RFID, ZigBee, LTE, LP WAN, SigFox, Ethernet.
- **Operating Systems:**
  - Embed OS, Windows 10 IoT, Contiki NG, Ubuntu Core.

## Communication Models
1. **Device to Device:**
   - Direct communication between two devices.
2. **Device to Cloud:**
   - Devices communicate with the app service provider.
3. **Device to Gateway:**
   - Devices communicate with an IoT gateway which then connects to the app service provider.
4. **Backend Data Sharing:**
   - Device communicates with multiple app service providers.

## Security Challenges
- **Common Issues:**
  - No or weak security, poor access control, vulnerable web applications, clear text communications, lack of support, physical theft.

# IoT Threats and Vulnerabilities

## OWASP Top 10 IoT Threats
1. **Weak, Guessable, or Hard-coded Passwords**
   - Easily guessed or hard-coded credentials pose significant security risks.

2. **Insecure Network Services**
   - Services that lack encryption and other security measures are vulnerable to attacks.

3. **Insecure Ecosystem Interfaces**
   - Includes web applications, APIs, and other components that interact with the device.

4. **Lack of Secure Update Mechanism**
   - Firmware updates without secure methods can be exploited for attacks.

5. **Use of Insecure or Outdated Components**
   - Deprecated or insecure software components can be compromised.

6. **Insufficient Privacy Protection**
   - User data must be stored and transmitted securely to protect privacy.

7. **Insecure Data Transfer and Storage**
   - Sensitive data should be encrypted during transfer and storage.

8. **Lack of Device Management**
   - Poor management interfaces can lead to security lapses.

9. **Insecure Default Settings**
   - Default settings like "admin/admin" for username and password should be avoided.

10. **Lack of Physical Hardening**
    - Physical access to the device can lead to its compromise.

## IoT Attack Surfaces
1. **Physical Interfaces**
   - Ports and physical connections on the device that can be exploited.

2. **Firmware**
   - Vulnerabilities in the firmware can be exploited through updates.

3. **Network Traffic**
   - Unencrypted communications can be intercepted.

4. **Vendor and Third-Party APIs**
   - APIs must be secure to prevent unauthorized access.

5. **Local Storage**
   - Data stored on the device should be protected.

6. **Mobile Applications**
   - Security weaknesses in associated mobile apps can be exploited.

## Additional IoT Vulnerabilities
- **MFA/2FA:** Implementing multi-factor authentication to enhance security.
- **Lockout Policies:** Prevent brute force attacks by locking accounts after several failed attempts.
- **DDoS Protection:** Devices should be protected against denial-of-service attacks.
- **Regular Updates and Patches:** Ensure timely updates to address vulnerabilities.
- **Insecure Third-party Components:** Ensure third-party components are secure.
- **Hardware Access Ports:** Secure physical ports like JTAGs and UARTs to prevent unauthorized access.

# 
