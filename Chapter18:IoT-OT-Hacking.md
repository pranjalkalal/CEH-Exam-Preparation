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

# IoT Attacks Tools

## Hardware Tools
- **JTagulator**: Used for identifying JTAG interface pins.
- **UART TTL to USB Device**: Connects UART to USB, enabling device communication.
- **Bus Pirate**: Interfaces with hardware devices for testing and debugging.
- **SOIC Clip**: Connects to integrated circuits for direct interaction.
- **CR232 to USB Adapter**: Interfaces with Serial Peripheral Interface (SPI) chips.

## Software Tools
- **Shodan**: Searches for internet-connected devices and identifies vulnerabilities.
- **Censys and Thingful**: Similar to Shodan for identifying and analyzing IoT devices.
- **Wireshark/TCPDump**: Network protocol analyzers for monitoring network traffic.
- **Burp Suite/OWASP ZAP**: Web application security testing tools.
- **GNU Radio/RTL-SDR**: Software and hardware for software-defined radio (SDR) applications.

## Unique IoT Attacks
- **HVAC Attacks**: Exploiting web-managed heating, ventilation, and air conditioning systems.
- **Rolling Code Attacks**: Intercepting and predicting codes used in key fobs.
- **Bluetooth Attacks**: Exploits like BlueBorne and Bluejacking.
- **DDoS via Jamming**: Overwhelming IoT devices' communication channels.
- **Sybil Attack**: Overloading systems with false identities, e.g., causing traffic jams via manipulated GPS data.

# OT Overview

**Operational Technology (OT)**: 
- Technologies used in manufacturing, energy, and critical infrastructure.
- Involves managing, monitoring, and controlling industrial systems and operations.
- Companies like Siemens, Schneider Electric, and Allen Bradley are prominent OT manufacturers.

**Key Components and Systems**:
1. **ICS (Industrial Control Systems)**:
   - Systems that control industrial processes.
   - Example: Control systems in a power plant.

2. **SCADA (Supervisory Control and Data Acquisition)**:
   - Gathers and presents data to operators.
   - Operators use this data to make decisions and control processes.

3. **DCS (Distributed Control Systems)**:
   - Focuses on automation and process control with minimal operator interaction.

4. **PLCs (Programmable Logic Controllers)**:
   - Physical devices that control machinery and processes.
   - Example: A PLC could control a valve or a pump in a manufacturing process.

5. **RTUs (Remote Terminal Units)**:
   - Similar to PLCs but more robust and suitable for harsh environments.
   - Often have better environmental tolerances and higher autonomy.

6. **BPCS (Basic Process Control Systems)**:
   - Ensures operator decisions are implemented in the physical processes.
   - Receives information and makes sure actions are executed.

7. **SIS (Safety Instrumented Systems)**:
   - Ensures safety by automatically handling anomalies and emergencies.
   - Example: Shutting off power to prevent explosions.

8. **HMI (Human Machine Interface)**:
   - Interface through which operators interact with OT devices.
   - Often touchscreen-based for ease of use.

9. **IED (Intelligent Electronic Devices)**:
   - Devices that receive data and issue control commands.
   - Example: Tripping a breaker during a voltage anomaly.

10. **IIoT (Industrial Internet of Things)**:
    - Integration of IT and OT.
    - Connects traditional OT systems to IT networks for enhanced management.

**Security Challenges**:
- **Plain Text Protocols**: Many OT protocols are not encrypted.
- **Complexity**: High complexity can make security management difficult.
- **Proprietary and Legacy Technology**: Hard to secure due to outdated systems and proprietary designs.
- **Convergence Issues**: Combining IT and OT brings IT security vulnerabilities into OT environments.

# OT Threats, Tools, and Countermeasures

## Vulnerabilities in OT Systems
1. **Interconnected Systems**: Often connected to the internet for remote access, exposing them to external threats.
2. **Missing/Non-Existent Updates**: Lack of regular updates due to perceived isolation, increasing vulnerability.
3. **Weak Passwords/No Authentication**: Often overlooked as systems were initially isolated.
4. **Weak Firewall Rules**: Inadequate firewall configurations, leading to security breaches.
5. **Non-Existent Network Segmentation**: Flat networks without segmentation make it easier for attackers to access the entire system.
6. **Weak/Non-Existent Encryption**: Lack of encryption due to a false sense of security.

## Threats to OT Systems
1. **Malware**: Can be introduced via removable media, external hardware, web applications, and end-user devices.
2. **Denial of Service (DoS/DDoS) Attacks**: Can disrupt critical services, leading to indirect human life risks.
3. **Sensitive Data Exposure**: Breaches leading to exposure of critical operational data.
4. **HMI-Based Attacks**: Exploiting human-machine interfaces through software vulnerabilities or physical access.
5. **Human Error**: Programming or configuration errors, physical mishandling of equipment.
6. **Side Channel Attacks**: Exploiting physical aspects like timing, power consumption, and electromagnetic emanations.
7. **Radio Frequency (RF) Attacks**: Capturing or injecting RF signals to manipulate or gain access to OT systems.

## Tools for Securing and Testing OT Systems
1. **Shodan**: Search engine for internet-connected devices, useful for identifying vulnerable OT systems.
2. **Search Diggity**: Suite of tools for searching and analyzing potential attack vectors via search engines.
3. **S7 Scan**: Python tool for scanning and enumerating Siemens PLCs.
4. **PLC Scan**: Scans PLC devices over S7 or Modbus protocols.
5. **SmartRF Studio**: Texas Instruments tool for evaluating and debugging RF systems.
6. **Industrial Exploitation Framework (ISF)**: Framework similar to Metasploit for exploiting vulnerabilities in ICS and SCADA systems.

## Countermeasures
- **Regular Updates and Patches**: Ensure systems are regularly updated to mitigate known vulnerabilities.
- **Strong Authentication**: Implement strong passwords and multi-factor authentication.
- **Robust Firewall Configurations**: Set up and regularly review firewall rules.
- **Network Segmentation**: Divide networks into segments to limit access and contain breaches.
- **Encryption**: Use strong encryption for data in transit and at rest.
- **User Training**: Educate users on best security practices and potential risks.
- **Monitoring and Auditing**: Continuously monitor systems and conduct regular security audits.
- **Incident Response Planning**: Develop and regularly update an incident response plan.
