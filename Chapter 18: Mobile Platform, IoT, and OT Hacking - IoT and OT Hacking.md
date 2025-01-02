# IoT Overview
#### Definition
  - Connecting everyday objects and systems to networks to make them globally available and interactive.
  - also known as Internet of Everything-IoE

- **4 primary System**: IoT device,gateway system,data storage and remote control
  
## Components of IoT
1. **Things/Sensing Technology:**
   - Everyday devices like refrigerators, washing machines, sensors, cameras, and network devices connected to the internet.
2. **Gateway:**
   - Connects IoT devices to each other, end users, or the cloud.
3. **Cloud Server/Data storage:**
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
   - Protocol translation and messaging.
3. **Internet Layer:**
   - IP-based communication for IoT devices.
   - Connection Between Endpoints.
4. **Middleware:**
   - Services running in the background to support the application layer.
   - Device management and information management.
5. **Application Layer:**
   - End-user interface for interacting with IoT devices.

## IoT Applications
- **Healthcare:** Heart monitors, medical sensors.
- **Military:** Monitoring and control systems for military equipment.
- **IT:** Environmental monitoring of server rooms.
- **Transportation:** Tire pressure sensors, traffic monitoring.
- **Energy:** Monitoring and control in power plants, solar, hydroelectric.

## Communication Technologies and Protocols

- **Short-range wireless communication**
   - BLE, QR Codes and Barcodes,RFID,Thread(IPV6 based protocol),Wifi direct,Z-wave,ZigBee(10-100m),ANT-adaptive network topology used in sport fitness sensors.
    - WiFi: used wifi standard is 802.11n which offers maximum speed of 600 mbps and range 50m.
    - light-fidelity(Li-Fi):just like wifi but 2 differences-mode of communication and speed,and Li-Fi is visible light communications(VLC) system that use light bulb to transfer data at very high speed pf 224Gpds.
       
- **Medium-range wireless communication**
    - HaLow(varient of Wifi for rural areas),LTE-Advanced,6LoWPAN(IPV6),QUIC-Quick UDP Internet Connections 
- **Long-range wireless communication**
    - LPWAN (LoRaWAN,Sigfox,Neul),VSAT-very small aperture terminal,cellular,MQTT,NB-IoT-nerrowband IoT is varient of LoRaWAN an sigfox
- **Wired Communication**
    - Ethernet,multimedia over coax alliance-MoCA,Power line communication-PLC 
- **IoT O.S.**
    -  RTOS,ubuntu core(aka snappy),fuchsia(by google)
- **IoT application Protocols**
  - COAP,EDGE,LWM2M,Physical web,XMPP,Mihini/M3DA

## Communication Models
1. **Device to Device:**
   - Device-to-device communication is most commonly used in smart home devices such as thermostats, light bulbs, door locks, CCTV cameras, and fridges, which transfer small data packets to each other at a low data rate.
2. **Device to Cloud:**
   - devices communicate with the cloud directly, rather than directly communicating with the client to send or receive data or commands. It uses communication protocols such as Wi-Fi or Ethernet, and sometimes uses Cellular as well.
3. **Device to Gateway:**
   - In this model, the IoT device communicates with an intermediate device called a gateway, which in turn communicates with the cloud service.
4. **Backend Data Sharing:**
   - This type of communication model extends the device-to-cloud communication type such that the data from the IoT devices can be accessed by authorized third parties. Here, devices upload their data onto the cloud, which is later accessed or analyzed by third parties.

## Security Challenges
- **Common Issues:**
  - No or weak security, poor access control, vulnerable web applications, clear text communications, lack of support, physical theft.

## IoT Threats and Vulnerabilities
  - Threats to IoT can be sorted into 3 primary categories:Security,Privacy and safety.

# IoT Attacks
  - **IoT Security Problems**: IoT = Application + Network + Mobile + Cloud
  - Application vul.: validation of inputted string,AuthN,AuthZ,no automatic security updates,default password.
  - Network vul.: Firewall,improper communications encryption,services,lack of automatic updates.
  - Mobile vul.: Insecure API,Lack of communication channels encryption,authentication,lack of storage security.
  - Cloud vul.: Improper authentication,no encryption for storage and communications,insecure web interface
  - this all vul. comes under IoT
    
### OWASP Top 10 IoT Threats
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
        
### IoT Attack Surfaces
  1. Ecosystem(general)
  2. Device Memory
  3. Device Physical Interfaces
  4. Device Web Interface
  5. Device Firmware
  6. Device Network Services
  7. Administrative Interface
  8. Local Data Storage
  9. Cloud Web Interface
  10. Third party backend APIs
  11. Update Mechanism
  12. Mobile Application
  13. Vendor Backend APIs
  14. Ecosystem Communication
  15. Network Traffic
  16. Authentication/Authorization
  17. Privacy
  18. Hardware/sensors

 ### Additional IoT Vulnerabilities
- **MFA/2FA:** Implementing multi-factor authentication to enhance security.
- **Lockout Policies:** Prevent brute force attacks by locking accounts after several failed attempts.
- **DDoS Protection:** Devices should be protected against denial-of-service attacks.
- **Regular Updates and Patches:** Ensure timely updates to address vulnerabilities.
- **Insecure Third-party Components:** Ensure third-party components are secure.
- **Hardware Access Ports:** Secure physical ports like JTAGs and UARTs to prevent unauthorized access.
  
 ### Unique IoT Attacks
 
- **HVAC Attacks**: Exploiting web-managed heating, ventilation, and air conditioning systems.
  - hack corporate systems,security vulnerability
  - **steps:**
      1. attackers use Shodan and searches for vulnerable industrial control systems-ICSs
      2. after finding vulnerable ICS,attacker searches for default user creadentials using online tool-Defpass
      3. use those credentials
      4. after gaining access to ICSs, attampt to gain access to HVAC system remotely
      5. after gaining access, attacker can control temprature from HVAC or do other attacks on local network.
         
- **Rolling Code Attacks**: Intercepting and predicting codes used in key fobs, it is used to steal vehicle.
  - the code that locks or unlocks a vehicle or garage is called rolling code or hopping code.Here Jammer is used
  - tools rfcat-rolljam, RFCrack
    
- **Bluetooth Attacks**: Exploits like BlueBorne and Bluejacking.
  - **Steps**:
     1. Discover Blutooth Device
     2. Retrive MAC address
     3. Send probes
     4. retrive OS info
     5. Gain access and control device.
      
- **DDoS via Jamming**: Overwhelming IoT devices' communication channels.
- **Sybil Attack**: Overloading systems with false identities, e.g., causing traffic jams via manipulated GPS data.
  - transmits radio signals randomly and disables the endpoints from sending or receiving any messages.
    
- **SDR(Software defined radio) Based Attack**: using software based radio communication system, attacker can examine the communication signals passing through IoT network and can send spam messages to interconnected devices.
   - Types of SDR-based attacks: Replay Attack(tool:URH-Universal Radio Hacker), Cryptanalysis attack,Reconnaissance attack
     
- **DNS Rebinding Attack**: It is process of obtaining access to victim's router.
- **DDOS Attack**: exploiting vulnerability and install malicious software,Army of Botnets,large volume of request

**Case Study: Enemybot**
  - it is Mirai-based botnet malware dicoverd in 2022.
  - It uses sophisticated string obfuscation methods to bypass security solutions.
  - **Steps**:
    1. Creating Exploits : Scanner-bot killer
    2. Disabling Other Malware on target : mirai's source code with additional keywords 
    3. Gaining access : brute force attack
    4. Launching Attack : Crypto mining
    5. Persistence : XOR encoding
       
- **Malwares**
  - Enemybot: Enemybot is a Mirai-based botnet malware discovered in early 2022
  - EquationDrug: EquationDrug is a dangerous computer rootkit that attacks the Windows platform. It performs targeted attacks against various organizations and lands on the infected system by being downloaded and executed by the Trickler dubbed "DoubleFantasy,"
  - IExpress Wizard: IExpress Wizard is a wrapper program that guides the user to create a self-extracting package that can automatically install the embedded setup files, Trojans, etc.
  - BitCrypter: BitCrypter can be used to encrypt and compress 32-bit executables and .NET apps without affecting their direct functionality.
    
# IoT Hacking Methodology
  - Using this methodology, an attacker acquires information through techniques such as gathering info,identifying attack surface area and vulnerability scanning.
  - **Phases of Hacking Methodology**
     1. Information Gathering :
       - **tool**:
         - Shodan: information about internet connected devices,ip address,hostname,ISP,Device location,Banner of target IoT device.
         - MultiPing: find IP of any IoT device,scan to identify vulnerability.
         - FCC ID Search: find the details and granted cerification of the devices.It contains 2 elements (Grantee ID-Initial 3 or 5 char,Product ID-remaining char)
         - IoTSeeker: discover IoT device using default credentialsand vulnerable to hijacking attacks, check about factory set credentials
           
     2. Vulnerability Scanning
      - **tools**:
        - Nmap: identify open ports and services.
        - RIoT(Retina IoT) scanner: identifies at-risk IoT devices such as IP cameras,DVRs,printers,Routers.
        - Foren6: sniff the traffic of IoT devices,uses sniffer to capture 6LoWPAN traffic,captures RPL related information and able to capture live packets.
        - Wireshark: sniff traffic
        - Gqrx: It is SDR implemented with help of GNU radio and Qt GUI tool.attackers use funcube dongles,airspy,HackRF and RTL-SDR with Gqrx SDR to analyze spectrum.also can evesdrop on radio FM frequencies
        - IoT Inspector: It analyse network traffic to find vulnerability also helps to breach privacy and security mechanisms.
  
     3. Launch Attacks
        - RFCrack: Test RF communication, launch various attacks like DDOS,rolling-code attacks,signal-jamming attacks, Sybil attacks,MITM attacks.also can use other tools like KillerBee to attack zigbee and IEEE802.15.4 networks.
        - Attify Zigbee Framework: used for hack zigbee devices,can perform Replay attack,use abstumbler from framework to identify channel used by target device.
        - HackRF One: perform attacks like BlueBorne or AirBorne attacks such at replay,fuzzing and jamming.Hack RF is advanced h/w and s/w defined radio with 1MHz to 6MHz range.use half duplex mode.It can sniff wide range of wireless protocol ranging from GSM to Z-wave
        - H/w based attack: RTL-SDR, It is available in form of USB dongle that can be used to capture radio signals.
        - S/W based attack: GNU radio
        - ChipWhispere: Side-Channel Attack performed by this tool.and used for embeded hardware security research.perform side-channel power analysis and glitching attack.attacker can breake AES,triple DES using power analysis attack.ChipWhispere needs 2 things-Capture Board,Target Board
        - Side channel attacks: Cache attacks,timing attacks,power monitoring attacks,electromagnetic attacks,acoustic cryptanalysis,fault analysis,data remanence and optical attacks.
        -  Identify communication interfaces: tools-BUS Auditor,Damn Insecure and Vulnerable application(DIVA),PCB
        -  NAND Glitching: It is process of gaining privileged root access while booting device
     4. Gain Remote Access
     5. Maintain Access 
         - Firmware Mod kit: reconstruct the malicious firmware from legitimate firmware.
         - Firmwalker,Firmalyzer enterprise,firmware analysis toolkit

 - **Firmware Analysis and Reverse Engineering**
     1. Obtain Firmware
     2. Analyzer Firmware
     3. Extract the Filesystem
     4. Mount the Filesystem
     5. Analyze the Filesystem
     6. Emulate Firmware

- **Iot Hacking Tools**
- Information gathering tools:Censys,Thingful,shodan
- Sniffing Tools: Suphcap(Z-Wave sniffer),CloudShark,Ubiqua Protocol Analyzer,Perytons Protocol Analyzers,Tcpdump,open Sniffer
- Vulnerability Scanning tools: beSTROM(smater fuzzer-find buffer overflow vul.),Metasploit Pro,IoTsploit,IoTSeeker,Bitdefender Home Scanner,IoT Inspector
- Tools to perform SDR-Based Attacks: Universal Radio Hacker,BladRF,Rfcat,HackRF,FunCube Dongle,Gqrx
- IoT Hacking Tools: IoTVAS(automated security assessment),Firmwalker,rfcat-rolljam,KillerBee,GATTack.io,Jtagulator

# IoT Attack Countermeasures





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
