# Mobile Security Basics

## Attack Surfaces of Mobile Devices
Mobile devices have multiple entry points for attackers due to their extensive functionality and connectivity.

### Key Attack Surfaces
1. **Operating Systems**:
   - Vulnerable to outdated patches.
   - Regular updates are essential to address security flaws.
2. **Applications**:
   - Third-party or malicious apps can exploit devices.
   - Even official app stores occasionally host compromised apps.
3. **Bluetooth**:
   - Susceptible to attacks like Bluejacking, Bluesnarfing, Bluebugging, and BlueBorne.
   - Older specifications lack encryption and authentication.
4. **Wi-Fi**:
   - Subject to common wireless threats (e.g., Evil Twin, Honeypot attacks).
   - Devices on public Wi-Fi are particularly vulnerable.
5. **Telco (Cellular Networks)**:
   - Outdated protocols like SS7 allow attackers to eavesdrop on calls, intercept messages, and perform billing fraud.
6. **Web Browsing**:
   - Exposed to client-side attacks like Cross-Site Scripting (XSS), drive-by downloads, and clickjacking.


## Threats and Vulnerabilities
### Malware
- **Overview**: Malware targets all devices, including mobile.
- **Examples**: Malicious APKs, spyware apps.
- **Prevention**: Regular updates, antivirus tools, and avoiding third-party app stores.

### SIM Hijacking
- **Mechanism**:
  - Attackers hijack SIMs to intercept 2FA messages and calls.
  - Insider threats may involve telecom employees.
- **Impact**: Compromises sensitive accounts and communication.

### App Store Threats
- **Official Stores**:
  - Even trusted platforms like Google Play and Apple App Store can host malicious apps.
- **Third-Party Stores**:
  - Apps from third-party sources like FDroid require careful vetting.
- **Mitigation**:
  - Stick to official app stores and minimize app installs.

### Encryption Weaknesses
- **Unencrypted Communication**:
  - SMS and certain apps lack encryption.
- **Weak Encryption**:
  - Devices using outdated protocols are vulnerable.
- **Recommendations**:
  - Use apps with end-to-end encryption like Signal or WhatsApp.
  - Ensure devices utilize strong encryption protocols.

### Theft and Physical Access
- **Risks**:
  - Unlocked or poorly secured devices can lead to unauthorized access.
- **Mitigation**:
  - Enable auto-lock features with strong passwords or biometrics.
  - Use remote wipe capabilities.

---

## OWASP Mobile Top 10 Risks
The OWASP Mobile Top 10 outlines common mobile security risks:
1. **Improper Platform Usage**: Misuse of OS features.
2. **Insecure Data Storage**: Storing sensitive data unencrypted.
3. **Insecure Communication**: Lack of encrypted channels.
4. **Insecure Authentication**: Weak login mechanisms.
5. **Insufficient Cryptography**: Poor implementation of encryption.
6. **Insecure Authorization**: Allowing unauthorized access.
7. **Client Code Quality**: Vulnerable application code.
8. **Code Tampering**: Modified or malicious apps.
9. **Reverse Engineering**: Attackers decompiling apps to exploit vulnerabilities.
10. **Extraneous Functionality**: Exposing debug or test features in production.

- **Anatomy of Mobile attack**
   1. The Device: 
      - Browser based attacks: Phishing, Framing, Clickjacking,MITM,Buffer Overflow, Data Caching
      - Phone/SMS based attacks: Baseband Attacks,SMiShing
      - Application-bsed Attack: Sensitive Data Storage,No Encryption/Weak Encryption,Improper SSL Validation,Configuration Manipulation,Dynamic Runtime injection, Unintended Permissions, Escalated Privileges
      - System based (O.S): No passcode/Weak Passcode, ios jailbreaking,Android Rooting, OS data caching,Passwords and Data Accessible,Carrier-loaded software,User-initiated code
   2. The Network:
      - Wifi(Weak encryption/no encryption), Rogue Access Point, Packet Sniffing,MITM,Session Hijacking,DNS Poisoning,SSLStrip,Fake SSL Certificates
   3. The data center/Cloud 
      - Web server based attacks: Platform Vulnerabilities,Server Misconfiguration,XSS,CSRF,Weak Input Validation, Brute Force Attacks.
      - Database Attacks: SQL Injection, Privilege Escalation, Data Dumping, OS Command Execution

## General Security Guidelines
1. **Keep Devices Updated**:
   - Install patches and updates promptly.
2. **Use Antivirus Software**:
   - Detect and mitigate malware.
3. **Enable Encryption**:
   - Encrypt device storage and external media.
4. **Minimize App Installs**:
   - Only install necessary and verified apps.
5. **Disable Unused Features**:
   - Turn off Bluetooth, Wi-Fi, and location services when not needed.
6. **Secure Communication**:
   - Use apps with end-to-end encryption.
7. **Be Cautious of Public Networks**:
   - Avoid public Wi-Fi or use VPNs for secure connections.
8. **Monitor Device Activity**:
   - Look for suspicious behavior and unauthorized access.


#### Additional Risks and Considerations:
- **Sandbox Bypass:** It helps Protect systems and users by limiting the resources the app can access to the mobile plateform,however, malicious applications may exploit vulnerabilities and bypass the sandbox.
- **Sim Hijacking:** SIM card's S@T browser, apre-installed software on SIM cards that is designed to provide a set of instruction.Attackers exploit Simjacker to perform various malicious activities, such as capturing the locations of devices, monitoring calls, forcing device browsers to connect to malicious websites, and performing DoS attacks.
- **Mobile Spam and Phishing:** Mobile users are vulnerable to spam and phishing attacks via SMS (smishing) and voice calls (vishing), which aim to deceive users into disclosing sensitive information.
- **NSO Group and Pegasus:** Organizations like the NSO Group develop sophisticated malware like Pegasus, targeting mobile devices to infiltrate communications and compromise device security.
- **Bluetooth attacks**: Bluesnarfing(Stealing information via Bluetooth),
Bluebugging(Taking over a device via bluetooth)
- **Agent smith attack**: replace legitimate app to malicious app.
- **Exploiting SS7 Vulnerability**: Signaling System 7-SS7 like roaming,it perform MITM.This vulnerability in SS7 can also allow the attacker to bypass two-factor authentication and end-to-end encryption via SMS.
- **Camfecting Attack**: Webcam capturing attack, Android camera hijacking

### Summary
Mobile devices are indispensable but pose significant security risks due to their connectivity and multifunctionality. Awareness of attack surfaces, adherence to best practices, and leveraging robust security tools are critical for safeguarding mobile environments.


# Android Security
  
**Android OS Architecture**
   - System Apps,JAVA API Framework,Native C/C++ Libraries,Android Runtime,H/W Abstraction Layer,Linux Kernel
     
## Android Basics
- **Popularity**:
  - Android powers approximately **three out of four mobile devices** worldwide.
  - Dominates the smartphone and tablet markets due to its open-source nature and affordability.
- **Development**:
  - Created by Google and based on Linux.
  - Open-source and customizable, allowing manufacturers to adapt the OS for various devices.
- **Device Administration**:
  - Android supports app development via tools like Android Studio.
  - Deprecation of some administrative policies; developers should keep up-to-date with Android API changes.


## Rooting Android Devices
- **Definition**:
  - Rooting grants administrative (root) access, bypassing built-in security restrictions.
  - Similar to **jailbreaking** on iOS, but specific to Android.
- **Benefits**:
  - **Bypass Restrictions**: Install apps from external sources and enable tethering.
  - **Remove Bloatware**: Delete pre-installed apps that consume resources.
  - **Customization**: Modify the OS and install custom ROMs.
- **Risks**:
  - **Security Vulnerabilities**: Increased risk of malware through third-party apps.
  - **Warranty Void**: Rooting typically voids the manufacturer's warranty.
  - **Bricking**: Improper rooting can render the device inoperable.


## Rooting Tools
- **Popular Tools**:
  - **Kingo Root**: It can be used to with or without PC.It helps users to root android devices to achieve the following:
     - Preserve battery life, Access root-only apps,Remove carrier 'Bloatware',Customize appearance,Admin level permission 
  - **TunesGo Root Android Tool**: Recognizes and analyzes android device and automatically chooses appropriate android root plan for device.
  - **King Root,Towel Root,Magisk Manager,SuperSU Root,Framaroot,iRoot**
  - **One-Click Root**: It supports most devices.It comes with extra fail-safes (such as instant unrooting) and offers full technical support.It can able to install apps on SD cards,installing custom ROMs and accessing blocked features.
- **Requirements**:
  - Enable **USB Debugging Mode** on the device.
  - Follow tutorials specific to the device model.

## Android Hacking Tools
- **For Ethical Hacking and Penetration Testing**:
  
- **NetCut**: **wifi killing application**, it identify target device and block access to WiFi from victim devices in network.This tool works only on rooted device

  - **Drozer**: Vulnerability scanner.**Identify Attack Surfaces**.No need any USB debugging techniques. Has drozer agent(emulator used for testing) and drozer console(CLI)
    
  - **Zanti**: spoof mac address,creating malicious wifi hotspot and **hijacking session**,exploit route vuln.,MITM and DOS,view modify and redirect all HTTP requests and responses
  - **Network Spoofer**: chang website on other people's computer from android.It allows attacker to **redirect website** to other pages

  - **Low Orbit Ion Cannon(LOIC)**: **Dos/DDoS attacks**,can perform UPD,HTTP or TCP flood attacks.
  - **Kali NetHunter**: A mobile penetration testing platform that doesn’t require rooting.
    
  - **DroidSheep**: tools for Web **session hijacking(sidejacking)**.It listens for HTTP packets sent via a wireless(802.11) network connection and extracts the session IDs from these packets to reuse them. It capture sessions using libpcap library and support OPEN networks,WEP encryption networks and WPA and WPA2(PSK only) encrypted networks
 
  - **Orbot Proxy**: it empowers other apps to privately use the internet.also use **Tor** to encrypt internet traffic,use this app to hide their identity.
 
  - **ADB (Android Debug Bridge)**: It is Cli that allows attackers to communicate with android device.If android device has TCP debugging port 5555 is enabled than attacker able to use Phonesploit to perform malicious activities like screen capturing,dumping system info,viewing running applications,port forwarding,installing/uninstalling any application and turning wifi on/off.
  - **C-Sploit**: A Metasploit-like tool for Android.
  - **Android based sniffers**
     - FaceNiff: intercept web session profiles over wifi.possible to hijack session only when wifi not using EAP and over any private network(Open/WEP/WPA-PSK/WPA2-PSK)
     - Packet capture,tPacketCapture,Android PCAP,Sniffer Wicap 2 Demo,TestelDroid
 
    - **Man-in-the-Disk Attack**: when application do not incorporate proper security measures against usage of the device's external storage,It leads to installation of potantially malicious apps to the user's devices,thereby blocking access to legitimate apps. internal storage is sandboxed but external storage is vulnerable to MITD attacks
    - **Spearphone attack**: allows app to record loudspeaker data without any privilages,it can evesdrop on loudspeaker voice conversation by exploiting h/w based motion sensor like accelerometers.
    - **Advanced SMS Phishing**:attackers use any low priced USB modem and trick the victim into accepting the malicious settings in the mobile,which results in redirecting the victim's data to attacker.It can be mitigated using app like Harmony Mobile
    - **Bypass SSL Pinning**: it can exploit using reverse engineering(APKtool) and hooking(attacker can tamper runtime behavior,tool like frida) and also can perform MITM attack.
    - **Tap'n Ghost Attack**:It is Novel attack technique.this attack targets NFC technology and RX electrodes used in capacitive touchscreens of mobile devices.It is based on 2 attack techniques: Tag-based adaptive ploy(TAp) and Ghost touch generator.launched on voting machines and ATMs. 
   - **Android Trojans**
      - SharkBot: banking trojan,which intiate money transfer using Automatic transfer system ATS technique.
      - GiftHorse: embeded within more than 200 malicious applications.
      - TeaBot,Android Police virus,Octo,Aberebot,Xenomorph
   - **OTP Hijacking Tools**
      - AdvPhishing: Social media phishing tool
      - mrphish: bash-based script for phishing social meadia accounts with port forwarding and OTP bypassing control.It is works for both rott and non-root device.
      - **Stormbreaker: camera/microphone hijacking tool,CamPhish,CamHack,E-Tool,CamOver,Cam-Dumper**
      - **Android Hacking Tools:AndroidRAT(Full persistent backdoor, Java Android on the client side and Python on the server side), Fing-Network Tools, Arpspoof, Network discovery,NEXSPY,IntentFuzzer**

## Security Measures for Android Devices
1. **Avoid Rooting**:
   - Retain built-in security protections.
2. **Use Strong Screen Locks**:
   - Secure devices with PINs, passwords, or biometrics.
3. **Install Apps from Trusted Sources**:
   - Only download from Google Play to avoid malicious APKs.
4. **Install Antivirus and Anti-Malware**:
   - Examples: AVG, Avast, Norton, Bitdefender.
5. **Keep the OS Updated**:
   - Regular updates fix vulnerabilities and improve security.
6. **Avoid Public WiFi**:
   - Use VPNs for secure connections when necessary.
7. **Enable Location Services**:
   - Helps track and recover lost devices.
8. **Beware of Smishing**:
   - Treat suspicious text messages with caution and avoid clicking unknown links.
9. **Disable Unused Features**:
   - Turn off WiFi, Bluetooth, and location services when not in use.

- **Android Security tools**:
   - Kaspersky Mobile Antivirus: focusing on anti-theft and virus protection for mobile and tablets.also help users to find their losted or stolen device.
   - Avira Antivirus security, Avast Mobile Security,McAfee Mobile security,Lookout Security & Antivirus, Sophos Intercept X for mobile.
- **Android Tracking tool**:
   - Google Find my device, Prey Anti-theft,iHound,Mobile Tracker,Android Lost,Phone Tracker by number

- **Android V.scanner**:
   - Quixxi App shield: secure mobile apps from piracy, revenue loss, intellectual property (IP) theft, loss of user data, hacking, and cracking.
   - Vulner Scanner, Shellshock scanner,yaazhini,quick android review kit-QARK
   - **Sixo: Online APK Analyzer**: It can decompile binary XML files and resources
   - DeGuard,sandDroid,Apktool,APK Analyzer Online,Android APK decompiler
### Summary
Android's open nature provides flexibility but also introduces risks. Understanding rooting, using secure practices, and leveraging the right tools can help balance functionality with security.


# iOS Basics 

## iOS Basics
- **Introduction**:
  - Developed by Apple, iOS powers iPhones and iPads.
  - Released in 2007, initiating the smartphone revolution.
  - Renowned for its smooth performance, advanced hardware, and secure ecosystem.
- **IOS Architectur**:
   -  Cocoa application(Appkit framework), media, core services, core OS and kernel, and device drivers.  
- **Security Features**:
  - **Secure Boot**: Ensures only authorized boot processes occur.
  - **Biometric Authentication**: Face ID, Touch ID.
  - **Passcodes**: Adds another layer of security.
  - **Code Signing**: Requires apps to pass stringent Apple code reviews.
  - **Sandboxing**: Isolates apps to prevent unauthorized access to system resources.


## Jailbreaking
- **Definition**: 
  - Bypassing iOS restrictions to gain root-level access and remove sandboxing.
  - Similar to rooting on Android devices.
- **Advantages**:
  - Install third-party or unsigned apps.
  - Full customization of the device.
- **Disadvantages**:
  - Increased risk of malware and malicious apps.
  - Voids warranty and may brick the device.
  - Compromises built-in security measures.

### Types of Jailbreaking
1. **Userland Exploit**: It allows user level access but does not allow iboot-level access.only firmware updates can patch such vulnerabilities.
2. **iBoot Exploit**: It allows user level and iboot level access.it take advantage pf loophole in iboot to delink the code signing appliance.firmware updates can patch such exploits.
3. **Bootrom Exploit**: It uses a loophole in the secureROM to disable signature checks,which can use to load patch NOR firmware.firmware update can not patch it.both aceess allows here.only hardware update of bootrom by apple can patch it.

### Jailbraking Techniques
1. Untethered jailbreaking : device will be jailbroken after each reboot.
2. Semi-tethered jailbreaking : user needs to start device with help of jailbreaking tool.
3. Tethered jailbreaking : device starts up on its own.it must be re-jailbroken with computer using boot tethered feture each time ,it is turned on.
4. Semi-untethered jailbreaking : when the device reboots, the kernel is not patched.it is patched without computer use app installed on device.

### Jailbreaking Tools
- **Hexxa/Hexxa Plus**: Popular jailbreaking tools.
- **Apricot**: get a virtual jailbreak experiance
- **Checkra1n,Yuxigon,sileo,Fugu14,Bregxi**
- **Spyzie**: Attackers use various online tools such as Spyzie to hack the target iOS mobile devices. Spyzie allows attackers to hack SMS, call logs, app chats, GPS, etc.
- **Cydia**: Cydia is a software application for iOS that enables a user to find and install software packages (including apps, interface customizations, and system extensions) on a jailbroken iPhone, iPod Touch, or iPad.
- **Apricot**: Apricot is a web-based mirror OS for the latest iPhones. It supports iOS 13.2 devices. Users can run this mirror iOS version with the default iOS 13.2 simultaneously
-**Hexxa Plus**: Hexxa Plus is a Jailbreak Repo Extractor for iOS 13.2, which allows you to install themes, tweaks, and apps. It is compatible with iOS 13 and higher versions up to iOS 13.2.3 including iOS 13.3 beta.


## iOS-Specific Security Threats
1. **Trust Jacking**:
   - Exploits the "Trust This Device" feature during iTunes sync over WiFi.
   - Allows attackers remote access to sensitive data.
2. **iOS Malware**:
   - Includes threats like Pegasus(government agencies use this spyware to monitor terrorist activityor political propaganda,can exploit zero click exploit) and spyware tools.
   - NoRebbot trojan: fake device reboot and run in background.
   - Targets high-profile users and exploits zero-day vulnerabilities.
3. **Hacking Tools**:
   - Apps like **Network Analyzer Pro** can gather network information.
   - Tools like **Elcomsoft Phone Breaker** can access encrypted backups and iCloud data.
   - **Spyzie:** it is online tool.hack target device remotely in invisible mode without jailbreaking the device.
4. **Analyzing and manipulating iOS Applications**:
   - **Cycript**: Runtime manipulation tool,it is javascript interpreter.can understand c,c++ and js commands.can do swizzling,authentication bypass and jailbreak detection bypass.
   -**Swizzling**: aka monkey patching.modify existing method or add new functionality at run time.use to perform logging,javascript injection,detection bypass and authentication bypass
   -**keychain dumper**: iOS has encrypted storage system called keychain that stores secrets
   - **objection**: for analyze iOS, perform method hooking,bypass SSL pinningand bypass jailbreak detection.
    

## Security Measures for iOS Devices
1. **Avoid Jailbreaking**:
   - Retain built-in security protections.
2. **Enable Screen Locks**:
   - Use Face ID, Touch ID, or strong PINs.
3. **Install Trusted Apps**:
   - Avoid sideloading apps or downloading from unverified sources.
4. **Regular Updates**:
   - Apply patches and updates as soon as they are available.
5. **Use VPNs**:
   - Encrypt data during network transmission.
6. **Disable Unused Features**:
   - Turn off WiFi, Bluetooth, and location services when not in use.
7. **Enable "Find My iPhone"**:
   - Track your device if lost or stolen.
8. **Use a Password Manager**:
   - Avoid weak or reused passwords.
9. **Install Mobile Security Suites**:
   - Examples include Trend Micro, Norton, or Bitdefender.
10. **Avoid Public WiFi**:
    - Minimize exposure to untrusted networks.

### iOS Hacking Tools
- **Network Analyzer Pro**: For information gathering.
- **Trustjacking**: Exploiting the trusted device feature to access the device remotely.
- **Malware Examples**: Pegasus, developed by the NSO Group, used for espionage.
**iOS Device security Tools**
- **Avira Mobile Security**: Web protection and identify safeguarding
**iOS Device Tracking Tools**: Find My, SpyBubble,Prey Find my phone tracker GPS,iHound,FoolowMee GPS Location Tracker,Mobistealth
  
### Summary
iOS devices are secure by design, but security depends on user behavior. Avoid risky actions like jailbreaking, practice good digital hygiene, and use security tools to safeguard your data.


# Mobile Device Management (MDM) and BYOD


## Mobile Device Management (MDM)
- **Definition**: Software solution allowing administrators to manage and secure mobile devices across various operating systems (e.g., Android, iOS, Windows, Chrome OS).
- **Capabilities**:
  - **Authentication Enforcement**: Require passcodes or biometric authentication.
  - **Remote Actions**: Lock or wipe lost/stolen devices.
  - **Root/Jailbreak Detection**: Flag compromised devices for security.
  - **Policy Enforcement**: Apply security rules (e.g., app restrictions, password policies).
  - **Inventory Tracking**: Monitor devices as part of organizational assets.
  - **Real-Time Monitoring**: Generate alerts for compliance and security issues.
- **Examples of MDM Solutions**:
  - **ManageEngine Mobile Device Manager Plus**:
    - Supports cloud or on-premises deployment.
    - Manages devices running Android, iOS, macOS, Windows, and Chrome OS.
  - **IBM Maas360 with Watson**:
    - Cloud-based mobility management solution.
    - Integrates with AI-driven insights for enhanced device security.


## Bring Your Own Device (BYOD)
- **Definition**: Employees use personal devices for work-related tasks.
- **Benefits**:
  - **Increased Productivity**: Employees can work on familiar devices.
  - **Flexibility**: Access business resources anytime, anywhere.
  - **Cost Savings**: Reduces organizational expenditure on devices.
  - **Employee Satisfaction**: Allows use of preferred devices.
- **Risks**:
  - **Diverse Devices**: Increased attack surface for IT and security teams.
  - **Data Co-Mingling**: Personal and business data coexist, complicating security.
  - **Unsecured Networks**: Users may connect to insecure Wi-Fi.
  - **Device Disposal**: Improper disposal could expose sensitive data.
  - **Lost/Stolen Devices**: High potential for data breaches.
  - **Policy Circumvention**: Users may bypass corporate restrictions (e.g., use cellular networks to access restricted sites).


## BYOD Policies
1. **Secure Environment**:
   - Require secure passwords and full-disk encryption.
   - Implement device health checks before granting access.
2. **Standardized Technology**:
   - Approve a list of supported hardware, software, and apps.
3. **Policy Documentation**:
   - Publish and disseminate clear guidelines on acceptable use.
4. **Local Storage and Removable Media Control**:
   - Define what data can be stored locally or on external drives.
5. **Network Access Control (NAC)**:
   - Use NAC to assess and allow device connections based on compliance.
6. **Web and Messaging Security**:
   - Enforce secure communication and browsing practices.
7. **Data Loss Prevention (DLP)**:
   - Apply measures to prevent unauthorized data sharing or exfiltration.
     

## General Security Guidelines for Mobile Devices
1. **Use Antivirus and Anti-Spyware**:
   - Examples: Norton, Bitdefender, or Trend Micro.
2. **Restrict App Installs**:
   - Avoid unnecessary or suspicious apps.
3. **No Sideloading, Jailbreaking, or Rooting**:
   - Prevent actions that compromise built-in security.
4. **Remote Wipe Capabilities**:
   - Ensure sensitive data can be securely deleted from lost devices.
5. **Enable Disk Encryption**:
   - Protect data in case of device theft.
6. **Apply Regular Updates and Patches**:
   - Keep the OS and apps current to mitigate vulnerabilities.
7. **Secure Network Connections**:
   - Avoid public Wi-Fi or use VPNs for encrypted access.
8. **Educate Users**:
   - Train employees on secure usage and recognizing phishing (e.g., smishing).

### Summary
MDM tools streamline the management of mobile devices, enhancing security and productivity. BYOD policies balance convenience and security, but require robust guidelines and user education to mitigate risks. Adhering to general security practices ensures a secure mobile environment for both personal and corporate devices.
