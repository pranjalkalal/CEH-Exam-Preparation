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

# Classification According to Network Layers

## ***Application Layer Session Hijacking***
**Description:**
Application layer session hijacking occurs when an attacker exploits vulnerabilities in web applications or software to steal session identifiers or manipulate session-related data. By targeting weaknesses in the application logic or implementation, the attacker can gain unauthorized access to user accounts, manipulate transactions, or extract sensitive information.

**Example:**
An attacker exploits a Cross-Site Scripting (XSS) vulnerability in a web application to inject malicious JavaScript code into a user's browser. The injected malicious JavaScript code steals the user's session cookie, granting the attacker unauthorized access to the user's session on the banking website. With the session hijacked, the attacker can now impersonate the user, view account balances, initiate transactions, or perform any actions that the legitimate user would be able to do. This type of attack demonstrates how network layer session hijacking, combined with other vulnerabilities like XSS, can lead to severe security breaches and financial loss for victims.

## ***Network Layer Session Hijacking***
Network layer session hijacking takes place at the network level of the OSI model. Attackers intercept and manipulate network packets to steal session identifiers or manipulate session-related data, bypassing application-level security controls. This type of hijacking can be more difficult to detect and mitigate compared to application layer hijacking.

**Example:**
An attacker intercepts network traffic between a user and an online banking website. Using a man-in-the-middle attack, the attacker manipulates the packets to hijack the session. By redirecting traffic to a server under their control, the attacker gains access to sensitive user data, such as login credentials and financial information. This allows the attacker to perform unauthorized transactions or steal personal information.

### Types
**Blind Hijacking:**
Blind hijacking is a type of session hijacking attack where the attacker attempts to hijack a session without having access to the actual session data. In blind hijacking, the attacker relies on guesswork or brute force techniques to predict or guess session identifiers, such as session cookies or tokens. This can be challenging for the attacker since they lack direct access to the session information and may require extensive trial and error to succeed.

**UDP Hijacking:**
UDP (User Datagram Protocol) hijacking involves the interception and manipulation of UDP packets to hijack a session between a client and server. Unlike TCP, UDP is connectionless and does not include mechanisms for session establishment or maintenance. As a result, UDP hijacking attacks typically target applications or services that use UDP for communication, such as online gaming or VoIP (Voice over Internet Protocol) applications. Attackers may inject or modify UDP packets to disrupt communication, inject malicious payloads, or hijack sessions between the client and server.

***TCP Hijacking***

**RST Hijacking:**
RST (Reset) hijacking is a technique used to hijack TCP sessions by sending forged TCP RST packets to terminate established connections between a client and server. TCP RST packets are used to signal the abrupt termination of a TCP connection, and they can be abused by attackers to forcibly close connections between legitimate parties. By spoofing or injecting TCP RST packets into the network traffic, the attacker can disrupt ongoing sessions, terminate connections prematurely, or manipulate the flow of data between the client and server. RST hijacking attacks can be effective in disrupting communication and causing denial-of-service (DoS) conditions for targeted services or applications.

