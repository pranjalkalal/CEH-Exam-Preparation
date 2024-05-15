# Windows Authentication

### Windows SAM (Security Accounts Manager):
- SAM is a database stored locally on a Windows system and contains user account information, including usernames and hashed passwords.
- When a user attempts to log in, Windows checks the provided username and password against the entries in the SAM database.
- If the credentials match, the user is authenticated, and access is granted.
- The file is locked up once the system boots up. Windows loads content to the memory.

### NTLM (NT LAN Manager):
- NTLM is an authentication protocol used in Windows environments.
- NTLM is considered less secure than Kerberos and is gradually being phased out in favor of more modern authentication mechanisms.
- NTLM Authentication Steps:
  + Client Request: The user attempts to log in to a Windows system by providing a username and password.
  + Challenge-Response: The client sends a request to the server with the username. The server responds with a random challenge.
  + Hash Calculation: The client computes a cryptographic hash (NT hash) of the user's password concatenated with the challenge.
  + Hash Exchange: The client sends the hashed response to the server.
  + Server Verification: The server receives the hashed response and verifies it by comparing it to the hash stored in its local database (SAM or Active Directory).
  + Authentication: If the hashes match, the user is authenticated, and access is granted. Otherwise, authentication fails.

### Kerberos:
- Kerberos is a network authentication protocol that provides strong authentication for client/server applications.
- Authentication in Kerberos involves multiple steps:
- Kerberos Authentication Steps:
  + Client Authentication Request: The user attempts to access a service or resource on the network.
  + Ticket Request (TGT): The client sends an Authentication Service Request (AS-REQ) to the Key Distribution Center (KDC) to obtain a Ticket Granting Ticket (TGT).
  + TGT Issuance: The KDC validates the user's identity and issues a TGT encrypted with a session key.
  + Service Ticket Request (TGS): When the user needs to access a specific service, the client sends a Ticket Granting Service Request (TGS-REQ) to the KDC, requesting a service ticket for the desired service.
  + Service Ticket Issuance: The KDC verifies the TGT and issues a Service Ticket (TGS) encrypted with a session key.
  + Service Authentication: The client presents the Service Ticket to the target service.
  + Service Verification: The service decrypts the Service Ticket using its own secret key and verifies its authenticity.
  + Access Granted: If the ticket is valid, access is granted to the requested service.

# Password Attacks

### LLMNR Poisoning:
- LLMNR (Link-Local Multicast Name Resolution) poisoning is a technique used to intercept and manipulate DNS (Domain Name System) resolution requests sent over a local network.
- An attacker sends malicious responses to LLMNR queries, tricking the target system into redirecting its DNS requests to the attacker-controlled machine.
- This allows the attacker to redirect the victim to malicious websites, intercept sensitive information, or conduct further attacks.

### Pass the Hash:
- Pass the Hash is a method used by attackers to authenticate to a system using the hashed credentials of a user without needing to know the plaintext password.
- Instead of cracking the password hash, the attacker captures the hashed credentials (typically NTLM hashes) from the target system's memory or network traffic.
- The attacker then uses these hashes to authenticate to other systems or services where the same credentials are used, effectively "passing" the hash for authentication.

### Internal Monologue:
- Internal Monologue is a technique where an attacker uses NTLM authentication traffic to impersonate a legitimate user and execute commands on a target system silently.
- The attacker captures NTLM authentication requests from the victim's system and then replays these requests to the target system.
- By impersonating the victim's identity, the attacker can execute commands on the target system without the victim's knowledge.

## Tools used for these attacks:
- Responder: Used for LLMNR/NBT-NS/MDNS poisoning.
- Mimikatz: Used for Pass the Hash and extracting plaintext passwords from memory.
- Impacket: A collection of Python classes for working with network protocols, used for Pass the Hash and NTLM authentication.
- Metasploit: A penetration testing framework that includes modules for various attacks, including Pass the Hash and LLMNR poisoning.
- fgdump, PWDump
   
## Password Cracking Tools:
- Hydra: A password-cracking tool used for brute-force attacks against various network services, such as SSH, FTP, HTTP, etc.
- Hashcat: A powerful password-cracking tool that supports multiple hash algorithms and attack modes, including brute-force, dictionary, and mask attacks.
- John the Ripper: Another popular password-cracking tool that supports various hash formats and attack modes, including dictionary and brute-force attacks.
- Lophtrack
- 
## Rainbow Tables:
- Rainbow tables are precomputed tables used for reversing cryptographic hash functions, typically for password cracking.
- They contain sets of plaintext passwords and their corresponding hash values.
- Rainbow tables allow attackers to quickly look up a hash and find the corresponding plaintext password, significantly speeding up the password-cracking process compared to brute-force attacks.

## Shadow file
The `/etc/shadow` file is a critical component of Unix-based operating systems, including Linux. It stores encrypted password information for user accounts on the system. Each line in the /etc/shadow file represents a user account and contains several fields separated by colons (:).

## Password Attacks Cracking Enhancement Techniques
1. The "Prince" approach in password cracking involves using Markov chains to generate password guesses more efficiently. The Prince approach aims to improve this process by analyzing patterns in existing passwords and generating likely candidates based on those patterns.
2. The combinator is a technique where we combine more than a dictionary together. It is recommended to remove the duplicates after combining.
3. Toggle case is used to try different case characters.

# Buffer Overflow
If we have a program which has a buffer overflow issue, it means it doesn't handle the extra data correctly which then can cause it to crash OR we can use the vulnerability as: if we know the data sent overflows in a register for example ESB and I know when it flows (how many bytes) then I can control what is sent which can be a reverse shell code (by msfvenom tool for example).

Countermeasures:
- ASLR Address Space Layout Randomization.
- Data Execution Prevention (DEP): DEP marks certain areas of memory as non-executable, preventing the execution of code stored in those regions.
- Control Flow Integrity (CFI): CFI ensures that the control flow of a program follows a predetermined set of rules, preventing attackers from hijacking program execution through buffer overflow exploits.

# Privilege Escalation
what is panther and sysprep under system32 folder and what is unattended xml. 

Privilege escalation refers to the process of gaining higher levels of access or privileges on a system or network than what was initially granted to a user or process. It's a common goal for attackers who have gained initial access to a system with limited privileges. There are two types:

1. Horizontal Privilege Escalation:
  - In horizontal privilege escalation, the attacker gains access to another account or process with the same level of privileges as their current account.
  - This typically involves impersonating another user or process that has similar access rights.
2. Vertical Privilege Escalation:
  - In vertical privilege escalation, the attacker gains access to higher levels of privileges than their current account or process.
  - This can involve escalating privileges from a low-privileged user account to an administrator or root-level account.

## How?
1. DLL Hijacking: Attackers exploit vulnerable applications by replacing legitimate DLL files with malicious ones.

2. Unquoted Services Path: Improperly configured service paths can allow attackers to execute malicious code with elevated privileges.

3. Scheduled Tasks: Attackers can abuse scheduled tasks to execute malicious code at specified times with elevated privileges.

4. Patching: Failure to apply security patches leaves systems vulnerable to known exploits that can lead to privilege escalation.

5. Misconfiguration: System misconfigurations, such as incorrect file permissions, can create opportunities for attackers to escalate privileges.

#### what is "unattended XML"?
An unattended XML file, commonly referred to as an "unattended answer file," is a configuration file used during Windows installation to automate the setup process. It contains predefined settings and configurations that instruct the Windows Setup process how to proceed without requiring user intervention. These settings can include regional and language options, disk partitioning, product key input, user account creation, network configuration, and more.

Which can be found under Panther and sysprep folders in system32 directory, this file has a lot of information useful to gain higher privileges.

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
