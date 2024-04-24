# Basic Cybersecurity Concepts
## CIA Model
The CIA model stands for Confidentiality, Integrity, and Availability. It is a foundational concept in information security that outlines three core principles to ensure the security of information and systems. 
- Confidentiality: ensures that sensitive information is accessible only to authorized individuals or entities. (Data is accessed by authorized entities).
- Integrity: ensures that data remains accurate, complete, and trustworthy throughout its lifecycle. It involves protecting data from unauthorized modification, deletion, or alteration, whether intentional or accidental. (Data haven't been tampered with).
- Availability: ensures that information and resources are accessible and usable when needed by authorized users.
#### Authenticity: 
Authenticity refers to the assurance that information or communication originates from a trusted source and has not been tampered with or altered during transmission. It ensures that the sender of the information is who they claim to be, and the receiver can verify the source's identity.
#### Non-repudiation: 
Non-repudiation ensures that a sender cannot deny the authenticity or integrity of a message or transaction they have sent. It provides proof of the origin and integrity of the communication, preventing the sender from later denying their involvement.

# Attack Classifications
## Active
In an active attack, the attacker attempts to alter or disrupt the target system or communication. The goal is to manipulate data, compromise systems, or disrupt services. 
> For example, a denial-of-service (DoS) attack floods a network or system with traffic to overwhelm it, causing it to become unavailable to legitimate users.
## Passive
In a passive attack, the attacker observes or eavesdrops on the target system or communication without altering the data. The goal is to gather information or intelligence covertly. (There is no sign at all of someone gathering the info and that's why nmap scanning is considered active since it involves sending probe packets to target systems).
> For example, an attacker may capture network traffic using a packet sniffer.
## Close in
Also known as proximity-based attack, involves physical access to the target system or device. 
> For example, an attacker gains unauthorized physical access to a server room and installs a hardware keylogger to capture keystrokes entered by authorized users.
## Insider
An insider attack occurs when a person with authorized access to an organization's systems or information abuses their privileges for malicious purposes. 
## Distribution
Also known as supply chain attacks, and it occurs when an attacker exploits vulnerabilities in a supplier's systems, software, or processes to gain unauthorized access to the target organization's network, data, or infrastructure. 
> For example, the NotPetya malware, which originated from a compromised Ukrainian accounting software update, spread to thousands of systems worldwide, causing widespread disruption and financial losses.

# Cyber Kill Chain
Cyber Kill chain: A series of steps that describe the progression of a cyber attack from reconnaissance all the way to exfiltration
- Developed by Lockheed Martin, the Cyber Kill Chain provides a framework for understanding and countering advanced persistent threats.
- The term "kill chain" comes from military terminology, where it refers to the structure of an attack, from identifying the target to the destruction of the target.

Stages:
1. Reconnaissance: Attackers gather information about the target, often using publicly available data, social engineering, or scanning tools to identify potential vulnerabilities and targets within the organization.

2. Weaponization: Attackers create or obtain malicious software, exploits, or other tools that can be used to compromise systems. This stage involves turning the identified vulnerabilities into functional weapons.

3. Delivery: Attackers deliver the weaponized payload to the target. This can occur through emails with malicious attachments, infected websites, or other means that trick users into activating the malware.

4. Exploitation: The malicious payload is executed, taking advantage of vulnerabilities to gain unauthorized access, escalate privileges, or execute specific commands on the target system.

5. Installation: This often involves establishing persistence mechanisms, ensuring the malware remains active even after system reboots, and setting up communication channels with remote servers controlled by the attackers.

6. Command and Control (C2): The attacker establishes a connection to the compromised system, allowing them to send commands and receive data. This stage enables remote control and coordination of the compromised devices.

7. Actions on Objectives: The attackers carry out their ultimate goals, which could involve data theft, financial fraud, disrupting operations, or any other malicious activities as per their objectives.

# TTPs
TTPs stand for Tactics, Techniques, and Procedures. They are the methods and approaches used by attackers to achieve their objectives during cyberattacks. 

- Tactics describe the overarching goals or objectives of an attack. (disruption of service)
- Techniques are the specific methods or actions used to achieve those goals (Denial of service attack)
- Procedures are the step-by-step instructions followed to execute the techniques effectively.

TTPs help security professionals understand and respond to cyber threats by providing insights into how attackers operate and what defensive measures can be taken to mitigate risks.

# Common Adversarial Behaviours
## Web Shell
A web shell is a malicious script or program that attackers upload to a compromised web server to gain remote access and control. It allows attackers to execute commands, upload or download files, and perform other malicious activities on the server. Web shells are commonly used in website defacements, data breaches, and other cyberattacks.

## DNS Tunneling
DNS tunneling is a technique used by attackers to bypass network security controls and exfiltrate data from a target network. It involves embedding data within DNS queries or responses, which are then transmitted over the DNS protocol. By encoding data in DNS traffic, attackers can evade traditional security measures that may not inspect DNS traffic thoroughly.

## Data Staging

## Internal Recon

# Threat Hunting
Threat hunting is the proactive process of searching for signs of malicious activity or security threats within an organization's network, systems, or data. It involves systematically analyzing and investigating data, logs, and other sources of information to identify potential security incidents or indicators of compromise that may have evaded traditional security controls. The goal of threat hunting is to detect and respond to threats before they can cause damage or disruption, thereby enhancing the organization's overall cybersecurity posture.

## Indicators of Compromise
1. Atomic: These could include things like specific file hashes, IP addresses, domain names, or registry keys associated with known malware or suspicious activity.
   
2. Computed: These could include things like correlating multiple events over time, identifying unusual network traffic patterns, or detecting anomalies in user behavior. Computed indicators often require more advanced analysis and may involve aggregating, correlating, or applying statistical techniques to large volumes of data.
  > For example, if a security analyst notices a spike in failed login attempts across multiple user accounts from various IP addresses within a 10-minute window, this could indicate a brute-force password attack.

3. Behavioral: Behavioral indicators focus on identifying patterns of activity or behavior that deviate from normal based on heuristics or machine learning algorithms. These could include things like unauthorized access attempts, unusual file access patterns, or abnormal network traffic.
   > For example, if a user account that typically accesses only a specific set of files suddenly starts accessing sensitive or confidential files outside of their normal behavior, this could indicate potential data exfiltration or insider threat activity.

# Risk & Risk Managament
***Risk*** refers to the potential for loss, harm, or damage resulting from uncertainties.

***Risk management*** is the process of identifying, assessing, prioritizing, and mitigating risks to minimize their impact.

# Cyber Threat Intel
Cyber threat intelligence (CTI) involves collecting, analyzing, and disseminating information about cybersecurity threats to help organizations identify, understand, and mitigate potential risks. It provides insights into the tactics, techniques, and procedures (TTPs) used by threat actors, as well as information about vulnerabilities, indicators of compromise (IOCs), and emerging threats.

1. ****Strategic CTI*** focuses on providing high-level insights and *long-term* planning to support strategic decision-making within an organization. It typically involves analyzing trends, threat actors' motivations and capabilities, geopolitical factors, and industry-specific risks to inform strategic planning, resource allocation, and investment in cybersecurity measures.

2. ***Operational CTI*** focuses on providing actionable intelligence to support *day-to-day* cybersecurity operations and incident response activities. It involves analyzing real-time or near-real-time threat data, such as IOCs, malware signatures, and network traffic patterns, to detect and respond to active threats in the organization's environment.
