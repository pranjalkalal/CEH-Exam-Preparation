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

# Information Warfare and Related Strategies

## 1. Psychological Warfare
- Utilizes tactics like **struggle sessions** to manipulate beliefs over time, leading to compliance or acceptance.
- **Stockholm syndrome** exemplifies captives identifying with captors.

## 2. Hacker Warfare
- Hackers act as soldiers in cyber and information wars, conducting attacks on targeted systems and theft.
- Governments respond with sanctions and hunt down hackers, as seen in the **Colonial Pipeline hack**.

## 3. Economic Warfare
- Targets adversaries' financial systems, exemplified by U.S. sanctions on Russia during the Ukraine conflict.
- Includes disrupting payment processing, stealing intellectual property, and spreading false reputational claims.

## 4. Cyber Warfare
- A subset of information warfare that includes:
  - **APTs (Advanced Persistent Threats)**: Covertly infiltrate and maintain access to systems.
  - **Simulated Warfare**: Saber-rattling through military exercises to deter adversaries.

## 5. Strategies in Warfare
### Defensive Strategies
- Detection and alerts
- Emergency preparedness
- Systems like EDR and firewalls

### Offensive Strategies
- Web attacks
- System hacking
- Man-in-the-middle attacks
- Session hijacking


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

## Covert Channels
- Data is sent back to the attacker using HTTP, disguised as normal traffic.
- Uses user agent string for covert communication, making it less detectable in logs.
- HTTPS adds encryption, complicating detection of malicious activities.

## Defensive Measures
- **Monitoring and Logging**: Essential to detect and respond to covert channels and other attacks.
- **Web Application Firewall (WAF)**:
  - Can decode and analyze traffic for malicious content.
  - Alerts on suspicious activity.
- **Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS)**:
  - Need proper tuning to detect covert communications.
- **Manual Inspection**: Regular review of logs and alerts for anomalies.

## Importance of Programming
- Learning programming helps automate log monitoring and threat detection.
- Writing scripts can refine detection processes, showcasing skill and enhancing job performance.

## Web Shells
- Common tool used by attackers for remote control after compromising a server.
- Types of web shells: ASP, ASPX, CFM, JSP, Perl, PHP.
- Can execute commands and upload files through compromised web servers.
- **Defense Against Web Shells**:
  - Monitor web directories for unauthorized files.
  - Utilize WAFs, antivirus, endpoint detection, and response (EDR) tools.

## Command and Control (C2) Servers
- C2 servers communicate with compromised systems.
- Known malicious URLs can be identified and blocked using databases.
- Regularly monitor for traffic to known C2 servers.

## DNS Tunneling
- Malicious data can be exfiltrated through DNS, often bypassing firewalls.
- Tools like DNSCat2, Iodine, and Heyoka are used for DNS tunneling.
- **Defense**:
  - Monitor DNS traffic for unusual patterns or commands.

## Data Staging
- Attackers stage data in a hidden area of the system before exfiltration.
- **Defense**:
  - Monitor for unusual changes, such as new directories.
  - Regularly audit system for unexpected changes.
  - Maintain backups to recover from potential data loss.

## Conclusion
- Continuous monitoring and awareness of system behaviors are crucial for defending against covert channels and attacks.
- Employ both offensive and defensive strategies to enhance security posture.


# Threat Hunting
Threat hunting is the proactive process of searching for signs of malicious activity or security threats within an organization's network, systems, or data. It involves systematically analyzing and investigating data, logs, and other sources of information to identify potential security incidents or indicators of compromise that may have evaded traditional security controls. The goal of threat hunting is to detect and respond to threats before they can cause damage or disruption, thereby enhancing the organization's overall cybersecurity posture.

## Indicators of Compromise
1. Atomic: These could include things like specific file hashes, IP addresses, domain names, or registry keys associated with known malware or suspicious activity.
   
2. Computed: These could include things like correlating multiple events over time, identifying unusual network traffic patterns, or detecting anomalies in user behavior. Computed indicators often require more advanced analysis and may involve aggregating, correlating, or applying statistical techniques to large volumes of data.
   > For example, if a security analyst notices a spike in failed login attempts across multiple user accounts from various IP addresses within a 10-minute window, this could indicate a brute-force password attack.

4. Behavioral: Behavioral indicators focus on identifying patterns of activity or behavior that deviate from normal based on heuristics or machine learning algorithms. These could include things like unauthorized access attempts, unusual file access patterns, or abnormal network traffic.
   > For example, if a user account that typically accesses only a specific set of files suddenly starts accessing sensitive or confidential files outside of their normal behavior, this could indicate potential data exfiltration or insider threat activity.

# Risk & Risk Managament
***Risk*** refers to the potential for loss, harm, or damage resulting from uncertainties.

***Risk management*** is the process of identifying, assessing, prioritizing, and mitigating risks to minimize their impact.

![image](https://github.com/user-attachments/assets/31968061-ff00-4f52-b226-cc6d821a5aed)


# Cyber Threat Intel
Cyber threat intelligence (CTI) involves collecting, analyzing, and disseminating information about cybersecurity threats to help organizations identify, understand, and mitigate potential risks. It provides insights into the tactics, techniques, and procedures (TTPs) used by threat actors, as well as information about vulnerabilities, indicators of compromise (IOCs), and emerging threats.

1. ****Strategic CTI*** focuses on providing high-level insights and *long-term* planning to support strategic decision-making within an organization. It typically involves analyzing trends, threat actors' motivations and capabilities, geopolitical factors, and industry-specific risks to inform strategic planning, resource allocation, and investment in cybersecurity measures.

2. ***Operational CTI*** focuses on providing actionable intelligence to support *day-to-day* cybersecurity operations and incident response activities. It involves analyzing real-time or near-real-time threat data, such as IOCs, malware signatures, and network traffic patterns, to detect and respond to active threats in the organization's environment.

# Threat Modelling
It is a systematized approach to assess the risk/security of an organization.
- Know thy enemy: What are the common/most likely attack methods
- Know thyself: Where are we vulnerable

## 5 steps of threat modelling
1. Identify security objectives
   - What needs to be secured?
   - Any regulatory or policy compliance requirements?
2. Application overview
- Identify:
   - Roles
   - Who will be using this?
- Usage scenarios
   - How will this be used normally?
   - How could this be misused?
- Technologies
   - OS
   - Supporting Apps and services
   - Network technologies
- Security mechanisms
   - Authentication
   - Authorization
   - Input validation
   - Encryption
3. Decompose the application
- Diagrams help here
   - https://threatdragon.com
   - https://microsoft.com/en-us/download/details.aspx?id=49168
![image](https://github.com/Darwish-md/CEH/assets/72353586/293476c5-e420-436b-8a47-c78e62c2732f)
- Identify
   - Trust boundaries
   - Data flows
   - Entry points
   - Exit points
4. Identify threats
5. Identify Vulnerabilities

## Standard models
To use as a guide while developing a threat model: 

### STRIDE: 
STRIDE is a threat modeling framework that helps identify and classify different types of security threats. It stands for:
- Spoofing: Falsifying identity or credentials.
- Tampering: Unauthorized modification of data or systems.
- Repudiation: Denying responsibility or involvement in actions.
- Information disclosure: Unauthorized access to sensitive information.
- Denial of Service (DoS): Disrupting or degrading system availability.
- Elevation of Privilege: Gaining unauthorized access to higher levels of privilege or control.

### PASTA: 
PASTA (Process for Attack Simulation and Threat Analysis) is a threat modeling methodology that guides organizations through the process of identifying, analyzing, and prioritizing security threats. It involves six stages:
- Planning: Define the scope, objectives, and participants of the threat modeling exercise.
- Application Decomposition: Break down the application into smaller components and identify assets, entry points, and trust boundaries.
- Threat Analysis: Identify potential threats, vulnerabilities, and attack vectors associated with each component.
- Risk Ranking: Assess the likelihood and impact of each threat and prioritize them based on risk.
- Mitigation Planning: Develop and prioritize mitigation strategies to address identified threats.
- Reporting: Document the results of the threat modeling exercise and communicate findings to stakeholders.

### DREAD: 
DREAD is a risk assessment model used to evaluate and prioritize security risks associated with software vulnerabilities. It consists of five factors:
- Damage potential: The potential impact or harm caused by the exploitation of the vulnerability.
- Reproducibility: The ease with which the vulnerability can be exploited or reproduced.
- Exploitability: The likelihood that an attacker could successfully exploit the vulnerability.
- Affected users: The number of users or systems affected by the vulnerability.
- Discoverability: The ease with which the vulnerability can be discovered or detected.

# Incident Management and Response Overview

## Software Tools
- **Forensic Tools:** 
  - **Autopsy** and **FTK (Forensic Toolkit)** are highlighted as competent forensic tools. 
  - Autopsy can be installed on Kali Linux or easily obtained for hands-on experience.
  
- **Write Blockers:**
  - Essential for making forensically sound copies of compromised drives.
  
- **Forensic Operating Systems:**
  - **Caine:** A virtual machine with built-in forensic tools.
  - **Remnex:** Primarily used for malware analysis.

## Incident Response Process

### Step 1: Preparation
- Audit resources and assets to define security purposes, rules, policies, and procedures.
- Build and train an incident response team.
- Define readiness procedures and gather required tools.
- Train employees to secure systems and accounts.

### Step 2: Incident Recording and Assignment
- Record and report incidents.
- Define incident communication plans for employees.
- Notify IT support or create a ticket for tracking.

### Step 3: Incident Triage
- Analyze, validate, categorize, and prioritize incidents.
- Examine compromised devices to determine:
  - Attack type, severity, and target.
  - Impact, propagation method, and exploited vulnerabilities.

### Step 4: Notification
- Notify stakeholders such as:
  - Management, third-party vendors, and clients.

### Step 5: Containment
- Prevent the spread of infection to other assets.
- Minimize additional damage.

### Step 6: Evidence Gathering and Forensic Analysis
- Collect and analyze evidence to investigate:
  - Attack methods, exploited vulnerabilities, compromised devices, and averted mechanisms.

### Step 7: Eradication
- Eliminate root causes and close attack vectors.
- Prevent similar future incidents.

### Step 8: Recovery
- Restore affected systems, services, resources, and data.
- Ensure no service or business disruption.

### Step 9: Post-Incident Activities
- Conduct a final review and analysis:
  - Document the incident.
  - Assess impact and revise policies.
  - Disclose the incident as required.
  - Close the investigation.



# Artificial Intelligence and Machine Learning Overview

## Introduction
- Hosts Sophie and Daniel discuss machine learning (ML) and artificial intelligence (AI), emphasizing the need for familiarity with these concepts for the CEH exam and cybersecurity.

## Definitions
- **Artificial Intelligence (AI):** 
  - Machines designed to mimic human thought processes and decision-making. 
  - AI can analyze large datasets programmatically, making it useful in various applications, including cybersecurity.

- **Machine Learning (ML):**
  - A subset of AI focused on learning from data.
  - Comprises conditional statements (if-then logic) to classify data based on provided datasets.

## Key Concepts in Machine Learning
1. **Supervised Learning:**
   - Involves labeled datasets to train models (e.g., categorizing fruits and cars).
   - Enables classification and prediction based on past data.

2. **Unsupervised Learning:**
   - Works with unlabeled datasets to find patterns and group data based on similarities (e.g., clustering).

### Learning Techniques
- **Supervised Learning Techniques:**
  - **Classification:** Identifying categories based on labeled data.
  - **Regression:** Understanding relationships between variables to make predictions.

- **Unsupervised Learning Techniques:**
  - **Clustering:** Grouping data based on attributes.
  - **Association:** Finding relationships between different variables (e.g., recommendations).
  - **Dimensionality Reduction:** Simplifying data inputs for easier processing.

## Applications in Cybersecurity
- AI and ML are utilized in:
  - **Endpoint Security:** Monitoring unusual behavior (e.g., access anomalies).
  - **Authentication:** Improving security measures against unauthorized access.
  - **Phishing Detection:** Identifying and mitigating phishing attempts.

## Conclusion
- Understanding AI and ML terminology and concepts is essential for the CEH exam and practical applications in cybersecurity.

# Standards and Regulations


## Key Points
1. **Regulatory Importance**:
   - Cybersecurity professionals often work in regulated industries.
   - Standards help ensure compliance and data protection.
   - Regulations provide guidelines for handling customer data responsibly.

2. **Standards Overview**:
   - **PCI DSS (Payment Card Industry Data Security Standard)**:
     - Essential for organizations handling credit card transactions.
     - Compliance is crucial for operational viability.
     - Resources for PCI DSS can be found on the PCI Standards Council website.
  
   - **ISO 27001:2013**:
     - International standard for information security management systems.
     - Useful for cybersecurity professionals; understanding it can lead to job opportunities.
     - Accreditations available for organizations seeking ISO 27001 compliance.

   - **HIPAA (Health Insurance Portability and Accountability Act)**:
     - Protects personal health information (PHI).
     - Healthcare organizations must comply to prevent identity theft and fraud.
     - Cybersecurity experts are needed to ensure compliance and secure sensitive information.

   - **Sarbanes-Oxley Act (SOX)**:
     - Ensures corporate transparency and accountability in financial reporting.
     - Developed in response to corporate scandals like Enron.
     - Aims to protect investors by improving the accuracy of corporate disclosures.
   - **Sarbanes-Oxley Act (SOX)**:
     - Requires outside auditors for corporate accountability to prevent insider trading.
     - Focuses on corporate and criminal fraud accountability, especially in financial disclosures and conflict of interest.
     - Includes aspects of cybersecurity management.

   - **Digital Millennium Copyright Act (DMCA)**:
   	 - Protects intellectual property (IP) and copyrighted works in digital formats.
	   - Complicates the legality of making backup copies of encrypted DVDs; while it's legal to own a digital copy, decrypting the DVD to create it is illegal.

   - **Federal Information Security Modernization Act (FISMA)**:
	   - Governs information security policies for U.S. federal entities.
	   - Provides guidelines for information security management.

   - **General Data Protection Regulation (GDPR)**:
	   - EU regulation that grants individuals rights over their personal data.
     - Affects businesses handling data within the EU; requires timely reporting of breaches and imposes significant fines for non-compliance.
	   - Following Brexit, the UK created its own version, the Data Protection Act (DPA), to align with GDPR standards.

## Conclusion
- Understanding these regulations is essential for cybersecurity professionals.
- Familiarity with compliance standards opens up career opportunities in various industries.

# CEH Hacking Methodolgy
https://www.eccouncil.org/cybersecurity-exchange/ethical-hacking/what-is-ethical-hacking/

# MITRE ATT&CK Framework Overview

## What is the MITRE ATT&CK Framework?
- A **knowledge base** of adversary tactics and techniques derived from real-world observations.
- Used for **threat modeling** by both blue teams (defensive) and red teams (offensive).
- Helps organizations identify common attack vectors and improve cybersecurity measures.

## Key Features
- **Accessible Website**: [attack.mitre.org](https://attack.mitre.org) contains various matrices.
- **Matrices**: Includes Enterprise, Mobile, and ICS (Industrial Control Systems) matrices.
- **Tactics and Techniques**:
  - **Tactics**: Represent the *why* of an attack (e.g., achieving credential access).
  - **Techniques**: Represent the *how* an adversary achieves a goal (e.g., dumping credentials).
  - **Sub-techniques**: More specific methods within a technique (e.g., specific ways to abuse elevation controls).

## Practical Use
- Enables organizations to prepare their systems against common attack methods.
- Supports detailed threat modeling and planning for red and blue team operations.
- **Attack Navigator**: A web-based tool to visualize and annotate attack matrices, aiding in analysis of adversary behaviors and techniques.

## Resources
- Extensive documentation and resources available on the MITRE website for further learning.
- Data can be exported to Excel for easier sorting and analysis.

## Conclusion
Understanding the MITRE ATT&CK framework is crucial for cybersecurity professionals to effectively respond to threats and improve defensive strategies. It is a widely recognized tool in the cybersecurity field.


# Diamond Model of Intrusion Analysis
The Diamond Model of Intrusion Analysis is a framework used to understand and analyze cyber threats. The model emphasizes the interactions between these elements and how they contribute to cyber attacks. It helps analysts identify TTPs used by adversaries, assess their capabilities and infrastructure, and understand their motivations and objectives.

![image](https://github.com/Darwish-md/CEH/assets/72353586/4782e1b5-e874-48ac-a569-8edba69389fc)

## Core-Features
  - **Adversary**
    + The threat actor and/or group that is responsible for utilizing a Capability
      against the Victim to achieve their goals and intents.
    + Little to no knowledge about the Adversary usually
      - Empty for most events
    + <u>Adversary Operator</u>
      - Actual threat actor performing attacks
    + <u>Adversary Customer</u>
      - Person(s) that stand to gain from attack
        + Might be the same as Adversary Operator, but not necessarily
  - **Capability**
    + TTPs of the Adversary
      - <u>Capability Capacity</u>
      - <u>Adversary Arsenal</u>
  - **Victim**
    + The target of the Adversary
      - <u>Victim Persona</u>
        + The people and organizations
      - <u>Victim Asset</u>
        + The Victim's attack surface
	  - Networks, servers, email, hosts, etc 
  - **Infrastructure**
    + Any physical and/or logical communication structures used to attack the
      Victim and effect the Victim
    + Type 1
      - Fully owned and controlled by the Adversary and used to carry out attack
    + Type 2
      - Infrastructure owned by a 3rd-party, but used by Adversary to attack
	+ Bots, Zombies, compromised accounts, etc
    + Service Providers
      - Any organization that provides the Attacker with services
	+ Wittingly or Unwittingly
        + ISPs, Email providers, DNS, Cloud, etc

## Meta-Features
  - Timestamp
    + Date/Time an event occurred
  - Phase
    + Which step, or "Phase" of hacking
      - Think Cyber Kill-Chain or CEH Hacking Methodology
  - Result
    + What did the Adversary accomplish and how does it affect the Victim
      - Which of the CIA were compromised?
      - "Post-Conditions"
  - Direction
    + For example, if we pointing to c2 server then direction would be victim to infrastructure to adversary.
  - Methodology
    + Labling of the general "class of activity"
      - e.g. Phishing Attack
  - Resources
    + The resrouces required for the event to occur
      - Software
      - Hardware
      - Funds
      - Access (how does the Adversary make actual contact with Victim?)
