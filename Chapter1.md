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
