# Footprinting Concepts

Footprinting is the process of gathering information about a target. It is often the first step in a penetration test or attack. Both ethical hackers and malicious actors use footprinting to learn as much as possible about a system, network, or organization. The main goal is to build a profile of the target, which can later be used to discover vulnerabilities.

---

## Types of Footprinting
There are two primary categories of footprinting:

### 1. Passive Footprinting
- **Definition**: Collecting information about the target without direct interaction. The target is unaware of the activity.
- **Methods**:
  - Browsing websites and social media.
  - Analyzing public records and archives.
  - Using search engines for organizational and employee details.
  - Observing open discussions and forums.
- **Examples**:
  - Reading publicly available financial reports.
  - Checking DNS records.
  - Monitoring social media for job announcements or location-based posts.
- **Risks**: Hard to detect since no direct communication or interaction occurs.

### 2. Active Footprinting
- **Definition**: Gathering information by directly interacting with the target systems.
- **Methods**:
  - Using tools to perform DNS queries.
  - Conducting port scans or host discovery.
  - Employing social engineering techniques to elicit information.
- **Examples**:
  - Sending targeted emails to gather user responses.
  - Running network scanning tools to identify active hosts and services.
- **Risks**: Easier to detect, as it generates logs and can trigger alerts on target systems.

---

## Information Collected During Footprinting
Footprinting aims to gather data in three main categories:

### 1. System Information
- Operating systems in use.
- Services (e.g., Active Directory, LDAP).
- Usernames and potential passwords.

### 2. Network Information
- DNS records, including domains and subdomains.
- Firewall configurations and access controls.
- Information about intrusion detection and prevention systems (IDS/IPS).
- Network topology and segmentation details.

### 3. Organizational Information
- Employee details, including roles and departments.
- Contact information (emails, phone numbers).
- Social media profiles and professional networking accounts.
- Organizational hierarchy and operational structure.

---

## Why Footprinting Is Crucial
Understanding the target helps identify potential vulnerabilities and craft effective attack strategies. Here’s how collected information is used:

1. **Revealing Security Controls**: Discovering firewalls, web application filters, and other security measures.
2. **Finding Live Targets**: Identifying systems that are active and worth investigating further.
3. **Identifying Vulnerabilities**: Matching system information with known exploits.
4. **Facilitating Social Engineering**: Crafting convincing phishing attacks using personal or organizational details.
5. **Unintended Exposure**: Employees often share sensitive data online (e.g., in photos of workspaces), revealing critical information like badge IDs or system access points.

---

## Real-World Examples
- **Social Media Leaks**: Employees accidentally exposing sensitive data through social media posts.
- **Job Board Intel**: Job descriptions that reveal technical information about internal systems (e.g., the use of specific software versions).
- **Exposed Cloud Storage**: Publicly accessible S3 buckets or storage accounts containing critical data.

---

## Conclusion
Footprinting may seem mundane but is foundational for successful penetration testing and hacking. It provides the necessary insights to plan effective attacks or strengthen defenses.


# Google Dorks
Google dorks, also known as Google hacking or Google dorking, are search queries that use advanced operators to find specific information indexed by Google. 

# Useful link 
https://www.boxpiper.com/posts/google-dork-list


### Examples
- Finding specific file types:
  + `filetype:pdf site:example.com` - This query will search for PDF files specifically on the example.com domain.
- Identifying vulnerable web servers:
  + `intitle:"Index of /"` - This query can reveal directory listings on web servers that may expose sensitive files or directories.
- Searching for login pages:
  + `intitle:"Login" site:example.com` - This query will search for login pages specifically on the example.com domain.
- Locating network devices:
  + `intitle:"Router Login" inurl:login` - This query can find login pages for routers or other network devices.

# Shodan & Censys
Shodan and Censys are search engines that specialize in scanning and indexing information about devices and systems connected to the internet.

- They allow users to discover and access information (such as open ports, services running on those ports, banners, and other metadata) about internet-connected devices, including servers, routers, webcams, IoT devices, and more.

> "The most fundamental difference is that Shodan crawls the Internet whereas Google crawls the World Wide Web. However, the devices powering the World Wide Web only make up a tiny fraction of what's actually connected to the Internet. Shodan's goal is to provide a complete picture of the Internet."

# Subdomain Enumeration

Subdomain enumeration is a crucial technique in cybersecurity, particularly in ethical hacking, penetration testing, and bug bounty hunting. It involves identifying all subdomains associated with a domain to expand the attack surface and find potential vulnerabilities.

---

## What Is a Subdomain?

A **domain** is the main identifier of a website, like `example.com`. A **subdomain** is a subdivision of this main domain, appearing to the left of the domain name. For instance, in `blog.example.com`:
- `example.com` is the domain.
- `blog` is the subdomain.

Subdomains are often used to organize different services or parts of a website, like:
- `app.example.com`: A web application.
- `dev.example.com`: A development environment.
- `staging.example.com`: A testing environment before production.

---

## Importance of Subdomain Enumeration

Subdomain enumeration helps ethical hackers discover additional points of entry that may not be as secure as the main website. Reasons to perform this process include:

1. **Expanding the Attack Surface**: Identifying all possible targets for testing or exploitation.
2. **Finding Vulnerable Areas**: Subdomains may be less secure, especially those used for development or testing.
3. **Bug Bounties**: Hunters search for weaknesses in subdomains to report them for rewards.
4. **Scope of Engagement**: When participating in security assessments, knowing the full extent of subdomains helps define testing boundaries.

---

## Methods of Subdomain Enumeration

### 1. Manual Methods
- **Google Dorking**: Use search queries like `site:example.com` to identify subdomains indexed by search engines.
- **Viewing Page Source**: Check the HTML source code of a website to find references to other subdomains, such as API endpoints or external links.
- **Open-Source Intelligence (OSINT)**: Browse forums, social media, and publicly available records for clues.

### 2. Automated Tools
Several tools automate subdomain enumeration, including:

- **Netcraft**: An online service that reveals subdomains by analyzing DNS records and search data.
  - Navigate to Netcraft, go to **Resources** > **Search DNS**, and enter the target domain to discover subdomains.
- **Sublister**: A Python-based tool that queries multiple sources like Google, Bing, VirusTotal, and more to find subdomains.
  - **Usage Example**:
    ```bash
    python sublist3r.py -d example.com --threads 100
    ```
  - Note: Be cautious with web scraping; excessive automated requests may lead to IP blocking.

---

## Example Findings
Common subdomains you may encounter include:
- `www.example.com`: The main subdomain, typically hosting the website.
- `blog.example.com`: A blog or news section.
- `dev.example.com`: A development server, potentially vulnerable.
- `app.example.com`: The main web application.

### Real-World Scenarios
- **Development & Testing Subdomains**: Often overlooked by security teams, these can harbor unpatched vulnerabilities.
- **Open Storage Buckets**: Misconfigured cloud storage subdomains, such as `s3.example.com`, could expose sensitive data.
- **Security Awareness**: Organizations should regularly audit their subdomains to prevent accidental data leaks or unauthorized access.

---

## Summary

Subdomain enumeration is a fundamental practice for ethical hackers, offering a pathway to uncover hidden vulnerabilities. By expanding the attack surface, security professionals can better assess and secure an organization's digital infrastructure.

# Social Engineering Reconnaissance

Social media is a powerful tool for reconnaissance, allowing attackers to gather useful information about individuals or organizations. This information can include:

- **Personal Details**: Names, job titles, interests, or even technology use.
- **Employee Information**: Email addresses, usernames, and job-related details.
- **Company Insights**: Internal technologies (e.g., OS use), office badge designs, and employee habits.

## Techniques and Key Concepts

1. **Stalking with a Purpose**: Unlike casual browsing, ethical hackers focus on targets to find exploitable information.
2. **Platform Focus**:
   - **Facebook, Twitter, Instagram**: Common platforms for detailed personal info.
   - **LinkedIn**: A goldmine for professional and company-related details, though privacy settings can limit visibility. Advanced LinkedIn search settings are crucial for anonymous research.
3. **Leaked Information**: Even when profiles are set to private, unintentional public posts or improperly secured details may still leak sensitive data.

## Tools and Methods

- **Username Search Tools**:
  - **Sherlock**: A Python-based tool that searches for usernames across multiple platforms.
    ```bash
    # Usage
    python3 sherlock.py <username>
    ```
  - **Social Searcher**: A web-based tool for searching hashtags and usernames across various networks.

- **Data to Look For**:
  - **Email Patterns**: Often, usernames are derived from email addresses.
  - **Location and Routine**: Where employees have lunch, visit, or gather—potential for physical attacks.
  - **Photos and Badges**: Employees often post photos with badges visible, enabling physical or badge cloning attacks.

## Advanced Search Techniques

- **Google Dorks**: Using advanced Google search parameters to find information not easily accessible.
- **Twitter Dorks**: Similar to Google Dorks but optimized for Twitter, uncovering tweets with specific data.

## Privacy and Defensive Measures

1. **Review Your Own Digital Footprint**:
   - Check what information about you is publicly accessible.
   - Regularly update privacy settings on social platforms.
2. **Use of Sock Puppet Accounts**:
   - For reconnaissance, ethical hackers may create fake accounts to browse without using their real identity.
3. **Monitoring Tools**: Set up alerts for mentions of your name or organization to be aware of potential leaks.

> **Note**: Ethical hackers should respect privacy laws and only use these techniques with proper authorization.

---

**Stay Vigilant**: Regularly search for your own information and understand what is publicly available to ensure your digital safety.

# Job Board Reconnaissance

Job board reconnaissance involves using publicly available job postings to gather information that can be beneficial for ethical hacking and security assessments. This technique allows ethical hackers to uncover valuable insights about a target organization.

## Key Insights from Job Boards

1. **Understanding Job Postings**:
   - Job postings often contain detailed information about the company's needs, including roles and responsibilities, technologies used, and sometimes direct contacts for hiring managers.
   - By analyzing these postings, ethical hackers can extract information that may help them understand the organization's structure and technology stack.

2. **Types of Information to Extract**:
   - **Contact Information**: Names and emails of HR representatives or hiring managers.
   - **Job Roles**: Understanding who the roles report to can help create an organizational chart.
   - **Technologies**: Details about the technologies required for the job, which may reveal the company's tech stack.
   - **Locations**: Information about company offices, which can help identify physical security considerations.

## Example Process

1. **Job Search**:
   - Begin by searching job boards like Indeed, Monster, or directly on company websites. 
   - For example, searching for "Buzzfeed" can reveal job postings for positions like video editors or assistant editors.

2. **Analyze Job Descriptions**:
   - Upon finding a job listing, analyze the job description for details. For instance, if a position mentions the use of Adobe Premiere, this could lead to a search for vulnerabilities associated with that software.
   - Look for specific technologies mentioned that may have known vulnerabilities, which can be explored further.

3. **Search for Vulnerabilities**:
   - Conduct searches for known exploits of the software mentioned in job postings. For example, searching for "Adobe Premiere vulnerabilities" can yield useful information about potential security flaws that could be exploited.

4. **Social Engineering Considerations**:
   - The information gathered can also facilitate social engineering attempts. For instance, knowing that Buzzfeed uses Adobe Premiere can help craft convincing phishing attempts by enticing employees to open malicious files disguised as legitimate media.

## Conclusion

Job board reconnaissance is a straightforward yet effective way to gather useful intelligence about a target organization. By systematically analyzing job postings, ethical hackers can uncover a wealth of information that assists in profiling and assessing security postures.


# Deep-Dark Web

## Differences
- ***Deep Web***: The deep web refers to all parts of the internet that are not indexed by search engines, including both the dark web and other unindexed parts of the internet, such as private databases, password-protected websites, and other restricted content. It includes content that is not publicly accessible but does not necessarily involve anonymity or encryption.
- ***Dark Net***: The dark net encompasses the dark web and other networks, such as I2P (Invisible Internet Project) and ZeroNet, that are not accessible using standard web browsers. It includes encrypted and anonymized networks used for various purposes, including privacy, security, and anonymity.
- ***Dark Web***: Websites on the dark net. It is considered subset of Deep web.

## Tor
Tor (The Onion Router) and VPNs (Virtual Private Networks) are two distinct technologies with different purposes, although they both can be used to enhance online privacy and security.

Here's a brief comparison:

- ***Tor***:
  + Tor is a network of volunteer-operated servers that helps users enhance their privacy and security online by routing their internet traffic through a series of encrypted nodes.
  + Tor anonymizes users' internet traffic by encrypting it multiple times and routing it through a random sequence of nodes (also known as relays) before it reaches its destination.
  + Tor is commonly used to access the internet anonymously, bypass internet censorship, and protect against traffic analysis and surveillance.
  + Tor is used to access dark web like the `.onion` extension.
- ***VPN***:
  + A VPN is a technology that creates a secure, encrypted connection (often referred to as a tunnel) between a user's device and a remote server operated by the VPN provider.
  + VPNs are commonly used to encrypt internet traffic, hide users' IP addresses, and protect their online activities from eavesdropping, censorship, and surveillance.
  + VPNs can also be used to bypass geo-restrictions and access content that may be blocked or restricted in certain regions.

# Email Tracking
Email tracking involves embedding invisible tracking code or unique identifiers (such as tracking pixels or tracking links) into emails sent to recipients. This allows senders to monitor various aspects of recipient behavior, such as when an email is opened, how many times it's opened, the recipient's IP address, and the type of device used.

- ***Tracking Links***:
Tracking links are URLs embedded in emails that contain unique identifiers or parameters to track clicks. When a recipient clicks on a tracking link, the URL redirects them to the intended destination, while also recording information about the click, such as the time, date, and location of the click.

It can be created using Linkly, Bitly.

- ***Tracking Pixels***:
Tracking pixels (also known as web beacons or pixel tags) are tiny, transparent images embedded within the body of an email. When a recipient opens the email, their email client automatically loads the tracking pixel from the sender's server, which sends a request back to the server, indicating that the email has been opened.

# Social engineering
Social engineering is the manipulation of individuals to deceive them into divulging confidential information or performing actions that compromise security.

Examples:
- Phishing: Sending deceptive emails, messages, or websites that impersonate legitimate entities to trick individuals into revealing sensitive information, such as login credentials, credit card numbers, or personal details.
 - Pretexting: Creating a fabricated scenario or pretext to obtain information from individuals, such as pretending to be a trusted authority figure, service provider, or colleague to gain access to sensitive data.
 - Baiting: Leaving physical or digital "bait" in the form of infected USB drives, CDs, or downloads, which, when accessed, install malware or prompt users to disclose sensitive information.
 - Tailgating/Piggybacking: Gaining unauthorized physical access to secure areas by following behind an authorized person, or holding the door open for someone who does not have access.
 - Quid Pro Quo: Offering something of value (e.g., free software, services, or prizes) in exchange for sensitive information, such as login credentials or access to a network.
 - Watering Hole Attack: Compromising a website frequented by a target group or community and injecting malware to infect visitors' devices or steal credentials.
 - Impersonation: Posing as someone else, such as a coworker, IT support personnel, or a trusted authority figure, to gain access to sensitive information or systems.
 - Vishing: Using voice calls (phone phishing) to deceive individuals into providing sensitive information or performing actions, such as transferring funds or disclosing passwords.
 - Smishing: Sending deceptive text messages (SMS phishing) to trick individuals into clicking on malicious links, downloading malware, or providing sensitive information.
 - Scareware: Displaying fake warnings or alerts on a user's device, claiming it is infected with malware, and instructing them to download malicious software or pay for fake tech support services.

# Whois and DNS Recon

## Overview
- **Whois and DNS Recon** are tools used in **reconnaissance** and **footprinting** to gather information about a target.
- They help ethical hackers and attackers learn about domains, IP addresses, and other related information.

## Whois
- **Definition**: A registry of information about registered domains.
- **Models**:
  - **Thick Model**: Provides complete information, including administrative, billing, and technical contacts.
  - **Thin Model**: Only includes the domain's registrar information.
- **Usage**: Perform Whois queries through online services (e.g., who.is) to gather domain registration details.
- **Importance**: Information can aid in **social engineering** attacks by revealing useful details about a target.

### Key Points
- Whois queries return public domain registration data, which may include:
  - Domain name
  - Important dates (registration, expiration, last update)
  - Name servers
  - Contact information (if not redacted)

## DNS (Domain Name System)
- **Definition**: Translates domain names to IP addresses and provides information about the domain's infrastructure.
- **Common Tools**:
  - **NSLookup**: Standard tool for querying DNS.
  - **DIG**: A more robust tool often used in penetration testing.
  
### Information Gathered
- **IP Addresses**: Obtain multiple IP addresses for a single domain.
- **Mail Server Info**: Identify mail exchange servers (e.g., Outlook.com suggests O365 usage).
- **Zone Transfers**: An advanced technique where all DNS records for a domain can be retrieved, providing extensive information about the target.

### Zone Transfers
- **Significance**: Zone transfers reveal all DNS records, which is valuable for attackers mapping out networks for vulnerabilities.
- **Execution**: Tools like NSLookup or DIG can be used to perform zone transfers.

## Conclusion
- Understanding how to use Whois and DNS effectively is crucial for conducting thorough reconnaissance and footprinting during ethical hacking efforts.
- The information gathered can provide insights into potential vulnerabilities and targets.

# Social Engineering Recon

Social engineering is a crucial aspect of reconnaissance, involving methods to gather information about targets. Here are four techniques highlighted in the discussion:

## 1. Eavesdropping
Eavesdropping involves listening in on conversations to extract valuable information. This can occur in-person or through electronic means such as phone calls. Some tactics include:
- **Public Conversations**: Listening to loud phone calls in public spaces.
- **Intercepting Communication**: Using technology to capture private communications.

## 2. Shoulder Surfing
Shoulder surfing is the act of observing someone’s actions, typically to gather information such as passwords or sensitive data. Examples include:
- **Observing Password Entry**: Watching someone type their password in a public setting.
- **Gathering Information in an Office**: Looking over someone’s shoulder while they work.

## 3. Dumpster Diving
Dumpster diving is searching through trash to find discarded sensitive information. Items of interest include:
- **Day Calendars and Notepads**: These often contain passwords or personal information.
- **Documents with Personal Data**: Any printouts that could provide insight into the target’s security practices.

## 4. Impersonation
Impersonation involves pretending to be someone else to gain information or access. This can happen through:
- **Phone Calls**: Calling individuals while claiming to be from a legitimate organization to extract information.
- **In-Person Visits**: Using a disguise or a convincing story to enter restricted areas and gather data.

These techniques exemplify how social engineering can exploit human psychology and information vulnerabilities to achieve objectives, emphasizing the importance of awareness and vigilance in information security.

# Footprinting Tools Overview

## Introduction
- Footprinting tools are essential for gathering information about target systems, aiding in effective targeting and organization of thoughts.

## Tools Discussed

### 1. FOCA (Fingerprinting Organizations with Collected Archives)
- **Purpose**: OSINT tool for finding metadata and hidden information in online documents (e.g., Office, PDF).

### 2. OSINT Framework
- **Purpose**: Provides a categorized collection of OSINT tools and resources for gathering information like usernames, IP addresses, and more.
- **Features**: Menu-driven interface for exploring various OSINT techniques.

### 3. Recon Dog
- **Purpose**: Python-based automation script for OSINT.
- **Features**: Menu-driven interface for tasks like port scans, CMS detection, and reverse IP lookups.

### 4. Maltigo
- **Purpose**: Graphical tool for mapping assets and organizing information.
- **Usage**: Create assets for IPs and domains, connect them, and document findings.

### 5. Recon NG
- **Purpose**: Web reconnaissance framework similar to Metasploit.
- **Features**: Workspace management for organizing OSINT tasks and data.
- **Usage**: Load modules for various OSINT functions, like finding subdomains.

## Conclusion
- Each tool provides unique capabilities for footprinting and OSINT, enhancing real-world penetration testing and ethical hacking practices.

# Footprinting and Recon Countermeasures

## Overview
The episode discusses countermeasures to protect against footprinting and reconnaissance techniques that can expose personal and organizational information.

## Key Points

1. **Understanding the Challenge**: 
   - Defensive cybersecurity is difficult; it's an uphill battle to protect against information gathering.

2. **Security Policies**:
   - Establish and enforce security policies across the organization to ensure everyone knows their responsibilities regarding privacy and security.

3. **End User Security Awareness Training**:
   - Implement training for all employees to ensure they understand security policies and practices.

4. **WHOIS Privacy Services**:
   - Opt into privacy services to protect personal information from being publicly accessible.

5. **Encryption**:
   - Utilize encryption to protect sensitive information, as modern network speeds allow for effective encryption without significant performance loss.

6. **Authentication Methods**:
   - Implement authentication mechanisms (e.g., multi-factor authentication) to restrict access to sensitive data.

7. **Social Media Caution**:
   - Be vigilant about what personal information is shared on social media to prevent identity theft and other malicious acts.

8. **Location Services**:
   - Disable location services when not in use to protect against tracking.

9. **Sanitize Job Listings**:
   - Carefully curate job postings to limit the amount of technical information shared publicly.

## Conclusion
Promoting a culture of security awareness and implementing these countermeasures can significantly reduce the risks associated with footprinting and reconnaissance.

# Side Notes
## Ingress vs egress 
Ingress and egress filtering are two complementary security measures used to control network traffic entering and exiting an organization's network based on specified criteria, such as IP addresses, port numbers, protocols, and application-layer information. Here's a brief explanation of each:

- Ingress Filtering:
   + Ingress filtering is the process of inspecting and controlling incoming network traffic at the perimeter of a network.
   + The goal of ingress filtering is to prevent unauthorized or malicious traffic from entering the organization's network, thereby protecting against external threats such as denial-of-service (DoS) attacks, malware, and unauthorized access attempts.

- Egress Filtering:
  + Egress filtering is the process of inspecting and controlling outgoing network traffic leaving an organization's network.
  + The goal of egress filtering is to enforce security policies and prevent sensitive or unauthorized data from leaving the organization's network, as well as to detect and prevent outbound communication attempts by malware or compromised systems.

## Zone transfer in DNS
Zone transfer is a process in the Domain Name System (DNS) where a secondary DNS server obtains a copy of DNS zone data (such as domain names, IP addresses, and other resource records) from a primary DNS server. This transfer allows the secondary server to serve DNS queries for the zone independently if the primary server becomes unavailable.

We can use `dig axfr @nsztm1.digi.ninja zonetransfer.me` to perform zone transfer. The command is attempting to perform a DNS zone transfer for the `zonetransfer.me` domain from the primary DNS server `nsztm1.digi.ninja` using the AXFR query type.

## Spoofing vs Masquerading
It is kinda overlapping, I agree.

- Spoofing: Spoofing involves falsifying information in a way that makes it appear to come from a different source or origin than it actually does. This can include spoofing IP addresses, email addresses, MAC addresses, or other identifiers. For example:
  > IP spoofing involves altering the source IP address of a packet to make it appear to come from a different source.
  
  > ARP spoofing, also known as ARP poisoning or ARP cache poisoning, is a technique used to intercept, modify, or redirect network traffic on a local area network (LAN). It involves sending falsified Address Resolution Protocol (ARP) messages to associate the attacker's MAC address with the IP address of a legitimate network device. This allows the attacker to intercept traffic intended for the targeted device, perform man-in-the-middle attacks, or conduct network reconnaissance.
  
- Masquerading: Masquerading, also known as impersonation, involves assuming the identity of another entity or system in order to gain unauthorized access or privileges. This can include impersonating a legitimate user, device, or service to bypass authentication mechanisms or gain access to sensitive information. For example, an attacker might masquerade as a trusted employee to gain access to a secure facility or network.
