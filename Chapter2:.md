# Google Dorks
Google dorks, also known as Google hacking or Google dorking, are search queries that use advanced operators to find specific information indexed by Google. 
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

# Sub-Domain Enumeration
We can use 3 methods to find the subdomains:
1. using tool like with netcraft.
2. Searching through web page source code on the domain name.
3. In Google, we can use dorking like `site:example.com`.

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
- Spoofing: Spoofing involves falsifying information in a way that makes it appear to come from a different source or origin than it actually does. This can include spoofing IP addresses, email addresses, MAC addresses, or other identifiers. For example:
  > IP spoofing involves altering the source IP address of a packet to make it appear to come from a different source.
  > ARP spoofing, also known as ARP poisoning or ARP cache poisoning, is a technique used to intercept, modify, or redirect network traffic on a local area network (LAN). It involves sending falsified Address Resolution Protocol (ARP) messages to associate the attacker's MAC address with the IP address of a legitimate network device. This allows the attacker to intercept traffic intended for the targeted device, perform man-in-the-middle attacks, or conduct network reconnaissance.
  
- Masquerading: Masquerading, also known as impersonation, involves assuming the identity of another entity or system in order to gain unauthorized access or privileges. This can include impersonating a legitimate user, device, or service to bypass authentication mechanisms or gain access to sensitive information. For example, an attacker might masquerade as a trusted employee to gain access to a secure facility or network.
