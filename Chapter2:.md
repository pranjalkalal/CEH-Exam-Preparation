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


# Side Notes
## Ingress vs egress 
Ingress and egress filtering are two complementary security measures used to control network traffic entering and exiting an organization's network based on specified criteria, such as IP addresses, port numbers, protocols, and application-layer information. Here's a brief explanation of each:

- Ingress Filtering:
 + Ingress filtering is the process of inspecting and controlling incoming network traffic at the perimeter of a network.
 + The goal of ingress filtering is to prevent unauthorized or malicious traffic from entering the organization's network, thereby protecting against external threats such as denial-of-service (DoS) attacks, malware, and unauthorized access attempts.

- Egress Filtering:
 + Egress filtering is the process of inspecting and controlling outgoing network traffic leaving an organization's network.
 + The goal of egress filtering is to enforce security policies and prevent sensitive or unauthorized data from leaving the organization's network, as well as to detect and prevent outbound communication attempts by malware or compromised systems.
