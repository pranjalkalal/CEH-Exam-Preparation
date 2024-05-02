# Vulnerability Assessment
Vulnerability assessment is the process of identifying, quantifying, and prioritizing security vulnerabilities in systems, networks, or applications. Common software tools used for vulnerability assessment include:

1. Nessus: A widely used vulnerability scanner that identifies security issues in networks, hosts, and web applications.
2. OpenVAS: An open-source vulnerability scanner that detects security vulnerabilities in networks and systems.
3. Qualys: A cloud-based vulnerability management platform that provides continuous monitoring and assessment of security risks.
4. Nmap
5. Burp Suite: A web vulnerability scanner and security testing tool used for identifying vulnerabilities in web applications.

## CVEs Vs CWEs

### CWE (Common Weakness Enumeration):
- CWE is a community-developed list of common software weaknesses and security issues.
- CWE focuses on identifying and describing the root causes of vulnerabilities, such as buffer overflow, SQL injection, and cross-site scripting.
- Examples of CWE entries include CWE-119 (Buffer Errors), CWE-89 (SQL Injection), and CWE-79 (Cross-Site Scripting).

### CVE (Common Vulnerabilities and Exposures):
- CVE is a standardized framework used to uniquely identify and reference publicly known cybersecurity vulnerabilities.
- CVE focuses on providing unique identifiers for vulnerabilities to facilitate communication, tracking, and prioritization of security issues.
- Examples of CVE entries include CVE-2021-3456 (a vulnerability in a specific software product) and CVE-2020-12345 (a vulnerability in a specific network protocol).

In summary, CWE categorizes and describes common software weaknesses, while CVE uniquely identifies and references specific vulnerabilities. 

## CVSS

# Vulnerability Management Lifecycle
Here are the steps of the vulnerability life cycle process:

1. Creating a baseline: In this phase, we look at critical assets, identify them, and prioritize them to create a good baseline for vulnerability management.
2. The assessment: This is a critical phase of vulnerability management. What we do, as security professionals, is identify and know the vulnerabilities within our infrastructure.
3. Risk assessment: All we're doing here is measuring or summarizing the vulnerability and the risk level – some systems may be at a higher risk level than others. Again, it depends on what their function is and who is operating them.
4. Remediation: Remediation is the process of fixing those vulnerabilities based on the risk assessment. We need to know which ones are the most important and then tackle them accordingly.
5. Verification: We take this step to make sure we've fixed the issue. It allows the security team to check whether all the phases we've done previously have been followed and if the identified vulnerabilities have been fixed.
6. Monitoring: Regular monitoring needs to be performed to help you maintain and always have the lastest updates. This is because a new update will have you create a new baseline where new threats will come out daily. So, we're going to continue monitoring.

# Vulnerability Classification
Vulnerabilities can be classified into the following categories:

1. Misconfiguration: You'll hear me preach about this all the time because it's one of the most common vulnerabilities. Misconfiguration is caused by human error. It allows attackers to gain unauthorized access to your systems. There are different types of misconfigurations because they could happen on application platforms, databases, the network itself, and even web servers. As misconfiguration could occur because someone may have forgotten to update the application or the database. They may have disabled the security settings or some features that are needed, or they may have gone set up permissions incorrectly or misconfigured SSL certificates.

2. Default installation vulnerabilities : These are typically done when we hit the Next options during installation. I get it. Sometimes, this happens. Installing an application where the attackers and everybody else are expecting it to be and using the same directory structure can create a vulnerability.

3. Buffer overflows: These are common software vulnerabilities, and they happen because of coding errors. What typically happens here is the attacker undermines the functionality of the program and tries to take control of the system by writing content beyond the allocated buffer size. If you overload the buffer, you end up creating a vulnerability, which could be anything from a system crash, the system becoming unstable, or even allowing some programs to do things they normally wouldn't do.

4. The server's operating system: Not patching the server's operating system (OS) appropriately may cause a vulnerability. Attackers are always looking or scanning for servers to see if they have them in a patch with the latest and greatest OS.

5. Design flaws: These are caused by either incorrect encryption or junky data validation processes; either the communication or the backend of an app or even a bad design flaw within the network infrastructure itself.

6. OS flaws: I know what you're thinking, and the answer is no, it's not just limited to Windows. Linux probably has more patches than Microsoft does. But it's because of these types of flaws that attackers can use Trojans, worms, and even viruses to attack those machines. So again, it comes back to patching.

7. Application flaws: Research your applications or any mainstream product regarding what flaws are associated with your applications. You also need to be notified of when those flaws take place, or when they've been discovered. So, update and keep your applications current.

8. Open services and ports: Often, we install stuff, and it opens ports or starts up services or features we may not use on that product or from that application. So, why have it open? Security professionals need to be on a constant lookout and scan the networks or systems for any unnecessary or insecure services or ports.

9. Default passwords: It cracks me up how many times people continue to use default passwords on devices, software, or the OS itself. The reason these are vulnerabilities is that if somebody just wants to get the application installed, they just hit next and take the defaults, and then in those defaults is the default password. They think, "Oh, I'll change it later" and then they forget, move on from the project, get fired, or someone else takes over. Whatever the case, these default passwords are going to be the bane of our existence. So, please do me a favor – make sure that you keep your passwords secret as you are installing the applications.

# Vulnerability Assessment Types
1. Active assessments: These are typically where we use network scanners to scan the network to identify the hosts, any vulnerabilities on those hosts, all the different nodes, and the services – anything that's on the network. Active network scanners can reduce the intrusiveness of the checks that they perform. So, you can make them extremely loud, or extremely quiet, or stealthy, if you will.

2. Passive assessments: This is where we sniff the traffic. So, we're not going after a specific target – we're just looking at the traffic to see if we can identify active systems, services, or applications, and then try to determine the vulnerabilities present. Now, because we're sniffing the traffic, we should also be able to get a list of users who are currently on the network.

3. External Assessment:
- This assessment simulates attacks from outside the organization's network, such as from the internet or other external sources.
- Common targets for external assessments include external-facing websites, web applications, email servers, remote access services (e.g., VPN), and publicly accessible infrastructure.
- The goal of an external assessment is to identify vulnerabilities and security weaknesses that could be exploited by external attackers to gain unauthorized access to the organization's systems or data.

4. Internal Assessment:
- This assessment simulates attacks that originate from within the organization's network, such as from a compromised employee device or an insider threat.
- Common targets for internal assessments include internal servers, workstations, databases, file shares, and other resources accessible to authenticated users within the organization's network.
- The goal of an internal assessment is to identify vulnerabilities and security weaknesses that could be exploited by insider threats, compromised accounts, or unauthorized users with access to the internal network.

5. Host-based assessments: Here, we're going to do a configuration-level check at each of the host machines, whether they're a server or a desktop. The type of thing I want to look at includes whether I can get a hold of a registry and see if it has been incorrectly configured, as well as any file permissions and software configuration issues.

6. Network assessments: This shows you vulnerabilities such as unnecessary services, weak authentication, and missing patches on your desktops, laptops, servers, and the network devices themselves. Is the interface for your switch through HTTP? Is it open? What's authentication mechanism is used? Is there weak encryption?

7. Application assessments: Here, we're looking at apps that are installed everywhere. When I say apps, I'm not just referencing apps on workstations. SQL, Exchange, SharePoint, and WordPress are all examples of apps. Anything that loads up on the servers is an app and we must make sure it has been patched and configured correctly and is up to date.

8. Wireless network assessments: It encompasses identifying active networks, assessing encryption protocols, detecting rogue access points, and conducting risk analysis to ensure the integrity and confidentiality of wireless communications.

# Vulnerability Assessment Models and Tools

## Types of vulnerability assessment solutions
There are four types of vulnerability assessment solutions. They are as follows:

1. Product-based solutions:
- These are software tools or appliances installed within your network.
- They scan for vulnerabilities on your systems and networks.
- Examples include vulnerability scanners like Nessus, OpenVAS, or Qualys.

2. Service-based solutions:
- These are vulnerability assessment services provided by third-party vendors or consultants.
- They may be hosted externally or within your organization's infrastructure.
- They offer expertise and resources for vulnerability assessment without the need for internal tools or personnel.

3. Tree-based solutions:
- These are hybrid solutions that use different scanners for different types of systems or services.
- For example, one scanner may be used for Windows systems, another for databases, and another for web servers.
- This approach ensures comprehensive vulnerability assessment across diverse environments.

4. Inference-based solutions:
- These solutions start by identifying all protocols and services present on each machine.
- They then use this information to infer potential vulnerabilities based on known issues associated with specific services.
- Inference-based solutions provide a systematic approach to identifying and testing vulnerabilities based on discovered services and protocols.

## Types of vulnerability assessment Tools
1. Host-Based Tools: they focus on identifying vulnerabilities and misconfigurations on individual systems or hosts. They scan the operating system, installed software, configurations, and file systems for security weaknesses. Examples include OpenVAS, Nessus, and Qualys.
   
2. Depth Assessment Tools: Depth assessment tools perform thorough examinations of specific components or layers within an environment to uncover vulnerabilities that may be overlooked by traditional scanning methods. These tools often focus on deep inspection of network protocols, application logic, or system interactions to identify subtle vulnerabilities. Examples include specialized network protocol analyzers and application security testing tools.

3. Application Layer Tools: Application layer vulnerability assessment tools focus on identifying vulnerabilities specific to web applications, APIs, and other software applications. They analyze application code, input validation mechanisms, authentication mechanisms, and session management to uncover vulnerabilities such as SQL injection, cross-site scripting (XSS), and insecure direct object references (IDOR).

4. Mobile Tools: Mobile vulnerability assessment tools are specifically designed to assess the security of mobile applications and mobile device configurations. They analyze mobile application binaries, communication protocols, storage mechanisms, and device settings to identify vulnerabilities and privacy risks unique to mobile platforms. Examples include MobSF (Mobile Security Framework), OWASP Mobile Security Testing Guide, and AppScan Mobile Analyzer.

5. Location and Data Examination Tools:
- Cluster-Based Scanners: Cluster-based scanners are implemented by distributing the scanning workload across multiple nodes in a cluster or grid. Each node in the cluster performs a portion of the scanning tasks, allowing for parallel processing and efficient analysis of large datasets and complex environments.
  + Cluster-based scanners are typically implemented using multiple physical or virtual machines configured to operate as nodes in a cluster.
  + Each node in the cluster runs scanning software or agents that perform vulnerability assessments on a portion of the target environment.
  + The nodes communicate with each other to distribute the scanning workload, coordinate tasks, and aggregate results.
  + The cluster may be set up on-premises within an organization's data center or deployed in a cloud environment for scalability and flexibility.

- Proxy-Based Scanners: Proxy-based scanners are implemented by intercepting and inspecting network traffic between clients and servers. They act as intermediaries between clients and servers, allowing them to analyze network traffic in real-time for vulnerabilities, malware, and malicious activities. This interception and analysis occur transparently to users and applications, providing continuous monitoring and protection of network communications.
  + Implemented using specialized hardware appliances or software applications installed on dedicated servers or virtual machines.
  + May be deployed at key points in the network infrastructure, such as at the perimeter firewall, within a demilitarized zone (DMZ), or at strategic network chokepoints.

- Network-Based Scanners: Network-based scanners scan network devices, protocols, and services to identify vulnerabilities and misconfigurations. They analyze network traffic, packet payloads, and device configurations to detect security weaknesses such as open ports, outdated software, and weak encryption. Network-based scanners operate at the network layer and are typically deployed as standalone appliances or software tools.

- Agent-Based Scanners: Agent-based scanners deploy lightweight software agents on individual systems or devices to perform continuous monitoring and assessment. These agents collect data on system configurations, software installations, and user activities to identify vulnerabilities and security events in real-time. Agent-based scanners provide visibility into the security posture of endpoints and can be particularly useful in environments with dynamic or distributed infrastructure.
