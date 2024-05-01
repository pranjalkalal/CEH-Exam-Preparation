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
