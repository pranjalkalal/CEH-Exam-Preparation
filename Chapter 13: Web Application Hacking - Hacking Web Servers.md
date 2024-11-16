# Web Servers: Basics

### What is a Web Server
**Description:**
A web server is a network service that serves web content to clients over the Internet or an intranet. It processes incoming network requests over HTTP/HTTPS and delivers web pages or resources.

**Examples:**
- **Apache:** Open-source web server known for its robustness and flexibility.
- **Nginx:** High-performance web server and reverse proxy server.
- **IIS (Internet Information Services):** Web server software created by Microsoft.
- **Python HTTP Server:** Simple, built-in web server for Python applications.

### Related Concepts
**Virtual Directory:**
A directory that appears in the web server’s file system but is mapped to a different location. Used for organizing web resources without changing their physical locations.

**Example:**
In an Apache web server, you can configure a virtual directory to map `/media` to `/var/www/media` on the same server or to a network location like `\\server\share\media`.

**Root Document:**
The main directory of a web server from which all web content is served, typically known as the document root.

**Web Proxies:**
Servers that act as intermediaries for requests from clients seeking resources from other servers, used for filtering, caching, and anonymity.

## Introduction
A **web server** is a network service that delivers web applications and pages to users.  
- Common examples: Apache, Nginx, IIS (Microsoft).  
- Web servers are crucial for ethical hackers to understand, including their components, vulnerabilities, and security measures.


## Common Web Server Software
1. **Apache**:  
 Most widely used open-source web server.  
 Stable, free, and highly configurable.

2. **Nginx**:  
Known for its performance and efficiency in handling concurrent connections.  
Often used for load balancing and reverse proxying.

3. **IIS (Internet Information Services)**:  
 Proprietary Microsoft server software.  
Integrated into Windows Server with advanced features for Windows-based environments.

Other options: Lightweight servers like Python’s `http.server` or LiteSpeed for quick setups.


## Web Server Components
1. **Document Root**:  
   - Directory where the primary website files (e.g., `index.html`) are stored.  
   - Example: `/var/www/html` for Apache.

2. **Server Root**:  
   - Location for configuration files, logs, and supporting scripts.  
   - Example: `/etc/apache2/` for Apache servers.

3. **Virtual Directories**:  
   - Remote or external storage locations for website content.  

4. **Virtual Hosts**:  
   - Allows hosting multiple websites on a single server using distinct domain names.  
   - Example: `admin.example.com` for admin access.

5. **Web Proxies**:  
   - Handles requests between clients and servers, filtering traffic for security or performance purposes.


## Common Web Server Vulnerabilities

1. **Outdated Software**: Unpatched operating systems, web servers, or applications expose known vulnerabilities.  
2. **Default Configurations**: Default usernames, passwords, or file locations are often exploited.  
3. **Poor Authentication Mechanisms**: Weak or absent authentication controls allow unauthorized access.
4. **Misconfigurations**: Incorrect permissions or settings can expose sensitive data.  
5. **Software Vulnerabilities**: Security flaws in CMSs (e.g., WordPress) or web applications can be exploited.  


## Countermeasures and Mitigations
1. **Network Design**:
   - **DMZ (Demilitarized Zone)**: Isolates public-facing servers from internal networks.
   - **Network Segmentation**: Limits access and damage in case of a breach.
   - **Firewalls**: Use Web Application Firewalls (WAFs) to filter traffic based on HTTP/HTTPS rules.

2. **Security Practices**:
   - **Patches and Updates**: Regularly update all components, including server software and applications.
   - **Change Defaults**: Avoid default credentials and file locations.
   - **File Permissions**: Set restrictive permissions to limit access.
   - **Secure Coding**: Filter user input to prevent injection attacks (e.g., SQLi, XSS).

3. **Additional Measures**:
   - **Encryption**: Use HTTPS and other encryption protocols for secure communication.
   - **Honeypots**: Detect and analyze attacker behaviors.
   - **Error Handling**: Avoid detailed error messages that expose sensitive information.  


## Key Takeaways
- Web servers are essential but vulnerable components of modern infrastructure.  
- Understanding their configuration, potential weaknesses, and defensive strategies is critical for maintaining security.  
- Employing layered security measures like WAFs, encryption, and proper configurations helps mitigate risks.

# Web Server Attacks: Types and Examples

## Introduction
Web servers are critical components of modern infrastructure but are frequent targets for attackers.  
- Understanding the common attack types helps secure these systems effectively.  
- This summary covers various attack methods, their impacts, and examples.


## Types of Web Server Attacks

### 1. **Denial of Service (DoS/DDoS)**
- Overwhelms a server with excessive traffic, making it unavailable to legitimate users.  
- **Example**: Targeting enterprise websites (e.g., Amazon) can result in significant financial losses.  


### 2. **Directory Traversal**
- Exploits vulnerabilities to navigate beyond the web root directory into the server’s file system.  
- **Technique**: Using `../` to move up directory levels and access sensitive files like `etc/passwd`.  
- **Impact**: Exposes configuration files, logs, or sensitive data stored on the server.  
- **Example**: Accessing `/var/www/admin/settings.php` to retrieve database credentials.


### 3. **Phishing**
- Cloning a website to trick users into providing credentials or downloading malware.  
- **Method**:
  - Craft a phishing email or text with a link to a fake website.
  - Harvest user credentials when they attempt to log in.
- **Impact**: Compromised user accounts or malware infection.


### 4. **Defacement**
- Attackers alter a website’s front page to display messages, slogans, or images.  
- **Common Targets**: Organizations targeted by hacktivists.  
- **Impact**: Damages brand reputation and trust.


### 5. **Brute Force Remote Administration**
- Repeatedly guesses credentials for remote access services like SSH, RDP, or web admin portals.  
- **Tools**: Hydra, Ncrack, Burp Suite, WPScan (for WordPress).  
- **Impact**: Unauthorized access to administrative interfaces.  


### 6. **Server-Side Request Forgery (SSRF)**
- Forces a server to send unauthorized requests on behalf of the attacker.  
- **Use Cases**:
  - Internal port scanning.
  - Accessing internal resources using trusted server privileges.  
- **Example**: Sending requests to `127.0.0.1:22` to check if SSH is enabled.


### 7. **Cross-Site Scripting (XSS)**
- Injects malicious scripts into a webpage, executed in users’ browsers.  
- **Impact**:
  - Session hijacking.
  - Redirection to malicious websites.
  - Data theft.
- **Variants**: Stored, Reflected, DOM-based XSS.


### 8. **Insecure Direct Object References (IDOR)**
- Exploits insufficient access controls to access restricted objects directly.  
- **Example**: Manipulating URL parameters to access unauthorized files or records.


### 9. **Injection Attacks**
- Injects malicious code or commands into applications or servers.  
- **Subtypes**:
  - **SQL Injection**: Manipulating SQL queries.
  - **Command Injection**: Executing system commands using input fields.
- **Example**: Using `; ls -la` to list server files.


### 10. **File Inclusion (RFI/LFI)**
- **Remote File Inclusion (RFI)**: Includes external files via URL input.  
- **Local File Inclusion (LFI)**: Exploits the server to access local files.  
- **Impact**: Exposes sensitive data or executes malicious scripts.


## Countermeasures
- **Patches and Updates**: Regularly update web servers and software to fix known vulnerabilities.  
- **Least Privilege**: Restrict permissions to limit access to sensitive directories and files.  
- **Input Validation**: Sanitize user inputs to prevent injection attacks.  
- **Use WAFs**: Deploy Web Application Firewalls to filter malicious traffic.  
- **Monitor Logs**: Identify abnormal activity through log analysis.  
- **Error Handling**: Avoid exposing detailed error messages that aid attackers.


## Conclusion
Web server attacks range from resource exhaustion to data theft and defacement.  
- Proactive measures like patching, access control, and monitoring are crucial for defense.  
- Understanding these attack methods is vital for maintaining secure web services.

# Web Server Hacking Methodology

## Introduction
Web server hacking requires a **methodological approach** to identify vulnerabilities and exploit them effectively.  
- The process includes reconnaissance, scanning, fuzzing, exploiting defaults, and executing web application attacks.  
- This guide outlines the key phases and tools commonly used.


## Methodology Steps

### 1. **Reconnaissance**
- The initial phase to gather information about the target system.
- **Key Activities**:
  - Identify open ports and services (e.g., HTTP, HTTPS, MySQL).  
  - Determine server type and version (e.g., Apache, Nginx, IIS).  
  - Check for CMS platforms (e.g., WordPress, Joomla).  
  - Perform subdomain enumeration and DNS analysis.
- **Tools**:
  - `nmap`: Port scanning and version detection.
  - Manual inspection of webpage banners, source code, and DNS records.


### 2. **Vulnerability Scanning**
- Identify known vulnerabilities in web servers and applications.  
- **Popular Tools**:
  - **Nessus** and **Tenable**: Industry-standard vulnerability scanners.  
  - **OpenVAS**: Open-source vulnerability scanning.  
  - **Nikto**: Scans for common web server vulnerabilities.  
  - **OWASP ZAP**: Open-source tool with extensive features for web app testing.  
  - **Burp Suite Pro**: Paid tool offering advanced scanning and manual testing.


### 3. **Directory Fuzzing**
- Identify hidden directories or files on the web server.  
- **Process**:
  - Use tools to brute-force directory paths using common naming conventions.  
  - Check for sensitive directories like `/admin/`, `/passwords/`, or `/logs/`.  
  - Inspect files like `robots.txt` for disallowed directories.
- **Tools**:
  - **Fairox Buster**: Fast, Rust-based directory fuzzing tool.  
  - **GoBuster** and **Dirb**: Widely used for directory discovery.  
- **Example**:
  - Discover directories containing sensitive files (`wp-config.php`, `settings.xml`) with misconfigured permissions.


### 4. **Abusing Defaults**
- Exploit default configurations, credentials, or files left unchanged.
- **Common Issues**:
  - Default usernames and passwords (e.g., `admin/admin`, `root/root`).  
  - Unsecured configuration files (e.g., `phpinfo.php` exposing server details).  
  - Unrestricted access to administrative pages.
- **Mitigation**:
  - Change default credentials immediately after installation.  
  - Restrict access to sensitive files and configuration pages.


### 5. **Web Application Attacks**
- Leverage information gathered to exploit vulnerabilities.
- **Attack Vectors**:
  - Exploiting default credentials to gain admin access.  
  - Using tools like **Burp Suite** or **OWASP ZAP** to craft and execute attacks.
- **Example**:
  - After obtaining admin credentials, perform authenticated scans to find additional vulnerabilities.
- **Goal**:
  - Report findings to the client for remediation.


## Tools Overview
| **Tool**          | **Purpose**                                  |
|-------------------|----------------------------------------------|
| `nmap`            | Port scanning and service enumeration.       |
| **Nikto**         | Web server vulnerability scanning.           |
| **Burp Suite Pro**| Web application vulnerability scanning.      |
| **OWASP ZAP**     | Web app testing and directory fuzzing.       |
| **Fairox Buster** | Fast directory discovery.                    |
| **GoBuster**      | Directory fuzzing and enumeration.           |
| **Nessus**        | Comprehensive vulnerability scanning.        |


## Conclusion
The methodology involves a systematic approach to web server hacking:  
1. Perform **recon** to gather information about the target.  
2. Conduct **vulnerability scans** to identify weaknesses.  
3. Use **fuzzing** to locate hidden directories or files.  
4. Exploit **defaults** to gain access.  
5. Execute **web application attacks** to confirm vulnerabilities.
