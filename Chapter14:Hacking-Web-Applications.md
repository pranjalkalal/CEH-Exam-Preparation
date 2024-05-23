## SOAP vs REST
**SOAP (Simple Object Access Protocol):**
- **Protocol:** A protocol for exchanging structured information in web services.
- **Complexity:** More complex, with strict standards.
- **Format:** XML only.
- **Security:** Built-in WS-Security standards.
- **Statefulness:** Supports stateful operations.
- **Example:** Used in enterprise environments requiring robust security and transaction compliance.

**REST (Representational State Transfer):**
- **Style:** An architectural style for designing networked applications.
- **Simplicity:** Simpler, more flexible.
- **Format:** Supports multiple formats like JSON, XML, HTML.
- **Security:** Relies on HTTP-based security, like HTTPS.
- **Statefulness:** Stateless operations.
- **Example:** Used in web applications, mobile apps, and IoT services for its simplicity and performance.
  
## Web App Security Defense
**Security Testing:**
- **SAST (Static Application Security Testing):**
  - **Description:** Analyzes source code for vulnerabilities without executing programs.
  - **Example:** Checking for insecure coding patterns during development.

- **DAST (Dynamic Application Security Testing):**
  - **Description:** Tests running applications for vulnerabilities.
  - **Example:** Simulating attacks on a live web app to find security flaws.

**Fuzz Strategies:**
- **Mutation Fuzzing:**
  - **Description:** Modifies existing input data to create new test cases.
  - **Example:** Altering valid data slightly to uncover unexpected behavior.

- **Generational Fuzzing:**
  - **Description:** Generates new inputs based on the specification of input format.
  - **Example:** Creating data from scratch to ensure coverage of all input scenarios.

- **Protocol-Based Fuzzing:**
  - **Description:** Focuses on testing protocols by sending unexpected or malformed data.
  - **Example:** Sending incorrect data packets to test network protocol implementations.

**Encoding:**
- **Description:** Converting data into a different format to protect it during transmission.
- **Example:** URL encoding user input to prevent XSS attacks.

**Whitelisting and Blacklisting:**
- **Whitelisting:**
  - **Description:** Allowing only approved inputs/sources (Allow List).
  - **Example:** Only accepting valid email formats in a form field.
- **Blacklisting:**
  - **Description:** Blocking known malicious inputs/sources (Deny List).
  - **Example:** Blocking input containing SQL command keywords.

**Content Filtering and Input Sanitization:**
- **Description:** Removing or modifying potentially dangerous content from user inputs.
- **Example:** Stripping out HTML tags from user comments to prevent XSS.

**WAF (Web Application Firewall):**
- **Description:** Filters and monitors HTTP traffic to and from a web application.
- **Example:** Blocking SQL injection attempts by inspecting incoming requests.

**RASP (Runtime Application Self-Protection):**
- **Description:** Security technology that runs within the application to detect and prevent attacks in real-time.
- **Example:** Identifying and blocking an attack by analyzing application behavior during runtime.

## OWASP Top 10 for 2021 - Summary
1. **Broken Access Control (A01)**:
   - This category focuses on flaws related to inadequate enforcement of access controls, such as improper authorization mechanisms, missing authentication, or failure to restrict users' access to certain functionalities or resources.

2. **Cryptographic Failures (A02)**:
   - Cryptographic failures refer to vulnerabilities related to the incorrect implementation or misuse of cryptographic techniques, such as encryption, hashing, or key management. These failures can lead to sensitive data exposure or compromise of system integrity.

3. **Injection (A03)**:
   - Injection vulnerabilities occur when untrusted data is sent to an interpreter as part of a command or query, leading to the execution of unintended commands or unauthorized access to data. This category includes common injection attacks such as SQL injection, NoSQL injection, and command injection.

4. **Insecure Design (A04)**:
   - Insecure design vulnerabilities stem from flaws in the architectural or design aspects of a system, such as inadequate threat modeling, insecure design patterns, or failure to follow secure coding principles. These vulnerabilities can lead to systemic weaknesses that are difficult to address without fundamental design changes.

5. **Security Misconfiguration (A05)**:
   - Security misconfiguration vulnerabilities occur when security settings are not properly configured, such as default passwords, unnecessary features enabled, or excessive permissions granted. These misconfigurations can expose systems to unauthorized access, data leaks, or other security risks.

6. **Vulnerable and Outdated Components (A06)**:
   - This category addresses risks associated with the use of outdated or vulnerable software components, such as libraries, frameworks, or third-party dependencies. Failure to update or patch these components can expose applications to known exploits and security vulnerabilities.

7. **Identification and Authentication Failures (A07)**:
   - Identification and authentication failures occur when authentication mechanisms are improperly implemented or authentication credentials are not adequately protected. These failures can lead to unauthorized access, account takeover, or other security breaches.

8. **Software and Data Integrity Failures (A08)**:
   - This category focuses on vulnerabilities related to assumptions made about software updates, critical data, or CI/CD pipelines without verifying integrity. These failures can lead to unauthorized modifications to software or data, compromising system integrity and security.

9. **Security Logging and Monitoring Failures (A09)**:
   - Security logging and monitoring failures occur when applications fail to generate adequate logs or monitoring alerts, hindering detection and response to security incidents. These failures can impact visibility, incident alerting, and forensic analysis, making it difficult to detect and mitigate security threats.

10. **Server-Side Request Forgery (A10)**:
    - Server-side request forgery vulnerabilities occur when attackers can manipulate server-side requests to access internal resources or perform unauthorized actions on behalf of the server. These vulnerabilities can lead to data leaks, unauthorized access, or server-side attacks.

## Key Steps in Web App Hacking
1. **Reconnaissance and Footprinting**:
   - Understand the application and its environment.
   - Gather information about the target's organization, technology stack, and potential vulnerabilities.

2. **Enumeration**:
   - Identify IP addresses, DNS information, subdomains, virtual hosts, firewalls, WAFs, proxies, rate limiting, etc.
   - Discover software versions, open ports, files, directories, and hidden content.

3. **Vulnerability Assessment**:
   - Use automated tools and manual testing to find vulnerabilities.
   - Identify potential exploits by mapping out discovered vulnerabilities.

4. **Exploitation**:
   - Attack identified vulnerabilities to gain unauthorized access or escalate privileges.
   - Perform various types of attacks such as injection attacks, authentication bypasses, logic flaws, CSRF, XSS, and more.

### Tools in Web Apps Hacking
1. **Nikto**: A web server scanner that checks for over 6700 potentially dangerous files/programs, outdated versions, and server misconfigurations.

2. **Skipfish**: An active web application security reconnaissance tool that prepares an interactive site map for the targeted site by carrying out recursive crawl and dictionary-based probes.

3. **Wapiti**: A web application vulnerability scanner that checks for SQL injections, XSS, and other common vulnerabilities by crawling the web pages of the deployed application.

4. **OWASP ZAP (Zed Attack Proxy)**: An open-source web application security scanner that helps find security vulnerabilities in web applications during development and testing.

5. **Burp Suite**: A comprehensive platform for web application security testing that includes tools for crawling, scanning, and exploiting vulnerabilities. It is widely used by security professionals for penetration testing.

6. **SQLmap**: An open-source tool that automates the process of detecting and exploiting SQL injection flaws and taking over database servers.

7. **Comix**: A command injection vulnerability tool that helps in finding and exploiting command injection bugs in web applications.

8. **WFuzz**: A web application security fuzzer that allows users to perform brute force attacks on various parameters such as forms, headers, cookies, and URLs to find vulnerabilities.

9. **WPScan**: A black-box WordPress vulnerability scanner that can detect security issues in WordPress installations, including plugins, themes, and core files.

10. **JoomScan**: A Joomla vulnerability scanner that helps in identifying vulnerabilities in Joomla CMS, including outdated versions, vulnerable extensions, and misconfigurations.

11. **Drupal Security Scanner**: Tools like Drupwn, which scan for vulnerabilities in Drupal CMS installations, identifying security issues in modules and core components.

12. **Searchsploit**: A command-line tool for searching the Exploit DB database, enabling quick searches for exploits and vulnerabilities based on various parameters.

13. **Acunetix**: A commercial web application security scanner that automatically tests for vulnerabilities such as SQL injection, XSS, and others. It includes advanced scanning capabilities and reporting features.

14. **Volners**: A comprehensive security vulnerability database that aggregates data from multiple sources, providing detailed information about known vulnerabilities and exploits.


## Unvalidated Forwards/Redirects
- **Unvalidated Redirect:** Redirecting users to different websites without validating the target URL.
- **Unvalidated Forward:** Similar to redirects but often used within applications, potentially granting access to restricted areas.

### Explanation and Risks
- **Unvalidated Redirects:**
  - Commonly seen when a link redirects you to a different site.
  - Attackers exploit these to create phishing sites that appear legitimate.
  - Users may not notice the change in URL, leading to credential theft or malware downloads.
  
- **Unvalidated Forwards:**
  - May grant access to restricted pages, such as admin portals.
  - Harder to demonstrate as they require specific vulnerable systems.

### Practical Demonstration
- **Tools Used:**
  - **BWAP (Buggy Web Application):** Used to demonstrate the attack.
  - **Social Engineering Toolkit (SE Toolkit):** For cloning the login page.

- **Steps:**
  1. **Create a Phishing Email:** Informing users of a fake data breach and asking them to log in.
  2. **Clone Login Page:** Using SE Toolkit to create a fake login page that mimics the real one.
  3. **Set Up Redirect:** Direct the phishing link to the fake login page.
  4. **Capture Credentials:** When users enter their credentials, they are logged, demonstrating how easily information can be stolen.

## Introduction to XSS and CSRF

### Cross-Site Scripting (XSS)
XSS is a vulnerability where an attacker can inject malicious scripts into web pages viewed by other users. These scripts are typically written in JavaScript and can execute arbitrary code in the victim's browser, stealing data or performing actions on their behalf.

#### Types of XSS
1. **Reflected XSS**
   - Occurs when user input is immediately returned by a web application without proper sanitization.
   - Example: Searching for a term on a website that displays the search term back to you without encoding.
   
2. **Stored (Persistent) XSS**
   - Occurs when user input is stored on the server and then displayed on web pages.
   - Example: Comment sections on blogs where malicious scripts are stored in the database and executed every time the comment is viewed.

3. **DOM-based XSS**
   - Occurs when the vulnerability exists in the client-side code rather than the server-side code.
   - Example: Manipulating the DOM environment in the browser to execute malicious scripts.

#### Testing for XSS
To test for XSS, you can inject a simple JavaScript alert script into inputs to see if it gets executed:

```html
<script>alert('XSS');</script>
```

Using tools like Burp Suite or automated scripts can help in identifying such vulnerabilities more efficiently.

### Cross-Site Request Forgery (CSRF)
CSRF exploits the trust that a web application has in the user. It tricks the user into performing actions on behalf of the attacker, often without the user's knowledge.

#### How CSRF Works
- **Trust Relationship**: The user is authenticated on a site (e.g., logged into their bank).
- **Malicious Request**: The attacker crafts a request to perform a sensitive action (e.g., transferring money) and embeds it in a malicious link or script.
- **Execution**: The user unknowingly triggers the action by visiting a malicious website or clicking a link, which uses their credentials to perform the action.

### Combining XSS and CSRF
An attacker can leverage XSS to inject a CSRF attack, combining the power of both vulnerabilities. Here’s an example scenario:

1. **Identify CSRF Vulnerability**: Find a URL that performs a sensitive action, like transferring money, which includes the action and parameters in the URL.
2. **Craft XSS Payload**: Use an XSS vulnerability to inject a script that automatically triggers the CSRF request.
3. **Deliver Payload**: The payload can be delivered via a blog comment, social media post, or any other method where users will view the malicious content.

```html
<script>
  new Image().src = "http://victim.com/transfer?amount=100&account=attacker_account";
</script>
```
