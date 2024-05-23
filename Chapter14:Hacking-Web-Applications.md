### SOAP vs REST
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
  
### Web App Security Defense
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

### OWASP Top 10 for 2021 - Summary
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

