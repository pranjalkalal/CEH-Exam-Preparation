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

### Common Security Risks Associated with Web Apps
- **SQL Injection:** Injecting malicious SQL queries to manipulate databases.
- **Cross-Site Scripting (XSS):** Injecting malicious scripts into web pages.
- **Cross-Site Request Forgery (CSRF):** Forcing users to perform unwanted actions.
- **Insecure Direct Object References (IDOR):** Accessing unauthorized objects.
- **Security Misconfigurations:** Poorly configured security settings.
- **Sensitive Data Exposure:** Inadequate protection of sensitive information.
- **Broken Authentication and Session Management:** Weak authentication mechanisms.
- **Using Components with Known Vulnerabilities:** Using outdated or vulnerable third-party components.

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
