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

### Web Server Attacks

**Directory Traversal:**
Accessing restricted directories and files outside the web server's root directory by manipulating URL paths.

**Page Defacement:**
Unauthorized alteration of a web page, often to display malicious or offensive content.

**SSRF (Server-Side Request Forgery):**
Forcing the server to make requests to internal resources, leading to data leakage or other exploits.

**XSS (Cross-Site Scripting):**
Injecting malicious scripts into web pages viewed by other users, stealing data or performing unauthorized actions.

**IDOR (Insecure Direct Object Reference):**
Exploiting direct access to objects (e.g., files, database records) without proper authorization checks.

**Code Injection:**
Injecting malicious code into a web application, causing it to execute unauthorized commands.

**File Inclusion:**
Including and executing files on the server, leading to code execution or information disclosure.

**DoS (Denial of Service):**

**Bruteforcing:**

**Phishing:**

### Tools

**Burp Suite:**
An integrated platform for performing web application security testing.

**Nessus:**
A vulnerability scanner that identifies security issues in networks and applications.

**OWASP ZAP (Zed Attack Proxy):**
A tool for finding vulnerabilities in web applications during the development and testing phases.

**Feroxbuster:**
A tool for content discovery and enumeration on web servers by brute-forcing directories and files.

### What is?
***robots.txt File:***
A text file in the root directory of a website that instructs web crawlers and search engines which pages or sections should not be crawled or indexed.

***Fuzzing:***
A testing technique that involves providing invalid, unexpected, or random data as inputs to a program to find security vulnerabilities and bugs.

**Example:**
A fuzzing tool might input random strings, numbers, or special characters into a web form to see if it causes the application to behave unexpectedly, such as crashing or exposing sensitive information.

