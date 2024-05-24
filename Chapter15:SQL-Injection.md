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

**Practical Demonstration**
- Boolean-Based Example:
  - Inject `OR 1=1--` and observe the application returning results.
  - Inject `OR 1=2--` and observe no results.
- Time-Based Example:
  - Inject `SLEEP(5)--` and observe a 5-second delay in response.
  - Using different sleep times to test the success of injections.
