# dvwa-security-lab
DVWA Security Lab Report

Author: Your Name
Date: March 2026
Environment: DVWA via Docker on localhost
Scope: Local machine only — no public exposure


Table of Contents

Environment Setup
SQL Injection
SQL Injection Blind
XSS Reflected
XSS Stored
XSS DOM
Command Injection
CSRF
File Inclusion
File Upload
Brute Force
Insecure CAPTCHA
Weak Session IDs
CSP Bypass
JavaScript
Docker Inspection
Security Analysis
OWASP Top 10 Mapping
Bonus: Nginx + HTTPS


1. Environment Setup
1.1 Docker Installation Verification
bashdocker --version
1.2 Pulling and Running DVWA
bashdocker pull vulnerables/web-dvwa

docker run -d \
  --name dvwa \
  -p 8080:80 \
  vulnerables/web-dvwa

docker ps
Screenshot: 
1.3 Accessing DVWA

Opened browser at: http://localhost:8080
Clicked Create / Reset Database
Logged in — Username: admin Password: password

Screenshot: (DVWA dashboard)

2. SQL Injection
Overview
SQL Injection manipulates database queries by injecting malicious SQL through user input fields, tricking the database into returning data it shouldn't.

 Security Level: Low
Payload Used:
sql1' OR '1'='1
Result: All users in the database were returned. The OR '1'='1' condition is always true, bypassing the WHERE clause entirely.
Screenshot: 
Why it worked:
Input is concatenated directly into the SQL query with zero sanitization:
php$query = "SELECT first_name, last_name FROM users WHERE user_id = '$id';";
Becomes:
sqlSELECT first_name, last_name FROM users WHERE user_id = '1' OR '1'='1';

 Security Level: Medium
Payload Used:
sql1 OR 1=1
(Modified via browser DevTools on the dropdown)
Result: Attack partially succeeded. Quote-based injection is blocked but integer-based injection still works.
Screenshot: 
Why it worked:
Medium uses mysql_real_escape_string() which escapes quotes but does not use prepared statements. Integer payloads without quotes bypass this entirely.

 Security Level: High
Payload Used:
sql1' OR '1'='1
Result: Attack failed. Only a normal single result returned.
Screenshot: 
Why it failed:
High uses PDO prepared statements:
php$stmt = $pdo->prepare('SELECT first_name, last_name FROM users WHERE user_id = :id');
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
Input is treated as pure data — no SQL logic can be injected.

4. XSS (Reflected)
Overview
Reflected XSS occurs when user input is immediately echoed back in the page response without sanitization, causing the browser to execute it as JavaScript.

 Security Level: Low
Payload Used:
html<script>alert('XSS')</script>
Result: JavaScript alert popup appeared confirming script execution.
Screenshot: 
Why it worked:
Input is directly echoed into HTML:
phpecho '<pre>Hello ' . $_GET['name'] . '</pre>';

 Security Level: Medium
Payload Used:
html<Script>alert('XSS')</Script>
Result: Alert popup appeared — capital S bypassed the filter.
Screenshot: 
Why it worked:
Medium uses str_replace() to strip <script> (lowercase only). Mixed case is not caught by the blacklist.

 Security Level: High
Payload Used:
html<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
Result: Attack failed. Code displayed as plain text.
Screenshot: 
Why it failed:
htmlspecialchars() converts < and > to HTML entities — the browser displays the text, never executes it.

5. XSS (Stored)
Overview
Stored XSS persists the malicious script in the database. Every user who loads the page will have the script execute in their browser automatically.

 Security Level: Low
Payload Used (Message field):
html<script>alert('Stored XSS')</script>
Result: Alert popup fired immediately and will fire again for every user who visits the page.
Screenshot: 
Why it worked:
No sanitization on input or output — the script is saved raw into the database and rendered directly into the HTML page.

 Security Level: Medium
Payload Used (Name field — after extending maxlength via DevTools):
html<img src=x onerror=alert('Stored XSS Medium')>
Result: Alert popup appeared — image event handler bypassed the script tag filter.
Screenshot: 
Why it worked:
Medium strips <script> tags but does not sanitize HTML event attributes. The maxlength restriction on the Name field was removed via DevTools to fit the payload.

 Security Level: High
Payload Used:
html<img src=x onerror=alert('XSS')>
Result: The Name field at High level still showed a popup due to incomplete protection — the Message field is fully secured with htmlspecialchars() but the Name field is not consistently protected. This is a real vulnerability even at the "High" level, demonstrating that security must be applied uniformly across all inputs.
Screenshot: 
Analysis:
A truly secure implementation must apply output encoding to every single input field — missing even one creates an exploitable gap.

7. Command Injection
Overview
Command Injection appends OS commands to a legitimate server-side function call (like ping), executing arbitrary commands on the server.

 Security Level: Low
Payload Used:
127.0.0.1; ls /var/www/html
Result: Ping output followed by the full directory listing of the web server files.
Screenshot: 
Why it worked:
Input passed directly to shell_exec() with no sanitization:
phpshell_exec('ping -c 4 ' . $target);

 Security Level: Medium
Payload Used:
127.0.0.1 | ls
Result: Directory listing appeared — pipe character was not in the blacklist.
Screenshot: 
Why it worked:
Medium blacklists && and ; but forgets |, which also chains commands.

 Security Level: High
Payload Used:
127.0.0.1; ls
127.0.0.1 | ls
127.0.0.1 && ls
Result: Attack failed. Only normal ping output returned.
Screenshot: 
Why it failed:
High uses escapeshellcmd() plus a strict character whitelist — all shell metacharacters are stripped before execution.

