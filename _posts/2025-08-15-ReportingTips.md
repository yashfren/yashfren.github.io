---
title: A detailed guide to Reporting for the CPTS with sysreptor
date: 2025-08-03 18:00:00 +05:30
categories: [CPTS]
tags: [cpts]    # TAG names should always be lowercase
description: A step by step guide of how I approached reporting for CPTS and passed in the first attempt
---

# Introduction

I am writing this guide because at least 3 people (this week) asked me about how to approach report writing as they failed their first attempt despite having 12 or more flags. While I cannot assist everyone by going through their reports and pointing out their errors (It is time consuming plus might be considered as cheating), I believe writing this guide will help everyone. Note that before going through this blog, 1. go through the report writing module on the CPTS path at least once so you have an idea of what I am talking about and 2. Read [this blog by BRM titled - HTB CPTS Reporting: The Easy Way](https://www.brunorochamoura.com/posts/cpts-report/).

I will be writing this blog with the assumptions that 1. The reader doesn't know markdown and 2. The reader doesn't know how to use sysreptor (I didn't as well, learnt on the exam lol). I highly recommend using Sysreptor, as it has a default templates for all the HTB exams and I will make a dummy report in this walkthrough. Also refer to the sample report that HTB has provided in the report writing module, and if I remember correctly they provide it along with the exam. First I will be covering basic Markdown syntax and then I will make a dummy report in sysreptor

![](/assets/images/CPTS/Sysreptor.png)

# Markdown crash guide for newbies

If you have never used Markdown before, do not fret, it is super easy, in fact, I am writing this blog in Markdown. Just like we save text files with .txt extensions, we save markdown files with .md extensions. Don't worry too much about it, sysreptor handles almost everything for us, we just need to know the basic syntax.

### 1. Headings/Titles in markdown

```
# Title 1
## Title 2
### Title 3
#### Title 4
##### Title 5
###### Title 6
```
Markdown renders sentences that start with 1-6 hashtags as headings/titles. These render in different sizes of course, from biggest being a single hashtag # to smallest being six hashtags ######. 

### 2. **Bold**, *italics* and `highlighting` (not sure what this is called) and code blocks in markdown

To render text in **bold like this** use `**these 2 asterisks like this**`

There are 2 ways to render text in *italics like this*, for this I am `*Using single asterisks*` but _another way is to use_ `_underscores like this,_` just make sure to not have a space between the last asterisk or underscore in either the bold or italics part.

Finally highlighting, we put text between a pair of ` what I think are called backticks. On my keyboard these share the same key as the tildes ~, on the left of the number 1 key. This renders special symbols as plaintext, which is why I can show syntax with ease.

### 3. Rendering Images

To render images, the syntax goes something like `![Caption](/path/to/the/image)`. Do not worry about the path to image, paste in the image as you would, sysreptor will handle everything, just be sure to write a good caption. I got this tip from BRM's feedback. Oh and this is also how you add hyperlinks `![Name/text](URL/site link)`.

### 4. Code Blocks

use three backticks, write your code/text and close this block with three backticks.

it should look 

```python
print("something like this)
```

Also, you can specify python, java, javascript, powershell, php on the side of the three backticks at the start of the code block to render the text more beautifully.

# Using sysreptor and a step by step guide to reporting + common pitfalls

Now, I am not sure why I did not get any tips in examiner's feedback on my report as BRM or some of my friends have gotten despite passing. I like to think that my report was at least passable (despite the fact that I have made several mistakes I will talk about here), if not good.

![Feedback I received](/assets/images/CPTS/feedback.png)

Before a step-by-step report, I would like to cover some common pitfalls which are like FAQs or rules that I followed. I know these from looking at various reddit discussions, asking my friends several doubts about it and also reading the examiners feedback others received and were kind enough to share.

After this I will cover a simple scenario and show how to write a report.

### Common pitfalls:

#### 1. Spelling mistakes 

I made a few typos myself and a friend of mine has about 2 typos a page. I think I passed because I had very few of these, but imagine going through a report that has multiple mistakes. Yes you can understand it however, it does not look professional and seems like something you rushed through or did in your sleep. A good practice for the exam would be to put each paragraph through chatGPT or an LLM for a quick spellcheck. I don't like to use it for grammar check as it would not sound human, only do it if you aren't proficient in english.

#### 2. Unclear steps

Write each step in internal network walkthrough. Yes, the exam is kind of like capturing flags, but one flag doesn't mean one step. There are multiple steps that will lead to a flag. It does not hurt to be detailed.

#### 3. Executive Summary

This is another place where for some reason everyone is stuck. I will write one in the sample report I do. The executive summary template has multiple sections in the sysreptor template. I will cover it in the next section.

Note that the executive summary is what the stake holders and management may read as they do not have the time or understanding to sit and go through our report. Since it is targeted towards them, avoid using jargons like `The tester was able to escalate privileges on the DC.target.local host using by dumping the NTDS`. They do not care, they do not understand. Something like `The tester was able to get complete control of the DC.target.local host` is better because it shows clear impact of our findings. The key here is impact, that is not how you can do something, but the fact that you can do it.

#### 4. Images, general rendering and redacting information

I used the backticks in a bunch of places because it rendered stuff highlighted, rendering text in green. I thought it was cool but I messed up. Sysreptor uses {{ report.candidate.name }} to mention your name. I think it is some sort of advanced markdown syntax I am unaware of. Don't worry, what it means is that you paste {{ report.candidate.name }} in place of your name and your name will be rendered, however, I pasted {{ report.candidate.name }} between the backticks, so it did not render my name in many places. I was sure I would fail because of it lol.

Speaking of images, be sure to caption them. Learnt that from the feedback BRM shared. 

Also, remember to redact hashes and passwords. use \<Redacted> or \<Snip> in text and just add a solid colored block on the passes/hashes in your screenshots. I missed it at a couple places but tried to follow through as much as I could

#### 5. File size constraints

The file size must be less than 20 Mb. Now you can definitely compress it, but the best tip I got was to reduce the number of images. Instead paste in command in code blocks wherever possible.

#### 6. Reporting findings

I broke down the details section of the findings into 2 parts, 1. Enumeration and 2. Exploitation and you may also use 3. Post Exploitation if needed, like stealing or overwriting the id_rsa file on a linux host or dumping hashes/changing passwords on a windows host. 

#### 7. Ordering the said findings

The findings must be ordered in the order of severity based on CVSS score.

#### 8. Internal network walkthrough

This is the step by step guide to how you rooted the entire network. You first cover the steps for the first Domain, then start over under it for the next domain and so on till you are done.

#### 9. CVSS rating and remediation

For this, paste in the findings steps in chatGPT. I used the o3 reasoning model on the exam. Note that it hallucinates like crazy at times. You have to argue with it if you have doubt. It WILL make mistakes. Understand how CVSS works and cross question it if you have doubts.

The regular 4o model is good enough for remediation suggestions but again, if any doubts, cross question it. Do NOT paste anything in blindly. I simply imagined that I will be questioned in a viva about the remediations and that a non technical person may ask me about how to go forth with remediating a vulnerability and if I am able to explain it to them.

#### 10. Write the report in third person.

Start each finding or step with `The tester did XYZ` or `{{ report.candidate.name }} did XYZ`. Avoid using first person speech, this was a tip I got from a friend and this was also on the feedback of someone who failed.

### Writing a report using sysreptor 

I will write a small report for a dummy scenario using sysreptor as this should clear all issues. 

#### Dummy Case

We find port 80 and 22 on the given IP. 80 is hosting a company website. It has multiple Vhosts. We find employee names on the site in the `Meet our team` Section. We also find a Vhost with some app running. Recon shows that the app is vulnerable to an RCE. But we are not able to get an RCE as a firewall is blocking outbound traffic. We see that the application is running as user `dev`. We overwrite the `dev` user's `authorized_keys` file with our own `ed25519 public key`. We SSH into the host, see that `dev` can run nmap with sudo privileges, use the GTFObins guide to escalate privileges and steal the root user's id_rsa key for persistence. Running a ping sweep on the internal subnet shows that it is connected to `DC01` host. We use username anarchy to generate usernames of employees we found on the main company website. We set up a pivot using ligolo-ng and try to `asrep roast` and find hashes for a user. We find the `ASREP hash` for a user, let's say `user1`. Using `user1` credentials (we got from cracking the ASREP hash) we run a kerberoasting attack and find `user2` and its hash. We crack this hash as well. We use `bloodhound-python` to get the files for bloodhound. Checking bloodhound reveals `user2` has `DCSync` privilege over the `DC01` host and we get the Admin's hash using `impacket-secretsdump` tool.

I know this is a very simple case, but it is good enough for reporting. I will only be writing a single finding in detail. 

Below are the steps I followed on the exam.

#### Metadata and information

 ![Structure of sysreptor](/assets/images/CPTS/Struct1.png)

Put in your details in the `meta` section, add customer contacts in the `Document Control` section.
A lot of stuff in the Executive Summary is already filled for you, just add in a paragraph talking about how the pentest started and how many hosts or domains were you able to get complete access on.

`Network Penetration Test Assessment Summary` is also mostly filled out for you. Just be sure to check it once.

`Internal Network Compromise Walkthrough` is the longest and this is where you break down everything you did into steps. After that you give a detailed walkthrough where you again paste in the single/two line steps and paste in commands or screenshots of each step.

`Remediation Summary` is broken down into Small, medium and long term steps. To be honest, I GPT'd my way through this. 

`Appendix` is self explanatory, just go through it once. 

#### Internal Network Compromise Walkthrough

1. The tester discovered open ports `80` (HTTP) and `22` (SSH) on the target IP using an Nmap scan.

2. The tester enumerated the HTTP service and identified multiple virtual hosts (Vhosts).

3. The tester located employee names in the `Meet our team` section on the main site.

4. The tester identified an additional Vhost running a web application vulnerable to Remote Code Execution (RCE).

5. The tester attempted to exploit the RCE, but outbound traffic was blocked by a firewall.

6. The tester observed that the application was running under the `dev` user account.

7. The tester overwrote `/home/dev/.ssh/authorized_keys` with an attacker-controlled `ed25519` public key.

8. The tester established SSH access to the host as `dev`.

9. The tester enumerated sudo privileges and found the `nmap` executable with elevated permissions.

10. The tester used the GTFObins nmap technique to escalate privileges to root.

11. The tester extracted `/root/.ssh/id_rsa` for persistence.

12. The tester performed an internal ping sweep to identify other hosts and discovered the `DC01` domain controller.

13. The tester generated potential usernames from previously enumerated employee names using Username Anarchy.

14. The tester established a network pivot into the internal network using Ligolo-NG.

15. The tester performed AS-REP roasting against the domain controller and retrieved the AS-REP hash for `user1`.

16. The tester cracked the `user1` AS-REP hash to obtain plaintext credentials.

17. The tester used `user1` credentials to perform a Kerberoasting attack and retrieved the hash for `user2`.

18. The tester cracked the `user2` Kerberos service ticket hash to obtain plaintext credentials.

19. The tester executed `bloodhound-python` to enumerate Active Directory privileges and attack paths.

20. The tester analyzed BloodHound data and identified that `user2` had `DCSync` privileges on `DC01`.

21. The tester used `impacket-secretsdump` with `user2` credentials to perform a DCSync attack and obtain the NTLM hash of the Domain Administrator account.

22. The tester achieved full administrative control over the `DC01` domain controller.

Now paste these steps in again under the detailed walkthrough title and add screenshots and commands and any more relevant information.

#### Reporting a finding and ordering findings

The steps can be clustered into several findings now. I pasted them again in GPT (This time I am using GPT-5, not o3, which was better in my opinion).

Here are what findings look like now.

Finding 1: Remote Code Execution on Web Application

Steps: 1–5, 6–8

* Discovery of vulnerable Vhost, attempted RCE, and successful access via SSH key overwrite as `dev`.

Finding 2: Privilege Escalation to Root on Web Server

Steps: 9–11

* Sudo misconfiguration with `nmap`, privilege escalation to root, persistence with root SSH key.

Finding 3: Pivoting, Internal Network Discovery & AS-REP Roasting

Steps: 12–16

* Internal recon (ping sweep, `DC01` discovery), username generation, pivot via Ligolo-NG, AS-REP roasting of `user1` and credential cracking.

Finding 4: Kerberoasting and Credential Compromise

Steps: 17–18

* Using `user1` credentials to perform Kerberoasting on `user2` and cracking the ticket hash to obtain plaintext credentials.

Finding 5: Privilege Escalation to Domain Admin via DCSync

Steps: 19–22

* BloodHound enumeration, discovery of `user2`’s DCSync privileges, execution of DCSync attack, and obtaining Domain Administrator NTLM hash.

Now I am going to just put these findings in Sysreptor and give them a CVSS score. For this, first turn off the default order function that orders findings by CVSS score in Sysreptor to make it easy.


![Set the ordering to custom](/assets/images/CPTS/findings1.png)

After this, changing to default ordering will sort the findings automatically by CVSS score.

![Default ordering automatically sorts the findings](/assets/images/CPTS/findings2.png)

Now I will write the details for a single finding and show how I did it.

First I pasted the steps in GPT and asked it to generate each of the components for the finding. 

![It generated the Overview and Impact first](image.png)

It had recommended a different CWE, `CWE-94: Improper Control of Generation of Code (‘Code Injection’)` but since we are using some outdated software in our example, I asked it for another CWE and it came up with `CWE-1104: Use of Unmaintained Third Party Components` which seems the best to me.

![We generate the rest of the components except deatils](/assets/images/CPTS/findings4.png)

Finally this is how I write my findings,

![Findings detail](/assets/images/CPTS/findings5.png)

Feel free to use a Post Exploitation part where needed.

The rest of the findings are the same. 

#### Executive summary

![Executive Summary](/assets/images/CPTS/ExecSummary.png)

As you can see, there is a TODO section in the Assessment Overview and recommendations in the Executive Summary component.

I simply asked chatGPT to generate a 3-4 line summary after feeding it the steps.

So in our dummy case, it would look something like: 

`During the assessment, {{ report.candidate.name }} successfully obtained initial access to a web application hosted on {{ report.customer\_short }}’s infrastructure, escalated privileges to root on the server, and pivoted into the internal network. Through targeted Active Directory attacks, including AS-REP roasting, Kerberoasting, and abuse of DCSync privileges, full administrative control over the domain controller was achieved. These findings demonstrate that a compromise of a single exposed application could lead to complete takeover of the internal network.
`

#### Conclusion

Report writing for CPTS is quite exhausting and time taking. Please allocate at least 2 if not 3 days for it. I had some time to go for the 13th flag but decided against it which was a great decision because I took a long time to get my report ready for submission

If this helped or you feel like I skipped anything, feel free to DM me on [Twitter](https://x.com/Yassh_twts) (Shameless plug, follow me) or Linkedin (I don't open it as much so might not respond immediately).

