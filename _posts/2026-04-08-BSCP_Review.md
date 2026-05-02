---
title: My BSCP experience - tips and tricks
date: 2026-04-08 10:30:00 + 05:30
categories: ["2026",Web, BSCP]
tags: ["2026", bscp]
description: My journey from web security noob to passing Portswigger's BSCP certification, with practical exam tips and lessons learned.
---

I just passed the BSCP this week and here are my thoughts about preparations and tips:

![](/assets/images/BSCPReview/burp-cert.png)

# How this review/post is structured:

1. Timeline of preparation from zero to certification

2. Tips and stuff to keep in mind

3. What's next for me

So if you are here for the tips and don't care about how I prepared, skip ahead and save time.

# 1. Timeline of preparation from zero to certification

First time I ever did Portswigger was about 2-3 years back. Why? because that's what you do to become a bug bounty hunter. Then I stopped to chase the CPTS and played some HTB. I had only finished SQLi back then. 

After this I attended my first cybersec conf/event last year - BSides Mumbai, where I made new friends. Many of them were halfway through Portswigger. Since I was newly CPTS certified I thought let me do this. I then wanted to just do common bugs from Portswigger that were likely to come on the OSCP. That is when I finished XSS last year. 

After this I got some wisdom from the guys I met there and thought, "Yeah OSCP doesn't make sense to me, too expensive" and stopped OSCP prep altogether. After this I was still grinding Portswigger for a few months and finished all server side vulnerabilities. 

Then I purchased pentesterlab pro and HTB gold annual to learn code review and whitebox pentesting and give the CWEE (as a precursor to OSWE). If I am spending the same large amount on a cert by offsec, ain't no way will it be something that is said to be "entry level" like OSCP. Might as well do advanced stuff lol.

Now I had 2 subscriptions active and Portswigger half done. I was doing everything at once but reaching nowhere. This is when I made the bet with my friends online in late January that I will attempt the BSCP before March end (won't reveal what the rest of the bet was).

So I learnt some basic javascript to understand wtf are objects and the DOM. This was important for learning client side bugs. XSS was already done, the rest took some time. After that I finished the advanced vulnerabilities. 

I think my last blog was on 24th March 2026 for prototype pollution walkthrough. I finished all Portswigger labs around that time. After this I reviewed everything and did the 5 mystery labs. Again, I did maybe 2-3 labs on my own and had to look at the solutions for 2-3. 

NOTE: I was able to grind Portswigger this fast as I had work from home for a few weeks and barely had to go to the office. If you are in a similar situation, you can finish Portswigger 0 to 100% in 4-6 months. If you are working full time it may easily take you twice or even thrice this much time. Adding this because it hasn't been even 24 hours since I shared the cert and at least 4 people have asked me. It doesn't matter, everyone has their own speed. Getting the job done is important no matter how long it takes. 

I had intentions to give the exam on 29th March evening. So I solved the first practice test app on 28th March. 2 hours, 1 application and I hacked it by myself in 1 hour 45 minutes. I was proud of myself. So I sat to hack the next one after dinner. And boy did that machine screw me badly. Could not solve it so went to sleep.

Revisited it again with a fresh mind and solved it in 1 hour 10 minutes. After this I was confident and immediately paid for the voucher. 

Surprise! The payment goes through but I get an email from Portswigger that the payment is processed but they need to verify something and that may take a day. I emailed them after 24 hours and got the voucher by 30th evening. By then it was too late. I decided to give it on 31st March. The last day to honour the bet I made. 

I sat to give the exam, and disaster struck. The proctor software made my laptop lag like crazy as if I was playing a FPS game like Valorant on 1000 ping, except it was my laptop's cursor and keys not moving.

I struggled with this for 45 minutes. This killed any and all excitement I had for the exam. In fact I got frustrated and lost focus. I was unable to do anything. I took a picture of my stuck screen, closed the proctor software and emailed to Portswigger about what had just happened. I tried to salvage the exam but I could barely hack the first app. I felt like all this was a waste. 

After this I called one of my friends on discord for tips about the retake since he took the exam last year and I remember it took him 2-3 attempts due to technical issues. He reassured me that Portswigger is quite understanding and will definitely give me a complimentary retake and it will be alright. And boy was he right. 

Shoutout to the Portswigger staff for being very kind and understanding and giving me a free retake. I passed on this attempt with about 20-30 minutes to spare. It went relatively smooth. I gave the second attempt on 5th April, 2026 and got the result that I had passed on 7th April, 2026.

Now I will write about tips and setup and how I fixed that proctor issue and everything else that is important.

# 2. Tips and stuff to keep in mind

##### 1. Let's start from prep, Do I need any additional resources to prepare? 

Nope. Portswigger labs, apprentice and practitioner level are more than enough, do them all. I'd say do the expert level labs just for fun. Even though they are expert level rated, they are fun and there is a certain satisfaction to completing everything entirely.

##### 2. 3rd party tools are allowed? 

Yes they are. I had sqlmap ready in case I ran into SQLi.

##### 3. What about AI? 

Yes even that is allowed. I used claude to fix a couple of my payloads on the exam. It will really be a life saver if you are sure about what you are doing. What I mean is, if you ask it to debug a payload for XSS but the vulnerability is deserialization, you are gonna be stuck. AI doesn't know if the bug is real or not (unless you are using an agent to solve the exam).

##### 4. How is this exam structured?

You have 4 hours and 2 webapps to hack. Hack whatever you want first, no problem. 

However, both webapps have 3 stages each. 

Initial access - Carlos mostly, could be another user, don't worry, they have given a list of usernames and passwords for bruteforcing. How to do that is upto you.

Privesc - Get to admin panel or the administrator account from low privilege account

File read / RCE - Read the flag at /home/carlos/secret and submit it to solve the lab. 

##### 5. But 4 hours are enough to solve everything? How to not get stuck?

Read this blog - [https://micahvandeusen.com/blog/burp-suite-certified-practitioner-exam-review/](https://micahvandeusen.com/blog/burp-suite-certified-practitioner-exam-review/).

I made a similar table and added the topics that were not covered (claude helped).

| Category                  | Stage 1 | Stage 2 | Stage 3 |
| ------------------------- | :-----: | :-----: | :-----: |
| SQL Injection             |         |    ✅    |    ✅    |
| XSS                       |    ✅    |    ✅    |         |
| CSRF                      |    ✅    |    ✅    |         |
| Clickjacking              |    ✅    |    ✅    |         |
| DOM-based vulnerabilities |    ✅    |    ✅    |         |
| CORS                      |    ✅    |    ✅    |         |
| XXE Injection             |         |         |    ✅    |
| SSRF                      |         |         |    ✅    |
| HTTP Request Smuggling    |    ✅    |    ✅    |         |
| OS Command Injection      |         |         |    ✅    |
| SSTI                      |         |         |    ✅    |
| Path Traversal            |         |         |    ✅    |
| Access Control / IDOR     |    ✅    |    ✅    |         |
| Authentication            |    ✅    |    ✅    |         |
| Web Cache Poisoning       |    ✅    |    ✅    |         |
| Insecure Deserialization  |         |         |    ✅    |
| HTTP Host Header          |    ✅    |    ✅    |         |
| OAuth                     |    ✅    |    ✅    |         |
| File Upload               |         |         |    ✅    |
| JWT                       |    ✅    |    ✅    |         |
| Prototype Pollution       |    ✅    |    ✅    |         |
| NoSQL Injection           |    ✅    |    ✅    |         |
| Web Cache Deception       |    ✅    |    ✅    |         |
| GraphQL                   |    ✅    |    ✅    |         |
| API Testing               |    ✅    |    ✅    |         |
| Business Logic            |    ✅    |    ✅    |         |
| Race Conditions           |    ✅    |    ✅    |         |
| Web LLM Attacks           |    ✅    |    ✅    |         |
| WebSockets                |    ✅    |    ✅    |         |
| Information Disclosure    |    ✅    |    ✅    |    ✅    |

What does this mean?

It means there is no point looking for OS command injection when are not a low privileged user or admin user. Same with path traversal or SSRF, as those vulnerabilities are useful for file reading. 

##### 6. How to get more practice?

SOLVE THE PRACTICE TESTS. I cannot stress this enough. This is the nearest experience to the exam environment you will get. In fact, the exam is a bit tougher than these practice tests I'd say.

##### 7. How did I not get stuck?

I ran a deep scan on every new functionality I found. EVERY ONE. It takes about 15 minutes to run on one endpoint and you can run many of them parallely, so just do it. I found a bug that I was unable to bypass the filters for. I thought it was a rabbit hole but the burp scanner gave me a working payload lol. This is how I legit solved something I thought was unhackable. 

##### 8. What was the proctor issue?

I remember reading other reviews that say that you can shut off the proctor after 5 minutes. That is not true. Do NOT do that. Let it remain ON till you submit your zip file. 

Now why did it make my PC lag? Short answer: Hardware acceleration.

Long answer: I shared my screen with my friend on discord and I was using the webapp and it again made my laptop lag. I understood that this is an issue with the browser. I had to disable hardware acceleration and this solved the issues I had. 

This is simple to do. Since I was using brave, I went to `brave://settings/system` and toggled `Use graphics acceleration when available` this to off, relaunch browser. 

##### 9. Old vs New setup?

I was using brave browser and running proctor on it and I used a kali vm with burp pro, ysoserial and sqlmap for the first attempt. 

After what happened then, I asked portswigger staff about the best setup + a friend recommended I stick to windows as burp is all I need. 

So for the second attempt I used brave as the proctor browser and I used the in-built browser in Burp Suite for solving the exam. I also had already cloned sqlmap repo on my laptop and I was ready to boot the VM with ysoserial just in case as that would be the last step.

##### 10. How to fix a broken burp UI on windows?

After installing BurpSuite Pro on windows, this is how the UI looked like. Almost everything I tried, failed. 

![](/assets/images/BSCPReview/brokenburp.png)

Solution:

First I opened powershell and cd'd into the directory that had the BurpPro's .exe file.

```powershell
New-Item user.vmoptions -ItemType File
```

Run this.

Then open this file.

Paste the following, save and close and restart burp.

```
-Dsun.java2d.uiScale=1.25
-Dsun.java2d.opengl=false
-Dsun.java2d.d3d=false
-Dsun.java2d.noddraw=true
```

Now if your resolution is 150%, change the 1.25 above to 1.5 and so on. 

This fixed the issue for me.

# 3. What's next for me

As luck would have it, I am now going to the office for my internship in person from this week, right after finishing BSCP. 

My goals for now are:

1. Learn python to write exploits for Webapps since I want to give the OSWE this year. Also useful skill on CWEE.

2. Learn linux and git for fun.

3. Finish pentesterlab for learning code review.

4. Finish HTB academy, all the labs so I can give the other exams next year after I give CWEE this year.

5. Study for CWEE

6. Most importantly, apply what I learnt to earn bounties. I really want to start bug bounty but I barely get any time for it. 

That's it. Let's see how it goes.