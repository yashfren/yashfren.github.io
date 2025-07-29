---
title: Week 2 of my OSCP preparation 
date: 2025-07-29 18:00:00 + 05:30
categories: [OSCP Prep]
tags: [oscp, xss]    # TAG names should always be lowercase
description: Another week of waiting for my CPTS results and solving XSS labs
---
# Week 2 of my OSCP preparation

![](/assets/images/celestial_symphony_by_kareguya_dic6o40-pre.jpg)

A bit late publishing this. Last week marked day 15 of the 20-day wait for my CPTS result, so I wasn’t expecting it just yet. This week is the final stretch. By the next blog post, I should be CPTS certified, assuming my report gets approved.

## OSCP Prep

### Web - XSS

Anyways, this week I finished all the 30 labs on PortSwigger for XSS. You may check out the detailed walkthrough that I published for each of the labs [here](https://yashfren.github.io/posts/XSS_PortswiggerLabs_Walkthrough/). Ironically, some payload(s) is/are maybe leaking into the page and executing. So yeah, visiting a walkthrough for XSS labs throws an XSS alert. Haven't had time to fix it yet. Might just leave it as it is because it's funny. Might update the blog to have a line on top - "See how you just had a pop-up, yeah that was an XSS payload running, learn all about it below". 
Most of my time went into doing these labs and making the walkthrough blog. Haven't touched AD the entire past week. Also, I read these 15 bug bounty reports spead across personal blogs, medium writeups as well as some hackerone hacktivity all exploiting XSS on real targets.

1. [https://portswigger.net/daily-swig/facebook-pays-out-25k-bug-bounty-for-chained-dom-based-xss](https://portswigger.net/daily-swig/facebook-pays-out-25k-bug-bounty-for-chained-dom-based-xss) - The attacker found a DOM XSS in Facebook’s payments redirect page. It talks about XSS across multiple windows/pages using `postMessage` and how the attacker spoofed the request origin by using an internal subdomain. 

2. [https://alonnsoandres.medium.com/25k-instagram-almost-xss-filter-link-facebook-bug-bounty-798b10c13b83](https://alonnsoandres.medium.com/25k-instagram-almost-xss-filter-link-facebook-bug-bounty-798b10c13b83) - The attacker found an open redirect within meta tags which could be escalated to XSS using charset tricks as per the facebook security team. 

3. [https://portswigger.net/daily-swig/xss-vulnerability-in-login-with-facebook-button-earns-20-000-bug-bounty](https://portswigger.net/daily-swig/xss-vulnerability-in-login-with-facebook-button-earns-20-000-bug-bounty) - The attacker found a DOM-based XSS in Facebook’s SSO plugin. Any malicious website that embedded the Facebook-hosted login iframe could exploit it to execute JavaScript in the facebook.com context.

4. [https://infosecwriteups.com/16-000-bounty-stored-xss-in-gitlab-a0f57e5c4245](https://infosecwriteups.com/16-000-bounty-stored-xss-in-gitlab-a0f57e5c4245) - The attacker exploited a filename injection flaw in GitLab's markdown parser to break HTML structure and achieve stored XSS, bypassing CSP and executing JavaScript across issues, comments, and merge requests.

5. [https://samcurry.net/cracking-my-windshield-and-earning-10000-on-the-tesla-bug-bounty-program](https://samcurry.net/cracking-my-windshield-and-earning-10000-on-the-tesla-bug-bounty-program) - The attacker embedded a blind XSS payload in their Tesla's vehicle name, which later executed on an internal Tesla support dashboard, exposing live car telemetry and earning a $10,000 bounty.

6. [https://www.ehpus.com/post/xss-fix-bypass-10000-bounty-in-google-maps](https://www.ehpus.com/post/xss-fix-bypass-10000-bounty-in-google-maps) - The attacker exploited a CDATA escaping flaw in Google Maps’ KML export feature to achieve stored XSS, and later bypassed Google's fix with a double-CDATAClose trick, earning a total bounty of $10,000.

7. [https://krishna-cyber.medium.com/how-i-uncovered-idor-xss-and-full-account-takeover-in-a-single-hunt-acfce2f9a84f](https://krishna-cyber.medium.com/how-i-uncovered-idor-xss-and-full-account-takeover-in-a-single-hunt-acfce2f9a84f) - The attacker chained an IDOR, stored XSS, and session hijacking to achieve full account takeover on a social media platform, earning a $6,500 bounty and forcing major security changes.

8. [https://vbharad.medium.com/stored-xss-in-icloud-com-5000-998b8c4b2075](https://vbharad.medium.com/stored-xss-in-icloud-com-5000-998b8c4b2075) - The attacker discovered a stored XSS in iCloud’s Pages/Keynote collaboration feature, where a malicious filename triggered JavaScript execution in another user’s session via the "Browse All Versions" panel.

9. [https://infosecwriteups.com/5-000-usd-xss-issue-at-avast-desktop-antivirus-for-windows-yes-desktop-1e99375f0968](https://infosecwriteups.com/5-000-usd-xss-issue-at-avast-desktop-antivirus-for-windows-yes-desktop-1e99375f0968) - The attacker discovered a reflected XSS in Avast’s desktop antivirus triggered by a malicious Wi-Fi SSID name, causing script execution via network pop-up notifications on Windows systems.

10. [https://hackerone.com/reports/207042](https://hackerone.com/reports/207042) - The attacker abused insecure postMessage handling in a Marketo iframe on HackerOne’s site to inject a JSONP-based XSS.

11. [https://hackerone.com/reports/1398305](https://hackerone.com/reports/1398305) - The attacker bypassed GitLab’s HTML sanitization by abusing malformed \<pre> tags and the gl-emoji custom element to inject stored XSS in issue comments, affecting all users who viewed them.

12. [https://hackerone.com/reports/1481207](https://hackerone.com/reports/1481207) - A second stored XSS in GitLab's markdown handling let attackers inject a \<base> tag via unsanitized HTML, enabling CSP bypass and turning any user-facing page (like issues or wikis) into an XSS vector. *IMP*

13. [https://hackerone.com/reports/1962645](https://hackerone.com/reports/1962645) Reddit’s login page had an open redirect via the dest parameter that allowed XSS after login, letting attackers execute arbitrary JavaScript like alert(document.domain).

14. [https://hackerone.com/reports/724889](https://hackerone.com/reports/724889) A blind XSS was triggered in Zomato’s admin dashboard by injecting a script into the food order’s special instructions via the app’s API.

15. [https://hackerone.com/reports/131450](https://hackerone.com/reports/131450) A stored XSS in Uber’s developer documentation (powered by Readme.io) allowed attackers to inject malicious JavaScript into public docs via the “Suggest Edits” feature.

### AD 

Didn't do anything. The coming week I will go all in on AD.

## Conclusion (and goals for next week)
 
Well, I didn't even touch AD. So I will be exclusively doing AD next. Too burnt out from doing portswigger labs. See y'all next week, hopefully CPTS certified ;) 

Art I used - [https://www.deviantart.com/kareguya/art/Celestial-Symphony-1108857744](https://www.deviantart.com/kareguya/art/Celestial-Symphony-1108857744)