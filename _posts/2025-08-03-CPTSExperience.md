---
title: My CPTS experience - tips and tricks 
date: 2025-07-29 18:00:00 +05:30
categories: [CPTS]
tags: [cpts]    # TAG names should always be lowercase
description: My journey from beginner to passing HTB's CPTS certification, with practical exam tips and lessons learned.
---

# HTB CPTS - My experience, tips and tricks

I recently passed the CPTS by HackTheBox. I got at least 50–100 DMs asking for tips, so in this blog I’ll share my experience and some practical advice that helped me pass. Some of these are my own, and some I learned from people or friends online. A lot of the DMs came from complete beginners, so I’ll start by sharing my journey from 0 to CPTS.

![](/assets/images/CPTS/cover.png)

Here’s the structure I’m going to follow (based on the questions I received). Feel free to jump to whatever part you’re interested in. It’s structured this way so I don’t waste your time:

- 1. My journey: 0 to CPTS (Skip this if you're just here for exam tips)
- 2. Tips I received from friends and people online - and how accurate they really are (important)
- 3. Additional learning materials I used (spoiler: not many) and preparation tips
- 4. Issues I faced while preparing and during the exam (again, important)

---

### 1. My journey: 0 to CPTS

At the time of writing this, I’m in the 7th semester of my Bachelor's in Computer Engineering. I started with some basic TryHackMe paths, up to the Jr. Pentester path (couldn’t finish Red Teaming) in my 4th Semester. After this, I was advised to jump straight into HackTheBox.

We’ve all heard that OSCP is the gold standard, but I watched [this video](https://www.youtube.com/watch?v=-5s2R0Mldgw) by Pink Draconian, who claimed you learn a lot more in CPTS, with better study material and much cheaper pricing. So I started the Pentester Job Role path on HTB around February 2024 and did it for 3–4 months before exams interrupted me.

I had completed 40% of the path by then. When I resumed, I realized all my notes were in a physical notebook (don’t judge, we all start somewhere). I switched to Obsidian and made module-wise notes. But I made the mistake of just copy-pasting everything, including screenshots from skills assessments. While helpful, they didn’t cover the core concepts.

I especially struggled with AD and some web attacks. A friend with a gold sub shared walkthroughs, which I speedran till Windows PrivEsc. My sub was expiring, and I wanted to move to boxes. I skipped the last 2 modules since I heard AEN was a better lab for exam practice.

Then I did boxes for around 3 months and I was stuck almost every time. Speedrunning the modules didn’t help. I must have done 60–80 retired boxes, but always with writeups. I understood the content but couldn’t do it alone. That’s when I realized I needed a methodology.

I bought a prolab voucher and completed Dante. Also did 7 flags on Zephyr. Dante was eye-opening. I actually hacked on my own (with help on Discord). Multiple pivots and port forwards using `ligolo-ng` made me feel like I was learning something real.

Feeling confident, I tried more boxes and tackled `chemistry` (payload didn’t work despite the right CVE) and `LinkVortex` (stuck at foothold, needed help again). I knew the attack paths but still struggled with execution.

By early 2025, I knew I had to get serious. I didn’t have a solid methodology. That’s when I found [these blogs](https://www.brunorochamoura.com/tags/cpts-%EF%B8%8F/) by BRM. He had a field manual template that I decided to replicate. I reached out to him on LinkedIn. He was incredibly kind and answered all my queries.

He also did a live presentation on the HackSmarter Discord and talked about creating checklists for when you get stuck. I reached out again, and he generously shared a few examples with me.

BRM recommended the `Using CrackMapExec` module. Since I didn't have enough cubes, I played HTB Season 7 for rewards. I barely knew what I was doing. My friends helped a lot. But I did learn hands-on AD, `bloodyAD`, Kerberos clock skew, and more. I solved all the Season 7 machines (with help), got the cubes, and unlocked the module.

When summer break started, I went all-in on making my field manual. I posted a daily log on [X (formerly Twitter)](https://x.com/Yassh_twts) (shameless plug, follow me).

This took 41 days where I re-did everything from scratch, made notes, and completed the skills assessments myself. I still got stuck, but now I understood the why. Then I tackled AEN on my own. Again, I struggled, but did most of it solo. As soon as I finished, I purchased the exam voucher and started my attempt. The rest is history.

---

### 2. Tips I received from friends and people online - how accurate are they?

Let’s break it down:

**1. “You don’t need to do boxes. They’re different from the exam.”**  
✅ True, if you have a solid methodology. Dante will teach you more as a beginner than any box. Boxes crushed my confidence. Skip them if you’ve already got fundamentals.

**2. “Do the CrackMapExec/API attacks modules.”**  
❌ Not needed post-update (2025). Instead, read CME’s docs and the `spider` module if you must. The CME skills assessment made me doubt myself a day before the exam.

**3. “Leave plenty of time for reporting.”**  
✅ 100% true. My report took 2–3 days. I was burnt out and made several mistakes including missed redactions, typos, and my name not rendering in 4 places. But I passed. The report was 195 pages.

**4. “Build solid notes.”**  
✅ True. I was bad at note-taking, but my field manual saved time and kept me away from Googling or using ChatGPT during the exam.

**5. “Enumeration is everything.”**  
✅ Absolutely true. The exam isn’t hard, it’s about finding the right things. Flag 5 was supposedly hard, but I found it easy because I knew the modules. Manual enumeration using PowerView or fuzzing is key.

**6. “AEN is the closest thing to the exam, but forget it when the exam starts.”**  
✅ Half true. The exam is harder. Do AEN blind, but if stuck for more than 1–2 hours, use the walkthrough.

---

### 3. Additional learning materials and preparation tips

I didn’t use much extra material. Here’s what helped:

1. **Enumeration is everything** (already covered above).
2. **Treat AEN like a real exam**. Use the same tools you’ll use during the real exam (e.g., `ligolo-ng`).
3. **Practice pivoting and double tunneling**. It’s easy to mess up. I highly recommend [this Ligolo-ng post](https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5).
4. **Main tools:**
   - `ligolo-ng` for tunneling
   - `bloodyAD` for AD
5. **Stay calm**. If stuck, try a different approach. Change the tool, wordlist, or method. Knowing the modules well makes a big difference.
6. **Practice report writing**. I used SysReptor for reporting. It’s a very easy-to-use tool and I had some experience with Markdown, but it can be overwhelming for first-time users. I just winged it on the exam. I would not recommend this to anyone.

---

### 4. Issues I faced during prep and the exam

1. **Exam lab being finicky**  
   Things didn’t load properly.  
   **Fix**: Contacted support. They told me to change my VPN. That fixed it.

2. **Ligolo-ng not working**  
   I faced [this issue](https://github.com/nicocha30/ligolo-ng/issues/125).  
   **Fix**: Build static binaries yourself. Here’s how:

```bash
sudo apt update
sudo apt install -y git golang-go build-essential mingw-w64
git clone https://github.com/nicocha30/ligolo-ng.git
cd ligolo-ng
````

Build static binaries:

```bash
CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o proxy cmd/proxy/main.go

CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 \
    go build -trimpath -ldflags "-s -w" -o agent cmd/agent/main.go

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    CC=x86_64-w64-mingw32-gcc \
    go build -trimpath -ldflags "-s -w" -o agent.exe cmd/agent/main.go
```

Use these in the exam. Precompiled binaries from GitHub releases didn’t work for me.

3. **Double pivot was unstable**
   No fix for this. I gave up after getting 12 flags.
