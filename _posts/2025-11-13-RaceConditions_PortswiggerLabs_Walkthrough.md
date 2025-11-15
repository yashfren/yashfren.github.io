---
title: Walkthrough - Race Condition Vulnerabilities Portswigger labs 
date: 2025-11-13 17:45:00 + 05:30
categories: [Web, BSCP]
tags: [bscp]
description: A comprehensive guide to race condition vulnerabilities with walkthroughs of all 6 Portswigger labs
---

Completed all 6 race condition vulnerability labs from Portswigger. Race conditions are timing-based vulnerabilities that occur when multiple operations execute simultaneously, creating windows where application state can be manipulated. These are particularly challenging to exploit because they require precise timing—sending requests in parallel to hit narrow time windows where validation hasn't completed yet. These labs covered limit overruns, rate limit bypasses, multi-endpoint races, single-endpoint races, time-sensitive exploits, and partial construction races. Below is a detailed explanation of race condition vulnerabilities followed by step-by-step walkthroughs for each lab.

## Everything about Race Conditions

##### 1. What are Race Conditions?

Race conditions occur when the outcome of a process depends on the timing or sequence of events, particularly when multiple threads or processes access shared resources without proper synchronization. In web applications, this typically manifests when:

- Multiple requests are processed simultaneously
- Validation checks haven't completed before subsequent operations
- State isn't properly locked during multi-step processes
- Time windows exist between check and use operations

The key characteristic is that the vulnerability only appears when operations happen in a specific timing sequence—making them difficult to reproduce and exploit reliably.

##### 2. Types of Race Conditions

Limit Overrun:
- Applying the same discount code multiple times simultaneously
- Exceeding resource limits (credits, tries, quotas)
- Bypassing "single-use" restrictions

Rate Limit Bypass:
- Sending multiple login attempts in parallel
- Bypassing throttling mechanisms
- Defeating lockout timers

Multi-Endpoint Races:
- Exploiting timing between different endpoints
- Adding items during checkout processing
- State changes across multiple requests

Single-Endpoint Races:
- Multiple requests to same endpoint with different data
- Email confirmation race conditions
- Update operations with insufficient locking

Time-Sensitive Operations:
- Token generation based on timestamp
- Predictable token generation in tight windows
- Session creation races

Partial Construction:
- Accessing objects before initialization completes
- Exploiting null/undefined states
- Validation bypass during object creation

##### 3. How Race Conditions Work

Classic Check-Then-Use Pattern:
```python
# Vulnerable code
if user.balance >= price:
    # Race window here - another request can execute
    user.balance -= price
    process_purchase()
```

What Happens:
1. Request 1: Check balance (OK)
2. Request 2: Check balance (OK) ← Both checks pass
3. Request 1: Deduct balance
4. Request 2: Deduct balance ← Balance goes negative

Proper Synchronization:
```python
# Secure code with locking
with transaction_lock:
    if user.balance >= price:
        user.balance -= price
        process_purchase()
```

##### 4. Common Vulnerable Patterns

Discount Code Application:
```
Normal flow:
1. Check if code used → No
2. Apply discount
3. Mark code as used

Race condition:
Request 1: Check code → Not used
Request 2: Check code → Not used (before step 3 of Request 1)
Request 1: Apply discount
Request 2: Apply discount ← Code applied twice
```

Rate Limiting:
```
Normal flow:
1. Check attempt count < limit
2. Process request
3. Increment counter

Race condition:
Multiple requests check counter simultaneously
All pass before any increments
Rate limit bypassed
```

Email Verification:
```
Normal flow:
1. Update email to new@example.com
2. Generate token
3. Send verification

Race condition:
Request 1: Change to email1
Request 2: Change to email2 (simultaneously)
Both generate tokens
Token from email1 verifies email2
```

##### 5. Exploitation Techniques

Single-Packet Attack (HTTP/2):
- Send all requests in single TCP packet
- Ensures simultaneous arrival
- Uses HTTP/2 multiplexing
- Highest success rate

Burp Suite Techniques:
```
1. Create request group
2. Use "Send group in parallel (single-packet attack)"
3. Ensure HTTP/2 is enabled
4. Use concurrentConnections=1
```

Turbo Intruder (Advanced):
```python
engine = RequestEngine(
    endpoint=target.endpoint,
    concurrentConnections=1,
    engine=Engine.BURP2  # HTTP/2 for single-packet
)

# Queue multiple requests
for i in range(20):
    engine.queue(target.req, payload, gate='race')

# Send all simultaneously
engine.openGate('race')
```

Timing Optimization:
- Minimize network latency
- Use fast connections
- Send from geographically close location
- Reduce request size for faster processing

##### 6. Detection Methods

Manual Testing Signs:
- Operations that should execute once
- Single-use tokens or codes
- Balance/credit systems
- Attempt counters
- Update operations

Testing Approach:
```
1. Identify state-changing operations
2. Send operation multiple times
3. Check if:
   - Limits exceeded
   - Codes reused
   - Multiple effects occurred
   - Validation bypassed
```

Automation:
- Burp Suite Repeater groups
- Turbo Intruder scripts
- Custom Python scripts with threading
- HTTP/2 multiplexing tools

##### 7. Real-World Scenarios

E-Commerce:
- Applying discount codes multiple times
- Purchasing items above balance
- Redeeming gift cards simultaneously
- Adding items during checkout

Authentication:
- Bypassing login attempt limits
- Brute-forcing passwords in parallel
- Token reuse vulnerabilities
- Session fixation races

Financial Systems:
- Double-spending attacks
- Balance manipulation
- Transaction duplication
- Withdrawal races

Registration Systems:
- Bypassing email verification
- Creating accounts without validation
- Username/email uniqueness bypass
- Referral code abuse

##### 8. Impact Assessment

Critical:
- Financial loss (balance manipulation)
- Authentication bypass
- Complete account takeover
- Privilege escalation

High:
- Rate limit bypass enabling brute force
- Resource exhaustion
- Unauthorized transactions
- Discount/coupon abuse at scale

Medium:
- Single-use code reuse
- Quota limit bypass
- Process workflow disruption

##### 9. Real-World Examples

Starbucks Race Condition (2015):
- Transfer money between gift cards
- Race condition in balance check
- Infinite money generation possible

Various E-Commerce Sites:
- Coupon codes applied multiple times
- Inventory going negative
- Purchase above credit limit

Banking Applications:
- ATM withdrawal races
- Double spending in mobile apps
- Concurrent transfer vulnerabilities

Bug Bounty Findings:
- Uber: Referral code race conditions
- Facebook: Like counter manipulation
- Various APIs: Rate limit bypasses

##### 10. Defense Mechanisms

Database-Level Solutions:
```sql
-- Use transactions with proper isolation
BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;
UPDATE accounts SET balance = balance - 100 WHERE id = 1;
COMMIT;

-- Use database locks
SELECT * FROM accounts WHERE id = 1 FOR UPDATE;
```

Application-Level Solutions:
```python
# Use pessimistic locking
with transaction.atomic():
    account = Account.objects.select_for_update().get(id=1)
    if account.balance >= price:
        account.balance -= price
        account.save()

# Use optimistic locking with version numbers
class Account(models.Model):
    balance = models.DecimalField()
    version = models.IntegerField(default=0)
    
    def withdraw(self, amount):
        old_version = self.version
        if self.balance >= amount:
            self.balance -= amount
            self.version += 1
            # This will fail if version changed
            affected = Account.objects.filter(
                id=self.id,
                version=old_version
            ).update(
                balance=self.balance,
                version=self.version
            )
            if affected == 0:
                raise ConcurrentModificationError()
```

State Management:
- Use atomic operations
- Implement proper locking
- Avoid check-then-use patterns
- Use database constraints

Rate Limiting Improvements:
```python
# Use atomic counters
redis_client.incr(f"attempts:{user_id}")
if redis_client.get(f"attempts:{user_id}") > MAX_ATTEMPTS:
    raise RateLimitError()

# Use distributed locks
with redis_lock.acquire(f"lock:{user_id}"):
    process_request()
```

Token Generation:
- Use cryptographically secure random
- Include user-specific data
- Add sufficient entropy
- Avoid timestamp-only generation

##### 11. Testing Methodology

Step-by-Step Approach:

1. Identify Candidates:
   - Balance/credit operations
   - Discount code application
   - Login attempt counters
   - Single-use tokens
   - State changes

2. Prepare Requests:
   - Capture legitimate request
   - Identify variable parameters
   - Set up Burp Repeater groups
   - Or prepare Turbo Intruder script

3. Execute Race:
   - Send 10-20 parallel requests
   - Use single-packet attack if possible
   - Monitor response differences
   - Check application state

4. Verify Impact:
   - Did limit get exceeded?
   - Was code applied multiple times?
   - Did balance go negative?
   - Was validation bypassed?

Common Pitfalls:
- Too few parallel requests
- Not using HTTP/2
- High network latency
- Insufficient timing precision
- Testing during high server load

##### 12. Advanced Exploitation

Multi-Stage Races:
```
Stage 1: Register user (race during creation)
Stage 2: Verify email (race with token)
Stage 3: Access resources (race with privilege check)
```

Partial Construction:
```
1. Object starts creation
2. Send request before initialization complete
3. Object in intermediate state
4. Validation doesn't exist yet
5. Exploit null/undefined values
```

Time-Based Prediction:
```
1. Identify token generation algorithm
2. Determine time-based component
3. Synchronize requests precisely
4. Predict and reuse tokens
```

Chaining with Other Vulns:
- Race condition + IDOR
- Race condition + CSRF
- Race condition + Business logic flaw

##### 13. Tools & Resources

Burp Suite Extensions:
- Turbo Intruder (essential for races)
- Race Condition Testing extensions
- HTTP/2 request editor

Custom Tools:
```python
# Python with asyncio
import asyncio
import aiohttp

async def send_request(session, url):
    async with session.post(url, data=payload) as resp:
        return await resp.text()

async def race_condition_test():
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, url) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        return results
```

Analysis:
- Response time comparison
- State verification queries
- Database query logs
- Application logs for race indicators

## Labs

### 1. Limit overrun race conditions

Description:

We are supposed to buy the `Lightweight L33t Leather Jacket`. This is similar to the business logic vulnerabilities labs.

![](/assets/images/RaceConditions/Pasted%20image%2020251113174501.png)

Explanation:

We are given an e-commerce app and our account has 50$ store credit. The `Lightweight L33t Leather Jacket` is 1337$ and we must use the `PROMO20` code to drive the price down during checkout.

![](/assets/images/RaceConditions/Pasted%20image%2020251113174643.png)

We can see that if we try to apply the coupon code again, it doesn't work. 

![](/assets/images/RaceConditions/Pasted%20image%2020251113174843.png)

We need to send the request that applies the coupon code to repeater. Create a tab group. Then duplicate this request about 20 times.

![](/assets/images/RaceConditions/Pasted%20image%2020251113175136.png)

We then need to send it via Send group in parallel (single-packet attack).

![](/assets/images/RaceConditions/Pasted%20image%2020251113175632.png)

This works but we are still over the store credit limit.

![](/assets/images/RaceConditions/Pasted%20image%2020251113175656.png)

At first I increased a request but it didn't work, instead it increased the price to around 200$ so I looked at the solution which said duplicate 19 instead of 20 requests.

![](/assets/images/RaceConditions/Pasted%20image%2020251113175845.png)

Sending this like before works.

![](/assets/images/RaceConditions/Pasted%20image%2020251113175911.png)

Clicking on place order solves the lab.

![](/assets/images/RaceConditions/Pasted%20image%2020251113175944.png)

I ended up asking grok about this and as per its explanation, out of 21 requests before, only 14 were hit, this most likely means that there was some sort of connection load for over 20 requests.
### 2. Bypassing rate limits via race conditions

Description:

We need to login as carlos, access the admin panel and delete the user carlos. We need to brute force the password via exploiting race conditions. Password list is given.

![](/assets/images/RaceConditions/Pasted%20image%2020251113181106.png)

Explanation:

We try to login as user wiener, but using the wrong password. Looks like we get a 60 second time out after 3 invalid attempts. I am assuming there is a race condition where if multiple passwords are sent in parallel we can find the valid one easily.

![](/assets/images/RaceConditions/Pasted%20image%2020251113181526.png)

I needed to use the Turbo Intruder extension for this. Since I don't know either Python or how to properly use the extension, I ended up copying the python template from the solution.

```python
def queueRequests(target, wordlists):

    # as the target supports HTTP/2, use engine=Engine.BURP2 and concurrentConnections=1 for a single-packet attack
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # assign the list of candidate passwords from your clipboard
    passwords = wordlists.clipboard
    
    # queue a login request using each password from the wordlist
    # the 'gate' argument withholds the final part of each request until engine.openGate() is invoked
    for password in passwords:
        engine.queue(target.req, password, gate='1')
    
    # once every request has been queued
    # invoke engine.openGate() to send all requests in the given gate simultaneously
    engine.openGate('1')


def handleResponse(req, interesting):
    table.add(req)
```

We need to send the login request with carlos and the wrong username to repeater, select the wrong password we had entered and click on send to turbo intruder. We then paste in the above python poc code.

After running the attack once, we can arrange the responses by words. 1995 means invalid username or password and 2006 is the timeout. As per the python code, the password wordlist was taken from my clipboard, so I pasted the entire wordlist on notepad and deleted every word from 1995 responses.

![](/assets/images/RaceConditions/Pasted%20image%2020251113183217.png)

Running it twice more gave a 302 response which means that we found the correct password.

![](/assets/images/RaceConditions/Pasted%20image%2020251113183801.png)

We are able to login with this password.

![](/assets/images/RaceConditions/Pasted%20image%2020251113184215.png)

Accessing the admin panel and deleting the user `carlos` solves the lab.

![](/assets/images/RaceConditions/Pasted%20image%2020251113184232.png)

### 3. Multi-endpoint race conditions

Description:

In this lab we again need to buy the `Lightweight L33t Leather Jacket` by exploiting the race condition.

![](/assets/images/RaceConditions/Pasted%20image%2020251113184432.png)

Explanation:

I was able to predict that there was a race condition in the checkout functionality when I read about the Multi-endpoint race conditions section while studying race conditions.

![](/assets/images/RaceConditions/Pasted%20image%2020251113191548.png)

We need to first purchase a gift card to understand how the checkout system works. When we place the order/check out, we can observe that it takes a couple seconds to process. (I didn't see the response time on burp).

![](/assets/images/RaceConditions/Pasted%20image%2020251113184714.png)

So as per this and the logic taught in the section, I am assuming that before the final checkout is processed, the system logic checks current balance and while its processing, we can add a new item to cart which will be purchased as well.

`productId=2` is the gift card, we send this request to repeater. We first need to send this request once to start solving the lab. This will add a gift card to our cart.

![](/assets/images/RaceConditions/Pasted%20image%2020251113190254.png)

`productId=1` is the `Lightweight L33t Leather Jacket`, we send this request to repeater as well but we add it to a group.

![](/assets/images/RaceConditions/Pasted%20image%2020251113190315.png)

This is the request for the checkout logic. We add this to the same group where we have the request that adds the `Lightweight L33t Leather Jacket` to our cart. After we know that the a gift card is added to our cart, we need to send the Group 1 requests in parallel.

![](/assets/images/RaceConditions/Pasted%20image%2020251113190330.png)

This solved the lab as while the checkout functionality was processing, the `Lightweight L33t Leather Jacket` was added to cart and purchased as well.

![](/assets/images/RaceConditions/Pasted%20image%2020251113190440.png)
### 4. Single-endpoint race conditions

Description:

We need to change our email to `carlos@ginandjuice.shop` to take over the account and for this we need to exploit the race condition.

![](/assets/images/RaceConditions/Pasted%20image%2020251113192334.png)

While reading about the topic, it says something about sending multiple requests to the same endpoint parallelly. This means there might be an issue in the change email functionality. 

![](/assets/images/RaceConditions/Pasted%20image%2020251113193620.png)

Lets try to change email to our current email (no change) to see how the functionality works.

![](/assets/images/RaceConditions/Pasted%20image%2020251113193659.png)

Clicking on the link works and confirms our email update.

![](/assets/images/RaceConditions/Pasted%20image%2020251113193716.png)

Now lets send this request to the repeater twice, group these requests and change the email id from wiener to wiener1 in one request and wiener2 in second request.

![](/assets/images/RaceConditions/Pasted%20image%2020251113193838.png)

We then send this as a group parallelly.

![](/assets/images/RaceConditions/Pasted%20image%2020251113193902.png)

We get a message that says we need to confirm change email to wiener2's email id.

![](/assets/images/RaceConditions/Pasted%20image%2020251113193926.png)

Let's try to see if we are able to verify our email for wiener2 email id by clicking on the verification link for wiener1.

![](/assets/images/RaceConditions/Pasted%20image%2020251113193944.png)

As we can see, we are able to change the email to wiener2 using the link from wiener1. This confirms the race condition.

![](/assets/images/RaceConditions/Pasted%20image%2020251113194001.png)

Now we can change wiener1 to the given email - `carlos@ginandjuice.shop` and resend the request parallelly. This should be done until we get the message to verify `carlos@ginandjuice.shop` as our email.

![](/assets/images/RaceConditions/Pasted%20image%2020251113194031.png)

In case we don't get the below message, just resend the requests in parallel till we do.

![](/assets/images/RaceConditions/Pasted%20image%2020251113194103.png)

Now we need to click on the verification link received by wiener2.

![](/assets/images/RaceConditions/Pasted%20image%2020251113194130.png)

This changes our email id to `carlos@ginandjuice.shop` and we are able to access the admin panel now.

![](/assets/images/RaceConditions/Pasted%20image%2020251113194214.png)

Deleting the user carlos will solve the lab.

![](/assets/images/RaceConditions/Pasted%20image%2020251113194231.png)
### 5. Exploiting time-sensitive vulnerabilities

Description:

There is a vulnerability in the method of password reset token generation that we must exploit to log in as carlos and delete the itself.

![](/assets/images/RaceConditions/Pasted%20image%2020251113201024.png)

Explanation:

First let us try to understand how the password reset functionality works. I tried to reset user wiener's password.

![](/assets/images/RaceConditions/Pasted%20image%2020251113222538.png)

We get this password reset URL that has a user and token parameter.

![](/assets/images/RaceConditions/Pasted%20image%2020251113222601.png)

We go to this URL and reset the password. Now we will send each of these requests to repeater.

![](/assets/images/RaceConditions/Pasted%20image%2020251113222622.png)

We have the GET request for the forgot password page.

![](/assets/images/RaceConditions/Pasted%20image%2020251113222517.png)

We have the POST request that will be sent via this page.

![](/assets/images/RaceConditions/Pasted%20image%2020251113222647.png)

This is the request that resets the password.

![](/assets/images/RaceConditions/Pasted%20image%2020251113222804.png)

First we need to remove the `phpsessionid` cookie and resend the GET request to the /forgot-password endpoint. We get a `phpsessionid` cookie via the `Set-Cookie` HTTP Header.

![](/assets/images/RaceConditions/Pasted%20image%2020251113223001.png)

Now we add the POST request to the /forgot-password endpoint to a group and we replicate this request. In the duplicate request, we will change the `phpsessionid` cookie and the csrf token that we got when we sent the GET request to the /forgot-password endpoint before. Then we send these in parallel.

![](/assets/images/RaceConditions/Pasted%20image%2020251113223015.png)

As we can see, we end up getting the same token. Let us assume that the token is generated using the `phpsessionid` cookie and has nothing to do with the username.

![](/assets/images/RaceConditions/Pasted%20image%2020251113223038.png)

![](/assets/images/RaceConditions/Pasted%20image%2020251113223112.png)

We will now get a fresh set of `phpsessionid` cookie and csrf tokens for both our requests and change the username in one request to carlos.

![](/assets/images/RaceConditions/Pasted%20image%2020251113223255.png)

We will then copy paste the `phpsessionid` cookie and the csrf token from this request to the POST request to the request that is responsible for resetting our password. We will then get the token parameter from the mail that wiener gets in its mailbox. We get a 302 found when we send it meaning the password was reset. 

![](/assets/images/RaceConditions/Pasted%20image%2020251113224610.png)

We login as user carlos and access the admin panel.

![](/assets/images/RaceConditions/Pasted%20image%2020251113224653.png)

Deleting user carlos solves the lab.

![](/assets/images/RaceConditions/Pasted%20image%2020251113224713.png)
### 6. Partial construction race conditions

Description:

We need to bypass the email validation using partial construction race conditions.

![](/assets/images/RaceConditions/Pasted%20image%2020251113224857.png)

Explanation:

We first try to register with the email of the email server we are given, it tells us that the email id is invalid meaning we can only register with an email from @ginandjuice.shop domain.

![](/assets/images/RaceConditions/Pasted%20image%2020251113225148.png)

When we try to register a user twice, we get that an account with this username already exists but we had reused the email. Therefore the mechanism is only checking for username repetition and not email.

![](/assets/images/RaceConditions/Pasted%20image%2020251113225257.png)

Going through the POST request for register, we can see that there is a javascript file being run which is - `/resources/static/users.js`. 

![](/assets/images/RaceConditions/Pasted%20image%2020251113225516.png)

We can head over to this endpoint and find the javascript code. We see that it is sending a post request to the /confirm endpoint.

![](/assets/images/RaceConditions/Pasted%20image%2020251113225613.png)

We can head over to the confirm endpoint, click on confirm and we will see missing `parameter: token`. We see the same request in repeater.

![](/assets/images/RaceConditions/Pasted%20image%2020251113231501.png)

I read the below theory on Partial construction race conditions which said that there may be a small window where the value of a corresponding object may not be initialized yet and we should be able to exploit it by passing a null value or empty value.

![](/assets/images/RaceConditions/Pasted%20image%2020251113231530.png)

We try to pass the token parameter and see that we get `Incorrect token: 1` as the response.

![](/assets/images/RaceConditions/Pasted%20image%2020251113231559.png)

We try to pass an empty array and get `Incorrect token: array` as the response meaning we were able to pass a null value to the server via an empty array.

![](/assets/images/RaceConditions/Pasted%20image%2020251113231623.png)

When we try to send no value with token parameter we get, 403 Forbidden. This means that the developers patched the method to send empty/null values but from the above example where we sent empty array value, we can see that the array method is not patched. 

![](/assets/images/RaceConditions/Pasted%20image%2020251113231649.png)

We will send the POST request to /register endpoint to Turbo Intruder and specifically the username parameter as it needs to be changed everytime. 

![](/assets/images/RaceConditions/Pasted%20image%2020251113231758.png)

We use this python code that will iterate through 20 users at a time and send the confirmation requests alongside each user hoping at least one hits during the race window.

```python
def queueRequests(target, wordlists):

    engine = RequestEngine(endpoint=target.endpoint,
                            concurrentConnections=1,
                            engine=Engine.BURP2
                            )
    
    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: 0a03001e03a8111f81d5e81400870097.web-security-academy.net
Cookie: phpsessionid=q3UhKhAaztk7U8a7pS7espnCH5qrkEqh
Content-Length: 0

'''
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'User' + currentAttempt
    
        # queue a single registration request
        engine.queue(target.req, username, gate=currentAttempt)
        
        # queue 50 confirmation requests - note that this will probably sent in two separate packets
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        
        # send all the queued requests for this attempt
        engine.openGate(currentAttempt)

def handleResponse(req, interesting):
    table.add(req)
```

We will fuzz for each username and send the confirm request with null array token in order to confirm a username.

![](/assets/images/RaceConditions/Pasted%20image%2020251113232017.png)

This took me multiple attempts but I finally got a response with length 2636 which says that `Account registration for user user1222111 is successful!`.  

![](/assets/images/RaceConditions/Pasted%20image%2020251113233201.png)

We login as user - user122111 and access the admin panel.

![](/assets/images/RaceConditions/Pasted%20image%2020251113233326.png)

Deleting the user will solve the lab.

![](/assets/images/RaceConditions/Pasted%20image%2020251113233412.png)

## Conclusion

These 6 labs demonstrated the complexity and variety of race condition vulnerabilities. Key takeaways include:

- Timing Is Everything: Success depends on precise synchronization of parallel requests
- HTTP/2 Single-Packet Attacks Work: Using Burp's single-packet attack feature significantly increases success rate
- Race Windows Are Narrow: Even small delays between check and use operations are exploitable
- Multi-Endpoint Races Are Real: Race conditions don't just occur on single endpoints—they happen across workflows
- Partial Construction Is Exploitable: Objects in intermediate states during creation can bypass validation
- Time-Sensitive Operations Are Vulnerable: Token generation based on timestamps creates predictable race windows
- Automation Is Essential: Manual timing rarely succeeds—tools like Turbo Intruder are necessary

What made these labs particularly challenging was the need to get timing exactly right. Unlike other vulnerabilities where you craft the perfect payload, race conditions require sending the right requests at precisely the right moment. The progression from simple limit overruns to complex partial construction races showed how race conditions manifest in different contexts.

The Turbo Intruder labs were especially educational. Writing Python scripts to automate request queuing and gate opening showed how attackers actually exploit these vulnerabilities at scale. The partial construction lab was mind-bending—exploiting the moment between object creation and validation by flooding the endpoint with confirmation requests hoping one hits the window.

Race conditions remain underexploited compared to other vulnerability classes, mainly because they require sophisticated tooling and precise timing. But they're increasingly relevant as applications become more concurrent and real-time. Modern web architectures with async processing, microservices, and distributed systems create more opportunities for race conditions.

The defense lesson is clear: never assume operations are atomic. Always use proper locking, transactions, and synchronization. Check-then-use patterns are inherently vulnerable—combine the check and use into a single atomic operation whenever possible.

Moving forward, I'm looking at every state-changing operation through the lens of "what if multiple requests hit this simultaneously?" Race conditions are a reminder that security isn't just about input validation and output encoding—it's also about managing concurrency correctly.