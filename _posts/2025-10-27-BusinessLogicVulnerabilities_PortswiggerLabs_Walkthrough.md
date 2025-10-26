---
title: Walkthrough - Business Logic Vulnerabilities Portswigger labs 
date: 2025-10-27 2:50:00 + 05:30
categories: [Web, BSCP]
tags: [auth, bscp]    ## TAG names should always be lowercase
description: An intro to Business Logic Vulnerabilities and walkthrough of all 12 portswigger labs
---

Completed all 12 business logic vulnerability labs from Portswigger. These are some of the most interesting vulnerabilities I've encountered—they don't rely on injecting payloads or exploiting technical flaws in code. Instead, they abuse the application's intended functionality in ways developers never anticipated. From integer overflows to encryption oracles, these labs showed how creative thinking can break even well-implemented systems. Below is a detailed explanation of business logic vulnerabilities followed by step-by-step walkthroughs for each lab.

## Everything about Business Logic Vulnerabilities

##### 1. What are Business Logic Vulnerabilities?

Business logic vulnerabilities are flaws in the design and implementation of an application that allow attackers to manipulate legitimate functionality for malicious purposes. Unlike technical vulnerabilities (SQLi, XSS), these arise from assumptions about how users will interact with the application—assumptions that attackers can violate.

##### 2. Why They're Dangerous

- Difficult to Detect: Automated scanners can't find them—they require understanding the application's purpose
- Hard to Prevent: Even perfectly written code can have logic flaws
- Context-Dependent: What's secure in one context may be exploitable in another
- Wide Impact: Can lead to financial loss, unauthorized access, data manipulation
- Often Overlooked: Developers focus on technical security, not workflow abuse

##### 3. Common Types of Business Logic Flaws

Trust in Client-Side Controls:
- Price manipulation in hidden form fields
- Quantity modification in POST parameters
- Role/privilege changes in cookies or headers

Inadequate Validation:
- Accepting negative quantities to reduce price
- No upper bounds on numerical inputs
- Accepting invalid state transitions

Flawed State Machines:
- Skipping mandatory steps in workflows
- Accessing endpoints out of sequence
- Dropping requests to bypass validation

Inconsistent Security Controls:
- Email validation differs between registration and update
- Different authorization checks on related endpoints
- Relaxed validation in edge cases

Integer Overflow/Underflow:
- Price calculations wrapping around to negative values
- Quantity limits that can be exceeded through overflow

Race Conditions:
- Concurrent requests exploiting timing windows
- Double-spending or duplicate redemptions

Discount/Coupon Logic Flaws:
- Stacking coupons that shouldn't combine
- Reusing single-use codes
- Applying discounts multiple times

##### 4. Real-World Examples

E-Commerce:
- Manipulating prices to buy items for less
- Using negative quantities to get refunds
- Integer overflow to wrap prices to negative
- Coupon abuse through stacking or reuse

Access Control:
- Bypassing role selection to gain admin access
- Email domain validation inconsistencies
- Parameter tampering to access other accounts

Authentication:
- Removing password validation parameters
- Exploiting encryption/decryption logic
- State machine bypass in multi-step auth

Financial Systems:
- Currency rounding errors accumulating over time
- Transaction replay attacks
- Balance manipulation through race conditions

##### 5. Detection Methodology

Understand the Application:
- Map out all workflows and business processes
- Identify assumptions about user behavior
- Document validation rules and constraints

Test Boundary Conditions:
- Maximum/minimum values
- Negative numbers where positive expected
- Zero or null values
- Very large numbers (overflow testing)

Workflow Manipulation:
- Skip steps in multi-step processes
- Access endpoints out of order
- Repeat steps that should execute once
- Drop requests to bypass validation

Parameter Tampering:
- Modify prices, quantities, user IDs
- Change roles, privileges, or account types
- Manipulate timestamps or expiration dates

State Machine Testing:
- Start processes from middle steps
- Jump between states improperly
- Use stale or invalid tokens

##### 6. Common Vulnerable Patterns

Trust Client-Side Data:
```javascript
// Vulnerable: Price sent from client
POST /cart/add
{
  "product": "laptop",
  "price": 999,  // Can be modified
  "quantity": 1
}
```

Inadequate Input Validation:
```javascript
// Vulnerable: No check for negative quantity
if (quantity) {
  total_price = price * quantity;  // -10 * $100 = -$1000
}
```

Missing Workflow Enforcement:
```javascript
// Vulnerable: Can directly access confirm without payment
/checkout/select-items → /checkout/payment → /checkout/confirm
// Attack: Skip to /checkout/confirm directly
```

Inconsistent Validation:
```javascript
// Registration: Must use @company.com
// Update Email: Any email accepted
// Admin Check: Checks for @company.com domain
```

##### 7. Exploitation Techniques

Integer Overflow:
- Add items until price wraps from positive to negative
- Exploit 32-bit or 64-bit integer limits
- Use negative prices to gain store credit

Coupon Stacking:
- Apply multiple discounts alternately
- Exploit lack of mutual exclusivity checks
- Automate with macros/scripts

Workflow Bypass:
- Drop or skip validation requests
- Access confirmation endpoints directly
- Manipulate session state

Encryption Oracle Abuse:
- Use error messages to decrypt data
- Manipulate encrypted values byte-by-byte
- Forge authentication tokens

Email Parsing Discrepancies:
- UTF-7 encoding bypass
- Comment injection in email addresses
- Quote handling differences

##### 8. Impact Assessment

Financial:
- Direct monetary loss through price manipulation
- Discount/coupon abuse at scale
- Refund fraud

Access Control:
- Unauthorized admin access
- Privilege escalation
- Account takeover

Data Integrity:
- Inventory manipulation
- Order fraud
- Balance tampering

Reputation:
- Customer trust erosion
- Regulatory violations
- Legal liability

##### 9. Mitigation Strategies

Server-Side Validation:
- Never trust client-supplied data
- Validate all inputs on the server
- Recalculate prices/totals server-side

State Machine Enforcement:
- Track workflow progress server-side
- Validate state transitions
- Prevent skipping mandatory steps

Comprehensive Testing:
- Manual security review of business logic
- Threat modeling for each workflow
- Edge case and boundary testing

Input Constraints:
- Set realistic upper and lower bounds
- Use appropriate data types (unsigned for quantities)
- Validate ranges for all numerical inputs

Atomicity & Consistency:
- Use database transactions
- Implement proper locking mechanisms
- Validate state before operations

Principle of Least Privilege:
- Default to most restrictive permissions
- Explicit grants rather than implicit
- Re-verify privileges at each step

Defense in Depth:
- Multiple validation layers
- Audit logging for unusual patterns
- Rate limiting on sensitive operations
- Alerting on anomalous behavior

##### 10. Real-World CVEs & Cases

- Steam Digital Gift Card Bug (2015): Negative quantity exploit for free credit
- Amazon Price Glitch (2014): Price manipulation through cache poisoning
- Various E-commerce Sites: Integer overflow in shopping carts
- Banking Apps: Race conditions in money transfers
- Ride-sharing Apps: Referral code abuse for unlimited credits

## Labs

### 1. Excessive trust in client-side controls

Description:

We are supposed to buy the `Lightweight l33t leather jacket` and as per the lab name, I think this has to do with bypassing client side validation.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023214346.png)

Explanation:

We head over to the `Lightweight l33t leather jacket` product and click on `add to cart`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023214553.png)

Examining the `POST` request in burp shows us that the request is sending the price as a parameter. Also the price seems to be in cents.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023214807.png)

Now we clear the cart, switch the `Intercept On` and intercept the request. Then change the price to 100 $ or 10,000 cents.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023214844.png)

We can see that the price of the item is now 100$ and it is added to our cart.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023215055.png)

Clicking on place order solves the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023215118.png)

### 2. High-level logic vulnerability

Description:

As per the lab description there is a problem in the logic.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023223235.png)

Explanation:

Looking at the `POST` request from when we click add to cart, we see that it is also passing the quantity of the order as a parameter. We can try to pass a negative value as a parameter.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023223523.png)

We see that the application accepted the negative value in quantity and that the price is also negative now.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023223827.png)

Simple, lets checkout and we should get 1337$ added to our store credit. Simple. Well, not really, the application is checking if the total price is negative or not.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023223839.png)

Lets add an item to make this number into a positive one, this item is just 11.43$.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023224033.png)

In the quantity I just changed it to 110.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023224119.png)

As we can see that the total price is now positive but still below 100$ which is our store credit.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023224144.png)

Clicking on Place order solves the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023224158.png)

### 3. Inconsistent security controls

Description:

To solve this lab, we need to delete the user Carlos' account. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024005314.png)

Explanation:

We first head over to this target > site map in burp and run the content discovery tool.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024005909.png)

We can see the /admin endpoint here.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010724.png)

We register a user called admin with our address from the email client.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010047.png)

We end up on the My account page after creating the account and logging in.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010123.png)

Heading over to the /admin endpoint shows that it is only accessible to the users with email domain DontWannaCry.com

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010425.png)

We head over to the my account page and in the update email box we put in the email as `admin@dontwannacry.com`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010447.png)

We can see that the email was updated successfully and admin panel is visible on the top right side.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010504.png)

We can now access the admin panel at the admin endpoint.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010521.png)

Deleting the user Carlos solves the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024010537.png)

### 4. Flawed enforcement of business rules

Description:

Same as before we need to purchase the `Lightweight l33t leather jacket`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024174607.png)

Explanation:

We can see a discount code `NEWCUST5` in the header.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024174653.png)

In the footer there is a sign up to our newletter form which we fill with a random email.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024174758.png)

A popup gives us a new code - `SIGNUP30`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024174810.png)

With these 2 codes, we add the `Lightweight l33t leather jacket` to our cart and apply the coupons. But we see that applying the same coupon as before, again, fails.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024174957.png)

However we can apply the coupons alternatively till we drive the price to zero. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024175205.png)

Clicking on Place Order solves the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024175221.png)

### 5. Low-level logic flaw

Description:

This is one of my favorite labs. There is an error in the input validation.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023224322.png)

Explanation:

Lets try to add a few `Lightweight l33t leather jacket` to the cart. When we try to add 100 products, it fails.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023231520.png)

But we are able to add 99 jackets. This means that 3 digit numbers can't be added.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023231540.png)

We will add this request to Intruder and at the end add a payload and generate null payloads.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023233549.png)

Change the resource pool to 1 request and not 10 concurrent requests.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023233605.png)

Sending over 170 requests will cause the total price to overflow. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023234244.png)

Total number of items - 19651110.96 / 1337 = 14697.913956619

Total number of requests - 14697.913956619 / 99 = 148.46377734

I tried to send more requests to make the number smaller but it ended up making the number positive again. So I had to send the requests again to loop it back to negative.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023235422.png)

Finally we are at about -64,000$ approx. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023235744.png)

Now we add a random item to cart and try to get the total back to a positive number that is below our store credit.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251023235840.png)

Now the negative number is below 64,000$.

Total number of items - 63970.04/90.92 = 703.586009679

Now I added a bunch of items, like about 700 and a couple more then to get to a positive number.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024000056.png)

Solving on place order will solve the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024000154.png)

### 6. Inconsistent handling of exceptional input

Description:

As per the lab description, there is a flaw in the account registration process that we must exploit.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024001527.png)

Explanation:

We use the content discovery tool first to enumerate endpoints.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024002958.png)

We get the /admin/ endpoint.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024004213.png)

First we register a regular account.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024002624.png)

As per the register page, we need to login with DontWannaCry domain.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024003817.png)

Going to the /admin/ endpoint shows us that we must login with DontWannaCry domain.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024004257.png)

We need to register an email id that is exceptionally long. Seems like, the email address is getting truncated.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024003558.png)

This email truncated to 255 characters. So the email address I send must be 255 characters long ending with the DontWannaCry domain and then we put in the exploit server email address.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024003636.png)

Added the exploit server email address and it becomes about 315 characters long.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024003721.png)

Logging in to this new account shows that we have successfully registered the account with DontWannaCry domain. This works as we can see the Admin Panel is accessible.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024003918.png)

We can see access the admin panel on the /admin/ endpoint. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024004329.png)

Deleting the user - carlos will solve the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024004341.png)

### 7. Weak isolation on dual-use endpoint

Description:

We are supposed to delete the user carlos by accessing administrator account.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024013804.png)

Explanation:

Logging in as the given user and trying to reset the password with an incorrect current password and it fails.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014054.png)

Examining the request shows that we are passing the username, current password, and 2 new passwords. This request will change the password.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014139.png)

First I reset the password back to `peter` for convenience.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014308.png)

Now lets send in an empty current-password parameter and it fails.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014424.png)

When we remove the current-password parameter, we able to reset the password.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014446.png)

Let's change the username to administrator and reset the administrator user's password to peter

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014509.png)

We are able to login to administrator's account and access the admin panel

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014544.png)

Deleting the user carlos will solve the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024014630.png)

### 8. Insufficient workflow validation

Description:

To solve this lab we must buy the `Lightweight l33t leather jacket`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024162912.png)

Explanation:

We first buy an item that we are able to purchase with our balance.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024163437.png)

Examining the workflow shows us this `GET` request that is heading to some endpoint that is validating that our order is getting confirmed. We will send this request to repeater.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024163453.png)

We will now add the `Lightweight l33t leather jacket` to our cart.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024163615.png)

I then sent the `GET` from repeater.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024163748.png)

This solved the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024163805.png)

### 9. Authentication bypass via flawed state machine

Description:

Again, access the admin panel and delete the user carlos.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171150.png)

Explanation:

Heading to the admin endpoint, we see that we must be logged in as administrator.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171232.png)

We next head to the page that is select-role. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171300.png)

I tried to change the role to administrator in the request via burp, but that does not work. Maybe this needs to be done via intercept.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171436.png)

Intercepting the same `POST` request and changing role to administrator does not work again.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171538.png)

I had to refer to the solution and I just skimmed through it. It said something about dropping a request (I didn't read properly which as I wanted to figure it out myself).

We can drop the `POST` request first. But this crashed the application.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171646.png)

There is a `GET` request that is being sent that I believe is fetching the role-selector page through which the `POST` request will be sent next. We will drop this `GET` request.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171824.png)

We can see that we have the Admin Panel access right now. It looks like the role reverts to administrator when a role is not sent via the role-requester.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171913.png)

We can access the admin panel by clicking on it.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024171952.png)

Deleting the user carlos will solve the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024172013.png)

### 10. Infinite money logic flaw

Description:

This lab is also a favorite one of mine. There is a bug here to get infinite money. We are supposed to buy the `Lightweight l33t leather jacket`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024175636.png)

Explanation:

We notice that we also have a product called `Gift Card` besides `Lightweight l33t leather jacket`. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180027.png)

In the footer, we have a Sign up to newsletter form. We fill this form.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024175834.png)

We end up getting a coupon code - `SIGNUP30`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180012.png)

In the My account section, we are able to redeem gift cards.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180048.png)

Lets buy 5 giftcards and apply the `SIGNUP30` coupon code. We will buy 10$ gift cards for 7$ profiting 3$.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180132.png)

We get 5 codes.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180157.png)

We redeem all these codes and see that we are able to now have 5 X 3 = 15 $ in profit. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180352.png)

We must automate this process with a macro. For that we will buy a single giftcard.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180609.png)

We will then redeem this giftcard.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180644.png)

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180628.png)

We will now go to session handling and add all URLs to scope.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024181918.png)

Next we will create a macro with the following 5 requests:

1. POST request to add giftcard to cart 
2. POST request to reduce its price with `SIGNUP30` coupon code.
3. POST request to finally checkout and buy it.
4. GET request to get the coupon code.
5. POST request to redeem the gift card.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024180904.png)

Now we need to define a custom parameter. We will select the coupon code from the 4th request.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024181229.png)

Now we click on the 5th request and configure the macro item. We add the custom parameter gift-card and we derive it from previous response, i.e. response 4.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024181414.png)

We can now test this macro and seems to work.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024181531.png)

Now we send the `GET` request that fetches our my-account page to Intruder and then we will add a payload and set it to null payloads, which will run 500 requests.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024181639.png)

We will set custom resource pool from 10 concurrent requests to 1.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024181656.png)

Running Intruder will show us that our store credit increased meaning its working. Now we need to wait.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024182017.png)


Just cross-checking and we are still seeing an increase.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024182046.png)


At around 405 requests, we see that we are beyond 1337$ in store credit which is beyond what we need for buying the `Lightweight l33t leather jacket`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024183644.png)


We will now add `Lightweight l33t leather jacket` to our cart.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024183722.png)

Clicking on Place order solves the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024183737.png)

### 11. Authentication bypass via encryption oracle

Description:

As per the lab description, we are able to access the encryption and decryption logic somehow.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024184241.png)

Explanation:

We will login with the given account and use the stay signed in option.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024184429.png)

We login and head to homepage.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024184449.png)

We will leave a comment on any single post.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024184519.png)

We will see that we get `invalid address: wiener` on our webpage.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024184405.png)

We will se that this `POST` request to comment endpoint that is returning a set-cookie header.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190236.png)

And this `GET` request to the postId=x shows us the response on the page.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190303.png)

I then sent the same request in repeater and got the set-cookie header.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190321.png)

Pasting the notification cookie and sending it is not reflecting any value in the notification-header tag. This is strange.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190338.png)

Also, when I sent the request, the notification cookie is getting removed and there is nothing being reflected back.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190401.png)

I tried to do this one last time and got the notification cookie.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190511.png)

Then I pasted it into the `GET` request.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190725.png)

After sending the request we can see that there is no reflection in the response body. Looks like the application is broken.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190752.png)

I then intercepted the request and pasted in the stay-logged-in cookie in the notification cookie's value in the `POST` request.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190906.png)

Then I intercepted the `GET` request and again pasted in the stay-logged-in cookie's value in place of notification cookie's value.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190924.png)

Forwarding the request shows us that we get the value `username:timestamp`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024190952.png)

I then reset the lab and redid the steps of sending the `POST` and `GET` requests to repeater. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024191014.png)

Pasting the stay-logged-in cookie's value and sending it via the `GET` request shows us the username:timestamp in response.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024192234.png)

We get the username wiener:timestamp.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024192251.png)

Now instead of email, we put in administrator:timestamp in place of email and get the new notification cookie.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024192347.png)

Now we get the response in the notification-header tag as `Invalid email address: administrator:timestamp`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024192456.png)

We can see that `Invalid email address: ` is 23 characters long.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024192513.png)

We will now send the cookie to decoder, URL Decode it, base64 decode it, delete the first 23 bytes then base64 encode and the URL encode it.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024195621.png)

Sending this updated cookie gave us a `500 internal server error` and it says that the input must be a multiple of 32.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024195605.png)


Now we know that we first removed 23 characters. 23+9 = 32. Therefore we can add 9 more characters to the `administrator:timestamp`. This will make it `123456789administrator:timestamp`.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024195843.png)

Now we will paste in the cookie value in decoder again. Then we will again URL decode > base64 decode > This time remove the first 32 bytes instead of 23 bytes > base64 encode > URL encode. 

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024200000.png)

Pasting in the cookie will show the response as `administrator:timestamp` and none of the invalid email or other characters in response.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024200036.png)

Now I reloaded the page, removed the notification and session cookie and pasted in the value we got before, the cookie that returned `administrator:timestamp` in place of `stay-logged-in` cookie.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024200132.png)

We can see that the admin panel button is avaliable on top right.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024200146.png)

We can access the /admin/ endpoint.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024200200.png)

Deleting the user carlos solves the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024200301.png)

### 12. Bypassing access controls using email address parsing discrepancies

Description:

Read this paper - [https://portswigger.net/research/splitting-the-email-atom](https://portswigger.net/research/splitting-the-email-atom) to understand how to solve this lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251024200354.png)

Explanation:

We open the lab and see an account registration option.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026020924.png)

`=?iso-8859-1?q?=61=62=63?=foo@ginandjuice.shop` We use this payload to test for q encoding. It fails.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026020910.png)

`=?utf-8?q?=61=62=63?=foo@ginandjuice.shop` We use this payload next to test for utf-8 encoding. It fails as well.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021019.png)

`=?utf-7?q?&AGEAYgBj-?=foo@ginandjuice.shop` We use this payload next to test for utf-7 encoding.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021042.png)

Here we are able to bypass the filter via utf-7 encoding.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021054.png)


We will use the following payload to register a new account.

`=?utf-7?q?attacker&AEA-[YOUR-EXPLOIT-SERVER_ID]&ACA-?=@ginandjuice.shop`

So for me it should look something like this - 

`=?utf-7?q?attacker&AEA-exploit-0adc00b0033162da80800291016100d9.exploit-server.net&ACA-?=@ginandjuice.shop`

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021420.png)

We are able to register the account successfully.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021434.png)

We get the verification mail on our server.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021513.png)

Verification is successful.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021527.png)

We will next login to the account.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021549.png)

We will see that the admin panel is available to us.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021601.png)

We will access the admin panel.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021621.png)

Deleting the user - carlos will solve the lab.

![](/assets/images/BusinessLogicVulns/Pasted%20image%2020251026021634.png)


## Conclusion

These 12 labs demonstrated that business logic vulnerabilities require a fundamentally different approach than technical vulnerabilities. Key takeaways include:

- Think Like a Developer (and Break It): Understanding the intended workflow is the first step to breaking it
- Client-Side Validation is Not Security: Prices, quantities, and privileges sent from the client can always be manipulated
- Integer Overflow Still Works: Despite being a classic issue, integer overflow in pricing calculations remains exploitable
- State Machines Can Be Fragile: Skipping or dropping requests can bypass entire validation flows
- Encryption Isn't Magic: Even encrypted data can be manipulated through error messages and oracle attacks
- Email Parsing is Complex: Different systems parse email addresses differently—UTF-7 encoding can bypass filters
- Automation Amplifies Impact: Macros and scripts turn single exploits into large-scale abuse

What made these labs particularly interesting was how they required understanding the application's purpose, not just its technical implementation. The infinite money lab with gift card automation was especially clever—turning a simple coupon bug into unlimited credit through Burp macros.

Business logic vulnerabilities remind us that security isn't just about preventing injection attacks or implementing encryption. It's about questioning every assumption: Can users send negative numbers? Can they skip steps? Can they apply the same coupon twice? These "what if?" questions are what separate secure applications from exploitable ones.

Moving forward, I'm applying this mindset to every application I test—not just looking for technical vulnerabilities, but asking "what could go wrong if a user does something unexpected?"