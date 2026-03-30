---
title: Walkthrough - JWT Attacks Portswigger labs
date: 2026-03-19 00:30:00 + 05:30
categories: [Web, BSCP]
tags: [bscp]
description: An intro to JWT Attacks vulnerabilities and walkthrough of all 8 portswigger labs
---

Completed all 8 JWT Attacks labs from Portswigger. JSON Web Tokens are the dominant mechanism for stateless session management in modern web applications—but their flexible specification has historically been a minefield. Unlike traditional server-side sessions where the server holds state and the client holds only an opaque identifier, JWTs embed the session data directly in the token and trust the client to present it unmodified. That trust model is exactly what these labs exploit. The labs covered unverified signatures, the `alg:none` attack, weak signing keys cracked with hashcat, JWK and JKU header injection attacks, `kid` path traversal to a null byte signing key, and two variants of algorithm confusion—one with an exposed public key and one where the key must be derived from two JWT samples. Below is a detailed explanation of JWT authentication vulnerabilities followed by step-by-step walkthroughs for each lab.

## Everything about JWT Attacks Vulnerabilities

##### 1. What is a JSON Web Token?

A JSON Web Token (JWT) is a compact, URL-safe token format used to transmit claims between parties. It consists of three Base64URL-encoded parts separated by dots:
```
<header>.<payload>.<signature>
```

Example Header:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Example Payload:
```json
{
  "iss": "portswigger",
  "exp": 1773753850,
  "sub": "wiener"
}
```

The signature is computed over `base64url(header) + "." + base64url(payload)` using the algorithm specified in the header and a secret key held by the server. The server verifies the signature on every request—if it's valid, the server trusts the claims in the payload.

##### 2. Why JWTs Are Vulnerable

The core problem is that the token tells the server how to verify itself. The header specifies the algorithm, the key identifier (`kid`), and optionally even the key itself (`jwk`, `jku`). If the server blindly trusts these header parameters, attackers can manipulate them to bypass verification entirely.

Common vulnerability classes:

- **No signature verification**: Server accepts any token without checking the signature
- **`alg: none` acceptance**: Server accepts tokens with the algorithm set to `none` and an empty signature
- **Weak signing keys**: HMAC keys short or common enough to brute-force with hashcat
- **JWK header injection**: Server uses an attacker-supplied public key embedded in the token header to verify the same token
- **JKU header injection**: Server fetches the verification key from an attacker-controlled URL specified in the token header
- **`kid` path traversal**: Server uses the `kid` parameter as a filesystem path to find the key, enabling path traversal to a predictable file
- **Algorithm confusion (RS256 → HS256)**: Server uses an asymmetric key pair but also accepts HMAC; attacker signs with the public key (which is public knowledge) treated as an HMAC secret

##### 3. The JWT Structure in Detail

**Header parameters relevant to attacks:**

| Parameter | Purpose | Attack Surface |
|---|---|---|
| `alg` | Signing algorithm | Set to `none` to strip signature; set to `HS256` for algorithm confusion |
| `kid` | Key identifier | Path traversal to control which key is used |
| `jwk` | Embedded public key | Inject attacker's own public key for verification |
| `jku` | URL to fetch key set | Point to attacker-controlled server hosting malicious JWK set |

**Payload claims relevant to attacks:**

| Claim | Purpose | Attack Goal |
|---|---|---|
| `sub` | Subject (user identity) | Change to `administrator` |
| `iss` | Issuer | Rarely targeted |
| `exp` | Expiration timestamp | Extend to prevent expiry |

##### 4. The `alg: none` Attack

The JWT specification defines `none` as a valid algorithm meaning "no digital signature or MAC." Some libraries, designed to be spec-compliant, accept tokens with `alg: none` and an empty signature. The attack:

1. Take a valid JWT
2. Decode the header, change `"alg": "HS256"` to `"alg": "none"`
3. Decode the payload, change `"sub": "wiener"` to `"sub": "administrator"`
4. Re-encode both parts as Base64URL
5. Construct the token as `<modified_header>.<modified_payload>.` (note the trailing dot with empty signature)

##### 5. Brute-Forcing Weak HMAC Keys

When `alg` is `HS256`, `HS384`, or `HS512`, the signing key is a symmetric secret. If that secret is weak or from a common wordlist, hashcat can crack it offline:
```bash
hashcat -a 0 -m 16500 <jwt_token> jwt.secrets.list
```

Hashcat mode `16500` is specifically for JWT tokens. Once the secret is recovered, you can re-sign any modified token with the correct signature, making it indistinguishable from a legitimate one.

##### 6. JWK Header Injection

The `jwk` (JSON Web Key) header parameter was designed to let servers include their public key in the token for verification purposes. The vulnerability arises when servers use whatever key is embedded in the token header to verify that same token—a circular trust problem. Attack flow:

1. Generate a new RSA key pair (attacker-controlled)
2. Modify the payload (`sub` → `administrator`)
3. Add a `jwk` parameter to the header containing the attacker's public key
4. Sign the token with the attacker's private key
5. Server reads the `jwk` from the header, uses it to verify the signature—which passes because you signed it with the matching private key

##### 7. JKU Header Injection

The `jku` (JSON Web Key Set URL) parameter tells the server where to fetch the public key set for verification. If the server fetches from any URL without restriction:

1. Generate a new RSA key pair
2. Host a JWK set containing your public key on an attacker-controlled server (e.g., the exploit server)
3. Add a `jku` parameter in the token header pointing to your hosted JWK set
4. Set the `kid` to match the key ID in your JWK set
5. Sign the token with your private key
6. Server fetches your JWK set, finds the matching `kid`, and verifies the signature—which passes

##### 8. `kid` Path Traversal

The `kid` parameter is meant to identify which key the server should use from its key store. If the server uses `kid` as a file path without sanitization:
```
../../../dev/null
```

`/dev/null` on Linux is an empty file, which when read produces a null byte. By generating a symmetric key whose secret is also a null byte (Base64: `AA==`) and signing the token with it, the server will verify successfully because both sides reduce to the same zero-length secret.

##### 9. Algorithm Confusion (RS256 → HS256)

This is the most subtle attack. When a server uses RSA (`RS256`), it:
- Signs with the **private key** (secret)
- Verifies with the **public key** (publicly available)

If the server also accepts `HS256` (HMAC), and reuses the same RSA public key as the HMAC secret (a common implementation pattern), an attacker who knows the public key can:

1. Fetch the public key from `/jwks.json` or the server response headers
2. Change `alg` in the header to `HS256`
3. Sign the modified token using the RSA public key as the HMAC secret
4. Server verifies with `HS256` using its stored "key"—which is the same public key—and the signature passes

The public key is not secret. That is the entire point of asymmetric cryptography. But when it's used as an HMAC secret, knowing it is enough to forge tokens.

When the public key isn't directly exposed, it can be derived mathematically from two JWT tokens signed with the same private key using tools like `rsa_sign2n`.

## Labs

### 1.  JWT authentication bypass via unverified signature

Description:

The lab uses jwt tokens with unverified signature for session management which we must exploit to access the admin panel and delete the user `carlos`.

![](/assets/images/JWT/Pasted%20image%2020260317173119.png)

Explanation:

We login with the given credentials and see the cookie uses jwt tokens. We will send this to repeater.

![](/assets/images/JWT/Pasted%20image%2020260317173331.png)

We see the payload part says `"sub":"wiener"`. We will send the decoded json object to decoder.

![](/assets/images/JWT/Pasted%20image%2020260317173426.png)

We will change `"sub":"wiener"` to `"sub":"administrator"`. 

![](/assets/images/JWT/Pasted%20image%2020260317173519.png)

We will replace the payload of the cookie with the modified base64 encoded payload. Reloading the page will show us the admin panel being visible.

![](/assets/images/JWT/Pasted%20image%2020260317173654.png)

We can see that the admin panel is accessible.

![](/assets/images/JWT/Pasted%20image%2020260317173708.png)

Deleting the user `carlos` solves the lab.

![](/assets/images/JWT/Pasted%20image%2020260317173720.png)

### 2. JWT authentication bypass via flawed signature verification

Description:

The lab uses jwt tokens with unsigned jwts for session management which we must exploit to access the admin panel and delete the user `carlos`.

![](/assets/images/JWT/Pasted%20image%2020260317173848.png)

Explanation:

We will login with the given credentials and send the parts of the jwt token to the decoder. First we will send the header and change the `alg` to `none`. We will save this base64 encoded header.

![](/assets/images/JWT/Pasted%20image%2020260317174540.png)

Next we will send payload part to decoder and change `sub` to `administrator` and save this base64 encoded payload. 

![](/assets/images/JWT/Pasted%20image%2020260317174038.png)

We will paste in the modified cookie in the browser as `<base64 modified header>.<base64 modified payload>.`. Reloading the page will show us the admin panel.

![](/assets/images/JWT/Pasted%20image%2020260317174611.png)

Deleting the user `carlos` solves the lab.

![](/assets/images/JWT/Pasted%20image%2020260317174629.png)

### 3. JWT authentication bypass via weak signing key

Description:

We need to brute force the jwt token's signing key and sign a modified token. Then we need to access the admin panel and delete the user carlos.

![](/assets/images/JWT/Pasted%20image%2020260317175354.png)

Explanation:

We will first have to install the JWT Editor extension. We will login with the given credentials and see the jwt token in the session cookie.

![](/assets/images/JWT/Pasted%20image%2020260317175517.png)

We will copy paste the jwt token and download the wordlist from the link in portswigger. Then we will crack it using hashcat.

```
.\hashcat.exe -a 0 -m 16500 eyJraWQiOiJkYTMzZGNjMS0xYWZiLTRlZmEtODQwNy0yZWNmZDA3OGZlODkiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTc3Mzc1Mzg1MCwic3ViIjoid2llbmVyIn0.zANgx8DZUyz7opYzDGHHHex3zHKrEMuZFMb5H8sJFeA .\jwt.secrets.list
```

We can see that it is brute forced and `secret1`.

![](/assets/images/JWT/Pasted%20image%2020260317175649.png)

Now we will base64 encode the string.

![](/assets/images/JWT/Pasted%20image%2020260317180251.png)

Then we will go to the JWT Editor tab and generate a new symmetric key. We will change the value of `k` to base64 encoded payload and click OK. 

![](/assets/images/JWT/Pasted%20image%2020260317180328.png)

Now we will change `sub` from `wiener` to `administrator`. 

![](/assets/images/JWT/Pasted%20image%2020260317180452.png)

We can also use the the JSON Web Token tab within repeater. We have the sign button in the bottom.

![](/assets/images/JWT/Pasted%20image%2020260317180730.png)

We will chose the generated key as the signing key, make sure the header is not modified. Click OK to sign the token.

![](/assets/images/JWT/Pasted%20image%2020260317180747.png)

We can now access the admin panel.

![](/assets/images/JWT/Pasted%20image%2020260317180808.png)

Deleting the user `carlos` will solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260317180913.png)

### 4. JWT authentication bypass via jwk header injection

Description:

The server supports jwk parameter. We need to do a jwk header injection attack to access the admin panel and delete the user `carlos` to solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260317181410.png)

Explanation:

We will login with the given credentials and send the request to homepage with the jwt token in cookie to repeater.

![](/assets/images/JWT/Pasted%20image%2020260317181514.png)

In the JWT Editor extension tab, we will generate a New RSA key in jwk format and save it.

![](/assets/images/JWT/Pasted%20image%2020260317182414.png)

We will go in the JSON Web Token tab for the request in repeater. We will change `sub` from `wiener` to `administrator`.

![](/assets/images/JWT/Pasted%20image%2020260317182515.png)

Next we need to click on Attack to do an Embedded JWK attack.

![](/assets/images/JWT/Pasted%20image%2020260317182530.png)

We will chose the RSA key we had generated and click OK.

![](/assets/images/JWT/Pasted%20image%2020260317182541.png)

We can now access the admin panel.

![](/assets/images/JWT/Pasted%20image%2020260317182623.png)

Deleting the user `carlos` will solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260317182657.png)

### 5. JWT authentication bypass via jku header injection

Description:

The server supports jku parameter. We need to do a jku header injection attack to access the admin panel and delete the user `carlos` to solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260317182737.png)

Explanation:

We will login with the given credentials and send the request with the jwt token in session cookie to the repeater.

![](/assets/images/JWT/Pasted%20image%2020260318175829.png)

In the JWT Editor extension tab, we will generate a New RSA key in jwk format and save it. We will copy the keys.

![](/assets/images/JWT/Pasted%20image%2020260318175738.png)

We will paste it in the exploit server as :

```
{
	"keys":[
	<pasted keys>
	]
}
```

We will change the file name from `/exploit` to `/jwks.json`.

![](/assets/images/JWT/Pasted%20image%2020260318175801.png)

Now we will change the payload's `sub` from `wiener` to `administrator` and add the `jku` parameter in the header with the link to the exploit server's URL and path to `jwks.json`. We will also change the `kid` to be the same as that of the keys in the exploit server.

![](/assets/images/JWT/Pasted%20image%2020260318181002.png)

Now we will sign the token with the key we had generated.

![](/assets/images/JWT/Pasted%20image%2020260318181011.png)

We can now access the admin panel.

![](/assets/images/JWT/Pasted%20image%2020260318181053.png)

Deleting the user `carlos` will solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260318181134.png)

### 6. JWT authentication bypass via kid header path traversal

Description:

The lab uses `kid` parameter to fetch the key from it's filesystem. We need to manipulate it to fetch nothing and access the admin panel and delete the user `carlos` to solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260318184125.png)

Explanation:

We will login with the given credentials and send the request with the jwt token in the session cookie to repeater.

![](/assets/images/JWT/Pasted%20image%2020260318184324.png)

The base64 encoding of a null byte is `AA==`. This will be useful in signing the token later.

![](/assets/images/JWT/Pasted%20image%2020260318184545.png)


We will generate a symmetric session key in the JWT editor extension's tab and paste in this base64 encoded null byte in place of `k`.

![](/assets/images/JWT/Pasted%20image%2020260318184852.png)

Now we will change the `sub` in the payload to `administrator` and `kid` in the header to `../../../dev/null`. Then we will sign it with the key we generated.

![](/assets/images/JWT/Pasted%20image%2020260318184935.png)

We can access the admin panel.

![](/assets/images/JWT/Pasted%20image%2020260318184955.png)

Deleting the user `carlos` will solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260318185022.png)

### 7. JWT authentication bypass via algorithm confusion

Description:

We need to exploit algorithm confusion to access the admin panel and delete the user `carlos` to solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260319013824.png)

Explanation:

We will login with the given credentials and send this request with the jwt token in session cookie to repeater.

![](/assets/images/JWT/Pasted%20image%2020260319022518.png)

We will now visit `/jwks.json`. We can see the public keys hosted on the server. 

![](/assets/images/JWT/Pasted%20image%2020260319022419.png)

We will now generate a new RSA key where will copy paste the keys we found from `/jwks.json`.

![](/assets/images/JWT/Pasted%20image%2020260319022759.png)

Now we will copy public key as PEM.

![](/assets/images/JWT/Pasted%20image%2020260319022826.png)

We will paste it in the decoder and base64 encode it.

![](/assets/images/JWT/Pasted%20image%2020260319022907.png)

Now we will generate a symmetric key where we will paste in the base64 encoded public PEM key in `k` and click OK.

![](/assets/images/JWT/Pasted%20image%2020260319022940.png)

Now we will change the `alg` to `HS256` in Header part and `sub` to `administrator` in the payload part and we will sign it with the symmetric key we had generated. When we send a request to `/admin` with the new token, we will be able to access the admin panel.

![](/assets/images/JWT/Pasted%20image%2020260319023100.png)

Deleting the user `carlos` will solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260319023134.png)

### 8. JWT authentication bypass via algorithm confusion with no exposed key

Description:

We need to exploit algorithm confusion to access the admin panel and delete the user `carlos` to solve the lab, but this time we don't have an exposed key.

![](/assets/images/JWT/Pasted%20image%2020260319023402.png)

We will login with given credentials and save the jwt token.

![](/assets/images/JWT/Pasted%20image%2020260319162216.png)

We will logout and login again to get a new jwt token and we will save this new token as well.

![](/assets/images/JWT/Pasted%20image%2020260319162245.png)

We will now run this script with the two jwt tokens and we get the values for base64 encoded x509 key, tampered jwt for it and a base64 encoded pkcs1 key and its tampered jwt.

![](/assets/images/JWT/Pasted%20image%2020260319165203.png)

Now we will paste the tampered jwt for the x509 key and we get a 200 OK.

![](/assets/images/JWT/Pasted%20image%2020260319165219.png)

Now we will generate a symmetric key where we will paste the value of the base64 encoded x509 key in place of `k`.

![](/assets/images/JWT/Pasted%20image%2020260319165605.png)

Now we will make sure that the `alg` is `HS256` in the header part and `sub` as `administrator` in the payload part and sign it with the newly generated symmetric key. We will now be able to access the admin panel. 

![](/assets/images/JWT/Pasted%20image%2020260319165805.png)

Deleting the user `carlos` will solve the lab.

![](/assets/images/JWT/Pasted%20image%2020260319165840.png)

## Conclusion

These 8 labs demonstrated the breadth of JWT authentication vulnerabilities—from trivially skipping signature verification to the mathematically subtle algorithm confusion attack. Key takeaways include:

- Signature Verification Must Always Happen: Accepting tokens without verifying the signature (Lab 1) is a complete authentication bypass—the entire security model of JWTs collapses without this check
- `alg: none` Should Never Be Accepted: The spec's allowance of `none` as a valid algorithm is a design flaw; any library or server that accepts it in production is broken by design
- Symmetric Keys Must Be Strong: An HMAC signing key short enough to appear in a wordlist is equivalent to no key at all—hashcat can crack `secret1` in seconds offline against captured tokens
- Header Parameters Are Attacker-Controlled: The `jwk`, `jku`, and `kid` parameters all originate from the token itself, which the attacker controls entirely. Trusting them without restriction hands over the verification process to the attacker
- JKU and JWK Require Strict Allowlisting: Servers must validate that `jku` URLs belong to a trusted domain and must never use keys embedded in `jwk` headers to verify the same token
- Path Traversal in `kid` Has Unique Primitives: Traversing to `/dev/null` as the signing key is an elegant attack—null bytes are predictable and consistent across Linux systems, making it a reliable target
- Algorithm Confusion Is a Trust Model Failure: Accepting both RS256 and HS256 and reusing the same key material for both breaks the asymmetric trust model entirely. The public key is public—using it as an HMAC secret is equivalent to publishing your password
- Key Derivation from Token Pairs Is Powerful: Even without an exposed public key, capturing two tokens from the same signing key is enough to derive it mathematically, removing the last barrier to algorithm confusion attacks

The progression across these labs followed a natural escalation. Labs 1 and 2 required no cryptographic knowledge—just modifying Base64-encoded JSON. Lab 3 introduced offline cracking. Labs 4 and 5 exploited the server's willingness to outsource key trust to the token itself. Lab 6 was a creative abuse of Linux filesystem semantics. Labs 7 and 8 required understanding asymmetric cryptography well enough to exploit the boundary between RS256 and HS256.

The algorithm confusion labs (7 and 8) were the most instructive. They revealed that the vulnerability isn't in the JWT standard itself but in how implementations handle multiple algorithms. A server that accepts only RS256 and never HS256 cannot be confused this way. The attack requires the server to support both, and to reuse the same key material across them—a combination that emerges from trying to be flexible without thinking through the security implications. Lab 8 added the additional step of deriving the public key from scratch, which is a realistic scenario since many servers don't expose `/jwks.json` publicly but still use predictable RSA key pairs across sessions.

JWTs themselves are not inherently insecure—the standard is fine when implemented correctly. The vulnerabilities in these labs all stem from deviating from the spec (accepting `alg: none`), trusting attacker-controlled inputs without validation (`jwk`, `jku`, `kid`), using weak secrets, or conflating asymmetric and symmetric algorithm contexts. The defenses are equally clear: always verify signatures, pin the expected algorithm server-side, allowlist key sources, use strong randomly-generated secrets, and treat every header parameter as untrusted input.


