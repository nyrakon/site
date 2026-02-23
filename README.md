# site backend
The backend runs on the same site aka the frontend.


# USER REGISTRATION SYSTEM PROPOSAL (ACES):
Registration/Login Via Access Code + Extraterraneous security. (or ACES)

normally, registration is done painstakingly via email + password + 2fa... then verify email, etc.
this is so an attacker cannot access your data without password + 2fa.
But this kind of security is pointless if someone can just use the token and use it to do everything AS you.
Potentially Affected service(s):
- Discord
- Slack
- Instragram
- Azure/Microsoft
- Google
- Twitter(X)
- Steam
- Ebay
- Humble Bundle/Paypal

And also, this practically wastes the user's time if anyone can just login to your account via other methods which are also common like:
- cross-site attacks
- social engineering (any kind of customer support that can do administrative actions on your account or view info)
- malware (RATs, malicious extensions, etc.)

### About ACES
**Introducing** RLACES. Or ACES.
ACES is designed primarily for password-less login or simplicity, while offering advanced security over traditional login methods.
Where the only thing you need to keep track of is your account ID. No passwords. No MFA or physical hardware to secure your account traditionally.

### How does ACES offer advanced security?
**Event scenario legend:** A=user1, B=user2, C=system, D=access code(or user id), E=session token, F=recovery key
- Tight & strict rate limits.
    On any resource regarding session verification, there are rate limits in place that specifically is designed around ACES, so that an attacker would get rate limited quickly, while a normal user has leniency. And the rate limiting is strict.
- Different sets of information taken into context, makes session/cookie based attacks practically impossible.
    So, assume B had A's E. B cannot do anything as E because IP mismatch + likely metadata mismatch.

    Now, let's assume **a near worst case scenario** where B was in the home of A, and thus B has A's ip, but not the same device as A.
    B likely would fail the metadata check. 
    
    But in another near worst case scenario where B also spoofed metadata to be like A: B still cannot do anything until A logs out or A's E expires.

    Assume another bad scenario. A is logged out. B has A's ip + metadata. B can't login as A yet, because A setup questions to their account, and must answer.

    Assume **absolute worst case scenario.** B has A's ip + metadata, but doesn't need to login because B ALSO has A's E.
    This practically means B is A. But by that point, **A has MUCH worse things to worry about, because someone is physically within their current area of residency, ON their internet/network.**
    This is not the end necessarily. A still has their F, aka recovery key. A can use their F to recover their account, essentially wiping all sessions and thus B is no longer able to access anything about A's account. And since A logged in, B now has to gather A's new E to be able to impersonate A.

    Again, this kind of attack is out of scope. By this point, you need hardware-level authentication, which is overkill. ACES already defends the user against traditional remotely-located attackers. And you need physical security. **It doesn't really matter what kind of security we place by this point, as now, B is fully impersonating you, and server-side level verification about at its limits. This is also pretty much common with traditional login methods, if someone had your device you were logged into, or they fully had a RAT and was able to copy your session token + in the same network as you to not need to do MFA.**
- Physical file-based recovery.
    You need F to recover your account in case of an emergency. It replaces the recovery key for the person + removes all sessions.

    Let's assume an attacker acquired your recovery key + account id, and used it to try to access your account.
    Your account is now locked, and now a third party (customer service or someone of the sort) must assess the situation before unlocking the account.
    Your account is safe. Your data is safe.
- The requirement to trust sessions.
    Let's say an attacker is on your IP, but no access to your E or session token. That's a new device.
    They can't do ANYTHING until you MANUALLY trust that device. **You can remove the session.**

    But let's also say, you ALLOWED other IPs to login to your account. This reduces security but may be required for people with dynamic IPs.
    Even if they logged in, if your IP is the primary, they are untrusted device(s) and you must trust them explicitly to allow them access to your data.
- Realistically the only 2nd method of verification you need.
    Security questions. Really, you just need to disallow other IPs from logging into your account if you have a static IP or not moving anywhere where the IP may change.

    But if you have a dynamic IP but want the same + more security, enable and add security question(s).
    Essentially, if an attacker was on a different machine and tried logging in, they need to answer the security questions, WHICH ARE HEAVILY RATE LIMITED.

    These questions don't have to be 'whats the name of your first pet' but they could be whatever you want, so you could technically add a password here if you want to prevent someone from rotating IPs (or using proxies essentially) and brute-forcing potentially insecure answers.

    If you have a static IP, this feature is redundant as a lot of security is already done to keep your account safe. But if you want extra security for edge cases where someone may for example, spoof your IP (but they have no physical access to your device), enable and add security questions so that your account is practically impenetrable. **Overkill security.**

    

### Summary about ACES
**In short**, ACES is designed for accessibility, and simplicity (you technically only need D to login, but nobody else may be able to login using your D), while also offering improved security. ACES, this exact spec, was developed by Nyrakon/upsilon.

If your device was compromised, you have bigger problems to worry about. IF OUR INFRASTRUCTURE IS COMPROMISED, **we** have bigger things to worry about. but that's also common with traditional login systems. At least we tried to keep user data safe, unlike them.