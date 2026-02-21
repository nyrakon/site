# site backend
The backend runs on the same site aka the frontend.


# USER REGISTRATION SYSTEM PROPOSAL (ACES):
Registration/Login Via Access Code + Extraterraneous security. (or ACES)
Event scenario legend: A=user1, B=user2, C=system, D=access code, E=token (for decrypting data of the user)
normally, registration is done painstakingly via email + password + 2fa... then verify email, etc.
this is so B cannot access A's data without password + 2fa.
But this kind of security is pointless if someone can just use the token and use it to do everything AS you.
(Roblox suffers from this, and likely others like Discord)

And also, this practically wastes the user's time if anyone can just login to your account via other methods which are also common like:
- cross-site attacks
- phishing (or malware)
- bribing/exploiting customer support (that are likely outsourced, like something like Sofi bank suffered from iirc.)
- malware (RATs, malicious extensions, etc.)

Proposal:
A registers, C gives them their own D & E(via cookies).
On the server-side, E prevents B from using A's E however E was obtained from A.
Optionally:
    - have a preference feature where A can increase security to disallow other machines/IPs from being able to use their D.
        This means that B, if somehow was on the same wifi network as A, cannot get access to A's data if on a different REPORTED machine.
            Drawback(s): 
                - (REPORTED means the browser gives C information about A, so if B had same information as A, then technically this check may be bypassed.)
            For more security: 
                - Devise a specific user data spec we will call F, where it is not saved as a cookie, and instead downloaded.
                    This is so that even if B==A, B cannot get access to A's data because they lack this F variable.
                - Disable Dx so only 1 machine can have access to D at once.
                    This automatically negates B==A scenarios, because even if B had same exact REPORTED machine as A, that doesn't mean that B has the same D as A.
    - Have a second method of verification, which is to ask a question, based on user preference.
        The answer is non-case-sensitive + hashed and then stored so that it is not in plain-text and not easily readable.
        If anyone tries to gain access to A's data with this method of verification enabled, even if(or not) on the same IP/Machine, need to answer the question correctly. **This is considered overkill.** But probably necessary if on a public computer. 

Regarding Potential Recovery:
    - In the event where A does not have the answer to the security question (or method) regarding their D:
        A must input the correct 'recovery key' for D that auto-expires every year. And for anti-lockout, the 2nd method of verification is automatically disabled when this happens until A gets the new 'recovery key'.

        This feature is susceptible to 3 max tries before lockout for a week for that IP. And if multiple machines have the same 'fingerprint' but rotating IPs, apply this to them for anti-proxies.
    - In the event where A does not know their D:
        If A has F, return D, but NOT access to their data. Route back to traditional login based method.

**In short**, ACES is designed for accessibility, and simplicity (you technically only need D to login, but nobody else may be able to login using your D), while also offering improved security. ACES, this exact spec, was developed by Nyrakon/upsilon.

If your device was compromised, you have bigger problems to worry about. IF OUR INFRASTRUCTURE IS COMPROMISED, **we** have bigger things to worry about. but that's also common with traditional login systems.