# Business Email Compromise: Session Token Theft Investigation

## Summary

This is a generalized walkthrough of a business email compromise pattern I have investigated: MFA bypass through session token theft. The user passed MFA and nothing about the login looked wrong on its own. The attacker replayed a stolen session cookie from a different location and worked inside the mailbox. Details here are generalized. No employer, client, or account information is included.

## Timeline

- T+0: User completes a normal sign-in with MFA from their usual location.
- T+40 min: A new session for the same account appears from a distant location. No fresh MFA prompt is recorded for it.
- T+1 hr: An inbox rule is created that forwards mail and marks messages as read.
- T+3 hr: A user reports that replies in an active mail thread look wrong. The alert path starts here.
- T+4 hr: Investigation confirms token replay. Containment begins.

## Investigation steps

1. **Start with the sign-in logs.** I correlated Entra ID sign-in records for the account across the full window. The pattern that mattered was impossible travel paired with authentication state. The second session showed success with single factor only, which fits a replayed session rather than a new login.
2. **Check the session, not just the login.** Token theft lives in the session layer. I reviewed token and session identifiers, sign-in risk events, and whether the second session reused the same session ID as the legitimate one.
3. **Sweep the mailbox.** In the unified audit log I searched for inbox rule creation, consent grants, and mail access activity for the account. The forwarding rule with mark as read behavior confirmed mailbox compromise rather than a simple suspicious login.
4. **Scope wider.** I searched the tenant for the same source address, the same rule patterns, and similar sign-in anomalies across all accounts. One compromised mailbox is a finding. The sweep decides whether it is also an incident with siblings.
5. **Check what the session touched.** Mail read and sent from the rogue session, files accessed, and any new app consents in the window all went into the scope notes before containment calls were made.

## Containment

- Revoked all active sessions and refresh tokens for the account.
- Reset the password and re-registered MFA.
- Removed the malicious inbox rule and swept for any other rules on the account.
- Ran the same rule and session sweep across the tenant to close out scoping.
- Where automation was available, the containment steps ran through a SOAR playbook so the sequence was fast and recorded the same way every time.

## Lessons and detections

- MFA is not the end of the story. Session protection matters. This case pushed Conditional Access sign-in risk policy and shorter session lifetimes for high risk sign-ins.
- The inbox rule was the highest signal artifact in the whole case. It is now one of my first checks in any mailbox investigation, and it has its own Sigma rule in this repo.
- Impossible travel alone is noisy. Impossible travel plus a session with no fresh MFA is a much stronger detection. That pairing became a rule, tuned per user baseline.
- Findings from this pattern fed the detection backlog. The session token theft and inbox rule Sigma rules in the sigma-rules folder came directly out of this class of investigation.
