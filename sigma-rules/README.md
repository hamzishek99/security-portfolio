# Sigma Rules

These are original Sigma rules I wrote from patterns I see in my own work and lab exercises. They are written at the generic Sigma level so they can convert to KQL, SPL, or another backend with sigma tooling. Each rule maps to MITRE ATT&CK and carries my tuning notes below.

## Approach

I write rules from the investigation backwards. First I find the behavior in telemetry I trust. Then I write the narrowest detection that catches the behavior without keying on one indicator. Indicators expire. Behavior is harder for an attacker to change. After a rule is live I watch its first weeks of hits and tune on real false positives, not guesses.

## The rules

### Entra ID Sign-In Pattern Consistent With Session Token Theft

File: `entra_session_token_theft.yml`
ATT&CK: T1550.001 (Use Alternate Authentication Material: Application Access Token), T1539 (Steal Web Session Cookie)

Token theft skips MFA because the attacker replays a session that already passed it. The detection looks for the shape of that replay at the sign-in layer: a successful session with no fresh MFA where the surrounding sign-in pattern does not fit normal use.

Tuning and false positives: VPN egress and carrier NAT are the noise sources. I tune by user baseline. A user who always signs in from one metro area gets a tighter version of this rule than a user who travels. I pair this rule with the inbox rule detection below, because token theft cases often show both.

### Active Directory Enumeration Consistent With BloodHound SharpHound Collection

File: `ad_bloodhound_enumeration.yml`
ATT&CK: T1087.002 (Account Discovery: Domain Account), T1069.002 (Permission Groups Discovery: Domain Groups), T1018 (Remote System Discovery)

SharpHound is loud when you know where to look. Collection runs produce LDAP query volume and SAMR enumeration that normal user workstations do not. I built this rule first in my lab by running collection against my own domain and reading the Security event log it left behind.

Tuning and false positives: Scanners and identity sync tools are the main noise. I allowlist known scanner service accounts and asset management hosts, and I keep the threshold time based. A slow, patient enumeration can slip under the volume bar, so this rule is one layer next to ACL change monitoring, not the whole answer.

### Microsoft 365 Malicious Inbox Rule Creation

File: `m365_malicious_inbox_rule.yml`
ATT&CK: T1137.003 (Office Application Startup: Outlook Rules), T1114.003 (Email Collection: Email Forwarding Rule)

This is the rule I reach for first in any mailbox compromise. Attackers create forwarding and hide-the-reply rules within minutes of getting in. The detection watches rule creation with forwarding, redirect, or move and mark as read behavior in the audit log.

Tuning and false positives: Legitimate leave coverage rules exist. Context decides. A rule created during an active incident window, from an unusual sign-in, or pointing outside the tenant is treated as hostile until proven otherwise. In investigations I sweep for rule creation across the tenant once one bad rule is confirmed, because these are rarely created for one mailbox only.
