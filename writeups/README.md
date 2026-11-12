# Write-ups

Investigation walkthroughs and home lab exercise write-ups. Each write-up lives in its own folder, so opening a folder shows the full article right away. Screenshots and supporting files stay inside the same folder as the write-up they belong to.

| Write-up | What it covers | Main tools |
|---|---|---|
| [Business Email Compromise: Session Token Theft Investigation](bec-session-token-theft/) | A generalized BEC investigation: MFA bypass through session token theft, mailbox rule hunting, scoping, and containment. | Microsoft Entra ID, unified audit log, Microsoft Sentinel |
| [Detecting SharpHound Active Directory Collection with Wazuh](sharphound-wazuh-detection/) | A Wazuh detection build for SharpHound: domain controller auditing for Event ID 5145, Sysmon on the endpoint, custom Wazuh rules 111151 to 111157, and the alerts captured from my own collection run. | Wazuh, Sysmon, SharpHound, BloodHound, Neo4j |

New write-ups are added here as they are completed.
