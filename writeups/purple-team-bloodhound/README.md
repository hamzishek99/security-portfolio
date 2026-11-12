# Home Lab Purple Team: BloodHound Attack Paths to Detections

## Summary

My lab exists for one loop. Run the attack. Read the telemetry it leaves. Write the detection. This write-up covers an Active Directory enumeration exercise built around BloodHound and SharpHound, and how the findings became Sigma detections.

## Lab build summary

The lab runs on VMware vSphere, segmented with pfSense so the attack range, the Windows domain, and my workstations sit in separate zones. The domain side has Windows hosts sending telemetry to an Elastic Stack. Suricata and Zeek sensors watch the range traffic. Wazuh agents cover the endpoints. Velociraptor is my live response tool when an exercise needs host level collection. I keep cases in TheHive so exercises are worked like real tickets, with notes and artifacts in one place.

## The exercise

1. Built a small domain with deliberate flaws: a service account with a weak password in its description field, group nesting that gave a standard user a path to a high value group, and unconstrained delegation left on one server.
2. Ran PingCastle first to get the defender view of the domain posture. It flagged most of the planted issues.
3. Ran SharpHound collection from a standard user context, the way an attacker would after a first foothold.
4. Loaded the data into BloodHound and read the attack paths. The shortest path to Domain Admins took three hops through the nested group.
5. Fixed nothing yet. First I went to the telemetry.

## Telemetry it produced

- **Domain controller Security log:** a burst of LDAP related events and SAMR enumeration from one workstation account inside a five minute window. Normal user workstations do not do this.
- **Zeek:** a spike in LDAP and Kerberos connections from the collection host to the domain controller, well above the host baseline.
- **Suricata:** the sensor flagged the enumeration pattern on the range segment where the collection ran.
- **Elastic:** pulling the three sources together on one timeline made the collection run obvious. One host, one short window, every directory query type at once.

## How findings became detections

- The LDAP and SAMR burst became the AD enumeration Sigma rule in this repo. I tuned it against my own scanner traffic in the lab so service accounts doing real inventory work do not fire it.
- The BloodHound paths themselves became hardening work: remove the nested group path, fix the service account, and kill the delegation setting. Then I reran collection to confirm the paths were gone.
- The exercise also produced a hunt habit I use at work. When I see enumeration telemetry, I check what the account could reach, not just what it touched. The path matters more than the event count.

## What I took from it

Attackers graph the domain before they move. If I only alert on the loud final step, I miss the mapping phase where they are still cheap to catch. Lab reps like this are how I keep detection ideas honest. Every rule in this repo has been run against telemetry I generated myself before I trusted it.
