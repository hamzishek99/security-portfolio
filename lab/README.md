# Home Lab

I built this lab to practice the full defender loop: attack, telemetry, detection, write-up. It is small on purpose. Every host in it earns its place.

## Architecture

The lab runs on VMware vSphere. pfSense handles segmentation and routing between zones. Nothing in the attack range can reach my normal network.

```
                    +----------------------+
                    |       pfSense        |
                    |  firewall + routing  |
                    +---+--------+------+--+
                        |        |      |
              +---------v-+  +---v----+  +v-----------+
              | Mgmt zone |  | Range  |  | Domain     |
              | Elastic   |  | attack |  | DC + Win   |
              | TheHive   |  | tools  |  | hosts      |
              +-----------+  +--------+  +------------+
                        ^
              Suricata + Zeek sensors
              span traffic between zones
```

## Zones

- **Management zone:** Elastic Stack for log storage and search, TheHive for case work, MISP and OpenCTI for indicator enrichment during exercises.
- **Domain zone:** a Windows domain controller and Windows hosts with endpoint telemetry agents. This is where detection content gets tested.
- **Attack range:** isolated segment for offensive tooling. BloodHound and SharpHound collection, GoPhish campaigns against lab accounts, and HackTheBox style exercises that need a local target.

## Telemetry pipeline

Windows hosts ship event logs and endpoint telemetry into Elastic. Wazuh agents cover the same hosts for a second view. Suricata alerts and Zeek connection, DNS, and LDAP logs land in the same Elastic indexes, so one search can follow a host from network connection to process to directory query. Velociraptor sits on top for live response and artifact collection during exercises.

## Exercise workflow

1. Plan the technique and the ATT&CK mapping before running anything.
2. Run the attack in the range or domain zone.
3. Work the telemetry in Elastic and open a case in TheHive.
4. Write or tune the Sigma detection from what the telemetry actually showed.
5. Convert the detection and test it against a rerun of the attack.
6. Write up the exercise. The completed write-ups live in the writeups folder of this repo.

## Tooling

VMware vSphere, pfSense, Elastic Stack, Wazuh, Suricata, Zeek, Velociraptor, BloodHound, PingCastle, TheHive, MISP, OpenCTI, GoPhish, Docker, Kubernetes.
