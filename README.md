# CyberInspector
It's an automated Audit Tool. It scans for a HTTP misconfiguration in any given Keycloak Implementation and performs a Cookie Hijack attack. It stands as a Proof-of-Concept tool, that performs an automated Red Team Operation to highlight security lapses in Keycloak deployments. CyberInspector alerts developers of unsecured software to improve cybersecurity defenses.

## Note
The scripts here are newly improved, with a gui for an automatic keycloak http audit tool. 
added as an extension from previous, upgraded from research work

>Has to be run on Kali, because it has required network drivers. Ettercap is also preinstalled

**To RUN**
`pip3 install -r requirements.txt`

`sudo python3 ettercap.py`
`sudo python3 wifi-sniff.py`
