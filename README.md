# Splunk BOTS investigations
My investigations, walkthroughs, and overall thought processes from Splunk Boss of the SOC (BOTS) datasets focused on ransomware analysis, malware execution, DNS investigations, brute force attacks, Sysmon logging, Suricata alerts, and threat hunting using Splunk.

## Overview
Hands-on SOC and threat hunting lab work using Splunk BOTS datasets to practice real-world security investigations and detection engineering workflows/queries. Each investigation includes full methodology documentation, process lineage analysis, MITRE ATT&CK mapping, key IOCs, and vendor-agnostic Sigma detection rules authored from confirmed attack behavior.

## Tools & Data Sources
* Splunk Enterprise
* Sysmon
* Suricata
* Fortigate (fgt_utm)
* Windows Event Logs
* WinRegistry
* DNS Logs
* Network Traffic Logs (stream:http, stream:dns)

## Investigations
| #  | Investigation                           | Focus Area                       | Status   |
| -- | --------------------------------------- | -------------------------------- | -------- |
| 01 | BOTS v1 - Web Brute Force Investigation | Joomla, HTTP, Credential Attacks | Complete |
| 02 | BOTS v1 - Ransomware Investigation      | Cerber, DNS, Sysmon, Suricata    | Complete |

## Detection Engineering
Each investigation includes vendor-agnostic Sigma detection rules (YAML) authored from confirmed attack behavior observed during analysis. Rules target behavioral indicators rather than static IOCs, making them resilient to attacker modifications between campaigns. All rules are convertible to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM using sigmac or pySigma.

## MITRE ATT&CK Coverage
Techniques identified and mapped across both investigations span Initial Access, Execution, Defense Evasion, Credential Access, Lateral Movement, Discovery, Command & Control, and Impact tactics.

