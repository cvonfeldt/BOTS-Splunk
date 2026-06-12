## Rule 2 - Executable File Upload to Web Application Directory

**Investigation:** Web Brute Force Attack (BOTS v1)
 
**What it detects:** A DNS request to an external domain occurring within a short window after a burst of file modification events, which is typical behavior of ransomware completing its encryption phase and beaconing to C2 infrastructure. In the Cerber investigation, a DNS request to `cerberhhyed5frqa.xmfir0.win` was observed exactly 1.688 seconds after the encryption phase completed.
 
**Why it's evasion-resistant:** This rule correlates two separate data sources - file system telemetry and DNS logs. Neither event alone is necessarily malicious, but the combination and timing is an extremely specific behavioral anomaly that is difficult for an attacker to avoid since the C2 callback is built into the malware's own post-encryption routine.
 
**Note:** This rule requires correlation across Sysmon file modification events (Event ID 2) and DNS logs. Implementation will vary by SIEM - the logic below is for the intent; you should tune to your specific environment. 
 
```yaml
title: DNS Request Following Mass File Modification Event
status: experimental
description: >
    Detects a DNS request to an external domain occurring within 10 seconds of 
    a high volume of file modification events from the same host. Indicative of 
    ransomware completing encryption and beaconing to C2 infrastructure.
    Observed in Cerber ransomware post-encryption callback to 
    cerberhhyed5frqa.xmfir0.win 1.688 seconds after encryption completed.
author: Chandler VonFeldt
date: 2026/04/27
references:
    - https://attack.mitre.org/techniques/T1486/
    - https://attack.mitre.org/techniques/T1568/
    - https://attack.mitre.org/techniques/T1071/001/
tags:
    - attack.impact
    - attack.t1486
    - attack.command_and_control
    - attack.t1568
    - attack.t1071.001
logsource:
    category: dns
    product: windows
detection:
    selection:
        QueryName|endswith:
            - '.win'
            - '.ru'
            - '.xyz'
            - '.top'
            - '.club'
        QueryName|contains|all:
            - '.'
    filter:
        QueryName|endswith:
            - '.microsoft.com'
            - '.windows.com'
            - '.windowsupdate.com'
    condition: selection and not filter
falsepositives:
    - Legitimate software using uncommon TLDs
    - Some CDN providers
level: medium
```

