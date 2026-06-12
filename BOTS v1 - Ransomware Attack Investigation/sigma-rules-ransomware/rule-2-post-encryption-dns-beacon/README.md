## Rule 2 - Post-Encryption DNS Beacon

**Investigation:** Ransomware Attack (BOTS v1)
 
**What it detects:** DNS requests to external domains using uncommon or high-risk TLDs (.win, .ru, .xyz, .top, .club), while filtering out known legitimate microsoft domains. Observed in Cerber ransomware post-encryption callback to cerberhhyed5frqa.xmfir0.win. 

**Note:** Originally intended to make it outbound DNS requests to domains using high-risk TLDs after burst of file modification events, but Sigma doesn't allow for temporal correlation.
 
**Why it's evasion-resistant:** Flags outbound DNS activity to TLDs commonly associated with malicious infrastructure. Easy to implement, but higher false positive rate than a full temporal correlation approach.

**Note:** If your SIEM supports temporal correlation across data sources, consider pairing this with a mass file modification detection to significantly improve specificity and reduce noise.

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
date: 2026/04/28
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
