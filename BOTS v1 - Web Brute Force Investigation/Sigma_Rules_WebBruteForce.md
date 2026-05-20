# Sigma Detection Rules - BOTS v1 Web Brute Force Attack Investigation
 
These rules were made based on the BOTS v1 web brute force attack investigation. Each rule targets a behavioral indicator observed in the investigation rather than static IOCs like filenames or IP addresses, making them resilient to attacker modifications between campaigns.
 
All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM query language using [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) or [pySigma](https://github.com/SigmaHQ/pySigma).
 
---
 
## Rule 1 - IIS Worker Process Spawning Command Interpreter
 
**What it detects:** The IIS worker process (`w3wp.exe`) spawning a command interpreter, which is the behavioral signature of a web shell being executed on a compromised IIS server. In the web defacement investigation, `w3wp.exe` spawned `cmd.exe` which then executed the uploaded backdoor `3791.exe` from the Joomla web root.
 
**Why it's evasion-resistant:** There is no legitimate reason for `w3wp.exe` to ever spawn `cmd.exe` or `powershell.exe` during normal web server operation. This relationship is anomalous regardless of what payload the attacker uploads or what they name it.
 
```yaml
title: IIS Worker Process Spawning Command Interpreter
status: experimental
description: >
    Detects w3wp.exe (IIS Worker Process) spawning a command interpreter or 
    scripting engine. Strongly indicative of web shell execution on a compromised 
    IIS server. Observed during Po1s0n1vy web defacement attack via ExtPlorer 
    file manager abuse on Joomla CMS.
author: Chandler VonFeldt
date: 2026/04/27
references:
    - https://attack.mitre.org/techniques/T1505/003/
    - https://attack.mitre.org/techniques/T1059/003/
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\w3wp.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\cscript.exe'
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Extremely rare legitimate IIS configurations - should be investigated regardless
level: critical
```
 
---
## Rule 4 - Executable File Upload to Web Application Directory
 
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

