# Sigma Detection Rules - BOTS v1 Ransomware Attack Investigation
 
These rules were made based on the BOTS v1 cerber ransomware attack investigation. Each rule targets a behavioral indicator observed in the investigation rather than static IOCs like filenames or IP addresses, making them resilient to attacker modifications between campaigns.
 
All rules follow the [Sigma specification](https://github.com/SigmaHQ/sigma) and can be converted to Splunk SPL, Microsoft Sentinel KQL, or any other SIEM query language using [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) or [pySigma](https://github.com/SigmaHQ/pySigma).
 
---
<br>

## Rule 1 - Office Application Spawning Command Interpreter

**Investigation:** Ransomware Attack (BOTS v1)

**What it detects:** A Microsoft Office application spawning a command interpreter or scripting engine, which is the behavioral signature of a malicious macro executing a payload. In the Cerber investigation, `WINWORD.EXE` spawned `CMD.EXE` which then spawned `WSCRIPT.EXE` to execute the ransomware VBScript loader.
 
**Why it's evasion-resistant:** An attacker cannot avoid this parent-child relationship when abusing Office macros. Regardless of what the payload is named or where it is stored, the macro has to invoke a command interpreter to execute it, and that relationship will always appear in Sysmon Event ID 1.
 
```yaml
title: Office Application Spawning Command Interpreter
status: experimental
description: >
    Detects Microsoft Office applications spawning cmd.exe, wscript.exe, or 
    powershell.exe as a child process. Indicative of malicious macro execution.
    Observed in Cerber ransomware delivery via Miranda_Tate_unveiled.dotm.
author: Chandler VonFeldt
date: 2026/04/28
references:
    - https://attack.mitre.org/techniques/T1059/003/
    - https://attack.mitre.org/techniques/T1059/005/
tags:
    - attack.execution
    - attack.t1059.003
    - attack.t1059.005
    - attack.t1204.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
            - '\OUTLOOK.EXE'
        Image|endswith:
            - '\cmd.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\powershell.exe'
            - '\mshta.exe'
    condition: selection
falsepositives:
    - Legitimate macro-enabled documents in tightly controlled enterprise environments
    - Some enterprise software integrations that use Office automation
level: high
```
 
---
<br>

## Rule 2 - Post-Encryption DNS Beacon

**Investigation:** Ransomware Attack (BOTS v1)
 
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
