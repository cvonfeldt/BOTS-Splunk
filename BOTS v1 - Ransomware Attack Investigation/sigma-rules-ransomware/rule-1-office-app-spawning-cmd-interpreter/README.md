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
 
