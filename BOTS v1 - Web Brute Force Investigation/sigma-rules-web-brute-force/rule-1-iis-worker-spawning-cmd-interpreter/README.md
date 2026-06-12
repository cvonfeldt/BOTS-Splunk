## Rule 1 - IIS Worker Process Spawning Command Interpreter

**Investigation:** Web Brute Force Attack (BOTS v1)

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
 
