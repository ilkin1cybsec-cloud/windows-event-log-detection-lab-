# Windows Event Log Detection Lab

## Project Overview

This project is a Windows Event Log detection lab built for a SOC Analyst portfolio. It uses sample Windows event logs and Sigma-style YAML rules to detect brute-force activity, suspicious PowerShell usage, privileged group membership changes, and failed logons.

The goal is to simulate how a blue-team analyst reviews Windows logs, writes detection logic, maps suspicious activity to MITRE ATT&CK, and produces investigation-ready findings.

## Skills Demonstrated

- Windows Security Event Log analysis
- Detection engineering basics
- Sigma-style rule writing
- Python log parsing and automation
- Brute-force detection logic
- Suspicious PowerShell detection
- Privilege change monitoring
- MITRE ATT&CK mapping
- SOC investigation reporting

## Tools Used

- Python 3
- JSON Lines sample log data
- YAML/Sigma-style detection rules
- Markdown reporting
- Windows Security Event IDs
- MITRE ATT&CK framework

## Folder Structure

```text
windows-event-log-detection-lab/
├── data/
│   └── windows_events.jsonl
├── docs/
│   └── interview_explanation.md
├── reports/
│   └── detection_report.md
├── rules/
│   ├── brute_force.yml
│   ├── failed_logon.yml
│   ├── privilege_change.yml
│   └── suspicious_powershell.yml
├── src/
│   ├── detect.py
│   └── export_interview_explanation_pdf.py
├── .gitignore
└── README.md
```

## Windows Event IDs Used

| Event ID | Meaning | Why It Matters |
|---|---|---|
| 4624 | Successful logon | Can show successful access after suspicious failures |
| 4625 | Failed logon | Useful for failed login and brute-force detection |
| 4688 | Process creation | Useful for detecting suspicious command execution |
| 4104 | PowerShell script block logging | Useful for reviewing PowerShell script content |
| 4728 | User added to global security group | Can indicate privilege escalation or account manipulation |
| 4732 | User added to local security group | Can indicate local administrator access changes |

## Detection Rules

### Brute Force

File: `rules/brute_force.yml`

Detects five or more failed logons from the same username and source IP followed by a successful logon.

MITRE ATT&CK:

- Tactic: Credential Access
- Technique: T1110 Brute Force

### Suspicious PowerShell

File: `rules/suspicious_powershell.yml`

Detects PowerShell activity using suspicious keywords such as encoded commands, execution policy bypass, `IEX`, or `DownloadString`.

MITRE ATT&CK:

- Tactic: Execution
- Technique: T1059.001 PowerShell

### Privilege Change

File: `rules/privilege_change.yml`

Detects users added to privileged groups such as Administrators or Domain Admins.

MITRE ATT&CK:

- Tactic: Persistence
- Technique: T1098 Account Manipulation

### Failed Logon

File: `rules/failed_logon.yml`

Detects individual failed Windows logon events.

MITRE ATT&CK:

- Tactic: Credential Access
- Technique: T1110 Brute Force

## How To Run The Project

From the project folder, run:

```bash
python src/detect.py
```

The script creates this report:

```text
reports/detection_report.md
```

## Sample Output

Example finding:

```text
### Finding: Suspicious PowerShell Execution

- Severity: High
- Hostname: HR-WS-022
- Username: a.johnson
- Process: powershell.exe
- Command Line: powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand ...
- MITRE ATT&CK: Execution - T1059.001 PowerShell
- Recommended Action: Collect the full command line, review parent process activity, and check endpoint telemetry for downloaded payloads.
```

## Interview Explanation

You can explain this project like this:

> I built a Windows Event Log detection lab using sample log data and Sigma-style YAML rules. The lab detects failed logons, possible brute-force activity, suspicious PowerShell execution, and privileged group membership changes. A Python script loads the logs and rules, applies the detection logic, maps findings to MITRE ATT&CK, and generates an analyst-ready report.

You can also say:

> This project helped me practice Windows event IDs, detection logic, and SOC investigation workflows. I used event IDs like 4625 for failed logons, 4624 for successful logons, 4688 for process creation, 4104 for PowerShell script block logging, and 4728/4732 for privileged group changes.

## Resume Bullet

```text
Developed Windows event log detection rules to identify brute-force activity, suspicious PowerShell usage, privilege changes, and authentication anomalies.
```

Stronger version:

```text
Built a Python-based Windows Event Log detection lab using Sigma-style YAML rules to identify brute-force activity, suspicious PowerShell, failed logons, and privileged account changes mapped to MITRE ATT&CK.
```

## Possible Future Improvements

- Add more Windows event IDs
- Add CSV export for findings
- Add real Sigma rule conversion
- Add timeline grouping by user or host
- Add severity scoring
- Add Splunk or Microsoft Sentinel query examples
