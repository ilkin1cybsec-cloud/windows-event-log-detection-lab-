"""
Windows Event Log Detection Lab

This script reads sample Windows event logs, applies Sigma-style YAML detection
rules, maps detections to MITRE ATT&CK, and generates an analyst-ready report.
"""

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVENTS_FILE = PROJECT_ROOT / "data" / "windows_events.jsonl"
RULES_DIR = PROJECT_ROOT / "rules"
REPORT_FILE = PROJECT_ROOT / "reports" / "detection_report.md"


def load_events(events_file):
    """Load JSON Lines event records into a list of dictionaries."""
    events = []

    with events_file.open(mode="r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                events.append(json.loads(line))

    return events


def parse_simple_yaml(rule_file):
    """
    Parse the small Sigma-style YAML files used in this lab.

    This parser supports the simple key/value and list structure used by this
    project. In production, analysts usually use a real YAML parser and a SIEM.
    """
    result = {}
    section_stack = [(0, result)]
    current_list_key = None

    for raw_line in rule_file.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.strip().startswith("#"):
            continue

        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = raw_line.strip()

        while section_stack and indent < section_stack[-1][0]:
            section_stack.pop()

        current_section = section_stack[-1][1]

        if line.startswith("- "):
            value = line[2:].strip()
            if current_list_key:
                current_section[current_list_key].append(convert_value(value))
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        if value:
            current_section[key] = convert_value(value)
            current_list_key = None
        else:
            next_section = {}
            current_section[key] = next_section
            section_stack.append((indent + 2, next_section))
            current_list_key = key

            # If the next lines are list items, this placeholder is replaced.
            if key in {"event_ids", "process_names", "suspicious_keywords", "group_by", "fields", "falsepositives", "privileged_groups"}:
                current_section[key] = []
                section_stack.pop()
                current_list_key = key

    return result


def convert_value(value):
    """Convert simple YAML scalar values to useful Python values."""
    if value.isdigit():
        return int(value)
    return value


def load_rules(rules_dir):
    """Load all YAML detection rules from the rules folder."""
    rules = []

    for rule_file in sorted(rules_dir.glob("*.yml")):
        rule = parse_simple_yaml(rule_file)
        rule["file_name"] = rule_file.name
        rules.append(rule)

    return rules


def detect_failed_logons(events, rule):
    """Find individual Windows failed logon events."""
    event_id = rule["detection"]["event_id"]
    findings = []

    for event in events:
        if event["event_id"] == event_id:
            findings.append(build_finding(rule, [event], "Failed Windows logon event detected."))

    return findings


def detect_suspicious_powershell(events, rule):
    """Find suspicious PowerShell process creation or script block events."""
    detection = rule["detection"]
    event_ids = set(detection["event_ids"])
    process_names = {name.lower() for name in detection["process_names"]}
    keywords = [keyword.lower() for keyword in detection["suspicious_keywords"]]
    findings = []

    for event in events:
        command_line = event["command_line"].lower()
        process_name = event["process_name"].lower()

        event_match = event["event_id"] in event_ids
        process_match = process_name in process_names
        keyword_match = any(keyword in command_line for keyword in keywords)

        if event_match and (process_match or keyword_match):
            summary = "Suspicious PowerShell behavior detected in process or script block logs."
            findings.append(build_finding(rule, [event], summary))

    return findings


def detect_privilege_changes(events, rule):
    """Find additions to privileged Windows groups."""
    detection = rule["detection"]
    event_ids = set(detection["event_ids"])
    privileged_groups = {group.lower() for group in detection["privileged_groups"]}
    findings = []

    for event in events:
        group_name = event["group_name"].lower()

        if event["event_id"] in event_ids and group_name in privileged_groups:
            summary = f"User {event['target_user']} was added to privileged group {event['group_name']}."
            findings.append(build_finding(rule, [event], summary))

    return findings


def detect_brute_force(events, rule):
    """
    Find repeated failed logons followed by a successful logon.

    The lab groups events by username and source IP. If the number of failures
    reaches the threshold and a success follows, the activity is flagged.
    """
    detection = rule["detection"]
    threshold = detection["threshold"]
    failed_event_id = detection["failed_event_id"]
    success_event_id = detection["success_event_id"]
    grouped_events = defaultdict(list)
    findings = []

    for event in events:
        key = (event["username"], event["source_ip"])
        grouped_events[key].append(event)

    for (_username, _source_ip), grouped in grouped_events.items():
        failures = [event for event in grouped if event["event_id"] == failed_event_id]
        successes = [event for event in grouped if event["event_id"] == success_event_id]

        if len(failures) >= threshold and successes:
            related_events = failures + successes[:1]
            summary = f"{len(failures)} failed logons followed by a successful logon."
            findings.append(build_finding(rule, related_events, summary))

    return findings


def build_finding(rule, related_events, summary):
    """Create a normalized finding that can be written to the final report."""
    primary_event = related_events[0]
    mitre = rule["mitre"]

    return {
        "rule_title": rule["title"],
        "rule_id": rule["id"],
        "severity": rule["level"].capitalize(),
        "summary": summary,
        "mitre_tactic": mitre["tactic"],
        "mitre_technique_id": mitre["technique_id"],
        "mitre_technique": mitre["technique"],
        "timestamp": primary_event["timestamp"],
        "hostname": primary_event["hostname"],
        "username": primary_event["username"],
        "source_ip": primary_event["source_ip"],
        "process_name": primary_event["process_name"],
        "command_line": primary_event["command_line"],
        "target_user": primary_event["target_user"],
        "group_name": primary_event["group_name"],
        "event_count": len(related_events),
        "related_event_ids": sorted({event["event_id"] for event in related_events}),
        "recommendation": recommend_action(rule["id"]),
    }


def recommend_action(rule_id):
    """Return an analyst next step based on the rule that fired."""
    recommendations = {
        "win-bruteforce-001": "Review authentication logs, validate the source IP, and consider password reset or account lockout.",
        "win-powershell-001": "Collect the full command line, review parent process activity, and check endpoint telemetry for downloaded payloads.",
        "win-privilege-001": "Confirm the change was approved, review the actor account, and remove unauthorized privileged access immediately.",
        "win-failedlogon-001": "Check whether the failure is isolated or part of a larger authentication pattern.",
    }
    return recommendations.get(rule_id, "Review related logs and document analyst findings.")


def run_detections(events, rules):
    """Run each rule against the Windows event dataset."""
    findings = []

    for rule in rules:
        rule_id = rule["id"]

        if rule_id == "win-failedlogon-001":
            findings.extend(detect_failed_logons(events, rule))
        elif rule_id == "win-powershell-001":
            findings.extend(detect_suspicious_powershell(events, rule))
        elif rule_id == "win-privilege-001":
            findings.extend(detect_privilege_changes(events, rule))
        elif rule_id == "win-bruteforce-001":
            findings.extend(detect_brute_force(events, rule))

    return findings


def create_report(events, rules, findings):
    """Create a Markdown report summarizing detections and analyst next steps."""
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    severity_counts = defaultdict(int)

    for finding in findings:
        severity_counts[finding["severity"]] += 1

    report_lines = [
        "# Windows Event Log Detection Report",
        "",
        f"Generated: {generated_at}",
        "",
        "## Executive Summary",
        "",
        f"- Events analyzed: {len(events)}",
        f"- Rules loaded: {len(rules)}",
        f"- Findings generated: {len(findings)}",
        f"- Critical findings: {severity_counts['Critical']}",
        f"- High findings: {severity_counts['High']}",
        f"- Medium findings: {severity_counts['Medium']}",
        "",
        "## Detection Findings",
        "",
    ]

    for index, finding in enumerate(findings, start=1):
        report_lines.extend(
            [
                f"### Finding {index}: {finding['rule_title']}",
                "",
                f"- Rule ID: {finding['rule_id']}",
                f"- Severity: {finding['severity']}",
                f"- Summary: {finding['summary']}",
                f"- Timestamp: {finding['timestamp']}",
                f"- Hostname: {finding['hostname']}",
                f"- Username: {finding['username']}",
                f"- Source IP: {finding['source_ip']}",
                f"- Process: {finding['process_name']}",
                f"- Command Line: {finding['command_line']}",
                f"- Target User: {finding['target_user']}",
                f"- Group Name: {finding['group_name']}",
                f"- Related Event IDs: {', '.join(str(event_id) for event_id in finding['related_event_ids'])}",
                f"- Related Event Count: {finding['event_count']}",
                f"- MITRE ATT&CK: {finding['mitre_tactic']} - {finding['mitre_technique_id']} {finding['mitre_technique']}",
                f"- Recommended Action: {finding['recommendation']}",
                "",
            ]
        )

    return "\n".join(report_lines)


def save_report(report_text, report_file):
    """Write the Markdown detection report to the reports folder."""
    report_file.parent.mkdir(parents=True, exist_ok=True)
    report_file.write_text(report_text, encoding="utf-8")


def main():
    """Run the Windows detection lab workflow."""
    events = load_events(EVENTS_FILE)
    rules = load_rules(RULES_DIR)
    findings = run_detections(events, rules)
    report_text = create_report(events, rules, findings)
    save_report(report_text, REPORT_FILE)

    print(f"Detection complete. Report created: {REPORT_FILE}")


if __name__ == "__main__":
    main()
