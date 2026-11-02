import re
from pathlib import Path


def markdown_text(value):
    """Escape log-derived text so it displays as text in Markdown."""
    text = str(value).replace("\r", " ").replace("\n", " ")
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", text)


def export_markdown_report(events, alerts, skipped, output_file):
    """Write a readable summary and investigation checklist."""
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    failed = sum(event["outcome"] == "Failed" for event in events)
    successful = sum(event["outcome"] == "Accepted" for event in events)

    lines = [
        "# SSH Security Investigation Report",
        "",
        "This report summarises offline log analysis. "
        "Alerts require investigation and do not prove a compromise.",
        "",
        "## Analysis Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Parsed events | {len(events)} |",
        f"| Skipped non-empty lines | {skipped} |",
        f"| Failed logins | {failed} |",
        f"| Successful logins | {successful} |",
        f"| Security alerts | {len(alerts)} |",
        "",
        "## Detected Alerts",
        "",
    ]

    if not alerts:
        lines.extend([
            "No alerts matched the configured detection rules. "
            "This does not establish that the system is secure.",
            "",
        ])

    for number, alert in enumerate(alerts, start=1):
        lines.extend([
            f"### Alert {number}: {markdown_text(alert['type'])}",
            "",
            f"- **Time:** {markdown_text(alert['timestamp'].isoformat())}",
            f"- **Server:** {markdown_text(alert['host'])}",
            f"- **Source IP:** {markdown_text(alert['ip'])}",
            f"- **Triggering username:** {markdown_text(alert['username'])}",
            f"- **Failure count:** {alert['failure_count']}",
            f"- **Finding:** {markdown_text(alert['description'])}",
            "",
        ])

        if alert["type"] == "REPEATED_FAILURES":
            lines.extend([
                "The failure count is grouped by server and source IP. "
                "It can include multiple usernames; the triggering username "
                "is the account in the event that raised this alert.",
                "",
            ])

    lines.extend([
        "## Investigation Checklist",
        "",
        "- [ ] Review the original log entries around each alert.",
        "- [ ] Confirm whether the source IP and account activity are expected.",
        "- [ ] Check whether successful access was authorised.",
        "- [ ] Correlate the events with other available system logs.",
        "- [ ] Record the conclusion, supporting evidence, and next actions.",
        "",
        "## Interpretation Limits",
        "",
        "- Mistyped passwords or misconfigured clients can cause false positives.",
        "- Unsupported or invalid log entries are excluded from detection.",
        "- Repeated input entries are not deduplicated.",
        "- The analyser does not block connections or change user accounts.",
        "- Investigation checklist items require manual review.",
        "",
    ])

    output_file.write_text("\n".join(lines), encoding="utf-8")
    return output_file