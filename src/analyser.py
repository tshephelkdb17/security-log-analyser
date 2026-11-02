import csv
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta
from ipaddress import ip_address
from pathlib import Path


LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+) "
    r"(?P<host>\S+) sshd\[\d+\]: "
    r"(?P<outcome>Accepted|Failed) "
    r"(?P<method>password|publickey) for "
    r"(?P<invalid_user>invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+) ssh2(?: .*)?$"
)


def parse_log_line(line):
    """Extract and validate the fields in a supported SSH log entry."""
    match = LOG_PATTERN.fullmatch(line.strip())

    if match is None:
        return None

    event = match.groupdict()

    try:
        event["timestamp"] = datetime.fromisoformat(event["timestamp"])
        event["ip"] = str(ip_address(event["ip"]))
        event["port"] = int(event["port"])
    except ValueError:
        return None

    # Require a timezone for reliable time comparisons.
    if event["timestamp"].utcoffset() is None:
        return None

    if not 1 <= event["port"] <= 65535:
        return None

    event["invalid_user"] = event["invalid_user"] is not None
    return event


def detect_suspicious_activity(events, threshold=5, window_minutes=5):
    """Find repeated failures and successful logins following failures."""
    if threshold < 1 or window_minutes <= 0:
        raise ValueError("Threshold and time window must be positive.")

    window = timedelta(minutes=window_minutes)
    recent_failures = defaultdict(deque)
    alerts = []

    # Process events chronologically, even if the file is unordered.
    for event in sorted(events, key=lambda item: item["timestamp"]):
        key = (event["host"], event["ip"])
        failures = recent_failures[key]
        now = event["timestamp"]

        # Keep only failures within the rolling time window.
        while failures and now - failures[0]["timestamp"] > window:
            failures.popleft()

        if event["outcome"] == "Failed":
            failures.append(event)

            # Alert when the count reaches the threshold.
            if len(failures) == threshold:
                alerts.append({
                    "type": "REPEATED_FAILURES",
                    "timestamp": now,
                    "host": event["host"],
                    "ip": event["ip"],
                    "username": event["username"],
                    "failure_count": len(failures),
                    "description": (
                        f"{len(failures)} failed logins within "
                        f"{window_minutes} minutes"
                    ),
                })

        elif event["outcome"] == "Accepted":
            # Match failures for the same account, server, and IP.
            matching_failures = [
                failure for failure in failures
                if failure["username"] == event["username"]
                and not failure["invalid_user"]
            ]

            if len(matching_failures) >= threshold:
                alerts.append({
                    "type": "SUCCESS_AFTER_FAILURES",
                    "timestamp": now,
                    "host": event["host"],
                    "ip": event["ip"],
                    "username": event["username"],
                    "failure_count": len(matching_failures),
                    "description": (
                        f"Successful login for {event['username']} after "
                        f"{len(matching_failures)} failures within "
                        f"{window_minutes} minutes"
                    ),
                })

    return alerts


def export_alerts_csv(alerts, output_file):
    """Save alerts to CSV, including headers when there are no alerts."""
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    fields = [
        "type",
        "timestamp",
        "host",
        "ip",
        "username",
        "failure_count",
        "description",
    ]

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        for alert in alerts:
            row = {field: alert[field] for field in fields}
            row["timestamp"] = alert["timestamp"].isoformat()

            # Prevent log-derived text from becoming spreadsheet formulas.
            for field, value in row.items():
                if isinstance(value, str) and value.startswith(
                    ("=", "+", "-", "@", "\t", "\r", "\n")
                ):
                    row[field] = "'" + value

            writer.writerow(row)

    return output_file


def main():
    # Locate the project folder using this script's location.
    project_folder = Path(__file__).resolve().parent.parent
    log_file = project_folder / "data" / "sample_auth.log"

    events = []
    skipped = 0

    try:
        with log_file.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue

                event = parse_log_line(line)

                if event is None:
                    skipped += 1
                else:
                    events.append(event)

    except (OSError, UnicodeError) as error:
        print(f"Could not read the log file: {error}")
        return

    print("Security Log Analyser")
    print(f"File: {log_file.name}")
    print(f"Parsed events: {len(events)}")
    print(f"Skipped non-empty lines: {skipped}\n")

    # Display the extracted login information.
    for event in events:
        time = event["timestamp"].strftime("%H:%M:%S")
        outcome = event["outcome"]
        username = event["username"]
        source_ip = event["ip"]

        print(f"{time} | {outcome:<8} | {username:<10} | {source_ip}")

    failed = sum(event["outcome"] == "Failed" for event in events)
    successful = sum(event["outcome"] == "Accepted" for event in events)

    print(f"\nFailed logins: {failed}")
    print(f"Successful logins: {successful}")

    # Detect and display suspicious activity.
    alerts = detect_suspicious_activity(events)

    print(f"\nSecurity alerts: {len(alerts)}")

    for alert in alerts:
        print(f"\n[{alert['type']}]")
        print(f"Time: {alert['timestamp'].isoformat()}")
        print(f"Server: {alert['host']}")
        print(f"Source IP: {alert['ip']}")
        print(f"Details: {alert['description']}")

    # Save all alerts once, after displaying them.
    try:
        report_file = export_alerts_csv(
            alerts,
            project_folder / "reports" / "alerts.csv",
        )
        print(f"\nCSV report saved to: {report_file}")
    except OSError as error:
        print(f"\nCould not save the CSV report: {error}")


if __name__ == "__main__":
    main()
    