import argparse
import sys
from pathlib import Path

if __package__:
    from .analyser import (
        parse_log_line,
        detect_suspicious_activity,
        export_alerts_csv,
    )
    from .reporting import export_markdown_report
else:
    from analyser import (
        parse_log_line,
        detect_suspicious_activity,
        export_alerts_csv,
    )
    from reporting import export_markdown_report


def positive_integer(value):
    """Accept whole numbers greater than zero."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("Enter a positive whole number.")

    if number < 1:
        raise argparse.ArgumentTypeError("The value must be at least 1.")

    return number


def build_parser():
    project_folder = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="Analyse SSH logs and export security investigation reports."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=project_folder / "data" / "sample_auth.log",
        help="Input log file (default: project sample log).",
    )

    parser.add_argument(
        "--threshold",
        type=positive_integer,
        default=5,
        help="Failed-login threshold (default: 5).",
    )

    parser.add_argument(
        "--window",
        type=positive_integer,
        default=5,
        help="Rolling time window in minutes (default: 5).",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_folder / "reports",
        help="Report directory; existing report files are replaced.",
    )

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    log_file = args.input.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()

    csv_file = output_dir / "alerts.csv"
    markdown_file = output_dir / "investigation_report.md"

    # Avoid replacing the input file with a generated report.
    if log_file in (csv_file.resolve(), markdown_file.resolve()):
        parser.error("The input file must be different from the report files.")

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
        print(f"Could not read input: {error}", file=sys.stderr)
        return 1

    alerts = detect_suspicious_activity(
        events,
        threshold=args.threshold,
        window_minutes=args.window,
    )

    failed = sum(event["outcome"] == "Failed" for event in events)
    successful = sum(event["outcome"] == "Accepted" for event in events)

    print("Security Log Analyser")
    print(f"Input: {log_file}")
    print(f"Detection threshold: {args.threshold} failures")
    print(f"Time window: {args.window} minutes")
    print(f"Parsed events: {len(events)}")
    print(f"Skipped non-empty lines: {skipped}")
    print(f"Failed logins: {failed}")
    print(f"Successful logins: {successful}")
    print(f"Security alerts: {len(alerts)}")

    if not events:
        print("Warning: no supported events were parsed; check the input format.")

    for alert in alerts:
        print(
            f"\n[{alert['type']}] "
            f"{alert['host']} | {alert['ip']} | "
            f"{alert['description']}"
        )

    try:
        export_alerts_csv(alerts, csv_file)
        print(f"\nCSV report saved to: {csv_file}")

        export_markdown_report(events, alerts, skipped, markdown_file)
        print(f"Markdown report saved to: {markdown_file}")
    except OSError as error:
        print(f"Could not save a report: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())