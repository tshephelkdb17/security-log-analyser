import csv
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from src.analyser import export_alerts_csv
from src.reporting import export_markdown_report


def make_alert(username="admin"):
    """Create a fictional alert for export tests."""
    return {
        "type": "SUCCESS_AFTER_FAILURES",
        "timestamp": datetime(2026, 11, 2, 9, 6, 40, tzinfo=timezone.utc),
        "host": "lab-server",
        "ip": "192.0.2.50",
        "username": username,
        "failure_count": 5,
        "description": "Successful login after 5 failures",
    }


class ReportingTests(unittest.TestCase):
    def test_csv_preserves_alert_details(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "reports" / "alerts.csv"
            export_alerts_csv([make_alert()], output)

            with output.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["ip"], "192.0.2.50")
            self.assertEqual(rows[0]["username"], "admin")
            self.assertEqual(rows[0]["failure_count"], "5")
            self.assertEqual(
                rows[0]["timestamp"],
                "2026-11-02T09:06:40+00:00",
            )

    def test_empty_csv_still_has_headers(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "alerts.csv"
            export_alerts_csv([], output)

            with output.open(newline="", encoding="utf-8") as file:
                reader = csv.DictReader(file)
                fields = reader.fieldnames
                rows = list(reader)

            self.assertEqual(
                fields,
                [
                    "type", "timestamp", "host", "ip",
                    "username", "failure_count", "description",
                ],
            )
            self.assertEqual(rows, [])

    def test_csv_prefixes_formula_like_username(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "alerts.csv"
            export_alerts_csv([make_alert(username="=1+1")], output)

            with output.open(newline="", encoding="utf-8") as file:
                row = next(csv.DictReader(file))

            self.assertEqual(row["username"], "'=1+1")

    def test_markdown_summary_and_alert(self):
        events = [
            {"outcome": "Failed"},
            {"outcome": "Accepted"},
        ]

        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "reports" / "report.md"
            export_markdown_report(events, [make_alert()], 2, output)
            content = output.read_text(encoding="utf-8")

            self.assertIn("| Parsed events | 2 |", content)
            self.assertIn("| Skipped non-empty lines | 2 |", content)
            self.assertIn("| Failed logins | 1 |", content)
            self.assertIn("| Successful logins | 1 |", content)
            self.assertIn("| Security alerts | 1 |", content)
            self.assertIn("### Alert 1:", content)
            self.assertIn("Successful login after 5 failures", content)

    def test_markdown_no_alerts_message(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "report.md"
            export_markdown_report([], [], 0, output)
            content = output.read_text(encoding="utf-8")

            self.assertIn("No alerts matched", content)
            self.assertIn(
                "This does not establish that the system is secure.",
                content,
            )

    def test_markdown_escapes_html_in_username(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "report.md"
            alert = make_alert(username="<b>admin</b>")
            export_markdown_report([], [alert], 0, output)
            content = output.read_text(encoding="utf-8")

            self.assertNotIn("<b>admin</b>", content)
            self.assertIn("&lt;b&gt;admin&lt;/b&gt;", content)


if __name__ == "__main__":
    unittest.main()