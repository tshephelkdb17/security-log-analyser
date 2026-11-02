import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLI_FILE = PROJECT_ROOT / "src" / "cli.py"
SAMPLE_LOG = PROJECT_ROOT / "data" / "sample_auth.log"


class CommandLineTests(unittest.TestCase):
    def run_cli(self, *arguments):
        """Run the actual CLI and capture its output."""
        return subprocess.run(
            [sys.executable, str(CLI_FILE), *arguments],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_help_menu(self):
        result = self.run_cli("--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("--input", result.stdout)
        self.assertIn("--threshold", result.stdout)
        self.assertIn("--window", result.stdout)
        self.assertIn("--output-dir", result.stdout)

    def test_sample_generates_two_alerts_and_reports(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self.run_cli(
                "--input", str(SAMPLE_LOG),
                "--threshold", "5",
                "--window", "5",
                "--output-dir", folder,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Parsed events: 10", result.stdout)
            self.assertIn("Security alerts: 2", result.stdout)

            csv_file = Path(folder) / "alerts.csv"
            markdown_file = Path(folder) / "investigation_report.md"

            self.assertTrue(csv_file.is_file())
            self.assertTrue(markdown_file.is_file())

            with csv_file.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 2)

    def test_higher_threshold_generates_no_alerts(self):
        with tempfile.TemporaryDirectory() as folder:
            result = self.run_cli(
                "--input", str(SAMPLE_LOG),
                "--threshold", "10",
                "--output-dir", folder,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Security alerts: 0", result.stdout)

            with (Path(folder) / "alerts.csv").open(
                newline="", encoding="utf-8"
            ) as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(rows, [])

    def test_zero_threshold_is_rejected(self):
        result = self.run_cli("--threshold", "0")

        self.assertEqual(result.returncode, 2)
        self.assertIn("must be at least 1", result.stderr)

    def test_negative_window_is_rejected(self):
        result = self.run_cli("--window", "-1")

        self.assertEqual(result.returncode, 2)
        self.assertIn("must be at least 1", result.stderr)

    def test_non_numeric_threshold_is_rejected(self):
        result = self.run_cli("--threshold", "five")

        self.assertEqual(result.returncode, 2)
        self.assertIn("positive whole number", result.stderr)

    def test_missing_input_returns_error(self):
        with tempfile.TemporaryDirectory() as folder:
            missing_file = Path(folder) / "missing.log"
            output_dir = Path(folder) / "reports"

            result = self.run_cli(
                "--input", str(missing_file),
                "--output-dir", str(output_dir),
            )

            self.assertEqual(result.returncode, 1)
            self.assertIn("Could not read input", result.stderr)
            self.assertFalse(output_dir.exists())

    def test_input_cannot_be_overwritten_by_report(self):
        with tempfile.TemporaryDirectory() as folder:
            input_file = Path(folder) / "alerts.csv"
            original_content = "Original input must be preserved."
            input_file.write_text(original_content, encoding="utf-8")

            result = self.run_cli(
                "--input", str(input_file),
                "--output-dir", folder,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn(
                "input file must be different",
                result.stderr,
            )
            self.assertEqual(
                input_file.read_text(encoding="utf-8"),
                original_content,
            )


if __name__ == "__main__":
    unittest.main()