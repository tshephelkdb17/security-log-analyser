# Security Log Analyser

[![Python Tests](https://github.com/tshephelkdb17/security-log-analyser/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/tshephelkdb17/security-log-analyser/actions/workflows/test.yml)

A Python tool that analyses SSH authentication logs, identifies suspicious login patterns, and exports alerts to CSV and a readable Markdown investigation report.

This educational cybersecurity project demonstrates log parsing, time-based detection, input validation, command-line interfaces, automated testing, and reporting using Python’s standard library.

## Features

- Parse SSH authentication entries with timezone-aware ISO timestamps.
- Extract server, username, source IP, authentication method, and outcome.
- Validate timestamps, IP addresses, and port numbers.
- Count successful and failed logins.
- Detect repeated failures within a rolling time window.
- Identify successful logins following repeated failures for the same account.
- Process events chronologically, even when the input is unordered.
- Keep failure counts separate for different servers and source IPs.
- Count unsupported or invalid non-empty log lines.
- Export alerts to CSV.
- Generate a Markdown investigation report with an alert summary and review checklist.
- Escape log-derived text in Markdown reports.
- Prefix certain formula-leading text characters in CSV exports.
- Choose input files, detection thresholds, time windows, and output folders through command-line options.
- Reject invalid command-line values and protect the input from report files at the same resolved path.
- Include synthetic sample logs and 28 automated tests.
- Run the test suite automatically through GitHub Actions on pushes and pull requests.

## Detection Rules

The default threshold is five failures within five minutes.

| Alert | Detection logic |
|---|---|
| `REPEATED_FAILURES` | Generated when the rolling failure count reaches the threshold for the same server and source IP. Failures may involve different usernames. |
| `SUCCESS_AFTER_FAILURES` | Generated when a successful login follows at least the threshold number of failures for the same server, source IP, and username within the configured time window. Failures labelled “invalid user” are excluded from this account-specific check. |

Events are sorted by timestamp before analysis.

Events exactly at the time-window boundary are included. For example, with a five-minute window, a failure exactly 300 seconds before the current event still counts; one 301 seconds earlier does not.

For repeated-failure alerts, the reported username belongs to the event that triggered the alert. It does not necessarily represent every account included in the failure count.

Successful logins do not clear earlier failures.

Alerts are investigation leads, not proof of a compromised account.

## Project Files

| File | Purpose |
|---|---|
| `src/analyser.py` | Parser, detection logic, terminal output, and CSV exporter |
| `src/reporting.py` | Markdown report generation and text escaping |
| `src/cli.py` | Command-line interface for input files, detection settings, and output folders |
| `tests/test_analyser.py` | Fourteen parser and detection tests |
| `tests/test_reporting.py` | Six CSV and Markdown export tests |
| `tests/test_cli.py` | Eight command-line integration tests |
| `data/sample_auth.log` | Fictional SSH authentication events |
| `reports/alerts.csv` | Generated sample alerts |
| `reports/investigation_report.md` | Generated investigation report |
| `.github/workflows/test.yml` | GitHub Actions workflow for automated testing |
| `.gitignore` | Excludes the virtual environment and temporary files |

## Setup

Python 3 is required. The automated workflow runs on Python 3.14.

No third-party Python packages are needed.

Clone the repository:

```bash
git clone https://github.com/tshephelkdb17/security-log-analyser.git
cd security-log-analyser
```

Optionally create and activate a virtual environment on macOS or Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## Run the Analyser

From the project root, run the command-line interface:

```bash
python3 src/cli.py
```

By default, it reads:

```text
data/sample_auth.log
```

It displays detection settings, summary counts, and alert details, then generates:

- `reports/alerts.csv`
- `reports/investigation_report.md`

Each run replaces the previous contents of the report files in the selected output folder.

The original entry point also remains available:

```bash
python3 src/analyser.py
```

This original entry point uses the sample log and default detection settings, and also displays individual parsed login events.

## Command-Line Options

Display the help menu:

```bash
python3 src/cli.py --help
```

Choose an input file, failure threshold, time window, and report folder:

```bash
python3 src/cli.py --input data/sample_auth.log --threshold 5 --window 5 --output-dir reports
```

| Option | Purpose | Default |
|---|---|---|
| `--input` | Log file to analyse | Project's `data/sample_auth.log` |
| `--threshold` | Number of failed logins required | `5` |
| `--window` | Rolling time window in minutes | `5` |
| `--output-dir` | Destination for both reports | Project's `reports` folder |
| `--help` | Display usage instructions | — |

Threshold and window values must be positive whole numbers.

User-supplied relative paths are resolved from the current working directory. Default input and output paths are based on the project location.

Paths containing spaces should be enclosed in quotes.

### Example: Higher Threshold

Run with a threshold of ten failures and save the results separately:

```bash
python3 src/cli.py --threshold 10 --output-dir reports/threshold-10
```

The supplied sample produces zero alerts with this threshold.

Using a separate output folder preserves the default demonstration reports.

### Example: Different Input File

Replace the path below with the location of a log file in the supported format:

```bash
python3 src/cli.py --input "/path/to/auth.log" --threshold 5 --window 10 --output-dir reports/custom
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Analysis and report generation completed, or help was displayed |
| `1` | An input-reading or report-writing error occurred |
| `2` | Invalid command-line arguments or an input/report path conflict |

An exit code of `0` does not mean the analysed system is secure. It indicates that the command completed successfully.

If no supported events are parsed, the CLI displays a warning and still generates reports.

## Supported Log Format

The parser supports SSH authentication entries in the format demonstrated below:

```text
2026-11-02T09:00:00+00:00 lab-server sshd[1001]: Accepted publickey for alice from 192.0.2.10 port 51001 ssh2
```

Supported entries include:

- `Accepted` and `Failed` outcomes.
- `password` and `publickey` authentication methods.
- Entries labelled `invalid user`.
- ISO timestamps containing timezone information.
- Valid IPv4 or IPv6 addresses.
- Port numbers from 1 to 65535.

Blank lines are ignored. Unsupported or invalid non-empty lines are counted as skipped.

The parser does not support every Linux authentication log format. Traditional syslog timestamps without timezone information are not supported by the current implementation.

## Sample Results

With the default threshold of five failures within five minutes, the supplied synthetic dataset produces:

| Result | Count |
|---|---:|
| Parsed events | 10 |
| Skipped non-empty lines | 0 |
| Failed logins | 7 |
| Successful logins | 3 |
| Security alerts | 2 |

Both alerts relate to `192.0.2.50` on `lab-server`:

1. Five failed logins between 09:05:00 and 09:06:20 UTC.
2. A successful login for `admin` at 09:06:40 UTC following those failures.

A single failed login followed by a successful login for `bob` does not reach the default detection threshold.

View the sample outputs:

- [CSV alerts](reports/alerts.csv)
- [Markdown investigation report](reports/investigation_report.md)

The Markdown report includes summary counts, alert details, interpretation limits, and an investigation checklist. Checklist items require manual review.

## Run the Tests

From the project root:

```bash
python3 -m unittest discover -s tests -v
```

The current suite contains 28 tests.

| Test group | Count |
|---|---:|
| Parser and detection | 14 |
| CSV and Markdown reporting | 6 |
| Command-line interface | 8 |
| Total | 28 |

### Parser and Detection Tests

Fourteen tests cover:

- Parsing a valid login.
- Recognising an invalid-user entry.
- Rejecting malformed log entries.
- Rejecting invalid IP addresses.
- Avoiding an alert for a single login mistake.
- Detecting five failures within the time window.
- Detecting a successful login following repeated failures.
- Excluding expired failures.
- Keeping different source IPs separate.
- Avoiding a success-after-failures alert for a different username.
- Including failures exactly at the five-minute boundary.
- Excluding failures just outside the five-minute window.
- Keeping different servers separate.
- Processing out-of-order events correctly.

### Reporting Tests

Six tests cover:

- Preserving alert details in CSV output.
- Writing CSV headers when there are no alerts.
- Prefixing a formula-like username in CSV output.
- Including summary counts and alert details in Markdown.
- Including an appropriate message when no alerts are detected.
- Escaping HTML in a log-derived username.

### Command-Line Tests

Eight integration tests cover:

- Displaying the help menu.
- Generating two alerts and both reports from the sample.
- Generating no alerts with a higher threshold.
- Rejecting a zero threshold.
- Rejecting a negative time window.
- Rejecting a non-numeric threshold.
- Returning an error for a missing input file.
- Preventing a report from overwriting the input at the same resolved path.

The command-line tests launch the actual CLI as a subprocess.

Reporting tests and command-line tests that generate reports use temporary directories, so they do not overwrite the sample reports.

## Automated Testing with GitHub Actions

The [Python Tests workflow](.github/workflows/test.yml) runs the test suite:

- On pushes to the repository.
- On pull requests.
- When started manually through GitHub Actions.

The workflow uses an Ubuntu runner and Python 3.14. It checks out the repository and runs:

```bash
python -m unittest discover -s tests -v
```

No third-party dependencies need to be installed.

View workflow runs and test logs on the [Actions page](https://github.com/tshephelkdb17/security-log-analyser/actions).

The badge at the top of this README displays the workflow status for the `main` branch.

Passing tests confirm the behaviours covered by the test suite. They do not guarantee that the analyser detects every attack or contains no defects.

## Investigation Approach

When reviewing an alert:

1. Check the original authentication entries and timestamps.
2. Confirm whether the source IP and account activity are expected.
3. Determine whether successful access was authorised.
4. Correlate the login with other available system activity.
5. Record the evidence, uncertainty, and recommended response.

A successful login after repeated failures warrants investigation, but legitimate user errors or misconfigured clients can also produce this pattern.

## Limitations

- Supports the specific SSH log format demonstrated in the sample file, not every Linux authentication log format.
- Performs offline analysis rather than live monitoring.
- Loads parsed events into memory and sorts them; large-scale performance has not been assessed.
- Does not deduplicate repeated input entries.
- Does not detect distributed attacks or attempts spread beyond the configured time window.
- Shared IP addresses and legitimate user errors can produce false positives.
- Repeated-failure alerts are emitted whenever the rolling count equals the threshold after a new failure; overlapping windows can produce additional alerts.
- Successful logins do not clear earlier failures, so multiple subsequent successes can each produce an alert.
- CSV export prefixes certain formula-leading text characters with an apostrophe, which changes their exported representation.
- Unsupported or invalid log entries are excluded from detection.
- A report with no alerts does not establish that the system is secure.
- Reports do not yet include the input filename and configured detection settings.
- Report files are written sequentially; if one export fails, the other may already have been updated.
- Does not automatically block IP addresses or disable accounts.

## Planned Improvements

- Include the input filename and configured detection thresholds in reports.
- Expand automated testing across additional Python versions and operating systems.

## Sample Data

All supplied authentication entries are fictional. The sample IP addresses are from the documentation range `192.0.2.0/24`.