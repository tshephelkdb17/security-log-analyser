# Security Log Analyser

A Python tool that analyses SSH authentication logs, identifies suspicious login patterns, and exports alerts to CSV and a readable Markdown investigation report.

This educational cybersecurity project demonstrates log parsing, time-based detection, input validation, automated testing, and reporting using Python’s standard library.

## Features

- Parse SSH authentication entries with timezone-aware ISO timestamps.
- Extract server, username, source IP, authentication method, and outcome.
- Validate timestamps, IP addresses, and port numbers.
- Count successful and failed logins.
- Detect repeated failures within a rolling time window.
- Identify successful logins following repeated failures for the same account.
- Count unsupported or invalid non-empty log lines.
- Export alerts to CSV.
- Generate a Markdown investigation report with an alert summary and review checklist.
- Escape log-derived text in Markdown reports.
- Prefix certain formula-leading text characters in CSV exports.
- Include synthetic sample logs and 16 automated tests.

## Detection Rules

The default threshold is five failures within five minutes.

| Alert | Detection logic |
|---|---|
| `REPEATED_FAILURES` | Generated when the rolling failure count reaches five for the same server and source IP. Failures may involve different usernames. |
| `SUCCESS_AFTER_FAILURES` | Generated when a successful login follows at least five failures for the same server, source IP, and username within the preceding five minutes. Failures labelled “invalid user” are excluded from this account-specific check. |

Events are sorted by timestamp before analysis. Events exactly five minutes apart are included in the window.

Thresholds can be changed through the `threshold` and `window_minutes` arguments to `detect_suspicious_activity()`.

For repeated-failure alerts, the reported username belongs to the event that triggered the alert. It does not necessarily represent every account included in the failure count.

Alerts are investigation leads, not proof of a compromised account.

## Project Files

| File | Purpose |
|---|---|
| `src/analyser.py` | Parser, detection logic, terminal output, and CSV exporter |
| `src/reporting.py` | Markdown report generation and text escaping |
| `tests/test_analyser.py` | Ten parser and detection tests |
| `tests/test_reporting.py` | Six CSV and Markdown export tests |
| `data/sample_auth.log` | Fictional SSH authentication events |
| `reports/alerts.csv` | Generated sample alerts |
| `reports/investigation_report.md` | Generated investigation report |
| `.gitignore` | Excludes the virtual environment and temporary files |

## Setup

Developed and tested using Python 3.14.3 on macOS. No third-party Python packages are required.

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

From the project root:

```bash
python3 src/analyser.py
```

The script reads:

```text
data/sample_auth.log
```

It displays parsed login events, summary counts, and alerts in the terminal, then generates:

- `reports/alerts.csv`
- `reports/investigation_report.md`

Each run replaces the previous contents of both reports.

The input path is currently configured in `main()`; there is no command-line input-file option yet.

## Supported Log Format

The parser supports SSH authentication entries in the format demonstrated below:

```text
2026-11-02T09:00:00+00:00 lab-server sshd[1001]: Accepted publickey for alice from 192.0.2.10 port 51001 ssh2
```

Supported entries include:

- `Accepted` and `Failed` outcomes.
- `password` and `publickey` authentication methods.
- Failed attempts labelled `invalid user`.
- ISO timestamps containing timezone information.

Blank lines are ignored. Unsupported or invalid non-empty lines are counted as skipped.

## Sample Results

The supplied synthetic dataset produces:

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

A single failed login followed by a successful login for `bob` does not reach the detection threshold.

View the sample outputs:

- [CSV alerts](reports/alerts.csv)
- [Markdown investigation report](reports/investigation_report.md)

The Markdown report includes summary counts, alert details, interpretation limits, and an investigation checklist. Checklist items require manual review.

## Run the Tests

From the project root:

```bash
python3 -m unittest discover -s tests -v
```

The current suite contains 16 tests.

### Parser and Detection Tests

Ten tests cover:

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

### Reporting Tests

Six tests cover:

- Preserving alert details in CSV output.
- Writing CSV headers when there are no alerts.
- Prefixing a formula-like username in CSV output.
- Including summary counts and alert details in Markdown.
- Including an appropriate message when no alerts are detected.
- Escaping HTML in a log-derived username.

Reporting tests use temporary directories and do not overwrite the sample reports.

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
- A report with no alerts does not establish that the system is secure.
- Does not automatically block IP addresses or disable accounts.

## Planned Improvements

- Command-line options for input files and thresholds.
- Additional time-boundary, host-separation, and out-of-order event tests.
- Automated test execution through GitHub Actions.
- Include the input filename and configured detection thresholds in reports.

## Sample Data

All supplied authentication entries are fictional. The sample IP addresses are from the documentation range `192.0.2.0/24`.