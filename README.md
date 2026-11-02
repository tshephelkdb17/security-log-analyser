# Security Log Analyser

A Python tool that analyses SSH authentication logs, identifies suspicious login patterns, and exports alerts to CSV.

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
- Include synthetic sample logs and 10 automated tests.

## Detection Rules

The default threshold is five failures within five minutes.

| Alert | Detection logic |
|---|---|
| REPEATED_FAILURES | Generated when the rolling failure count reaches five for the same server and source IP. Failures may involve different usernames. |
| SUCCESS_AFTER_FAILURES | Generated when a successful login follows at least five failures for the same server, source IP, and username within the preceding five minutes. Failures labelled “invalid user” are excluded from this account-specific check. |

Events are sorted by timestamp before analysis. Events exactly five minutes apart are included in the window.

Thresholds can be changed through the `threshold` and `window_minutes` arguments to `detect_suspicious_activity()`.

Alerts are investigation leads, not proof of a compromised account.

## Project Files

| File | Purpose |
|---|---|
| `src/analyser.py` | Parser, detection logic, terminal output, and CSV exporter |
| `tests/test_analyser.py` | Automated parser and detection tests |
| `data/sample_auth.log` | Fictional SSH authentication events |
| `reports/alerts.csv` | Generated sample alerts |
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

The script reads `data/sample_auth.log` and writes `reports/alerts.csv`. Each run replaces the previous CSV report.

The input path is currently configured in `main()`; there is no command-line input-file option yet.

## Sample Results

The supplied synthetic dataset contains:

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

View the generated output in [reports/alerts.csv](reports/alerts.csv).

## Run the Tests

From the project root:

```bash
python3 -m unittest discover -s tests -v
```

The 10 tests cover:

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

The current tests cover parsing and detection; CSV export tests are a planned improvement.

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
- Does not automatically block IP addresses or disable accounts.

## Investigation Approach

When reviewing an alert:

1. Check the original authentication entries and timestamps.
2. Confirm whether the source IP and account activity are expected.
3. Correlate the login with other available system activity.
4. Record the evidence, uncertainty, and recommended response.

## Planned Improvements

- Markdown investigation reports.
- Command-line options for input files and thresholds.
- Additional boundary, host-separation, and export tests.
- Automated test execution through GitHub Actions.

## Sample Data

All supplied authentication entries are fictional. The sample IP addresses are from the documentation range `192.0.2.0/24`.