# SSH Security Investigation Report

This report summarises offline log analysis. Alerts require investigation and do not prove a compromise.

## Analysis Summary

| Metric | Count |
|---|---:|
| Parsed events | 10 |
| Skipped non-empty lines | 0 |
| Failed logins | 7 |
| Successful logins | 3 |
| Security alerts | 2 |

## Detected Alerts

### Alert 1: REPEATED\_FAILURES

- **Time:** 2026\-11\-02T09:06:20\+00:00
- **Server:** lab\-server
- **Source IP:** 192\.0\.2\.50
- **Triggering username:** admin
- **Failure count:** 5
- **Finding:** 5 failed logins within 5 minutes

The failure count is grouped by server and source IP. It can include multiple usernames; the triggering username is the account in the event that raised this alert.

### Alert 2: SUCCESS\_AFTER\_FAILURES

- **Time:** 2026\-11\-02T09:06:40\+00:00
- **Server:** lab\-server
- **Source IP:** 192\.0\.2\.50
- **Triggering username:** admin
- **Failure count:** 5
- **Finding:** Successful login for admin after 5 failures within 5 minutes

## Investigation Checklist

- [ ] Review the original log entries around each alert.
- [ ] Confirm whether the source IP and account activity are expected.
- [ ] Check whether successful access was authorised.
- [ ] Correlate the events with other available system logs.
- [ ] Record the conclusion, supporting evidence, and next actions.

## Interpretation Limits

- Mistyped passwords or misconfigured clients can cause false positives.
- Unsupported or invalid log entries are excluded from detection.
- Repeated input entries are not deduplicated.
- The analyser does not block connections or change user accounts.
- Investigation checklist items require manual review.
