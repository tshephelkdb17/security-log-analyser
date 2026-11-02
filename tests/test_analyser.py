import unittest
from datetime import datetime, timedelta, timezone

from src.analyser import parse_log_line, detect_suspicious_activity


def make_event(seconds, outcome="Failed", username="admin",
               ip="192.0.2.50", host="lab-server"):
    """Create a fictional event for testing."""
    return {
        "timestamp": (
            datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)
            + timedelta(seconds=seconds)
        ),
        "host": host,
        "outcome": outcome,
        "method": "password",
        "invalid_user": False,
        "username": username,
        "ip": ip,
        "port": 52001,
    }


class ParserTests(unittest.TestCase):
    def test_valid_login(self):
        line = (
            "2026-11-02T09:00:00+00:00 lab-server sshd[1001]: "
            "Accepted password for alice from 192.0.2.10 "
            "port 51001 ssh2"
        )

        event = parse_log_line(line)

        assert event is not None, "Expected the sample log to parse successfully"
        self.assertEqual(event["username"], "alice")
        self.assertEqual(event["ip"], "192.0.2.10")
        self.assertEqual(event["outcome"], "Accepted")

    def test_invalid_user(self):
        line = (
            "2026-11-02T09:00:00+00:00 lab-server sshd[1001]: "
            "Failed password for invalid user test from 192.0.2.60 "
            "port 53001 ssh2"
        )

        event = parse_log_line(line)

        assert event is not None, "Expected the sample log to parse successfully"
        self.assertTrue(event["invalid_user"])
        self.assertEqual(event["username"], "test")

    def test_malformed_line(self):
        self.assertIsNone(parse_log_line("This is not an SSH log"))

    def test_invalid_ip(self):
        line = (
            "2026-11-02T09:00:00+00:00 lab-server sshd[1001]: "
            "Failed password for admin from 999.999.999.999 "
            "port 52001 ssh2"
        )

        self.assertIsNone(parse_log_line(line))


class DetectionTests(unittest.TestCase):
    def test_single_mistake_does_not_alert(self):
        events = [
            make_event(0),
            make_event(20, outcome="Accepted"),
        ]

        self.assertEqual(detect_suspicious_activity(events), [])

    def test_five_failures_trigger_alert(self):
        events = [make_event(seconds) for seconds in (0, 20, 40, 60, 80)]

        alerts = detect_suspicious_activity(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "REPEATED_FAILURES")

    def test_success_after_failures(self):
        events = [make_event(seconds) for seconds in (0, 20, 40, 60, 80)]
        events.append(make_event(100, outcome="Accepted"))

        alerts = detect_suspicious_activity(events)

        self.assertEqual(
            [alert["type"] for alert in alerts],
            ["REPEATED_FAILURES", "SUCCESS_AFTER_FAILURES"],
        )

    def test_old_failures_do_not_count(self):
        events = [make_event(seconds) for seconds in (0, 301, 602, 903, 1204)]

        self.assertEqual(detect_suspicious_activity(events), [])

    def test_different_ips_are_not_combined(self):
        events = [
            make_event(index * 20, ip=f"192.0.2.{index + 1}")
            for index in range(5)
        ]

        self.assertEqual(detect_suspicious_activity(events), [])

    def test_success_for_different_user_is_not_flagged(self):
        events = [make_event(seconds) for seconds in (0, 20, 40, 60, 80)]
        events.append(make_event(100, outcome="Accepted", username="alice"))

        alerts = detect_suspicious_activity(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "REPEATED_FAILURES")

    def test_failures_exactly_five_minutes_apart_are_included(self):
        # The first and fifth failures are exactly 300 seconds apart.
        events = [
            make_event(seconds)
            for seconds in (0, 60, 120, 180, 300)
        ]

        alerts = detect_suspicious_activity(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["type"], "REPEATED_FAILURES")
        self.assertEqual(alerts[0]["failure_count"], 5)
        self.assertEqual(alerts[0]["timestamp"], events[-1]["timestamp"])

    def test_failure_just_outside_five_minutes_is_excluded(self):
        # At 301 seconds, the first failure has expired.
        # Only four failures remain inside the rolling window.
        events = [
            make_event(seconds)
            for seconds in (0, 60, 120, 180, 301)
        ]

        self.assertEqual(detect_suspicious_activity(events), [])

    def test_different_hosts_are_not_combined(self):
        # Same IP and username, but failures belong to two servers.
        # Neither server independently reaches five failures.
        events = [
            make_event(0, host="server-a"),
            make_event(20, host="server-b"),
            make_event(40, host="server-a"),
            make_event(60, host="server-b"),
            make_event(80, host="server-a"),
            make_event(100, outcome="Accepted", host="server-b"),
        ]

        self.assertEqual(detect_suspicious_activity(events), [])

    def test_out_of_order_events_produce_correct_alerts(self):
        ordered_events = [
            make_event(seconds)
            for seconds in (0, 20, 40, 60, 80)
        ]
        ordered_events.append(make_event(100, outcome="Accepted"))

        # Put the successful login first in the input.
        unordered_events = [
            ordered_events[index]
            for index in (5, 2, 0, 4, 1, 3)
        ]

        alerts = detect_suspicious_activity(unordered_events)

        self.assertEqual(
            [alert["type"] for alert in alerts],
            ["REPEATED_FAILURES", "SUCCESS_AFTER_FAILURES"],
        )
        self.assertEqual(
            [alert["timestamp"] for alert in alerts],
            [
                ordered_events[4]["timestamp"],
                ordered_events[5]["timestamp"],
            ],
        )
        self.assertEqual(
            [alert["failure_count"] for alert in alerts],
            [5, 5],
        )
        self.assertEqual(
            alerts,
            detect_suspicious_activity(ordered_events),
        )


if __name__ == "__main__":
    unittest.main()