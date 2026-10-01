import unittest
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import analyzer


class AnalyzerTests(unittest.TestCase):
    def test_parse_valid_log_line(self):
        line = "2026-09-23 10:01:05 LOGIN_FAILED 192.168.1.15 admin"

        entry, warning = analyzer.parse_log_line(line, 1)

        self.assertIsNone(warning)
        self.assertEqual(entry["date"], "2026-09-23")
        self.assertEqual(entry["time"], "10:01:05")
        self.assertEqual(entry["event_type"], "LOGIN_FAILED")
        self.assertEqual(entry["ip_address"], "192.168.1.15")
        self.assertEqual(entry["username"], "admin")

    def test_parse_malformed_log_line(self):
        entry, warning = analyzer.parse_log_line("bad log line", 7)

        self.assertIsNone(entry)
        self.assertIn("malformed", warning)

    def test_detect_brute_force_from_sample_logs(self):
        entries, warnings = analyzer.read_logs(analyzer.LOG_FILE)

        brute_force_alerts = analyzer.detect_brute_force(entries)
        alert_ips = {alert["ip_address"] for alert in brute_force_alerts}

        self.assertIn("192.168.1.15", alert_ips)
        self.assertIn("192.168.1.55", alert_ips)
        self.assertGreaterEqual(len(warnings), 1)

    def test_detect_password_spraying_from_sample_logs(self):
        entries, _ = analyzer.read_logs(analyzer.LOG_FILE)

        spraying_alerts = analyzer.detect_password_spraying(entries)
        alert_ips = {alert["ip_address"] for alert in spraying_alerts}

        self.assertIn("10.0.0.44", alert_ips)
        self.assertIn("10.0.0.77", alert_ips)

    def test_detect_suspicious_success_from_sample_logs(self):
        entries, _ = analyzer.read_logs(analyzer.LOG_FILE)

        compromise_alerts = analyzer.detect_suspicious_success(entries)
        alert_pairs = {
            (alert["ip_address"], alert["username"])
            for alert in compromise_alerts
        }

        self.assertIn(("172.16.0.9", "finance"), alert_pairs)


if __name__ == "__main__":
    unittest.main()
