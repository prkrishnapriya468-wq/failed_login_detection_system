"""
test_detector.py - Automated tests. Run with:  python -m unittest -v

Part 1 tests the detection logic in detector.py (no web server needed).
Part 2 tests the Flask app with Flask's built-in test client.
All data below is fictional and uses documentation-only IP addresses.
"""

import io
import os
import unittest

import detector
from app import create_app

IP_A = "198.51.100.23"
IP_B = "203.0.113.44"
IP_C = "192.0.2.10"


def failed_lines(ip, count, user="admin"):
    """Build `count` FAILED log lines for one IP."""
    return "\n".join(f"2026-10-15 09:{i:02d}:00 | {ip} | {user} | FAILED" for i in range(count))


class ParsingTests(unittest.TestCase):
    def test_valid_line_is_parsed_into_four_fields(self):
        event = detector.parse_line("2026-10-15 09:01:00 | 198.51.100.23 | admin | FAILED")
        self.assertEqual(event.to_dict(), {"timestamp": "2026-10-15 09:01:00", "ip": IP_A,
                                           "username": "admin", "status": "FAILED"})

    def test_status_is_case_insensitive(self):
        self.assertEqual(detector.parse_line("2026-10-15 09:01:00 | 192.0.2.10 | bob | success").status, "SUCCESS")

    def test_malformed_lines_are_reported_with_line_numbers(self):
        text = "\n".join([
            "2026-10-15 09:00:00 | 192.0.2.10 | alice | SUCCESS",   # valid
            "not a log line",                                       # wrong field count
            "2026-13-45 09:00:00 | 192.0.2.10 | alice | FAILED",    # bad date
            "2026-10-15 09:00:00 | 999.0.0.1 | alice | FAILED",     # bad IP
            "2026-10-15 09:00:00 | 192.0.2.10 | <b>x</b> | FAILED", # bad username
            "2026-10-15 09:00:00 | 192.0.2.10 | alice | MAYBE",     # bad status
            "x" * 600,                                              # too long
        ])
        result = detector.parse_log(text)
        self.assertEqual(len(result.events), 1)
        self.assertEqual([m.line_number for m in result.malformed], [2, 3, 4, 5, 6, 7])

    def test_blank_lines_and_comments_are_ignored_not_malformed(self):
        result = detector.parse_log("# comment\n\n2026-10-15 09:00:00 | 192.0.2.10 | alice | FAILED\n")
        self.assertEqual((len(result.events), len(result.malformed)), (1, 0))

    def test_ipv6_documentation_address_is_accepted(self):
        self.assertEqual(detector.parse_line("2026-10-15 09:00:00 | 2001:db8::1 | alice | FAILED").ip, "2001:db8::1")


class DetectionTests(unittest.TestCase):
    def test_successful_logins_are_not_counted_as_failures(self):
        text = "\n".join(f"2026-10-15 09:{i:02d}:00 | {IP_A} | admin | SUCCESS" for i in range(10))
        result = detector.analyze_log(text, 5)
        self.assertEqual((result["failed_total"], result["success_total"]), (0, 10))
        self.assertEqual(result["alerts"], [])

    def test_alert_at_exact_threshold(self):
        result = detector.analyze_log(failed_lines(IP_A, 5), 5)
        self.assertEqual([a["ip"] for a in result["alerts"]], [IP_A])

    def test_alert_above_threshold(self):
        result = detector.analyze_log(failed_lines(IP_A, 8), 5)
        self.assertEqual(result["alerts"][0]["failed"], 8)

    def test_no_alert_below_threshold(self):
        result = detector.analyze_log(failed_lines(IP_A, 4), 5)
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["failed_total"], 4)

    def test_failures_are_grouped_per_ip(self):
        text = failed_lines(IP_A, 6) + "\n" + failed_lines(IP_B, 2)
        result = detector.analyze_log(text, 5)
        counts = {row["ip"]: row["failed"] for row in result["per_ip"]}
        self.assertEqual(counts, {IP_A: 6, IP_B: 2})
        self.assertEqual([a["ip"] for a in result["alerts"]], [IP_A])
        self.assertEqual(result["top_ips"][0]["ip"], IP_A)

    def test_default_threshold_is_five(self):
        self.assertEqual(detector.DEFAULT_THRESHOLD, 5)
        self.assertEqual(len(detector.analyze_log(failed_lines(IP_A, 5))["alerts"]), 1)

    def test_malformed_entries_are_reported_separately(self):
        result = detector.analyze_log(failed_lines(IP_A, 2) + "\ngarbage", 5)
        self.assertEqual((result["total_events"], result["malformed_count"]), (2, 1))

    def test_all_lines_malformed_gives_zero_events_without_crashing(self):
        result = detector.analyze_log("garbage\nmore garbage", 5)
        self.assertEqual((result["total_events"], result["malformed_count"]), (0, 2))


class InputValidationTests(unittest.TestCase):
    def test_invalid_thresholds_are_rejected(self):
        for bad in ["abc", "", "0", "-3", "2.5", "100001", None, True, 1.5, [5]]:
            with self.subTest(value=bad):
                with self.assertRaises(detector.InvalidThresholdError):
                    detector.validate_threshold(bad)

    def test_valid_thresholds_are_accepted(self):
        self.assertEqual(detector.validate_threshold("7"), 7)
        self.assertEqual(detector.validate_threshold(" 12 "), 12)
        self.assertEqual(detector.validate_threshold(1), 1)

    def test_empty_inputs_raise_a_friendly_error(self):
        for bad in [b"", b"   \n\n"]:
            with self.subTest(value=bad):
                with self.assertRaises(detector.EmptyLogError):
                    detector.decode_log_bytes(bad)
        with self.assertRaises(detector.EmptyLogError):  # only comments and blank lines
            detector.analyze_log("# only a comment\n\n", 5)

    def test_binary_and_non_utf8_content_is_rejected(self):
        with self.assertRaises(detector.UnreadableLogError):
            detector.decode_log_bytes(b"\x00\x01\x02binary")
        with self.assertRaises(detector.UnreadableLogError):
            detector.decode_log_bytes(b"\xff\xfe\xfa bad bytes")


class CsvExportTests(unittest.TestCase):
    def test_report_csv_has_header_and_one_row_per_ip(self):
        analysis = detector.analyze_log(failed_lines(IP_A, 5) + "\n" + failed_lines(IP_B, 1), 5)
        lines = detector.report_to_csv(analysis).strip().splitlines()
        self.assertEqual(lines[0], "ip,failed_attempts,successful_attempts,needs_investigation,first_failed,last_failed,usernames_targeted")
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[1].startswith(f"{IP_A},5,0,YES"))
        self.assertIn(f"{IP_B},1,0,NO", lines[2])

    def test_events_csv_lists_every_event(self):
        analysis = detector.analyze_log(failed_lines(IP_A, 3), 5)
        self.assertEqual(len(detector.events_to_csv(analysis).strip().splitlines()), 4)

    def test_csv_cells_that_look_like_formulas_are_neutralised(self):
        analysis = detector.analyze_log("2026-10-15 09:00:00 | 192.0.2.10 | -admin | FAILED", 1)
        self.assertIn("'-admin", detector.events_to_csv(analysis))


# ------------------------------------------------------------------ web app
class AppTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app({"TESTING": True})
        self.client = self.app.test_client()

    def token(self, client=None):
        client = client or self.client
        client.get("/")
        with client.session_transaction() as s:
            return s["csrf_token"]

    def upload(self, content, name="test.log", threshold="5", client=None, token=True):
        client = client or self.client
        data = {"threshold": threshold, "logfile": (io.BytesIO(content), name)}
        if token:
            data["csrf_token"] = self.token(client)
        return client.post("/analyze", data=data, content_type="multipart/form-data")

    def test_home_page_loads(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_valid_upload_shows_real_numbers_and_alert(self):
        response = self.upload(failed_lines(IP_A, 6).encode())
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn(IP_A, page)
        self.assertIn("Needs investigation", page)
        self.assertIn('"failed_total": 6', page)

    def test_sample_log_produces_alerts(self):
        sample = os.path.join(os.path.dirname(__file__), "sample_logs.txt")
        with open(sample, "rb") as handle:
            self.upload(handle.read())
        page = self.client.get("/dashboard").get_data(as_text=True)
        for ip in ("198.51.100.23", "192.0.2.77", "203.0.113.44"):
            self.assertIn(ip, page)

    def test_csv_export_after_analysis(self):
        self.upload(failed_lines(IP_A, 5).encode())
        response = self.client.get("/export/report.csv")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "text/csv")
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertIn(IP_A, response.get_data(as_text=True))

    def test_export_without_analysis_redirects(self):
        self.assertEqual(self.client.get("/export/report.csv").status_code, 302)

    def test_reset_clears_analysis(self):
        self.upload(failed_lines(IP_A, 5).encode())
        self.client.post("/reset", data={"csrf_token": self.token()})
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_oversized_upload_is_rejected_safely(self):
        small = create_app({"TESTING": True, "MAX_CONTENT_LENGTH": 2048})
        client = small.test_client()
        response = self.upload(b"A" * 10_000, client=client)
        self.assertEqual(response.status_code, 413)
        self.assertIn("larger than", response.get_data(as_text=True))

    def test_binary_upload_gives_friendly_error(self):
        response = self.upload(b"\x00\x01\x02" * 50)
        self.assertEqual(response.status_code, 302)
        page = self.client.get("/").get_data(as_text=True)
        self.assertIn("does not look like a text log", page)

    def test_empty_upload_gives_friendly_error(self):
        self.upload(b"")
        self.assertIn("empty", self.client.get("/").get_data(as_text=True))

    def test_wrong_extension_is_rejected(self):
        self.upload(failed_lines(IP_A, 5).encode(), name="malware.exe")
        self.assertIn("Only .txt and .log", self.client.get("/").get_data(as_text=True))

    def test_invalid_threshold_is_rejected(self):
        self.upload(failed_lines(IP_A, 5).encode(), threshold="abc")
        self.assertIn("whole number", self.client.get("/").get_data(as_text=True))

    def test_post_without_csrf_token_is_rejected(self):
        self.assertEqual(self.upload(failed_lines(IP_A, 5).encode(), token=False).status_code, 400)

    def test_path_traversal_filename_is_neutralised(self):
        self.upload(failed_lines(IP_A, 5).encode(), name="../../etc/passwd.log")
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertNotIn("..", page.split("Results for")[1].split("</strong>")[0])

    def test_html_in_log_is_escaped_on_the_page(self):
        evil = b"2026-10-15 09:00:00 | 192.0.2.10 | <script>alert(1)</script> | FAILED\n"
        self.upload(evil)
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)

    def test_security_headers_are_present(self):
        response = self.client.get("/")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_sample_download_works(self):
        response = self.client.get("/sample-logs.txt")
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        response.close()

    def test_unknown_page_returns_404(self):
        self.assertEqual(self.client.get("/nope").status_code, 404)


if __name__ == "__main__":
    unittest.main()
