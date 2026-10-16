import json
from pathlib import Path
import unittest
from unittest.mock import patch
from tools.generate_report import read_alert, render, decoded_script, render_correlations, render_task, read_task, render_ssh


class ReportTests(unittest.TestCase):
    def test_ssh_source_log_is_escaped(self):
        row = {"timestamp": "2026-10-16T17:14:42+0000", "agent": {"id": "001", "name": "Ubuntu-Endpoint"}, "rule": {"id": "5763", "level": 10, "frequency": 8, "description": "sshd test"}, "data": {"srcip": "192.168.56.1", "srcport": "61628", "dstuser": "vboxuser"}, "full_log": "<script>bad()</script>"}
        result = render_ssh([row])
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("ne rejoue pas le moteur", result)

    def test_task_text_escaped_and_execution_limit_explicit(self):
        row = {"timestamp": "2026-10-15T16:18:12+0000", "agent": {"id": "002", "name": "host"}, "rule": {"id": "67014", "level": 3, "description": "<script>bad</script>"}, "data": {"win": {"system": {"systemTime": "2026-10-15T16:18:02Z", "eventID": "106", "eventRecordID": "15", "channel": "TaskScheduler"}, "eventdata": {"taskName": "<img src=x>"}}}}
        result = render_task(row)
        self.assertNotIn("<script>", result)
        self.assertNotIn("<img src=x>", result)
        self.assertIn("Non démontrée", result)
        self.assertIn("ne prouve pas l’exécution", result)

    def test_task_validation_failure_prevents_loading(self):
        with patch("tools.generate_report.task", side_effect=ValueError("task identity mismatch")):
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                read_task(Path("unused"))

    def correlation_row(self, second, rule, record):
        return {"timestamp": f"2026-10-15T15:37:{second}+0000", "agent": {"id": "002", "name": "host"}, "rule": {"id": rule}, "data": {"win": {"system": {"eventRecordID": record}, "eventdata": {"image": "C:\\Windows\\whoami.exe"}}}}

    def test_correlation_sorts_display_without_mutating_input(self):
        rows = [self.correlation_row("36", "100110", "second-record"), self.correlation_row("30", "100103", "first-record")]
        result = render_correlations([("test", "test.jsonl", rows)])
        self.assertLess(result.index("first-record"), result.index("second-record"))
        self.assertEqual(rows[0]["rule"]["id"], "100110")
        self.assertIn("+6.000 s", result)

    def test_correlation_absence_is_scoped_to_export(self):
        result = render_correlations([("test", "test.jsonl", [self.correlation_row("30", "100103", "1")])])
        self.assertIn("Aucune 100110 dans l’export sélectionné", result)
        self.assertIn("cause reste ouverte", result)

    def test_correlation_log_text_is_escaped(self):
        row = self.correlation_row("30", "100103", "<script>bad</script>")
        result = render_correlations([("<img src=x>", "test.jsonl", [row])])
        self.assertNotIn("<script>", result)
        self.assertNotIn("<img src=x>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_html_in_logs_is_displayed_as_text(self):
        row = {"timestamp": "2026-10-15T16:00:00+0000", "agent": {"id": "002", "name": "<script>alert(1)</script>"}, "rule": {"id": "92027", "level": 4, "description": "<img src=x onerror=alert(1)>"}, "data": {"win": {"eventdata": {"commandLine": "<script>bad()</script>"}}}}
        result = render([row, row])
        self.assertNotIn("<script>", result)
        self.assertNotIn("<img src=", result)
        self.assertIn("&lt;script&gt;", result)

    def test_decoding_reads_text_only(self):
        self.assertEqual(decoded_script("powershell -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA"), "Write-Output")

    def test_missing_command_fails_with_explanation(self):
        row = {"timestamp": "2026-10-15T16:00:00+0000", "agent": {"id": "002", "name": "host"}, "rule": {"id": "92027", "level": 4, "description": "test"}, "data": {"win": {"eventdata": {}}}}
        with patch.object(Path, "read_text", return_value=json.dumps(row)):
            with self.assertRaisesRegex(ValueError, "commandLine"):
                read_alert(Path("fixture"))

    def test_empty_input_fails(self):
        with patch.object(Path, "read_text", return_value=""):
            with self.assertRaisesRegex(ValueError, "exactly one"):
                read_alert(Path("fixture"))

    def test_invalid_json_fails(self):
        with patch.object(Path, "read_text", return_value="{bad"):
            with self.assertRaises(json.JSONDecodeError):
                read_alert(Path("fixture"))


if __name__ == "__main__":
    unittest.main()
