import json
from copy import deepcopy
from pathlib import Path
import unittest
from unittest.mock import patch
from tools.validate_evidence import load, check_source, correlation, task, ssh


class InvalidEvidenceTests(unittest.TestCase):
    fixtures = Path(__file__).parent / "fixtures"

    def test_correlation_swapped_process_data_is_rejected(self):
        rows = load(self.fixtures / "correlation-mixed-four.alerts.jsonl")
        left, right = (row["data"]["win"] for row in rows[:2])
        left["eventdata"], right["eventdata"] = right["eventdata"], left["eventdata"]
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, "source process data mismatch"):
                correlation(Path("unused"), "case.jsonl", None,
                            {"100100": 1, "100102": 1, "100103": 1, "100110": 1}, mixed=True)

    def test_source_command_mismatch_is_rejected(self):
        for filename in ("correlation-whoami-three.alerts.jsonl", "powershell-comparison.archives.jsonl"):
            with self.subTest(filename=filename):
                row = load(self.fixtures / filename)[0]
                row["data"]["win"]["eventdata"]["commandLine"] = "different command"
                with self.assertRaisesRegex(ValueError, "source process data mismatch"):
                    check_source(row)

    def test_correlation_early_alert_is_rejected(self):
        for filename, counts, mixed in (
            ("correlation-whoami-four.alerts.jsonl", {"100103": 3, "100110": 1}, False),
            ("correlation-mixed-four.alerts.jsonl", {"100100": 1, "100102": 1, "100103": 1, "100110": 1}, True),
        ):
            with self.subTest(filename=filename):
                rows = sorted(load(self.fixtures / filename), key=lambda row: row["timestamp"])
                rows[0]["rule"], rows[-1]["rule"] = rows[-1]["rule"], rows[0]["rule"]
                with patch("tools.validate_evidence.load", return_value=rows):
                    with self.assertRaisesRegex(ValueError, "correlation must be the last"):
                        correlation(Path("unused"), "case.jsonl", None, counts, mixed=mixed)

    def test_correlation_reversed_file_order_passes_without_mutation(self):
        rows = list(reversed(load(self.fixtures / "correlation-whoami-four.alerts.jsonl")))
        before = deepcopy(rows)
        with patch("tools.validate_evidence.load", return_value=rows):
            correlation(Path("unused"), "case.jsonl", None, {"100103": 3, "100110": 1})
        self.assertEqual(rows, before)

    def test_correlation_tied_final_alert_is_rejected(self):
        rows = sorted(load(self.fixtures / "correlation-whoami-four.alerts.jsonl"), key=lambda row: row["timestamp"])
        rows[-1]["timestamp"] = rows[-2]["timestamp"]
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, "correlation must be the last"):
                correlation(Path("unused"), "case.jsonl", None, {"100103": 3, "100110": 1})

    def test_ssh_intermediate_source_outside_window_is_rejected(self):
        for source_time in ("17:00:00", "17:16:00", "17:12:07"):
            with self.subTest(source_time=source_time):
                rows = self.ssh_fixture()
                self.replace_ssh_source_time(rows, 3, source_time)
                with patch("tools.validate_evidence.load", return_value=rows):
                    with self.assertRaisesRegex(ValueError, "source time window"):
                        ssh(Path("unused"))

    def test_ssh_source_window_uses_all_events_without_requiring_source_order(self):
        rows = self.ssh_fixture()
        self.replace_ssh_source_time(rows, 3, "17:12:08")  # 119 seconds before the last source.
        with patch("tools.validate_evidence.load", return_value=rows):
            self.assertEqual(len(ssh(Path("unused"))), 8)

    def replace_ssh_source_time(self, rows, index, source_time):
        old = rows[index]["full_log"]
        new = "Oct 16 " + source_time + old[15:]
        rows[index]["full_log"] = new
        rows[-1]["previous_output"] = rows[-1]["previous_output"].replace(old, new)

    def test_correlation_single_computer_passes(self):
        correlation(self.fixtures, "correlation-whoami-three.alerts.jsonl", None, {"100103": 3})

    def test_correlation_mixed_computers_are_rejected(self):
        rows = load(self.fixtures / "correlation-whoami-three.alerts.jsonl")
        rows[1]["data"]["win"]["system"]["computer"] = "Other-Endpoint"
        raw = json.loads(rows[1]["full_log"])
        raw["win"]["system"]["computer"] = "Other-Endpoint"
        rows[1]["full_log"] = json.dumps(raw)
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, "single non-empty computer"):
                correlation(Path("unused"), "case.jsonl", None, {"100103": 3})

    def test_correlation_empty_computer_is_rejected(self):
        rows = load(self.fixtures / "correlation-whoami-three.alerts.jsonl")
        for row in rows:
            row["data"]["win"]["system"]["computer"] = ""
            raw = json.loads(row["full_log"])
            raw["win"]["system"]["computer"] = ""
            row["full_log"] = json.dumps(raw)
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, "single non-empty computer"):
                correlation(Path("unused"), "case.jsonl", None, {"100103": 3})

    def test_task_provider_mismatch_is_rejected(self):
        self.assert_task_field_rejected("providerName", "Other-Provider", "provider mismatch")

    def test_task_source_time_mismatch_is_rejected(self):
        self.assert_task_field_rejected("systemTime", "2026-10-15T16:18:03.0773493Z", "source time mismatch")

    def test_task_channel_mismatch_is_rejected(self):
        self.assert_task_field_rejected("channel", "Other-Channel", "channel mismatch")

    def assert_task_field_rejected(self, field, value, message):
        rows = load(self.fixtures / "scheduled-task-created.alerts.jsonl")
        rows[0]["data"]["win"]["system"][field] = value
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, message):
                task(self.fixtures)

    def ssh_fixture(self):
        rows = []
        for index in range(8):
            raw = f"Oct 16 17:14:0{index} Ubuntu-Endpoint sshd[{2000+index}]: Failed password for vboxuser from 192.168.56.1 port {61000+index} ssh2"
            rows.append({"timestamp": f"2026-10-16T17:14:0{index}+0000", "id": str(index), "rule": {"id": "5760" if index < 7 else "5763", "level": 5 if index < 7 else 10, "frequency": 8}, "decoder": {"name": "sshd"}, "data": {"srcip": "192.168.56.1", "dstuser": "vboxuser", "srcport": str(61000+index)}, "full_log": raw})
        rows[-1]["previous_output"] = "\n".join(r["full_log"] for r in rows[:-1])
        return rows

    def test_ssh_wrong_source_is_rejected(self):
        rows = self.ssh_fixture()
        rows[0]["data"]["srcip"] = "192.168.56.99"
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, "source IP"):
                ssh(Path("unused"))

    def test_ssh_duplicate_history_is_rejected(self):
        rows = self.ssh_fixture()
        rows[-1]["previous_output"] += "\n" + rows[0]["full_log"]
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, "history"):
                ssh(Path("unused"))

    def test_ssh_missing_failure_is_rejected(self):
        rows = self.ssh_fixture()[1:]
        with patch("tools.validate_evidence.load", return_value=rows):
            with self.assertRaisesRegex(ValueError, "sequence"):
                ssh(Path("unused"))

    def test_ssh_complete_history_passes(self):
        with patch("tools.validate_evidence.load", return_value=self.ssh_fixture()):
            self.assertEqual(len(ssh(Path("unused"))), 8)

    def test_invalid_json_is_rejected(self):
        with patch.object(Path, "read_text", return_value="{broken"):
            with self.assertRaises(json.JSONDecodeError):
                load(Path("unused"))

    def test_empty_export_is_rejected(self):
        with patch.object(Path, "read_text", return_value="\n"):
            with self.assertRaisesRegex(ValueError, "empty"):
                load(Path("unused"))

    def test_wrong_agent_is_rejected(self):
        with patch.object(Path, "read_text", return_value='{"agent":{"id":"001"}}'):
            with self.assertRaisesRegex(ValueError, "agent"):
                load(Path("unused"))

    def test_missing_source_is_rejected(self):
        with self.assertRaises(KeyError):
            check_source({})

    def test_mismatched_source_identity_is_rejected(self):
        source = {"system": {"providerName": "A", "eventID": "1", "eventRecordID": "10", "computer": "host"}}
        decoded = {"system": dict(source["system"], eventRecordID="11")}
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            check_source({"full_log": json.dumps({"win": source}), "data": {"win": decoded}})


if __name__ == "__main__":
    unittest.main()
