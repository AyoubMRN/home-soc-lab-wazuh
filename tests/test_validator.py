import json
from pathlib import Path
import unittest
from unittest.mock import patch
from tools.validate_evidence import load, check_source, ssh


class InvalidEvidenceTests(unittest.TestCase):
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
