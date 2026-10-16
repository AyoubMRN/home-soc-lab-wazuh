from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from tools.replay_ssh import run_case, read_sources


class ReplayRunnerTests(unittest.TestCase):
    def output(self, rule="5760", level="5"):
        return f"**Phase 3: Completed filtering (rules).\n        id: '{rule}'\n        level: '{level}'\n"

    def test_matching_verdict_passes_and_uses_stdin(self):
        process = subprocess.CompletedProcess([], 0, self.output(), "")
        with patch("tools.replay_ssh.subprocess.run", return_value=process) as run:
            self.assertTrue(run_case(Path("logtest"), ["source"], [("5760", "5")])["passed"])
            self.assertEqual(run.call_args.kwargs["input"], "source\n")
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_wrong_level_fails(self):
        with patch("tools.replay_ssh.subprocess.run", return_value=subprocess.CompletedProcess([], 0, self.output(level="10"), "")):
            self.assertFalse(run_case(Path("logtest"), ["source"], [("5760", "5")])["passed"])

    def test_normal_verdict_on_stderr_passes(self):
        with patch("tools.replay_ssh.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", self.output())):
            result = run_case(Path("logtest"), ["source"], [("5760", "5")])
            self.assertTrue(result["passed"])
            self.assertEqual(result["stdout"], "")
            self.assertIn("Phase 3", result["stderr"])

    def test_unexpected_extra_verdict_fails(self):
        with patch("tools.replay_ssh.subprocess.run", return_value=subprocess.CompletedProcess([], 0, self.output(), self.output())):
            self.assertFalse(run_case(Path("logtest"), ["source"], [("5760", "5")])["passed"])

    def test_missing_phase_three_fails(self):
        with patch("tools.replay_ssh.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "raw text id: '5763' level: '10'", "")):
            self.assertFalse(run_case(Path("logtest"), ["source"], [("5763", "10")])["passed"])

    def test_engine_error_fails_even_with_expected_verdict(self):
        with patch("tools.replay_ssh.subprocess.run", return_value=subprocess.CompletedProcess([], 1, self.output(), "error")):
            self.assertFalse(run_case(Path("logtest"), ["source"], [("5760", "5")])["passed"])

    def test_empty_fixture_rejected(self):
        with patch.object(Path, "read_text", return_value=""):
            with self.assertRaisesRegex(ValueError, "eight"):
                read_sources(Path("unused"))


if __name__ == "__main__":
    unittest.main()
