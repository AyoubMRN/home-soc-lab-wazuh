"""Replay the recorded SSH count-boundary tests on a Wazuh manager.

Usage: sudo /var/ossec/framework/python/bin/python3 replay_ssh.py FIXTURE
Only invokes wazuh-logtest; no SSH connections, config edits or restarts.
The two sessions stream events immediately; they do not test timing boundaries.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


def read_sources(path):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    if len(rows) != 8:
        raise ValueError("Expected exactly eight recorded alerts")
    sources = []
    for row in rows:
        if row["agent"]["id"] != "001" or row["data"]["srcip"] != "192.168.56.1" or row["data"]["dstuser"] != "vboxuser":
            raise ValueError("Unexpected agent, source or target in SSH fixture")
        raw = row["full_log"]
        if not isinstance(raw, str) or not raw or "\n" in raw or "\r" in raw:
            raise ValueError("Expected one nonempty source log line per alert")
        sources.append(raw)
    if len(set(sources)) != 8:
        raise ValueError("Duplicate source log records")
    return sources


def run_case(binary, sources, expected):
    result = subprocess.run([str(binary), "-l", "journald"], input="\n".join(sources) + "\n",
                            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)
    # Read only phase-3 verdicts, not rule IDs inside raw log text.
    # Wazuh can write normal test results to stderr; stderr is not an error verdict.
    # Keep both streams separately in the report, inspect both for phase-3 results.
    output = result.stdout + "\n" + result.stderr
    verdicts = re.findall(r"\*\*Phase 3: Completed filtering \(rules\)\.\s+id: '([0-9]+)'\s+level: '([0-9]+)'", output)
    passed = result.returncode == 0 and verdicts == expected
    return {"passed": passed, "events": len(sources), "returncode": result.returncode,
            "expected": [list(pair) for pair in expected], "observed": [list(pair) for pair in verdicts],
            "stdout": result.stdout, "stderr": result.stderr}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--binary", type=Path, default=Path("/var/ossec/bin/wazuh-logtest"))
    parser.add_argument("--output", type=Path, help="New JSON result file; existing files are never overwritten")
    args = parser.parse_args()
    try:
        sources = read_sources(args.fixture)
        # Open output exclusively before running, to avoid losing a report to an overwrite error.
        handle = args.output.open("x", encoding="utf-8") if args.output else None
        try:
            cases = []
            for size, expected in ((7, [("5760", "5")] * 7), (8, [("5760", "5")] * 7 + [("5763", "10")])):
                case = run_case(args.binary, sources[:size], expected)
                cases.append(case)
                print(("PASS" if case["passed"] else "FAIL") + f": {size} SSH source events")
                if not case["passed"]:
                    print("Expected:", case["expected"])
                    print("Observed:", case["observed"])
                    if case["stderr"]:
                        print(case["stderr"], file=sys.stderr)
            if handle:
                json.dump({"scope": "SSH native-engine count-boundary replay; original delays not reproduced",
                           "fixture": str(args.fixture), "cases": cases}, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
        finally:
            if handle:
                handle.close()
        print("No SSH connection or configuration change performed. Timing boundary not tested.")
        return 0 if all(case["passed"] for case in cases) else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print("Replay failed:", exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
