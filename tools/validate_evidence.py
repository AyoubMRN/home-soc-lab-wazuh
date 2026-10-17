"""Validate recorded lab evidence, NOT Wazuh detection/replay behavior.

Usage: python validate_evidence.py PATH_TO_EXPORTED_TESTS
Reads evidence without modifying it. Exit 0: all checks pass; exit 1: failures.
"""
import argparse
from collections import Counter
from datetime import datetime
import json
import re
from pathlib import Path
import sys
import xml.etree.ElementTree as ET


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(path, expected_agent="002"):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    require(bool(rows), "empty evidence file")
    for row in rows:
        require(row["agent"]["id"] == expected_agent, "unexpected agent")
        datetime.fromisoformat(row["timestamp"])
    return rows


def event(row):
    return row["data"]["win"]


def check_source(row):
    raw = json.loads(row["full_log"])["win"]
    for key in ("providerName", "eventID", "eventRecordID", "computer"):
        require(raw["system"][key] == event(row)["system"][key], "source identity mismatch: " + key)
    require(raw["eventdata"] == event(row)["eventdata"], "source process data mismatch")


def correlation(folder, name, records, counts, spaced=False, mixed=False):
    rows = load(folder / name)
    require(Counter(r["rule"]["id"] for r in rows) == Counter(counts), "unexpected rule counts")
    computers = [event(r)["system"]["computer"] for r in rows]
    require(all(isinstance(c, str) and c.strip() for c in computers)
            and len(set(computers)) == 1, "expected a single non-empty computer per correlation case")
    ids = [event(r)["system"]["eventRecordID"] for r in rows]
    require(len(ids) == len(set(ids)), "duplicate Windows event identifiers")
    if records:
        require(set(ids) == set(records), "unexpected Windows event identifiers")
    chronological = sorted(rows, key=lambda row: datetime.fromisoformat(row["timestamp"]))
    times = [datetime.fromisoformat(r["timestamp"]) for r in chronological]
    gaps = [(b-a).total_seconds() for a, b in zip(times, times[1:])]
    require(all(g > 60 for g in gaps) if spaced else (times[-1]-times[0]).total_seconds() < 60,
            "unexpected observed alert timing")
    if counts.get("100110", 0):
        require(len(times) > 1 and chronological[-1]["rule"]["id"] == "100110"
                and times[-1] > times[-2],
                "correlation must be the last observed alert, with a distinct later timestamp")
    for row in rows:
        check_source(row)
        require(event(row)["system"]["providerName"] == "Microsoft-Windows-Sysmon", "unexpected provider")
        require(str(event(row)["system"]["eventID"]) == "1", "unexpected event type")
        if row["rule"]["id"] == "100110":
            require(int(row["rule"]["frequency"]) == 7, "unexpected empirical threshold")
            require("soc_correlation" in row["rule"]["groups"], "unexpected correlation group")
    images = [event(r)["eventdata"]["image"].replace("\\", "/").split("/")[-1].lower() for r in rows]
    expected = ["tasklist.exe", "ipconfig.exe", "whoami.exe", "systeminfo.exe"] if mixed else ["whoami.exe"] * len(rows)
    require(Counter(images) == Counter(expected), "unexpected executable set")


def powershell(folder):
    archive = load(folder / "powershell-comparison.archives.jsonl")
    require(len(archive) == 2, "expected two archived events")
    require({event(r)["system"]["eventRecordID"] for r in archive} == {"94715", "94736"}, "unexpected archived IDs")
    for filename, rule, level, record, option in (
        ("powershell-plain.alerts.jsonl", "92027", 4, "94715", "-Command"),
        ("powershell-encoded.alerts.jsonl", "92057", 12, "94736", "-EncodedCommand"),
    ):
        rows = load(folder / filename)
        require(len(rows) == 1, "expected one alert: " + filename)
        row = rows[0]
        require(row["rule"]["id"] == rule and row["rule"]["level"] == level, "unexpected PowerShell rule")
        require(event(row)["system"]["eventRecordID"] == record, "unexpected PowerShell event")
        require(option in event(row)["eventdata"]["commandLine"], "missing command option")
        source = next(r for r in archive if event(r)["system"]["eventRecordID"] == record)
        check_source(source)
        require(event(source) == event(row), "archive/alert decoded content differs")


def task(folder):
    rows = load(folder / "scheduled-task-created.alerts.jsonl")
    require(len(rows) == 1 and rows[0]["rule"]["id"] == "67014", "unexpected task alert")
    win = event(rows[0])
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    root = ET.parse(folder / "scheduled-task-created.event106.xml").getroot()
    for key, expected in (("EventID", "106"), ("EventRecordID", "15"), ("Channel", "Microsoft-Windows-TaskScheduler/Operational")):
        require(root.findtext("e:System/e:" + key, namespaces=ns) == expected, "unexpected XML " + key)
    require(str(win["system"]["eventID"]) == "106" and str(win["system"]["eventRecordID"]) == "15", "task identity mismatch")
    require(root.findtext("e:System/e:Computer", namespaces=ns) == win["system"]["computer"], "computer mismatch")
    provider = root.find("e:System/e:Provider", ns)
    require(provider is not None and provider.get("Name") == win["system"]["providerName"], "provider mismatch")
    created = root.find("e:System/e:TimeCreated", ns)
    # Keep all seven source fractional digits; Python datetime keeps only six.
    require(created is not None and created.get("SystemTime") == win["system"]["systemTime"], "source time mismatch")
    require(root.findtext("e:System/e:Channel", namespaces=ns) == win["system"]["channel"], "channel mismatch")
    name = root.find("e:EventData/e:Data[@Name='TaskName']", ns).text
    require(name == "\\SOC-Lab-V2-Test", "unexpected task name")
    require(win["eventdata"]["taskName"].replace("\\\\", "\\") == name, "task name mismatch")


def ssh(folder):
    rows = load(folder / "ssh-eight-failures.alerts.jsonl", expected_agent="001")
    rows = sorted(rows, key=lambda a: datetime.fromisoformat(a["timestamp"]))
    require([r["rule"]["id"] for r in rows] == ["5760"] * 7 + ["5763"], "unexpected SSH rule sequence")
    require(len({r["id"] for r in rows}) == 8, "duplicate SSH alert IDs")
    raw_logs = []
    source_times = []
    for row in rows:
        require(row["data"]["srcip"] == "192.168.56.1", "unexpected SSH source IP")
        require(row["data"]["dstuser"] == "vboxuser", "unexpected SSH user")
        require(row["decoder"]["name"] == "sshd", "unexpected SSH decoder")
        raw = row["full_log"]
        match = re.fullmatch(r"(Oct 16 \d{2}:\d{2}:\d{2}) Ubuntu-Endpoint sshd\[\d+\]: Failed password for vboxuser from 192\.168\.56\.1 port (\d+) ssh2", raw)
        require(match is not None, "SSH source does not match recorded failure")
        require(match.group(2) == str(row["data"]["srcport"]), "SSH port mismatch")
        source_times.append(datetime.strptime("2026 " + match.group(1), "%Y %b %d %H:%M:%S"))
        raw_logs.append(raw)
    require(len(set(raw_logs)) == 8, "duplicate SSH source events")
    require((max(source_times) - min(source_times)).total_seconds() < 120, "unexpected source time window")
    final = rows[-1]
    require(int(final["rule"]["frequency"]) == 8 and final["rule"]["level"] == 10, "unexpected SSH threshold or level")
    previous = final["previous_output"].splitlines()
    require(Counter(previous) == Counter(raw_logs[:-1]), "SSH history does not match the seven preceding failures")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    folder = parser.parse_args().evidence
    checks = [
        ("three commands", lambda: correlation(folder, "correlation-whoami-three.alerts.jsonl", ["81358", "81360", "81362"], {"100103": 3})),
        ("four commands", lambda: correlation(folder, "correlation-whoami-four.alerts.jsonl", ["81366", "81368", "81370", "81372"], {"100103": 3, "100110": 1})),
        ("spaced commands", lambda: correlation(folder, "correlation-whoami-spaced.alerts.jsonl", ["81432", "81435", "85252", "94591"], {"100103": 4}, spaced=True)),
        ("mixed commands", lambda: correlation(folder, "correlation-mixed-four.alerts.jsonl", None, {"100100": 1, "100102": 1, "100103": 1, "100110": 1}, mixed=True)),
        ("PowerShell comparison", lambda: powershell(folder)),
        ("task creation XML/alert", lambda: task(folder)),
        ("SSH repeated failures", lambda: ssh(folder)),
    ]
    failures = 0
    for name, check in checks:
        try:
            check()
            print("PASS:", name)
        except (ValueError, KeyError, TypeError, OSError, ET.ParseError, AttributeError, StopIteration) as exc:
            failures += 1
            print("FAIL:", name, "-", str(exc) or type(exc).__name__)
    print(f"{len(checks)-failures}/{len(checks)} evidence checks passed. No Wazuh engine replay performed.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
