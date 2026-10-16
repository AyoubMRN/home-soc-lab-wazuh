"""Check archived XML syntax and selected lab settings; does not run Wazuh/Sysmon."""
import argparse
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


def parse_file(path, fragment=False):
    content = path.read_text(encoding="utf-8-sig")
    if fragment:
        content = re.sub(r"^\s*<\?xml[^?]*\?>", "", content, count=1)
        content = "<rules_snapshot>" + content + "</rules_snapshot>"
    return ET.fromstring(content)


def expect(condition, message):
    if not condition:
        raise ValueError(message)


def check_rules(path, rule_id, settings):
    root = parse_file(path, fragment=True)
    rules = root.findall(".//rule")
    ids = [r.get("id") for r in rules]
    expect(len(ids) == len(set(ids)), "duplicate rule IDs in " + path.name)
    matches = [r for r in rules if r.get("id") == rule_id]
    expect(len(matches) == 1, "expected rule " + rule_id)
    rule = matches[0]
    for key, value in settings.items():
        expect(rule.get(key) == value, f"rule {rule_id}: unexpected {key}")
    if rule_id == "100110":
        expect(rule.findtext("if_matched_group") == "soc_discovery", "unexpected discovery source group")
        expect(rule.findtext("same_field") == "win.system.computer", "missing same-host condition")
        parent = next(g for g in root.findall(".//group") if rule in list(g))
        expect("soc_correlation" in parent.get("name", "").split(","), "unexpected output group")
    else:
        expect(rule.findtext("if_matched_sid") == "5760", "unexpected SSH source rule")
        expect(rule.find("same_source_ip") is not None, "missing same-source-IP condition")


def check_agent(path):
    root = parse_file(path)
    expect(root.tag == "ossec_config", "unexpected agent root")
    for channel in ("Sysmon", "PowerShell", "TaskScheduler"):
        name = f"Microsoft-Windows-{channel}/Operational"
        entries = [item for item in root.findall(".//localfile") if item.findtext("location") == name]
        expect(len(entries) == 1, "channel must appear exactly once: " + name)
        expect(entries[0].findtext("log_format") == "eventchannel", "unexpected channel format")


def check_sysmon(path):
    root = parse_file(path)
    expect(root.tag == "Sysmon", "unexpected Sysmon root")
    expect(root.get("schemaversion") == "4.90", "unexpected Sysmon schema snapshot")
    expect(root.find("EventFiltering") is not None, "missing Sysmon EventFiltering")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", nargs="?", type=Path, default=Path(__file__).resolve().parents[1] / "configs")
    folder = parser.parse_args().folder
    checks = (
        ("wazuh/snapshots/local_rules.xml", lambda p: check_rules(p, "100110", {"level": "8", "frequency": "7", "timeframe": "60"})),
        ("wazuh-native/0095-sshd_rules.xml", lambda p: check_rules(p, "5763", {"level": "10", "frequency": "8", "timeframe": "120", "ignore": "60"})),
        ("wazuh/windows-agent.conf", check_agent),
        ("sysmon/sysmonconfig.xml", check_sysmon),
    )
    failures = 0
    for name, check in checks:
        try:
            check(folder / name)
            print("PASS:", name)
        except (OSError, ValueError, ET.ParseError, StopIteration) as exc:
            failures += 1
            print("FAIL:", name, "-", exc)
    print(f"{len(checks)-failures}/4 configuration checks passed. No Wazuh/Sysmon engine validation performed.")
    return int(bool(failures))


if __name__ == "__main__":
    sys.exit(main())
