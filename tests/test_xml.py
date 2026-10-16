from pathlib import Path
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from tools.check_xml import parse_file, check_rules, check_agent


class XmlChecksTests(unittest.TestCase):
    def test_publication_extract_matches_recorded_lab_rules(self):
        root = Path(__file__).resolve().parents[1] / "configs" / "wazuh"
        snapshot = parse_file(root / "snapshots" / "local_rules.xml", fragment=True)
        published = parse_file(root / "custom" / "soc-discovery-rules.xml", fragment=True)
        ids = {"100100", "100101", "100102", "100103", "100110"}
        expected = {r.get("id"): ET.tostring(r).strip() for r in snapshot.findall(".//rule") if r.get("id") in ids}
        rules = published.findall(".//rule")
        actual = {r.get("id"): ET.tostring(r).strip() for r in rules}
        self.assertEqual(len(rules), 5)
        self.assertEqual(set(actual), ids)
        self.assertEqual(actual, expected)
        self.assertEqual([g.get("name") for g in published.findall("group")],
                         [g.get("name") for g in snapshot.findall("group") if g.find("rule").get("id") in ids])

    def test_wazuh_multiple_groups_supported(self):
        with patch.object(Path, "read_text", return_value='<group name="a,"></group><group name="b,"></group>'):
            self.assertEqual(len(parse_file(Path("rules"), fragment=True)), 2)

    def test_malformed_xml_rejected(self):
        with patch.object(Path, "read_text", return_value="<Sysmon>"):
            with self.assertRaises(ET.ParseError):
                parse_file(Path("sysmon"))

    def test_duplicate_rule_id_rejected(self):
        with patch.object(Path, "read_text", return_value='<group><rule id="5763"/><rule id="5763"/></group>'):
            with self.assertRaisesRegex(ValueError, "duplicate"):
                check_rules(Path("rules"), "5763", {})

    def test_modified_threshold_rejected(self):
        with patch.object(Path, "read_text", return_value='<group><rule id="5763" frequency="3"/></group>'):
            with self.assertRaisesRegex(ValueError, "frequency"):
                check_rules(Path("rules"), "5763", {"frequency": "8"})

    def test_missing_channel_rejected(self):
        with patch.object(Path, "read_text", return_value="<ossec_config/>"):
            with self.assertRaisesRegex(ValueError, "channel"):
                check_agent(Path("agent"))


if __name__ == "__main__":
    unittest.main()
