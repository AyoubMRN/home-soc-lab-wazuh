# Current custom discovery rules

soc-discovery-rules.xml is a publication extract of the manager's V2 local_rules.xml. It contains five IDs: 100100 tasklist (level 7), 100101 systeminfo (7), 100102 ipconfig /all (5), 100103 whoami (5), and 100110 discovery correlation (8). V1's four rules are included and extended with soc_discovery, not meant to be installed a second time.

The correlation uses frequency=7, timeframe=60 and same_field win.system.computer. This is an empirical setting with unresolved counting behaviour; it does not enforce distinct programs.

**Choose one current set.** Never load this extract alongside the V1 rule file or configs/wazuh/snapshots/local_rules.xml. Check for ID collisions on the target manager and back up its rules first. The vendor's example rule 100001 is omitted from this extract, not removed from any live server.

The full archived local_rules.xml was used in the running lab. This extracted file is structurally reviewed but has not been redeployed as a separate file. A syntax check does not prove complete detection behaviour. Follow [installation boundaries](../../../docs/installation.md).
