# Custom discovery rules

[soc-discovery-rules.xml](soc-discovery-rules.xml) contains the four rules created and validated in this lab. The original local_rules.xml export also had Wazuh's sample rule 100001; it is excluded here.

| Rule | Level | Match | ATT&CK |
|---|---|---|---|
| 100100 | 7 | Sysmon event-1 group and image ending in tasklist.exe | T1057 |
| 100101 | 7 | Same group and image ending in systeminfo.exe | T1082 |
| 100102 | 5 | Same group, ipconfig.exe and a delimited /all argument | T1016 |
| 100103 | 5 | Same group and image ending in whoami.exe | T1033 |

The PCRE2 expressions ignore case. Multiple field requirements are combined as AND. if_group refers to a ruleset group, not to an arbitrary event ID string: the observed Wazuh ruleset provided sysmon_event1.

Levels are lab choices, not calibrated probabilities of compromise. These rules can alert on legitimate administration. They do not perform sequence correlation, inspect user intent or suppress trusted activity. The first four test events were already generically alerted before the custom rules.

Deployment and restart steps are in [the setup guide](../../docs/installation.md). Syntax was checked on the running manager during the lab; endpoint evidence confirms the intended matches. The extracted file has also been checked locally for well-formed XML and unique IDs, but has not been redeployed separately on the stopped VM.
