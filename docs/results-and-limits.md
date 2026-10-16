# Results and limitations

These are observations from authorised lab tests on 15–16 October 2026, plus the preserved [V1 results](results.md). They are not confirmed incidents, a benchmark or proof of complete ATT&CK coverage.

| V2 test | Recorded result | What it does not establish |
| --- | --- | --- |
| Three close discovery commands | Three 100103 alerts, no 100110 in the selected export | General absence of activity or exhaustive collection |
| Four close discovery commands | Three 100103, then one 100110 | A universal four-command threshold |
| Four spaced discovery commands | Four 100103; no 100110 in the selected export | All timing boundaries tested |
| Four different close commands | 100110 observed on systeminfo | A rule requiring different commands |
| Plain / encoded PowerShell | 92027/4 and 92057/12, respectively | Detection of every encoded PowerShell variant |
| Task registration | 67014/3, event 106, record 15 matched to XML | Wazuh detection of task execution |
| Repeated SSH failures | Seven 5760/5, then 5763/10 | Malicious intent: this was a controlled simulation |
| Real SSH replay | Seven events: no correlation; eight: final 5763/10 | Original delays, a 120-second boundary or separation of multiple IPs |

## Three different kinds of checks

1. Unit tests exercise program behaviour, including rejected data and mocked Wazuh responses.
2. File checks examine selected XML settings and evidence consistency, without executing a detection engine.
3. The recorded SSH replay actually invoked wazuh-logtest on the manager. Its original outputs are in evidence/replay-ssh. No successful Windows EventChannel engine replay is established.

The initial suite has 32 unit tests. The publication layout passes 33, including a new regression check comparing the five-rule extract with the archived manager definitions. GitHub CI is prepared but has not run yet.

## Unresolved limitations

- The discovery frequency=7/timeframe=60 setting compensates empirically for an unexplained counting behaviour. Earlier attempts exposed duplicate history entries; the cause is not considered fixed.
- Correlation counts events, not distinct executable names. Legitimate administration can trigger the same rules.
- Windows agent buffer saturation occurred. Complete collection and reliable detection latency are not demonstrated. Source-event time and alert time are different observations.
- The task's local result 0 and cleanup were checked, but only registration is tied to a Wazuh alert. The native XML is a text-preserved copy, not a byte-verified original transfer.
- The Sysmon-modular balanced XML was recovered and its hash matched the loaded configuration. The exact upstream commit, reinstallation and snapshot restoration remain untested.
- There is no production false-positive rate, before/after detection percentage, automatic containment or AI decision-making.

## Last reported lab state

Manager, Indexer and Dashboard were active; both endpoint agents were active. Sysmon64 and WazuhSvc were running. SOC-Lab-V2-Test was absent. Temporary logall/logall_json archival was disabled after the PowerShell capture. These are dated checks, not live monitoring.
