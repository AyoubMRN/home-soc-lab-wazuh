# Results and measurement

> Historical V1 campaign. See [V2 results and limits](results-and-limits.md) for the later work. These eight scenarios are not claimed as a new V2 rerun.

## Scenario outcomes

| Behavior | Initial observation | Final rule / level | Validation |
|---|---|---|---|
| tasklist.exe | Generic shell alert and process telemetry present | 100100 / 7 | T1057 mapped |
| systeminfo.exe | 92032 / 3, T1087 + T1059.003 on examined event | 100101 / 7 | T1082 mapped |
| ipconfig /all | 92032 / 3, no T1016 on examined alert | 100102 / 5 | T1016 mapped; legitimate use also alerts |
| whoami.exe | 92032 / 3; original Atomic execution partly failed | 100103 / 5 | Manual T1033 validation; retested after reboot |
| Ubuntu file edit | Configured test directory and initial baseline | Native 550 / 7 | Diff, hashes, realtime mode; retested after reboot |
| Ubuntu SSH failure | Three local Failed password lines | Native 5760 / 5 | Three alerts; success separately uses 5715 / 3 |
| PowerShell registry write | Native 91843 first seen during logging setup | Native 91843 / 3 | 4104 script text, T1059.001/T1112, value read back and removed |
| Recursive file listing | Scoped manual adaptation of Atomic T1083 test 2 | Native 91820 / 4 | Exact 4104 text and T1083/T1119 |

Scenario pages contain the supporting screenshots and distinguish full Atomic execution from manual tests.

## Counts

- 8 documented scenarios: 6 Windows and 2 Ubuntu.
- 4 custom discovery rules.
- 4 scenarios using native final detections.
- 2 behaviors retested after reboot: whoami and Ubuntu file modification.
- 3 reviewed configuration exports: manager rules and both agents.
- 74 original screenshots audited locally before publication; this repository contains a curated subset.

T1033 is one scenario, despite its partial Atomic run and subsequent manual validation. PowerShell carries two ATT&CK labels but remains one scenario. Alerts, events, scenarios and techniques are different units.

## Why there is no global detection percentage

The first four events already produced generic alerts. New custom rules improved specificity and MITRE classification. Logging configuration changed during the other tests, and some scenarios were manual or partially executed.

A comparable baseline/final campaign with fixed telemetry, a defined denominator and a consistent detection criterion was not performed. Therefore, this repository claims neither a before/after percentage nor complete technique coverage.

The supported conclusion is that the expected targeted outcomes were observed for these eight scenarios, with the documented exceptions and limits.

## Controls and interpretation

- Manual ipconfig /all triggers 100102. This is a legitimate-use alert, not proof of compromise.
- No 100102 alert was reported for plain ipconfig. A corresponding local Sysmon proof was not saved, so this negative observation has weaker evidence.
- Manual whoami also triggers 100103.
- SSH valid and invalid authentication were correctly classified separately.
- The registry write and file edits were authorized tests. ATT&CK mappings do not turn them into malicious acts.
- The benign Write-Output marker was seen locally in 4104; its individual reception was not established by a Dashboard alert. Other 4104 scripts demonstrably reached Wazuh.

A false-positive rate cannot be estimated from a few manual controls. More normal activity and representative attack variants are needed.
