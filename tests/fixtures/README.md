# Selected lab fixtures

These reference records support local validation and report generation, not an exhaustive log archive. Keep source identity and chronology consistent if creating a separately sanitised variant, and rerun all checks. Never silently replace historical evidence with fabricated records.

| Files | Selection |
| --- | --- |
| correlation-whoami-three.alerts.jsonl | Three discovery alerts |
| correlation-whoami-four.alerts.jsonl | Four alerts, last one 100110 |
| correlation-whoami-spaced.alerts.jsonl | Four spaced alerts without 100110 in the selected export |
| correlation-mixed-four.alerts.jsonl | Four different-program alerts, including 100110 |
| powershell-plain.alerts.jsonl | One 92027 alert |
| powershell-encoded.alerts.jsonl | One 92057 alert |
| powershell-comparison.archives.jsonl | Two corresponding selected archive/source records; not all Wazuh archives |
| scheduled-task-created.alerts.jsonl | One registration alert |
| scheduled-task-created.event106.xml | Text-preserved Windows event 106, record 15; see adjacent provenance note |
| ssh-eight-failures.alerts.jsonl | Eight alerts; full_log provides all SSH replay inputs |

Windows tests: 15 October 2026, agent 002. SSH test: 16 October 2026, agent 001. These fixtures deliberately retain generic lab accounts, machine names, private host-only addresses, timestamps and event IDs needed to verify the evidence. They must not be interpreted as a live environment or real compromise.

No personal host username or school-specific path was found in the selected corpus during the targeted review. That is not an absolute secret-scanning guarantee. The selected corpus is published here; original private archives are not included.
