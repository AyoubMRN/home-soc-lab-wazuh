# Recorded real-engine SSH replay

Performed on the Wazuh manager on 16 October 2026. Server identified itself as 4.14.8, revision rc2. This folder stores historical results; it does not rerun the engine when opened or tested by CI.

| File | Meaning |
| --- | --- |
| seven-events.txt | Preserved manual logtest transcription for the negative count case |
| eight-events.txt | Preserved manual logtest transcription for the positive count case |
| replay-result.json | Corrected Python runner result with expected/observed verdicts, return codes and both output streams |

**Input:** the eight full_log fields in [ssh-eight-failures.alerts.jsonl](../../tests/fixtures/ssh-eight-failures.alerts.jsonl). tools/replay_ssh.py takes the first seven for one session and all eight for a second. No separate input file is missing.

Expected and recorded outcomes: seven times 5760/5, then in the second session seven times 5760/5 followed by 5763/10. Both runner cases passed with return code 0. Wazuh normal verdict text appeared on stderr, which the corrected runner deliberately parses alongside stdout. Unit tests cover that behaviour and reject wrong or extra verdicts.

No SSH connection, manager restart or configuration change is performed by the runner. It does not reproduce the original delays, measure detection latency or test different source IPs. Recorded fixture paths in the JSON refer to the historical VM export location, not a requirement for local report generation.
