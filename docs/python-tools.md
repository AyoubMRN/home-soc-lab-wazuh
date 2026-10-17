# Using the Python tools

Run from the repository root with Python 3.13. Python 3.13.16 was verified on the lab PC. No pip dependencies are required for the tools or tests.

| Tool | Inputs and purpose |
| --- | --- |
| tools/validate_evidence.py | Reads tests/fixtures; checks seven recorded evidence cases without changing files |
| tools/check_xml.py | Reads configs; checks XML structure and selected settings, not engine semantics |
| tools/generate_report.py | Reads fixtures and creates a new self-contained HTML report; no network calls |
| tools/replay_ssh.py | On the Wazuh manager only, sends recorded source logs to wazuh-logtest in two separate sessions |

## Local checks

```bash
python -m unittest discover -v -s tests -p "test_*.py"
python tools/check_xml.py
python tools/validate_evidence.py tests/fixtures
python tools/generate_report.py tests/fixtures report.html
```

The generator refuses an existing destination. Open the new report in a browser. It displays escaped log text and decodes Base64 locally as text, never as a command. Reports are ignored by Git; a report is a presentation of existing records, not a new detection.

These commands need no running lab VM. The test runner uses mocks for the Wazuh subprocess; it does not replay the real engine.

## Real SSH replay

On an authorised Wazuh manager with the appropriate access, a copy of replay_ssh.py and the SSH fixture can be used as follows. The output name must not already exist.

```bash
sudo /var/ossec/framework/python/bin/python3 replay_ssh.py ssh-eight-failures.alerts.jsonl --output ssh-replay-new.json
```

The runner invokes /var/ossec/bin/wazuh-logtest with journald location, streams the first seven source lines, then all eight in a separate session. It reads phase-3 verdicts from both stdout and stderr, checks return codes and exact rule/level sequences, and optionally records both streams. It opens no SSH connection, changes no configuration and performs no restart. It does not reproduce the original timing gaps.

See the [recorded replay](../evidence/replay-ssh/README.md). Do not confuse a fresh run with the preserved 16 October result.

## GitHub Actions

The workflow uses Python 3.13 on an Ubuntu runner with read-only repository permissions, no lab credentials and no access to the VM network. It runs unit tests, configuration checks, evidence checks and report generation. It does not call replay_ssh.py or prove an end-to-end deployment. A [successful published run](https://github.com/AyoubMRN/home-soc-lab-wazuh/actions/runs/38971208811) is preserved for reference; the [Actions page](https://github.com/AyoubMRN/home-soc-lab-wazuh/actions) records each revision's result.
