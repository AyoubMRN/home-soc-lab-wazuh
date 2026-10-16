# Five-minute demonstration

## V2 evidence walkthrough (offline)

This walkthrough uses preserved evidence. It generates no new endpoint activity and does not demonstrate live collection.

1. **45 seconds:** show the README architecture and identify the manager and two endpoints.
2. **90 seconds:** open [SSH correlation](scenarios/ssh-correlation.md), compare the seven 5760 alerts with the final 5763, then distinguish source and alert times.
3. **90 seconds:** from the repository root, run the checks below and open the generated report. Use an unused report filename; the generator refuses to overwrite a file.

```bash
python -m unittest discover -v -s tests -p "test_*.py"
python tools/check_xml.py
python tools/validate_evidence.py tests/fixtures
python tools/generate_report.py tests/fixtures report-demo.html
```

4. **75 seconds:** show the [preserved real-engine replay](../evidence/replay-ssh/README.md). Explain that local tests mock Wazuh, while that replay ran on the manager without reproducing original timing. Neither proves current VM health.

## Original V1 live demonstration

The following sequence concerns the original V1 campaign. Its four-rule count is historical; V2 has five custom rules in total. A new live test needs its own evidence and time filters.

## Preparation

Start Wazuh, wait for services, then start the endpoints. Confirm both agents are active. Open the Dashboard and endpoint consoles. Remove unrelated filters and use a time range around each new test.

## Architecture — 45 seconds

Show the machines and explain endpoint telemetry, agent transport, manager rules and indexed alerts.

## Windows discovery — 90 seconds

Run on Windows:

```powershell
Get-Date
cmd.exe /c whoami
```

Search Wazuh:

```text
agent.name:"Windows-Endpoint" AND rule.id:"100103"
```

Show command, image, rule and T1033. Explain that legitimate whoami use also alerts.

## Linux integrity — 90 seconds

Edit /opt/soc-lab/demo.conf with nano and save a new synthetic mode value. Search:

```text
agent.name:"Ubuntu-Endpoint" AND syscheck.path:"/opt/soc-lab/demo.conf" AND rule.id:"550"
```

Show the diff and realtime mode. Explain the baseline and why a change is not automatically malicious.

## Results and limits — 75 seconds

Explain eight targeted scenarios, four custom rules and four native final detections. Mention partial WMIC execution, manual adaptations and why no global detection percentage is claimed.
