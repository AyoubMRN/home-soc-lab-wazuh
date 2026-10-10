# Five-minute demonstration

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
