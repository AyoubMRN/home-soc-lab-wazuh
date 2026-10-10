# Limitations and next improvements

This version validates eight targeted lab scenarios, not complete ATT&CK coverage.

- The custom discovery rules match executable names and, for ipconfig, one argument. They can alert on legitimate administration and do not correlate sequences or inspect intent.
- T1033 Atomic test 1 partly failed because WMIC was unavailable. The final whoami validation was manual.
- T1083 was a scoped manual adaptation of Atomic test 2. Registry modification, FIM and SSH tests were also manual.
- Threat Hunting searches alerts; a missing result is not proof that a raw event was not collected.
- Linux auditd process-execution telemetry was not configured. FIM and SSH do not imply every Ubuntu command is monitored.
- The original Sysmon XML and exact Atomic source commit were not exported. A rebuild must choose and validate its own Sysmon configuration.
- Two behaviors were retested after reboot, not all eight. Snapshot restoration was not tested.
- Timestamps include UTC event fields and local Dashboard/endpoint time. No detection-latency benchmark was measured.
- Dashboard readiness problems occurred. Resource use and services were checked, but a conclusive root cause was not established.
- Automatic containment, production false-positive rates and a comparable global before/after detection percentage were not validated.

## Next improvements

1. Preserve the Sysmon configuration and pin the Atomic source revision.
2. Run a fixed baseline/final campaign with explicit criteria and additional variants.
3. Add tested parent/user context and sequence correlations where useful.
4. Test SSH repeated-failure correlation and extend Linux telemetry with auditd.
5. Export selected raw JSON alongside screenshots and validate snapshot restoration.

Sigma rules and a MITRE Navigator layer are possible extensions, not completed deliverables in this repository.
