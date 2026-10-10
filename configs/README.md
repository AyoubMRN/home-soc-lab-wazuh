# Configuration examples and exports

| File | Purpose |
|---|---|
| [windows/ossec-agent.conf](windows/ossec-agent.conf) | Reviewed Windows lab export; includes Sysmon and PowerShell event channels |
| [ubuntu/ossec-agent.conf](ubuntu/ossec-agent.conf) | Reviewed Ubuntu lab export; includes /opt/soc-lab FIM and journald collection |
| [windows/event-channels.xml](windows/event-channels.xml) | Minimal collection snippet to merge into an existing agent configuration |
| [ubuntu/fim-snippet.xml](ubuntu/fim-snippet.xml) | Minimal FIM snippet to merge inside an existing syscheck block |

The two .conf exports preserve the lab's settings and private lab IP. They do not contain enrollment passwords or agent keys. Ubuntu references etc/authd.pass; that secret file is deliberately not included.

These files are not universal defaults. Adapt them to the machine, Wazuh version and enrollment mechanism. Merge snippets rather than replacing an unrelated working configuration.

Script Block Logging is a Windows setting, separate from ossec.conf. See the setup guide. The original Sysmon XML is not exported here; choose and validate a configuration that logs event 1 before reproducing discovery tests.
