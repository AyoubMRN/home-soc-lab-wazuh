# Configuration examples and exports

## V2 references

- [Current custom rules](wazuh/custom/README.md): five cumulative rules; never load alongside the V1 rules or full snapshot.
- [Full manager snapshot](wazuh/snapshots/local_rules.xml): historical export including vendor sample 100001. SHA-256 c38ea9d12ee1a1d282695ee50407994826e1d01a3fd77597177e4a8e2a04aa3d. Evidence input, not a second deployment file.
- [Windows agent V2](wazuh/windows-agent.conf): export including TaskScheduler collection; no key or enrollment password files supplied.
- [Native SSH references](wazuh-native/SOURCE.md): third-party Wazuh rules, source note and licence.
- [Sysmon reference](sysmon/SOURCE.md): recovered third-party balanced configuration, source note and permission notice.

The earlier settings below remain from V1. windows/ossec-agent.conf is the V1 snapshot; wazuh/windows-agent.conf is the V2 one. They are references, not two configurations to install together.

## V1 collection references

| File | Purpose |
|---|---|
| [windows/ossec-agent.conf](windows/ossec-agent.conf) | Reviewed Windows lab export; includes Sysmon and PowerShell event channels |
| [ubuntu/ossec-agent.conf](ubuntu/ossec-agent.conf) | Reviewed Ubuntu lab export; includes /opt/soc-lab FIM and journald collection |
| [windows/event-channels.xml](windows/event-channels.xml) | Minimal collection snippet to merge into an existing agent configuration |
| [ubuntu/fim-snippet.xml](ubuntu/fim-snippet.xml) | Minimal FIM snippet to merge inside an existing syscheck block |

The two .conf exports preserve the lab's settings and private lab IP. They do not contain enrollment passwords or agent keys. Ubuntu references etc/authd.pass; that secret file is deliberately not included.

These files are not universal defaults. Adapt them to the machine, Wazuh version and enrollment mechanism. Merge snippets rather than replacing an unrelated working configuration.

Script Block Logging is a Windows setting, separate from ossec.conf. The Sysmon XML missing at V1 publication was recovered during V2; its original source commit and a fresh installation remain unverified.
