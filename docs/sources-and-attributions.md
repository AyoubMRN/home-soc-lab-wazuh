# Sources, attribution and licensing decisions

## Lab platforms and documentation

- [Wazuh documentation](https://documentation.wazuh.com/current/) and [custom rules guide](https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html).
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
- [Olaf Hartong / Sysmon-modular](https://github.com/olafhartong/sysmon-modular).
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) and [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam), used in the V1 work with documented manual/partial adaptations. The original Atomic commit was not preserved.
- [MITRE ATT&CK](https://attack.mitre.org/) for technique terminology, not a coverage certification.

## What belongs to whom

| Material | Provenance |
| --- | --- |
| Native SSH rules | Wazuh contributors; unchanged copy and upstream licence in configs/wazuh-native |
| Sysmon generated configuration | Sysmon-modular project; source note and permission notice in configs/sysmon |
| Agent configuration snapshots | Lab settings based on Wazuh-provided configuration; original notices retained |
| Five-rule custom extract | Lab discovery work plus correlation; omits the Wazuh sample rule 100001 |
| Full local_rules.xml snapshot | Historical lab export, including the vendor example; never call every rule in it original work |
| Python tools, documentation and diagrams | Prepared for the student lab with AI assistance |
| Screenshots and records | Authorised lab observations, not production incident data |

Lab manipulations and verification were performed by Ayoub. AI assisted coding, explanation, organisation and documentation. No AI service is integrated into detection or response.

## Licence scope

Third-party notices are retained with the corresponding files. Upstream Wazuh and Sysmon-modular licence texts do not automatically license all independent code, documentation or images in this repository. No project-wide licence has been chosen by the author during this preview; do not add a misleading MIT or GPL badge. The licence for original material is a decision to confirm before publication.

Upstream licences consulted for this preparation: [Wazuh v4.14.8 LICENSE](https://github.com/wazuh/wazuh/blob/v4.14.8/LICENSE) and [Sysmon-modular license.md](https://github.com/olafhartong/sysmon-modular/blob/master/license.md). Their contents have been preserved locally with the references; an exact Sysmon source revision remains unknown.
