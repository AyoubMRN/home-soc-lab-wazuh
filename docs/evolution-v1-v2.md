# V1 → V2: one lab, two stages

V1 established the three-VM setup, Windows/Linux collection, eight scenario pages and four custom discovery rules. V2 extends that same lab rather than replacing it with an unrelated project.

| Area | V1 foundation | V2 addition |
| --- | --- | --- |
| Discovery | Four executable/argument rules, 100100–100103 | Shared soc_discovery group and correlation 100110; four comparison cases |
| PowerShell | Script-block logging and registry/file-discovery exercises | Benign plain versus Base64 command comparison with archived source pairing |
| Scheduled task | Not part of the V1 campaign | Creation alert matched to a Windows XML event; local execution and cleanup documented |
| Ubuntu | FIM and individual SSH authentication alerts | Eight-failure correlation and real-engine seven/eight-event replay |
| Validation | Screenshots, configuration checks and selected reboot retests | JSONL/XML evidence checks, Python unit tests and a local HTML report |

## Where is V1?

The last public V1 state is [commit f13f2e7](https://github.com/AyoubMRN/home-soc-lab-wazuh/tree/f13f2e7570baa49a2699d6f3975b3c6383155d6e). Its full files and README remain available there. The current tree retains the useful V1 scenario pages, screenshots, Ubuntu settings and results, labelled as historical observations.

V2 is published on main. V1 is linked by commit rather than a version tag; the original commits have not been rewritten.

## Rules are cumulative, not additive installations

V2's five-rule publication extract contains IDs 100100–100103 **and** 100110. Do not deploy it alongside the V1 four-rule file or the archived manager local_rules.xml: this would duplicate IDs. The original archive contains Wazuh sample rule 100001, omitted from the custom publication extract. The five-rule extract has not itself been redeployed on the manager.

Publication does not mean the lab was rebuilt. Historical screenshots retain their original dates and language. A found Sysmon configuration is now archived; its source revision and a new installation remain unverified.
