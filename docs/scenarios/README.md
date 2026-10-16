# Scenario index

## V2 additions

| Scenario | Focus |
| --- | --- |
| [Discovery correlation](discovery-correlation.md) | Three/four events, close/spaced and mixed-program comparisons |
| [Plain/encoded PowerShell](powershell-encoded.md) | Native alerts and archived source pairing |
| [Scheduled task](scheduled-task.md) | Registration, local run and cleanup |
| [Ubuntu SSH correlation](ssh-correlation.md) | Eight failures and real-engine replay |

## V1 foundation

The eight scenarios below are preserved historical observations. The current custom rule set extends the four V1 discovery rules; do not install both versions together. See [V1 to V2](../evolution-v1-v2.md).

| Scenario | Method |
|---|---|
| [T1057](t1057.md) | Atomic test 2 |
| [T1082](t1082.md) | Atomic test 1 |
| [T1016](t1016.md) | Atomic test 1; focused ipconfig validation |
| [T1033](t1033.md) | Partial Atomic test 1, then manual whoami |
| [Ubuntu FIM](ubuntu-fim.md) | Manual file modification |
| [Ubuntu SSH](ubuntu-ssh.md) | Controlled failed and successful authentication |
| [PowerShell registry write](powershell-registry.md) | Manual synthetic registry value |
| [T1083](t1083.md) | Manual adaptation of Atomic test 2 |

Follow the [setup guide](../installation.md) first. These are eight scenarios, not eight complete Atomic executions.
