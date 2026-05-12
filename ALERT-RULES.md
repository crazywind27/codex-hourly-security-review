# Codex Hourly Security Review Alert Rules

Last updated: 2026-05-12
Alert launcher updated: 2026-05-12

These deterministic rules run before Codex analysis. High and critical
deterministic findings override a Codex non-alert decision. Codex still reviews
the collected data to decide whether medium/low trends require user action or
should remain tracked context.

Findings are assigned stable fingerprints and suppression keys. If the user
explicitly records an alert disposition with `Decision Ignored`, future matching
non-critical findings are still written to run evidence and the Markdown log as
suppressed, but they do not force a visible alert. Critical findings are not
suppressed unless local configuration explicitly enables critical suppressions.
The exact fingerprint preserves the specific evidence instance; the suppression
key is intentionally broader so a known-benign finding can remain suppressed
when event counts or volatile message fragments change between runs.

When an alert opens, the monitor shows a visible alert window. It launches an
interactive Codex session only when remote Codex analysis is enabled, an
absolute Codex command path is configured, and the current integrity level is
allowed. Otherwise the alert window shows the alert text and the manual
disposition command.

## Alerting Standard

The monitor should act as an expert filter, not a raw event forwarder. Preserve
weak signals in `findings.json`, the run folder, and the Markdown trend log, but
open a visible alert only when the user needs to take action, make a security
decision, or be told about a material risk change.

Use plain-language alert titles and summaries. Prefer titles such as "Broken
SysMain performance counter" or "Windows Update installer changed startup mode"
over generic rule names such as "Recurring error trend" or "Windows service
startup type changed."

Medium and low findings are context by default when they look like normal
Windows servicing, Microsoft Store/Xbox maintenance, isolated performance
counter failures, or other benign computer-health noise. They become
alert-worthy when several weak signals correlate, the same issue worsens,
security controls are affected, user action is needed, or the event appears
beside suspicious account, process, service, task, network, or policy evidence.

Suppressed and ignored findings still matter as context. They should not force a
visible alert by themselves, but they may support an alert if materially new
unsuppressed evidence changes the risk assessment.

## Critical Rules

| Rule | Event Source | Condition | Alert |
| --- | --- | --- | --- |
| Canary account success | Security 4624 | `TargetUserName` equals configured `CanaryAccountName` | Critical |
| Security log cleared | Security 1102 | Any event | Critical |

## High Rules

| Rule | Event Source | Condition | Alert |
| --- | --- | --- | --- |
| Canary account failed logon | Security 4625 | `TargetUserName` equals configured `CanaryAccountName` | High |
| Password spray | Security 4625 | At least 10 failed logons across at least 3 user names in one run | High |
| Remote interactive logon | Security 4624 | LogonType 10, excluding system service pseudo-users | High |
| Account/group change | Security 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4729, 4732, 4733, 4738, 4739, 4756, 4757 | Any event | High |
| Security/audit/firewall policy tampering | Security 4719, 4902, 4906, 4907, 4946-4958, 5025, 5031 | Any event | High |
| New suspicious service | Security 4697 or System 7045 | Service path references user-writable or temporary locations | High |
| Security service startup change | System 7040 | Event matches configured `SecurityServicePattern` | High |
| Security product service issue | System Service Control Manager | Event matches configured `SecurityProductServicePattern` and indicates stop, failure, timeout, termination, or unexpected state | High |
| Suspicious scheduled task | Security 4698-4702 or Task Scheduler Operational 106, 140, 141, 142 | Task content references suspicious commands or user-writable/temporary paths | High |
| Suspicious process command line | Security 4688 | Command line matches living-off-the-land, encoded execution, credential/user changes, backup deletion, log clearing, or security tampering patterns | High |
| Suspicious PowerShell | PowerShell Operational 4103/4104 | Script/module text matches suspicious execution or defense-evasion patterns and is not this monitor itself | High |
| WMI persistence | WMI Activity Operational 5860/5861 | Any permanent event registration signal | High |
| Critical system/application event | System/Application | Critical level event | High |

## Medium Rules

| Rule | Event Source | Condition | Alert |
| --- | --- | --- | --- |
| Repeated failed logons | Security 4625 | At least 5 failed logons for the same user/source key | Medium |
| Account lockout | Security 4740 | Any event | Medium |
| Explicit credential spike | Security 4648 | At least 5 explicit credential events in one run | Medium |
| New service | Security 4697 or System 7045 | Any new service not matching suspicious path rule; normal Microsoft servicing may be tracked as context instead of interrupting | Medium |
| Service startup type changed | System 7040 | Any non-security service startup type change; normal Windows servicing toggles may be tracked as context instead of interrupting | Medium |
| Scheduled task change | Security 4698-4702 or Task Scheduler Operational 106, 140, 141, 142 | Any task create/update/enable/delete not matching suspicious task rule | Medium |
| Network share change | Security 5142, 5143, 5144 | Any share added/changed/deleted | Medium |
| Firewall block burst | Security 5152/5157 | At least 25 Windows Filtering Platform block events in one run | Medium |
| Recurring error trend | System/Application | Same error fingerprint appears in at least 3 runs or at least 5 total times; alert only if recurrence implies action, degradation, or correlation with other suspicious evidence | Medium |

## Suspicious Command Patterns

The process, scheduled task, and PowerShell rules currently watch for:

- Encoded PowerShell or base64 decoding.
- `Invoke-Expression`, `DownloadString`, `Invoke-WebRequest`, or similar
  download-and-execute behavior.
- Hidden PowerShell windows or execution-policy bypass.
- `regsvr32` remote scriptlets, `mshta` URL execution, and suspicious
  `rundll32` JavaScript usage.
- `certutil` download/decode behavior.
- `bitsadmin` transfer behavior.
- `wmic process call create`.
- `schtasks /create` and `sc create`.
- `net user /add` and adding users to local Administrators.
- `vssadmin delete shadows`, `wbadmin delete`, and disabling recovery with
  `bcdedit`.
- Clearing logs with `wevtutil cl`.
- Adding Run/RunOnce persistence registry values.
- Defender/security product/firewall tampering commands such as disabling real-time
  protection, adding Defender exclusions, or stopping security services.

## Noise Controls

- The monitor excludes PowerShell Operational events generated by its own
  scripts and Codex review prompts.
- PowerShell Operational events are retained only when their text matches
  suspicious command patterns.
- Task Scheduler action start/complete noise is not collected; only create,
  update, enable, and delete style operational events are collected.

## References

- Microsoft Security Auditing event 4625, failed logon:
  https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
- Microsoft Security Auditing event 4697, service installed:
  https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4697
- Microsoft account management audit event list:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-account-management
- Microsoft Security Auditing event 5157, WFP blocked connection:
  https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157
- MITRE ATT&CK service creation data component:
  https://attack.mitre.org/datacomponents/DC0060/
