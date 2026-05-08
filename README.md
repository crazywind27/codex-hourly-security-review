# Codex Hourly Security Review

Windows scheduled-task monitor that reviews recent Windows event logs every
hour, appends a running Markdown log, and opens a visible alert window when a
finding should interrupt the user. It can optionally use the Codex CLI for
remote analysis and interactive alert triage.

## What It Does

- Reviews targeted Security, System, Application, Task Scheduler Operational,
  PowerShell Operational, and WMI Activity Operational events.
- Applies deterministic rules for common indicators of compromise, persistence,
  audit tampering, account changes, security-service issues, canary-account
  activity, and recurring system-health trends.
- Optionally asks `codex exec` for a structured JSON triage decision when an
  absolute `CodexCommandPath` is configured and the process is not elevated.
- Writes a durable Markdown trend log.
- Opens a visible alert window when an alert is warranted. If remote Codex
  analysis is configured and allowed for the current integrity level, the alert
  window can launch an interactive `codex resume` session.
- Records alert dispositions and user-approved ignore suppressions so matching
  known-benign findings can be tracked without repeatedly interrupting you.
- Keeps per-run evidence locally under `runs/`.

## Requirements

- Windows 10/11 with PowerShell 5.1 or later.
- Optional: OpenAI Codex CLI installed and authenticated for the user who will
  run non-elevated analysis. Deterministic alerting works without remote Codex
  analysis.
- Permission to read the Windows Security log. The installer creates the task
  with highest privileges for the current interactive user.
- A stable install folder whose scripts are writable only by trusted users.
  Because the scheduled task runs with highest privileges, do not install this
  in a directory that untrusted local users can modify.
- Recommended: process command-line auditing plus PowerShell script block/module
  logging, so the IOC rules have useful telemetry.

## Install

1. Clone or copy this repo to a stable local path, for example:

   ```powershell
   C:\Tools\codex-hourly-security-review
   ```

2. Copy the sample config:

   ```powershell
   Copy-Item .\config.example.json .\config.json
   ```

3. Edit `config.json` for your computer:

   - `ComputerLabel`: friendly name shown in alerts.
   - `WorkRoot` and `MonitorRoot`: leave empty to use the repo folder, or set
     them to an absolute path if you install the scripts somewhere else.
   - `DriveLogPath`: leave empty to use Documents, or set a Markdown log
     destination. This can be a Google Drive, OneDrive, Dropbox, or local
     Documents path.
   - `AlertDecisionsPath`: leave empty to store alert decisions in the repo
     folder, or set an absolute path for the local disposition/suppression
     record.
   - `AllowCriticalAlertSuppressions`: defaults to `false`; leave it that way
     unless you intentionally want ignored critical findings to suppress future
     alerts.
   - `CanaryAccountName`: optional account name that should never normally log
     in. Leave empty to disable canary-account rules.
   - `SecurityProductName` and service patterns: your AV/security product and
     related Windows services.

   - `CodexCommandPath`: absolute path to `codex.cmd` or `codex.exe` if you want
     remote Codex analysis. Leave empty for deterministic-only mode.
   - `DisableRemoteCodexAnalysis`: set `true` to force deterministic-only mode.
   - `AllowCodexWhenElevated`: defaults to `false`. Leave it disabled unless you
     have explicitly reviewed the local privilege risk of running Codex from a
     high-integrity scheduled task.

4. On a new workstation, make sure Windows PowerShell can run local scripts.
   The scheduled task intentionally does not use `ExecutionPolicy Bypass`.

   ```powershell
   Get-ExecutionPolicy
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

   If you downloaded the repo as a ZIP instead of cloning it with Git, unblock
   the scripts before installing:

   ```powershell
   Get-ChildItem -Recurse -File -Filter *.ps1 | Unblock-File
   ```

5. Install the scheduled task from an elevated PowerShell prompt:

   ```powershell
   powershell.exe -NoProfile -File .\Install-HourlySecurityReviewTask.ps1
   ```

The task runs hourly as the current interactive user with highest privileges so
it can read protected Windows logs. Routine task windows are hidden. Alert
windows are visible. By default, the elevated task does not start Codex; it uses
deterministic findings and displays alert context instead.

## Upgrade

To upgrade an existing installation, stop or wait for any current run to finish,
copy the new repository files over the installed script folder, keep the local
`config.json`, then rerun the installer if the scheduled-task action needs to be
refreshed:

```powershell
powershell.exe -NoProfile -File .\Install-HourlySecurityReviewTask.ps1
```

Generated evidence, `state.json`, `alert-decisions.json`, and `config.json`
should remain local to each installed machine.

## Test

After installation, run:

```powershell
powershell.exe -NoProfile -File .\Test-Alert.ps1
```

This writes a harmless PowerShell string containing IOC keywords, then starts
the scheduled task. If PowerShell operational logging is enabled, the monitor
should classify it as a high-severity test/false-positive alert and open a
visible alert window. By default, an elevated task shows the alert text and the
manual disposition command instead of starting Codex. If `CodexCommandPath` is
configured and Codex is allowed for that process, the alert window can start the
interactive Codex flow.

## Uninstall

```powershell
powershell.exe -NoProfile -File .\Uninstall-HourlySecurityReviewTask.ps1
```

## Files

- `Run-HourlySecurityReview.ps1`: main hourly monitor.
- `Launch-CodexSecurityAlert.ps1`: prepares and opens the interactive Codex
  alert session.
- `Install-HourlySecurityReviewTask.ps1`: creates the hourly scheduled task.
- `Uninstall-HourlySecurityReviewTask.ps1`: removes the scheduled task.
- `Set-CodexAlertDisposition.ps1`: records alert decisions and ignored-finding
  suppressions.
- `Test-Alert.ps1`: harmless manual alert test.
- `ALERT-RULES.md`: deterministic rule inventory.
- `codex-security-review.schema.json`: JSON schema for Codex analysis output.
- `config.example.json`: sample local configuration.

## Privacy

Do not commit `config.json`, `runs/`, `state.json`, `alert-decisions.json`,
`actions-taken.txt`, or generated log files. They may contain user names, host
names, local paths, commands, event log records, alert evidence, and local
disposition notes. The included `.gitignore` excludes those files by default.

If remote Codex analysis is enabled, selected Windows event-log-derived data is
sent to Codex/OpenAI for triage. That data can include usernames, hostnames, IP
addresses, local paths, command lines, process names, service names, scheduled
task names/content, event messages, and alert evidence. Set
`DisableRemoteCodexAnalysis` to `true` or leave `CodexCommandPath` empty for
deterministic-only local analysis.

## Alert Dispositions

Each finding gets a precise fingerprint plus a broader suppression key, and each
run writes `findings.json`. When an alert opens, the visible alert window shows
a disposition command. If an interactive Codex session is launched, its prompt
includes the same command. After you explicitly decide that an alert can be
ignored or should not trigger again, Codex can run this helper, or you can run it
manually:

```powershell
powershell.exe -NoProfile -File .\Set-CodexAlertDisposition.ps1 -AlertPath "<run>\alert.md" -Decision Ignored -Reason "<why this is known benign>"
```

That writes `alert-decisions.json`. Future runs still record matching findings
in `findings.json` and the Markdown log as suppressed, but matching non-critical
findings no longer force a visible alert. Matching uses the exact fingerprint
first, then the suppression key so repeated instances of the same alert category
can be handled even when event counts change. Use `Acknowledged`,
`Investigating`, or `Resolved` when you want an audit trail without suppressing
future matches.

The disposition file is intentionally simple JSON. To stop suppressing a finding,
edit `alert-decisions.json` and change that suppression's `Status` from
`ignored` to `resolved` or remove the suppression entry. Keep the decision
history if you want a durable audit trail.

## License

No open-source license is included yet. Add a license before publishing this as
a public repository; for a private personal repository, leaving it unlicensed is
acceptable.

## Safety Model

The scheduled review is read-only against Windows logs. It writes local evidence
and Markdown summaries, then opens an alert window when needed. Remote Codex
analysis is opt-in through an absolute `CodexCommandPath` and is skipped by
default when the monitor is elevated. Event-log text is treated as untrusted
telemetry, not as instructions. The alert session prompt tells Codex not to
change system settings, accounts, firewall or audit policy, security software,
apps, files, or scheduled tasks unless the user explicitly approves that change
in the interactive session.
