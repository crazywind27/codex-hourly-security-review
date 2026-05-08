# Codex Hourly Security Review

Windows scheduled-task monitor that uses the Codex CLI to review recent Windows
event logs every hour, append a running Markdown log, and open an interactive
Codex alert session when a finding should interrupt the user.

## What It Does

- Reviews targeted Security, System, Application, Task Scheduler Operational,
  PowerShell Operational, and WMI Activity Operational events.
- Applies deterministic rules for common indicators of compromise, persistence,
  audit tampering, account changes, security-service issues, canary-account
  activity, and recurring system-health trends.
- Asks `codex exec` for a structured JSON triage decision.
- Writes a durable Markdown trend log.
- Opens a visible interactive `codex resume` session only when an alert is
  warranted.
- Keeps per-run evidence locally under `runs/`.

## Requirements

- Windows 10/11 with PowerShell 5.1 or later.
- OpenAI Codex CLI installed and authenticated for the user that will run the
  scheduled task.
- Permission to read the Windows Security log. The installer creates the task
  with highest privileges for the current interactive user.
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
   - `CanaryAccountName`: optional account name that should never normally log
     in. Leave empty to disable canary-account rules.
   - `SecurityProductName` and service patterns: your AV/security product and
     related Windows services.

4. Install the scheduled task from an elevated PowerShell prompt:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-HourlySecurityReviewTask.ps1
   ```

The task runs hourly as the current interactive user. Routine task windows are
hidden. Alert windows are visible and interactive.

## Test

After installation, run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-Alert.ps1
```

This writes a harmless PowerShell string containing IOC keywords, then starts
the scheduled task. If PowerShell operational logging is enabled, the monitor
should classify it as a high-severity test/false-positive alert and open the
interactive Codex alert flow.

## Uninstall

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Uninstall-HourlySecurityReviewTask.ps1
```

## Files

- `Run-HourlySecurityReview.ps1`: main hourly monitor.
- `Launch-CodexSecurityAlert.ps1`: prepares and opens the interactive Codex
  alert session.
- `Install-HourlySecurityReviewTask.ps1`: creates the hourly scheduled task.
- `Uninstall-HourlySecurityReviewTask.ps1`: removes the scheduled task.
- `Test-Alert.ps1`: harmless manual alert test.
- `ALERT-RULES.md`: deterministic rule inventory.
- `codex-security-review.schema.json`: JSON schema for Codex analysis output.
- `config.example.json`: sample local configuration.

## Privacy

Do not commit `config.json`, `runs/`, `state.json`, `actions-taken.txt`, or
generated log files. They may contain user names, host names, local paths,
commands, event log records, and alert evidence. The included `.gitignore`
excludes those files by default.

## License

No open-source license is included yet. Add a license before publishing this as
a public repository; for a private personal repository, leaving it unlicensed is
acceptable.

## Safety Model

The scheduled review is read-only against Windows logs. It writes local evidence
and Markdown summaries, then opens an interactive alert session. The alert
session prompt tells Codex not to change system settings, accounts, firewall or
audit policy, security software, apps, files, or scheduled tasks unless the user
explicitly approves that change in the interactive session.
