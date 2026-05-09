# Changelog

## 0.3.0 - 2026-05-09

- Added `New-WeeklySecurityReport.ps1` for local weekly HTML reports.
- Added current-vs-previous-period trend summaries for alerts, findings,
  severity counts, telemetry gaps, missed-run estimates, and event groups.
- Added optional redacted SMTP email digest support.
- Updated installer and uninstaller to manage a limited-privilege weekly report
  scheduled task.

## 0.2.0 - 2026-05-08

- Added finding fingerprints, suppression keys, per-run `findings.json`, and
  alert fingerprints.
- Added `Set-CodexAlertDisposition.ps1` for acknowledged, investigating,
  resolved, and ignored alert decisions.
- Added ignored-finding suppressions through `alert-decisions.json` so matching
  non-critical findings are tracked without forcing repeated visible alerts.
- Updated the interactive alert prompt to tell Codex how to record a user-
  approved ignore disposition.

## 0.1.0 - 2026-05-07

- Initial GitHub-ready package.
- Hourly Windows event log review with deterministic IOC rules.
- Codex JSON analysis using `codex exec`.
- Interactive alert handoff using persisted sessions and `codex resume`.
- Configurable computer label, log path, canary account, and security-service
  patterns.
- Harmless manual alert test helper.
