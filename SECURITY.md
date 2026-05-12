# Security Policy

This project processes local Windows event log data. Treat generated run folders,
state files, alert files, alert decisions, and Markdown logs as sensitive.

If remote Codex analysis is enabled, selected event-log-derived data is sent to
Codex/OpenAI. That data can include usernames, hostnames, IP addresses, command
lines, local paths, process names, service names, scheduled task content, event
messages, and alert evidence. Leave `CodexCommandPath` empty or set
`DisableRemoteCodexAnalysis` to `true` for deterministic-only local analysis.

## Do Not Share

- `config.json`
- `runs/`
- `state.json`
- `alert-decisions.json`
- `actions-taken.txt`
- Generated alert, prompt, stdout, stderr, and event JSON files
- Weekly HTML reports and SMTP credential files

## Reporting Issues

If you publish this repository, use GitHub private vulnerability reporting or a
private issue channel for bugs that could leak event-log data, execute commands
unexpectedly, or weaken alerting behavior.

## Operational Notes

The monitor is designed to read logs and write local summaries. Any remediation
work should happen only after the user explicitly approves it in an interactive
session.

Because the scheduled task runs with highest privileges to read protected logs,
install scripts and configuration under a path writable only by trusted users.
By default, Codex is not launched from an elevated monitor process.

The scheduled task does not use `ExecutionPolicy Bypass`. New workstations
should use a script-capable PowerShell policy such as `RemoteSigned`, and script
files downloaded from ZIP archives should be unblocked before installation.

Weekly email digests are redacted by default and should stay that way. Do not
email full reports or raw event data unless the destination mailbox and transport
are approved for host telemetry, local paths, account names, IP addresses, and
command-line evidence.
