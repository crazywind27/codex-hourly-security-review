# Security Policy

This project processes local Windows event log data. Treat generated run folders,
state files, alert files, alert decisions, and Markdown logs as sensitive.

## Do Not Share

- `config.json`
- `runs/`
- `state.json`
- `alert-decisions.json`
- `actions-taken.txt`
- Generated alert, prompt, stdout, stderr, and event JSON files

## Reporting Issues

If you publish this repository, use GitHub private vulnerability reporting or a
private issue channel for bugs that could leak event-log data, execute commands
unexpectedly, or weaken alerting behavior.

## Operational Notes

The monitor is designed to read logs and write local summaries. Any remediation
work should happen only after the user explicitly approves it in an interactive
session.
