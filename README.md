# Project 06 — Linux Security Auditor

A Python tool that reviews selected Linux security settings and reports potential concerns.

## Features
- Collects operating system, hostname, Python version, and uptime.
- Lists sudo-group membership for access review.
- Checks files in the tests directory for world-writable permissions.
- Reviews SSH settings when sufficient privileges and utilities are available.
- Generates a timestamped text report.

## Technologies
- Ubuntu Linux and Python 3
- Linux command-line utilities
- SSH configuration auditing
- Git and GitHub

## Run
From the project root, execute:

```bash
python3 scripts/security_auditor.py
```

The report is saved locally to `reports/security-audit-report.txt`.

## Limitations
This is a learning prototype, not a complete security scanner. It checks only files directly inside `tests/`. Findings require investigation and do not prove compromise. The tool does not automatically change system settings.




## SSH Audit Note

The SSH check uses non-interactive `sudo` to avoid waiting for a password.
If the automatic check is skipped, inspect the effective SSH settings manually:

```bash
sudo /usr/sbin/sshd -T
```
