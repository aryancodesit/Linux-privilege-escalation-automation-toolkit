# Linux Privilege Escalation Automation Toolkit

Production-oriented, detection-only toolkit for Linux privilege escalation risk assessment.

## Repository Structure

- `src/privesc_toolkit/` - Core application package.
- `src/privesc_toolkit/checks/` - Detection modules (SUID, cron, sudo, services, kernel, permissions).
- `src/privesc_toolkit/analyzer/` - Risk scoring and finding correlation.
- `src/privesc_toolkit/reporter/` - Report export (JSON/Markdown/Text).
- `src/privesc_toolkit/collector/` - Command/system information collectors.
- `src/privesc_toolkit/config/` - Rules, signatures, and static risk data.
- `tests/` - Unit and integration tests.
- `docs/` - Project docs and architecture.
- `reports/` - Generated scan reports.

## Next Steps

1. Implement CLI entrypoint and scan orchestration.
2. Add module-by-module checks.
3. Add analyzer severity framework.
4. Add deterministic report output.

## Run (Current Milestone)

- `python -m privesc_toolkit.main --scan baseline`
- `python -m privesc_toolkit.main --scan system-info`
- `python -m privesc_toolkit.main --scan suid-sgid`
- `python -m privesc_toolkit.main --scan permissions`
- `python -m privesc_toolkit.main --scan sudo`
- `python -m privesc_toolkit.main --scan cron`
- `python -m privesc_toolkit.main --scan services`
- `python -m privesc_toolkit.main --scan capabilities`
- `python -m privesc_toolkit.main --scan kernel`
- `python -m privesc_toolkit.main --scan baseline --output reports/scan.json`

Each run now exports:
- JSON report: `reports/<name>.json`
- Executive markdown report: `reports/<name>.md`
