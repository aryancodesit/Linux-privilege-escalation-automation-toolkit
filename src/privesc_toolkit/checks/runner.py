"""Check execution registry."""

from __future__ import annotations

from pathlib import Path

from privesc_toolkit.checks.capabilities import run_capabilities_check
from privesc_toolkit.checks.cron import run_cron_check
from privesc_toolkit.checks.kernel import run_kernel_check
from privesc_toolkit.checks.permissions import run_permissions_check
from privesc_toolkit.checks.services import run_services_check
from privesc_toolkit.checks.suid_sgid import run_suid_sgid_check
from privesc_toolkit.checks.sudo_rules import run_sudo_rules_check


def run_checks(scan: str, config_dir: Path) -> list[dict]:
    """Run checks based on selected scan profile."""
    findings: list[dict] = []

    if scan in {"suid-sgid", "baseline"}:
        findings.extend(run_suid_sgid_check(config_dir=config_dir))
    if scan in {"permissions", "baseline"}:
        findings.extend(run_permissions_check())
    if scan in {"sudo", "baseline"}:
        findings.extend(run_sudo_rules_check())
    if scan in {"cron", "baseline"}:
        findings.extend(run_cron_check())
    if scan in {"services", "baseline"}:
        findings.extend(run_services_check())
    if scan in {"capabilities", "baseline"}:
        findings.extend(run_capabilities_check())
    if scan in {"kernel", "baseline"}:
        findings.extend(run_kernel_check(config_dir=config_dir))

    return findings
