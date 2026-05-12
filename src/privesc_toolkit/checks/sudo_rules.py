"""Sudo misconfiguration checks."""

from __future__ import annotations

import os
import re
import subprocess

from privesc_toolkit.models import Finding

MODULE_NAME = "sudo_rules"
DEFAULT_TIMEOUT_SECONDS = 20
HIGH_RISK_COMMAND_PATTERNS = [
    r"\bALL\b",
    r"\bvim\b",
    r"\bnano\b",
    r"\bless\b",
    r"\bman\b",
    r"\bfind\b",
    r"\bawk\b",
    r"\bperl\b",
    r"\bpython[0-9.]*\b",
    r"\bbash\b",
    r"\bsh\b",
    r"\btar\b",
    r"\bzip\b",
    r"\bcp\b",
    r"\btee\b",
]


def _run_sudo_list(non_interactive: bool) -> str:
    command = ["sudo", "-l", "-n"] if non_interactive else ["sudo", "-l"]
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return "\n".join([result.stdout.strip(), result.stderr.strip()]).strip()


def _extract_rule_lines(sudo_output: str) -> list[str]:
    return [
        line.strip()
        for line in sudo_output.splitlines()
        if line.strip() and ("NOPASSWD" in line or line.strip().startswith("("))
    ]


def _create_finding(
    suffix: str,
    title: str,
    severity: str,
    evidence: str,
    exploitation: str,
    mitigation: str,
) -> dict:
    return Finding(
        id=f"{MODULE_NAME}:{suffix}",
        module=MODULE_NAME,
        title=title,
        severity=severity,
        confidence="medium",
        evidence=evidence,
        affected_path_or_command="sudo -l",
        exploitation_possibility=exploitation,
        mitigation=mitigation,
        references=[],
    ).to_dict()


def run_sudo_rules_check() -> list[dict]:
    """Inspect sudo rules for privilege escalation risks."""
    if os.name != "posix":
        return []

    output = _run_sudo_list(non_interactive=True) or _run_sudo_list(non_interactive=False)
    if not output:
        return []

    findings: list[dict] = []
    normalized = output.upper()

    if "NOPASSWD" in normalized:
        findings.append(
            _create_finding(
                suffix="nopasswd",
                title="NOPASSWD sudo rule detected",
                severity="high",
                evidence="sudo -l output contains NOPASSWD rule.",
                exploitation=(
                    "Passwordless privileged command execution can allow rapid privilege escalation."
                ),
                mitigation="Limit or remove NOPASSWD entries for non-admin users.",
            )
        )

    if re.search(r"\bALL\s*=\s*\(ALL(?::ALL)?\)\s*ALL\b", output, flags=re.IGNORECASE):
        findings.append(
            _create_finding(
                suffix="all-all",
                title="Broad sudo rule (ALL=(ALL) ALL) detected",
                severity="critical",
                evidence="sudo -l includes unrestricted ALL privileges.",
                exploitation="User effectively has full root-equivalent sudo access.",
                mitigation="Replace with least-privilege command-specific sudo rules.",
            )
        )

    for line in _extract_rule_lines(output):
        for pattern in HIGH_RISK_COMMAND_PATTERNS:
            if re.search(pattern, line, flags=re.IGNORECASE):
                findings.append(
                    _create_finding(
                        suffix=f"risky-cmd:{abs(hash(line))}",
                        title="Potentially risky sudo-allowed command",
                        severity="high",
                        evidence=f"Matched sudo rule: {line}",
                        exploitation=(
                            "Interactive or shell-capable binaries may allow command escape as root."
                        ),
                        mitigation=(
                            "Restrict command list to audited binaries with fixed absolute paths."
                        ),
                    )
                )
                break

    if "!" in output and "env_reset" not in output:
        findings.append(
            _create_finding(
                suffix="env-controls",
                title="Potential insecure sudo environment controls",
                severity="low",
                evidence="sudo output indicates custom environment behavior.",
                exploitation="Environment manipulation can weaken command safety boundaries.",
                mitigation="Enable env_reset and review env_keep/env_check rules.",
            )
        )

    # Deduplicate by finding ID for stable output.
    unique: dict[str, dict] = {}
    for finding in findings:
        unique[finding["id"]] = finding
    return list(unique.values())
