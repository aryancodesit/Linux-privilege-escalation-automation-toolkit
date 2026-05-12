"""Kernel risk and CVE mapping checks."""

from __future__ import annotations

import json
import os
import platform
import re
from pathlib import Path

from privesc_toolkit.models import Finding

MODULE_NAME = "kernel"
EOL_MAJOR_MINOR_THRESHOLD = (5, 4)


def _parse_kernel_tuple(kernel_release: str) -> tuple[int, int, int]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", kernel_release)
    if not match:
        return (0, 0, 0)
    return tuple(int(part) for part in match.groups())


def _load_cve_rules(config_dir: Path) -> list[dict]:
    mapping_file = config_dir / "kernel_cve_map.json"
    if not mapping_file.exists():
        return []
    try:
        payload = json.loads(mapping_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rules = payload.get("rules", [])
    return rules if isinstance(rules, list) else []


def _match_rule(kernel_tuple: tuple[int, int, int], rule: dict) -> bool:
    max_version = rule.get("max_version_inclusive")
    if not isinstance(max_version, str):
        return False
    max_tuple = _parse_kernel_tuple(max_version)
    return kernel_tuple <= max_tuple


def _eol_heuristic_finding(kernel_release: str, kernel_tuple: tuple[int, int, int]) -> dict | None:
    if kernel_tuple == (0, 0, 0):
        return None
    if kernel_tuple[:2] >= EOL_MAJOR_MINOR_THRESHOLD:
        return None
    return Finding(
        id=f"{MODULE_NAME}:eol-heuristic:{kernel_release}",
        module=MODULE_NAME,
        title="Kernel appears outdated by baseline heuristic",
        severity="high",
        confidence="medium",
        evidence=(
            f"Detected kernel version {kernel_release} is below recommended baseline "
            f"{EOL_MAJOR_MINOR_THRESHOLD[0]}.{EOL_MAJOR_MINOR_THRESHOLD[1]}."
        ),
        affected_path_or_command="uname -r",
        exploitation_possibility=(
            "Older kernels are more likely to include known local privilege escalation vulnerabilities."
        ),
        mitigation=(
            "Upgrade to a vendor-supported kernel and apply latest security patches."
        ),
        references=[],
    ).to_dict()


def run_kernel_check(config_dir: Path) -> list[dict]:
    """Detect kernel risk based on version heuristics and local CVE rules."""
    if os.name != "posix":
        return []

    kernel_release = platform.release()
    kernel_tuple = _parse_kernel_tuple(kernel_release)
    findings: list[dict] = []

    for rule in _load_cve_rules(config_dir):
        if not isinstance(rule, dict):
            continue
        if not _match_rule(kernel_tuple, rule):
            continue

        cve = str(rule.get("cve", "unknown-cve"))
        severity = str(rule.get("severity", "high")).lower()
        summary = str(rule.get("summary", "Kernel version may be exposed to known vulnerability."))
        mitigation = str(
            rule.get(
                "mitigation",
                "Apply vendor kernel updates and validate against official advisories.",
            )
        )
        refs = rule.get("references", [])
        refs = refs if isinstance(refs, list) else []
        findings.append(
            Finding(
                id=f"{MODULE_NAME}:cve:{cve}:{kernel_release}",
                module=MODULE_NAME,
                title=f"Potential vulnerable kernel version match: {cve}",
                severity=severity,
                confidence="medium",
                evidence=(
                    f"Current kernel {kernel_release} matched rule max_version_inclusive="
                    f"{rule.get('max_version_inclusive')}. {summary}"
                ),
                affected_path_or_command="uname -r",
                exploitation_possibility=(
                    "Matching known vulnerable ranges can indicate potential local privilege escalation risk."
                ),
                mitigation=mitigation,
                references=[str(r) for r in refs],
            ).to_dict()
        )

    heuristic = _eol_heuristic_finding(kernel_release, kernel_tuple)
    if heuristic:
        findings.append(heuristic)

    return findings
