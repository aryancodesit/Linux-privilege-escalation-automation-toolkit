"""SUID/SGID discovery checks."""

from __future__ import annotations

import subprocess
import os
from pathlib import Path

from privesc_toolkit.models import Finding

MODULE_NAME = "suid_sgid"
DEFAULT_FIND_TIMEOUT_SECONDS = 120


def _load_high_risk_binaries(config_path: Path) -> set[str]:
    if not config_path.exists():
        return set()
    lines = config_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return {line.strip() for line in lines if line.strip() and not line.startswith("#")}


def _run_find_command(args: list[str]) -> list[str]:
    try:
        result = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=DEFAULT_FIND_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def run_suid_sgid_check(config_dir: Path) -> list[dict]:
    """Discover SUID/SGID binaries and flag high-risk candidates."""
    if os.name != "posix":
        return []

    high_risk = _load_high_risk_binaries(config_dir / "gtfobins_high_risk.txt")
    suid_paths = _run_find_command(["find", "/", "-xdev", "-type", "f", "-perm", "-4000"])
    sgid_paths = _run_find_command(["find", "/", "-xdev", "-type", "f", "-perm", "-2000"])
    findings: list[dict] = []

    for path in suid_paths + sgid_paths:
        binary_name = Path(path).name
        risky = binary_name in high_risk
        severity = "high" if risky else "low"
        confidence = "high" if risky else "medium"
        refs = [f"https://gtfobins.github.io/gtfobins/{binary_name}/"] if risky else []
        findings.append(
            Finding(
                id=f"{MODULE_NAME}:{binary_name}:{path}",
                module=MODULE_NAME,
                title=f"{'High-risk' if risky else 'SUID/SGID'} binary discovered: {binary_name}",
                severity=severity,
                confidence=confidence,
                evidence=f"Binary path: {path}",
                affected_path_or_command=path,
                exploitation_possibility=(
                    "Known GTFOBins abuse path may allow privilege escalation."
                    if risky
                    else "SUID/SGID context can be abused depending on binary behavior."
                ),
                mitigation=(
                    "Remove unnecessary SUID/SGID bit or replace with safer privilege model."
                ),
                references=refs,
            ).to_dict()
        )
    return findings
