"""Weak file and directory permission checks."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from privesc_toolkit.models import Finding

MODULE_NAME = "permissions"
DEFAULT_FIND_TIMEOUT_SECONDS = 120
SENSITIVE_FILES = ["/etc/passwd", "/etc/shadow"]
SENSITIVE_DIRS = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/systemd/system"]
NOISE_PREFIXES = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/lock/",
)


def _run_find(args: list[str]) -> list[str]:
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


def _is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def _has_sticky_bit(mode: int) -> bool:
    return bool(mode & stat.S_ISVTX)


def _is_noise_path(path: str) -> bool:
    return path.startswith(NOISE_PREFIXES)


def _sensitive_path_findings() -> list[dict]:
    findings: list[dict] = []
    for path in SENSITIVE_FILES:
        target = Path(path)
        if not target.exists():
            continue
        try:
            mode = target.stat().st_mode
        except OSError:
            continue
        if _is_world_writable(mode):
            findings.append(
                Finding(
                    id=f"{MODULE_NAME}:sensitive-file:{path}",
                    module=MODULE_NAME,
                    title=f"World-writable sensitive file: {path}",
                    severity="critical",
                    confidence="high",
                    evidence=f"{path} has world-writable permission bits.",
                    affected_path_or_command=path,
                    exploitation_possibility=(
                        "Attackers may modify authentication-critical files for privilege escalation."
                    ),
                    mitigation="Set strict ownership/permissions (root-owned, not world-writable).",
                    references=[],
                ).to_dict()
            )
    for directory in SENSITIVE_DIRS:
        target = Path(directory)
        if not target.exists():
            continue
        try:
            mode = target.stat().st_mode
        except OSError:
            continue
        if _is_world_writable(mode):
            findings.append(
                Finding(
                    id=f"{MODULE_NAME}:sensitive-dir:{directory}",
                    module=MODULE_NAME,
                    title=f"World-writable sensitive directory: {directory}",
                    severity="high",
                    confidence="high",
                    evidence=f"{directory} has world-writable permission bits.",
                    affected_path_or_command=directory,
                    exploitation_possibility=(
                        "Writable scheduler/service paths can be abused to run attacker-controlled code."
                    ),
                    mitigation="Remove world-write bit and enforce root ownership.",
                    references=[],
                ).to_dict()
            )
    return findings


def _world_writable_findings() -> list[dict]:
    findings: list[dict] = []
    # Keep scan practical: avoid proc/sys/dev/run noise.
    excluded = ["-path", "/proc", "-prune", "-o", "-path", "/sys", "-prune", "-o", "-path", "/dev", "-prune", "-o", "-path", "/run", "-prune", "-o"]
    ww_files = _run_find(
        ["find", "/"] + excluded + ["-type", "f", "-perm", "-0002", "-print"]
    )
    ww_dirs = _run_find(
        ["find", "/"] + excluded + ["-type", "d", "-perm", "-0002", "-print"]
    )

    for path in ww_files[:200]:
        if _is_noise_path(path):
            continue
        findings.append(
            Finding(
                id=f"{MODULE_NAME}:world-writable-file:{path}",
                module=MODULE_NAME,
                title="World-writable file discovered",
                severity="low",
                confidence="medium",
                evidence=f"File allows write access to all users: {path}",
                affected_path_or_command=path,
                exploitation_possibility=(
                    "If consumed by privileged processes, attackers can alter execution behavior."
                ),
                mitigation="Restrict write permissions to required owner/group only.",
                references=[],
            ).to_dict()
        )
    for path in ww_dirs[:200]:
        if _is_noise_path(path):
            continue
        try:
            mode = Path(path).stat().st_mode
        except OSError:
            continue
        if _has_sticky_bit(mode):
            continue
        findings.append(
            Finding(
                id=f"{MODULE_NAME}:world-writable-dir:{path}",
                module=MODULE_NAME,
                title="World-writable directory discovered",
                severity="low",
                confidence="medium",
                evidence=f"Directory allows write access to all users: {path}",
                affected_path_or_command=path,
                exploitation_possibility=(
                    "Writable directories can enable file planting or script replacement attacks."
                ),
                mitigation=(
                    "Remove unnecessary world-write bits and enforce sticky bit where appropriate."
                ),
                references=[],
            ).to_dict()
        )
    return findings


def run_permissions_check() -> list[dict]:
    """Discover weak Linux file and directory permission configurations."""
    if os.name != "posix":
        return []
    findings: list[dict] = []
    findings.extend(_sensitive_path_findings())
    findings.extend(_world_writable_findings())
    return findings
