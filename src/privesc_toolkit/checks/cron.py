"""Cron vulnerability checks."""

from __future__ import annotations

import glob
import os
import re
import stat
from pathlib import Path

from privesc_toolkit.models import Finding

MODULE_NAME = "cron"
SYSTEM_CRON_FILES = ["/etc/crontab"]
SYSTEM_CRON_GLOBS = ["/etc/cron.d/*"]
SYSTEM_CRON_DIRS = [
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
]


def _is_world_writable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _extract_command_field(cron_line: str) -> str:
    parts = cron_line.split()
    # System crontab format: m h dom mon dow user command...
    if len(parts) < 7:
        return ""
    return " ".join(parts[6:]).strip()


def _extract_executable_path(command: str) -> str:
    # Keep conservative: first absolute path token.
    match = re.search(r"(/[^ \t;|&]+)", command)
    return match.group(1) if match else ""


def _parse_cron_file(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    valid: list[str] = []
    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        valid.append(raw)
    return valid


def _cron_file_paths() -> list[Path]:
    paths = [Path(p) for p in SYSTEM_CRON_FILES]
    for pattern in SYSTEM_CRON_GLOBS:
        paths.extend(Path(p) for p in glob.glob(pattern))
    return [p for p in paths if p.exists() and p.is_file()]


def run_cron_check() -> list[dict]:
    """Detect cron-based privilege escalation opportunities."""
    if os.name != "posix":
        return []

    findings: list[dict] = []

    for cron_file in _cron_file_paths():
        if _is_world_writable(cron_file):
            findings.append(
                Finding(
                    id=f"{MODULE_NAME}:ww-cron-file:{cron_file}",
                    module=MODULE_NAME,
                    title=f"World-writable cron definition file: {cron_file}",
                    severity="high",
                    confidence="high",
                    evidence=f"{cron_file} is world-writable.",
                    affected_path_or_command=str(cron_file),
                    exploitation_possibility=(
                        "Attackers may inject jobs executed by privileged cron contexts."
                    ),
                    mitigation="Set root ownership and remove world-writable permissions.",
                    references=[],
                ).to_dict()
            )

        for line in _parse_cron_file(cron_file):
            if " root " not in f" {line} ":
                continue
            command = _extract_command_field(line)
            if not command:
                continue
            exec_path = _extract_executable_path(command)
            if not exec_path:
                continue
            exec_target = Path(exec_path)
            if exec_target.exists() and _is_world_writable(exec_target):
                findings.append(
                    Finding(
                        id=f"{MODULE_NAME}:root-job-writable-target:{exec_target}",
                        module=MODULE_NAME,
                        title="Root cron job executes writable file",
                        severity="critical",
                        confidence="high",
                        evidence=(
                            f"Cron line in {cron_file}: '{line}' references world-writable target {exec_target}."
                        ),
                        affected_path_or_command=str(exec_target),
                        exploitation_possibility=(
                            "Writable script/binary executed by root cron can lead to direct root code execution."
                        ),
                        mitigation=(
                            "Restrict file permissions, enforce root ownership, and validate cron targets."
                        ),
                        references=[],
                    ).to_dict()
                )

    for cron_dir in (Path(p) for p in SYSTEM_CRON_DIRS):
        if cron_dir.exists() and _is_world_writable(cron_dir):
            findings.append(
                Finding(
                    id=f"{MODULE_NAME}:ww-cron-dir:{cron_dir}",
                    module=MODULE_NAME,
                    title=f"World-writable cron directory: {cron_dir}",
                    severity="high",
                    confidence="high",
                    evidence=f"{cron_dir} allows write access to all users.",
                    affected_path_or_command=str(cron_dir),
                    exploitation_possibility=(
                        "Attackers may place malicious scripts for scheduled privileged execution."
                    ),
                    mitigation="Remove world-write permissions and enforce strict root ownership.",
                    references=[],
                ).to_dict()
            )

    unique: dict[str, dict] = {}
    for finding in findings:
        unique[finding["id"]] = finding
    return list(unique.values())
