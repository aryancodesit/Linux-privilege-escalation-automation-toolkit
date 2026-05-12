"""Systemd service misconfiguration checks."""

from __future__ import annotations

import glob
import os
import re
import stat
from pathlib import Path

from privesc_toolkit.models import Finding

MODULE_NAME = "services"
UNIT_PATTERNS = [
    "/etc/systemd/system/*.service",
    "/usr/lib/systemd/system/*.service",
    "/lib/systemd/system/*.service",
]


def _is_world_writable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & stat.S_IWOTH)
    except OSError:
        return False


def _unit_files() -> list[Path]:
    files: list[Path] = []
    for pattern in UNIT_PATTERNS:
        files.extend(Path(p) for p in glob.glob(pattern))
    return [f for f in files if f.exists() and f.is_file()]


def _read_unit(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _extract_execstart(content: str) -> list[str]:
    commands: list[str] = []
    for line in content.splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or not raw.startswith("ExecStart="):
            continue
        commands.append(raw.split("=", 1)[1].strip())
    return commands


def _extract_user(content: str) -> str:
    for line in content.splitlines():
        raw = line.strip()
        if raw.startswith("User="):
            return raw.split("=", 1)[1].strip()
    return "root"  # system services default to root if User is not specified


def _extract_absolute_path(command: str) -> str:
    match = re.search(r"(/[^ \t;|&]+)", command)
    return match.group(1) if match else ""


def _is_non_absolute_exec_risky(command: str) -> bool:
    cleaned = command.strip()
    while cleaned and cleaned[0] in "-@:+!":
        cleaned = cleaned[1:].lstrip()
    if not cleaned:
        return False
    token = cleaned.split()[0]
    if token.startswith("/"):
        return False
    # Ignore common safe variable/specifier forms handled by systemd.
    if token.startswith("$") or "%" in token:
        return False
    return True


def run_services_check() -> list[dict]:
    """Detect systemd privilege escalation misconfigurations."""
    if os.name != "posix":
        return []

    findings: list[dict] = []
    for unit in _unit_files():
        content = _read_unit(unit)
        if not content:
            continue
        user = _extract_user(content).lower()
        is_root_context = user in {"root", ""}
        exec_commands = _extract_execstart(content)

        if is_root_context and _is_world_writable(unit):
            findings.append(
                Finding(
                    id=f"{MODULE_NAME}:writable-unit:{unit}",
                    module=MODULE_NAME,
                    title="Root-context systemd unit file is world-writable",
                    severity="high",
                    confidence="high",
                    evidence=f"Unit file {unit} has world-writable permission bits.",
                    affected_path_or_command=str(unit),
                    exploitation_possibility=(
                        "Attackers can alter service definitions executed in privileged context."
                    ),
                    mitigation="Restrict unit file permissions and enforce root ownership.",
                    references=[],
                ).to_dict()
            )

        for command in exec_commands:
            abs_path = _extract_absolute_path(command)
            if is_root_context and abs_path and Path(abs_path).exists() and _is_world_writable(Path(abs_path)):
                findings.append(
                    Finding(
                        id=f"{MODULE_NAME}:writable-exec:{unit}:{abs_path}",
                        module=MODULE_NAME,
                        title="Root service executes world-writable target",
                        severity="critical",
                        confidence="high",
                        evidence=f"{unit} ExecStart points to writable target: {abs_path}",
                        affected_path_or_command=abs_path,
                        exploitation_possibility=(
                            "Replacing writable service executable/script may grant root code execution."
                        ),
                        mitigation="Lock down target file permissions and service ownership model.",
                        references=[],
                    ).to_dict()
                )

            if is_root_context and _is_non_absolute_exec_risky(command):
                findings.append(
                    Finding(
                        id=f"{MODULE_NAME}:relative-exec:{unit}:{hash(command)}",
                        module=MODULE_NAME,
                        title="Root service uses non-absolute ExecStart command",
                        severity="medium",
                        confidence="medium",
                        evidence=f"{unit} has non-absolute ExecStart value: {command}",
                        affected_path_or_command=str(unit),
                        exploitation_possibility=(
                            "PATH resolution ambiguity can increase command hijack risk."
                        ),
                        mitigation="Use fully qualified absolute paths in ExecStart directives.",
                        references=[],
                    ).to_dict()
                )

    unique: dict[str, dict] = {}
    for finding in findings:
        unique[finding["id"]] = finding
    return list(unique.values())
