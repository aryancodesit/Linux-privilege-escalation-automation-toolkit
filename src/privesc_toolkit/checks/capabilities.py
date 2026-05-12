"""Linux capabilities checks."""

from __future__ import annotations

import os
import re
import subprocess

from privesc_toolkit.models import Finding

MODULE_NAME = "capabilities"
DEFAULT_TIMEOUT_SECONDS = 120
HIGH_RISK_CAPABILITIES = {
    "cap_setuid": "Can set UID and potentially escalate to root context.",
    "cap_setgid": "Can set GID and potentially escalate privileges.",
    "cap_dac_override": "Can bypass file read/write/execute permission checks.",
    "cap_dac_read_search": "Can bypass read/search file permission checks.",
    "cap_sys_admin": "Broad administrative capability with high abuse potential.",
    "cap_sys_ptrace": "Can inspect/control processes and bypass boundaries.",
    "cap_chown": "Can alter file ownership and weaken permission controls.",
}


def _run_getcap() -> list[str]:
    try:
        result = subprocess.run(
            ["getcap", "-r", "/"],
            text=True,
            capture_output=True,
            timeout=DEFAULT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _parse_getcap_line(line: str) -> tuple[str, list[str]]:
    # Typical format: /path/to/bin cap_setuid,cap_net_bind_service=ep
    parts = line.split(maxsplit=1)
    if len(parts) != 2:
        return "", []
    path, cap_part = parts
    cap_tokens = re.split(r"[=,+]", cap_part)
    caps = [token.strip() for token in cap_tokens if token.startswith("cap_")]
    return path, sorted(set(caps))


def run_capabilities_check() -> list[dict]:
    """Detect risky Linux file capabilities."""
    if os.name != "posix":
        return []

    findings: list[dict] = []
    for line in _run_getcap():
        path, caps = _parse_getcap_line(line)
        if not path or not caps:
            continue

        risky_caps = [cap for cap in caps if cap in HIGH_RISK_CAPABILITIES]
        if not risky_caps:
            continue

        severity = "critical" if "cap_sys_admin" in risky_caps else "high"
        details = "; ".join(HIGH_RISK_CAPABILITIES[cap] for cap in risky_caps)
        findings.append(
            Finding(
                id=f"{MODULE_NAME}:{path}",
                module=MODULE_NAME,
                title="Risky Linux capability assignment discovered",
                severity=severity,
                confidence="high",
                evidence=f"{path} has capabilities: {', '.join(caps)}",
                affected_path_or_command=path,
                exploitation_possibility=(
                    "Capability-enabled binaries may bypass standard privilege boundaries."
                ),
                mitigation=(
                    "Remove unnecessary capabilities using setcap -r and apply least privilege."
                ),
                references=[],
            ).to_dict()
        )
        findings[-1]["evidence"] += f". Risk rationale: {details}"

    return findings
