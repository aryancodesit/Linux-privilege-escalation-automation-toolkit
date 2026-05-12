"""System information collection."""

from __future__ import annotations

import getpass
import os
import platform
import socket
from pathlib import Path

from privesc_toolkit.models import SystemInfo

try:
    import grp
except ImportError:  # pragma: no cover - platform dependent
    grp = None


def _read_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    """Parse /etc/os-release into a dictionary."""
    data: dict[str, str] = {}
    if not path.exists():
        return data

    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def _resolve_groups() -> list[str]:
    """Resolve current user's supplementary group names."""
    if grp is None:
        return []

    groups: list[str] = []
    for gid in os.getgroups():
        try:
            groups.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            groups.append(str(gid))
    return sorted(set(groups))


def collect_system_info() -> SystemInfo:
    """Collect baseline host and user context."""
    uid = os.getuid() if hasattr(os, "getuid") else -1
    gid = os.getgid() if hasattr(os, "getgid") else -1
    os_release = _read_os_release()

    return SystemInfo(
        username=getpass.getuser(),
        uid=uid,
        gid=gid,
        groups=_resolve_groups(),
        is_root=(uid == 0),
        hostname=socket.gethostname(),
        architecture=platform.machine(),
        kernel_release=platform.release(),
        kernel_version=platform.version(),
        os_pretty_name=os_release.get("PRETTY_NAME", "unknown"),
        os_id=os_release.get("ID", "unknown"),
        os_version_id=os_release.get("VERSION_ID", "unknown"),
    )
