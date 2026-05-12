"""Shared data models for findings and scan output."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class Finding:
    """Standardized finding schema."""

    id: str
    module: str
    title: str
    severity: str
    confidence: str
    evidence: str
    affected_path_or_command: str
    exploitation_possibility: str
    mitigation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert model to JSON-serializable dictionary."""
        return asdict(self)


@dataclass(slots=True)
class SystemInfo:
    """Core host and user context captured at scan start."""

    username: str
    uid: int
    gid: int
    groups: list[str]
    is_root: bool
    hostname: str
    architecture: str
    kernel_release: str
    kernel_version: str
    os_pretty_name: str
    os_id: str
    os_version_id: str

    def to_dict(self) -> dict:
        """Convert model to JSON-serializable dictionary."""
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    """Top-level scan output."""

    scan_name: str
    generated_at_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    system_info: SystemInfo | None = None
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert model to JSON-serializable dictionary."""
        return asdict(self)
