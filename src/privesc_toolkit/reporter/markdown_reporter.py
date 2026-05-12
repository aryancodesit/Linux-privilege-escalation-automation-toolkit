"""Markdown report output."""

from __future__ import annotations

from collections import Counter, defaultdict

from privesc_toolkit.models import ScanResult

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _severity_counts(findings: list[dict]) -> Counter:
    counts: Counter = Counter()
    for finding in findings:
        counts[str(finding.get("severity", "info")).lower()] += 1
    return counts


def _module_summary(findings: list[dict]) -> dict[str, Counter]:
    grouped: dict[str, Counter] = defaultdict(Counter)
    for finding in findings:
        module = str(finding.get("module", "unknown"))
        sev = str(finding.get("severity", "info")).lower()
        grouped[module][sev] += 1
    return dict(grouped)


def _top_action_items(findings: list[dict], limit: int = 10) -> list[str]:
    prioritized = sorted(
        findings,
        key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 99),
    )
    action_counts: Counter = Counter()
    for finding in prioritized:
        sev = str(finding.get("severity", "info")).lower()
        if sev not in {"critical", "high", "medium"}:
            continue
        mitigation = str(finding.get("mitigation", "")).strip()
        if mitigation:
            action_counts[mitigation] += 1
    return [text for text, _ in action_counts.most_common(limit)]


def generate_markdown_report(result: ScanResult, top_n: int = 10) -> str:
    """Render a manager-friendly markdown report from scan output."""
    findings = result.findings
    sev_counts = _severity_counts(findings)
    by_module = _module_summary(findings)
    sorted_findings = sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 99),
            str(item.get("module", "")),
        ),
    )
    top_findings = sorted_findings[:top_n]

    lines: list[str] = []
    lines.append(f"# Privilege Escalation Scan Report ({result.scan_name})")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append(f"- Total findings: **{len(findings)}**")
    lines.append(
        "- Severity split: "
        f"critical={sev_counts.get('critical', 0)}, "
        f"high={sev_counts.get('high', 0)}, "
        f"medium={sev_counts.get('medium', 0)}, "
        f"low={sev_counts.get('low', 0)}, "
        f"info={sev_counts.get('info', 0)}"
    )
    lines.append(f"- Generated at (UTC): `{result.generated_at_utc}`")
    lines.append("")
    lines.append("## System Context")
    if result.system_info is not None:
        info = result.system_info
        lines.append(f"- Host: `{info.hostname}`")
        lines.append(f"- User: `{info.username}` (uid={info.uid})")
        lines.append(f"- OS: `{info.os_pretty_name}`")
        lines.append(f"- Kernel: `{info.kernel_release}`")
    lines.append("")
    lines.append("## Findings By Module")
    for module in sorted(by_module):
        m = by_module[module]
        lines.append(
            f"- `{module}`: total={sum(m.values())}, "
            f"critical={m.get('critical', 0)}, high={m.get('high', 0)}, "
            f"medium={m.get('medium', 0)}, low={m.get('low', 0)}, info={m.get('info', 0)}"
        )
    lines.append("")
    lines.append(f"## Top {min(top_n, len(top_findings))} Prioritized Findings")
    for finding in top_findings:
        lines.append(
            f"- **[{str(finding.get('severity', 'info')).upper()}]** "
            f"`{finding.get('module', 'unknown')}` - {finding.get('title', 'Untitled')}"
        )
        lines.append(f"  - Evidence: {finding.get('evidence', 'n/a')}")
        lines.append(f"  - Mitigation: {finding.get('mitigation', 'n/a')}")
    lines.append("")
    lines.append("## Top 10 Action Items")
    action_items = _top_action_items(findings, limit=10)
    if action_items:
        for idx, item in enumerate(action_items, start=1):
            lines.append(f"{idx}. {item}")
    else:
        lines.append("1. No medium-or-higher remediation actions identified.")
    lines.append("")
    return "\n".join(lines)
