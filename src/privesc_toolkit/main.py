"""Toolkit CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from privesc_toolkit.checks.runner import run_checks
from privesc_toolkit.collector.system_info import collect_system_info
from privesc_toolkit.models import ScanResult
from privesc_toolkit.reporter.markdown_reporter import generate_markdown_report

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="privesc-toolkit",
        description="Linux Privilege Escalation Automation Toolkit (detection only).",
    )
    parser.add_argument(
        "--scan",
        default="baseline",
        choices=[
            "system-info",
            "suid-sgid",
            "permissions",
            "sudo",
            "cron",
            "services",
            "capabilities",
            "kernel",
            "baseline",
        ],
        help="Scan profile to run.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output JSON file path. Defaults to reports/system-info-<timestamp>.json",
    )
    return parser


def _default_output_path() -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("reports") / f"scan-{timestamp}.json"


def _write_json_report(result: ScanResult, output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return output_path


def _write_markdown_report(result: ScanResult, output_path: Path) -> Path:
    md_path = output_path.with_suffix(".md")
    md_path.write_text(generate_markdown_report(result), encoding="utf-8")
    return md_path


def _sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 99),
            str(item.get("module", "")),
            str(item.get("id", "")),
        ),
    )


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity", "info")).lower()
        counts[sev if sev in counts else "info"] += 1
    return counts

def main() -> None:
    """Run the toolkit."""
    parser = _build_parser()
    args = parser.parse_args()

    if os.name != "posix":
        print("Warning: Non-Linux host detected. Results may be limited.")

    system_info = collect_system_info()
    findings = _sort_findings(
        run_checks(
        scan=args.scan, config_dir=Path(__file__).resolve().parent / "config"
        )
    )
    result = ScanResult(scan_name=args.scan, system_info=system_info, findings=findings)
    report_path = _write_json_report(result, args.output or _default_output_path())
    markdown_path = _write_markdown_report(result, report_path)
    counts = _severity_counts(findings)

    print("Scan completed successfully.")
    print(f"Module        : {args.scan}")
    print(f"User          : {system_info.username} (uid={system_info.uid})")
    print(f"Root Context  : {'yes' if system_info.is_root else 'no'}")
    print(f"Kernel        : {system_info.kernel_release}")
    print(f"OS            : {system_info.os_pretty_name}")
    print(f"Findings      : {len(findings)}")
    print(
        "Severity      : "
        f"critical={counts['critical']}, high={counts['high']}, "
        f"medium={counts['medium']}, low={counts['low']}, info={counts['info']}"
    )
    print(f"Report        : {report_path}")
    print(f"Exec Report   : {markdown_path}")


if __name__ == "__main__":
    main()
