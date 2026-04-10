from __future__ import annotations

from pathlib import Path
from typing import Any, cast


def write_codex_benchmark_report(
    *,
    project_root: Path,
    summary: dict[str, Any],
    methodology: str,
    limitations: str,
    reproducibility: str,
) -> Path:
    docs_dir = project_root / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)
    report_path = docs_dir / "CODEX_BENCHMARK_REPORT.md"

    providers = cast(dict[str, dict[str, float]], summary["providers"])
    provider_summary = providers["codex"]
    findings = (
        f"Detection rate: {provider_summary['detection_rate']:.2f}\n\n"
        f"Exact match rate: {provider_summary['exact_match_rate']:.2f}\n\n"
        f"Partial match rate: {provider_summary['partial_match_rate']:.2f}\n\n"
        f"False positive rate: {provider_summary['false_positive_rate']:.2f}\n\n"
        f"False negative rate: {provider_summary['false_negative_rate']:.2f}"
    )
    report = (
        "# Codex Benchmark Report\n\n"
        "## Methodology\n\n"
        f"{methodology}\n\n"
        "## Findings\n\n"
        f"{findings}\n\n"
        "## Vulnerability Class Slices\n\n"
        f"{_render_nested_counts(cast(dict[str, Any], summary['by_vuln_type']))}\n\n"
        "## Language Slices\n\n"
        f"{_render_nested_counts(cast(dict[str, Any], summary['by_language']))}\n\n"
        "## Limitations\n\n"
        f"{limitations}\n\n"
        "## Reproducibility\n\n"
        f"{reproducibility}\n"
    )
    report_path.write_text(report, encoding="utf-8")
    return report_path


def _render_nested_counts(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    for label, counts in payload.items():
        lines.append(f"- {label}")
        if isinstance(counts, dict):
            for metric, value in counts.items():
                if value:
                    lines.append(f"  - {metric}: {value}")

    return "\n".join(lines) if lines else "- none"
