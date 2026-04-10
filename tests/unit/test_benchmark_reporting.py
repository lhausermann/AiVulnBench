from __future__ import annotations

from pathlib import Path

from src.benchmark.reporting import write_codex_benchmark_report


def test_write_codex_benchmark_report_creates_reproducible_markdown(
    tmp_path: Path,
) -> None:
    summary = {
        "providers": {
            "codex": {
                "completed_runs": 2,
                "detection_rate": 1.0,
                "exact_match_rate": 0.5,
                "partial_match_rate": 0.5,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
            }
        },
        "by_vuln_type": {"stack buffer overflow": {"true_positive": 1}},
        "by_language": {"C": {"true_positive": 1, "partial_match": 1}},
    }

    report_path = write_codex_benchmark_report(
        project_root=tmp_path,
        summary=summary,
        methodology=(
            "Codex was evaluated against the vulnerability dataset using "
            "deterministic prompt templates and normalized scoring."
        ),
        limitations=(
            "The current benchmark uses curated report-derived fixtures rather than "
            "fully automated repository checkout."
        ),
        reproducibility=(
            "Run make test, generate benchmark cases, execute the runner, and "
            "rebuild this report from stored artifacts."
        ),
    )

    content = report_path.read_text(encoding="utf-8")

    assert report_path == tmp_path / "docs" / "CODEX_BENCHMARK_REPORT.md"
    assert "## Methodology" in content
    assert "## Findings" in content
    assert "## Limitations" in content
    assert "## Reproducibility" in content
    assert "Detection rate: 1.00" in content
