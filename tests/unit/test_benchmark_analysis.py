from __future__ import annotations

from typing import cast

from src.benchmark.analysis import summarize_run_records
from src.benchmark.runner import RunRecord
from src.dataset.schema import DatasetEntry


def _entry(entry_id: str, vuln_type: str, language: str) -> DatasetEntry:
    return DatasetEntry(
        entry_id=entry_id,
        source_report_section=entry_id,
        product_name="Fixture",
        repository_url="https://example.com/repo",
        clone_url="https://example.com/repo.git",
        repository_kind="git",
        local_checkout_path="data/raw/repos/example",
        language=language,
        cve_id=None,
        cwe_ids=[],
        vuln_type=vuln_type,
        severity="high",
        introduced_commit=None,
        fixed_commit=None,
        benchmark_checkout_commit="deadbeef",
        affected_files=["src/example.c"],
        benchmark_file_paths=["src/example.c"],
        affected_line_ranges=["10-20"],
        description="Fixture entry",
        source_urls=["https://example.com/advisory"],
        validation_status="confirmed",
        validation_notes="Fixture",
        code_snippet_ref="src/example.c:10-20",
        benchmark_checkout_strategy="Use the pinned fixture commit for analysis tests.",
        dataset_version="2026.04",
    )


def _record(
    case_id: str,
    entry_id: str,
    outcome: str,
    *,
    language: str = "C",
    vuln_type: str = "stack buffer overflow",
) -> RunRecord:
    return RunRecord(
        run_id="codex-2026.04-codex-v1-codex-v1",
        case_id=case_id,
        provider="codex",
        model="gpt-5-codex",
        model_version="gpt-5-codex-2026-04-09",
        prompt_template_id="codex-v1",
        raw_output_ref="/tmp/raw.json",
        normalized_findings=[],
        score={
            "outcome": outcome,
            "matched": outcome in {"true_positive", "partial_match"},
            "partial": outcome == "partial_match",
            "false_positive": outcome == "false_positive",
            "false_negative": outcome == "false_negative",
            "matched_locations": [],
        },
        failure_mode=None,
        duration_ms=500,
        timestamp="2026-04-09T12:00:00Z",
        status="completed",
        dataset_version="2026.04",
        prompt_version="2026.04",
        language=language,
        vuln_type=vuln_type,
    )


def test_summarize_run_records_reports_detection_and_localization_metrics() -> None:
    entries = {
        "entry-a": _entry("entry-a", "stack buffer overflow", "C"),
        "entry-b": _entry("entry-b", "race condition", "C"),
    }
    records = [
        _record("entry-a:codex-v1", "entry-a", "true_positive"),
        _record(
            "entry-b:codex-v1", "entry-b", "partial_match", vuln_type="race condition"
        ),
    ]

    summary = summarize_run_records(records, entries_by_id=entries)
    providers = cast(dict[str, dict[str, float]], summary["providers"])

    assert providers["codex"]["completed_runs"] == 2
    assert providers["codex"]["detection_rate"] == 1.0
    assert providers["codex"]["exact_match_rate"] == 0.5
    assert providers["codex"]["partial_match_rate"] == 0.5


def test_summarize_run_records_groups_false_positives_and_false_negatives() -> None:
    entries = {
        "entry-a": _entry("entry-a", "stack buffer overflow", "C"),
        "entry-b": _entry("entry-b", "race condition", "Rust"),
    }
    records = [
        _record("entry-a:codex-v1", "entry-a", "false_positive"),
        _record(
            "entry-b:codex-v1",
            "entry-b",
            "false_negative",
            language="Rust",
            vuln_type="race condition",
        ),
    ]

    summary = summarize_run_records(records, entries_by_id=entries)
    providers = cast(dict[str, dict[str, float]], summary["providers"])
    by_vuln_type = cast(dict[str, dict[str, int]], summary["by_vuln_type"])
    by_language = cast(dict[str, dict[str, int]], summary["by_language"])

    assert providers["codex"]["false_positive_rate"] == 0.5
    assert providers["codex"]["false_negative_rate"] == 0.5
    assert by_vuln_type["stack buffer overflow"]["false_positive"] == 1
    assert by_language["Rust"]["false_negative"] == 1
