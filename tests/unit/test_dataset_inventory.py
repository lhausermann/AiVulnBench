from __future__ import annotations

from pathlib import Path

from src.dataset.storage import load_dataset_entries_json

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_real_world_dataset_excludes_benchmark_test_cases() -> None:
    entries = load_dataset_entries_json(
        PROJECT_ROOT / "data" / "vulnerability_dataset.json"
    )
    entry_ids = {entry.entry_id for entry in entries}

    assert "owasp-arraylist-sqli-false-positive" not in entry_ids
    assert "freebsd-rpcsec-gss-patched-negative-control" not in entry_ids


def test_benchmark_test_case_dataset_captures_owasp_and_patched_controls() -> None:
    entries = load_dataset_entries_json(
        PROJECT_ROOT / "data" / "benchmark_test_cases.json"
    )
    entry_ids = {entry.entry_id for entry in entries}

    assert "owasp-arraylist-sqli-false-positive" in entry_ids
    assert "freebsd-rpcsec-gss-patched-negative-control" in entry_ids
