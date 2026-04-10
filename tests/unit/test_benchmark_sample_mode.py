from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from src.app import main
from src.benchmark.checkout import materialize_entry_checkout
from src.benchmark.harness import ProviderExecutionResult, Transport
from src.benchmark.sample import run_sample_benchmark

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_run_sample_benchmark_writes_one_sample_result(tmp_path: Path) -> None:
    project_root = tmp_path
    (project_root / "data").mkdir(parents=True)
    (project_root / "data" / "vulnerability_dataset.json").write_text(
        json.dumps(
            [
                {
                    "entry_id": "entry-a",
                    "source_report_section": "A",
                    "product_name": "Fixture A",
                    "repository_url": "https://example.com/a",
                    "clone_url": "https://example.com/a.git",
                    "repository_kind": "git",
                    "local_checkout_path": "data/raw/repos/a",
                    "language": "C",
                    "cve_id": None,
                    "cwe_ids": [],
                    "vuln_type": "overflow",
                    "severity": "high",
                    "introduced_commit": None,
                    "fixed_commit": "deadbeef",
                    "affected_files": ["src/a.c"],
                    "affected_line_ranges": [],
                    "description": "A",
                    "source_urls": ["https://example.com/a"],
                    "code_snippet_ref": "src/a.c",
                    "dataset_version": "2026.04",
                },
                {
                    "entry_id": "entry-b",
                    "source_report_section": "B",
                    "product_name": "Fixture B",
                    "repository_url": "https://example.com/b",
                    "clone_url": "https://example.com/b.git",
                    "repository_kind": "git",
                    "local_checkout_path": "data/raw/repos/b",
                    "language": "Rust",
                    "cve_id": None,
                    "cwe_ids": [],
                    "vuln_type": "type confusion",
                    "severity": "high",
                    "introduced_commit": None,
                    "fixed_commit": None,
                    "affected_files": ["src/b.rs"],
                    "affected_line_ranges": [],
                    "description": "B",
                    "source_urls": ["https://example.com/b"],
                    "code_snippet_ref": "src/b.rs",
                    "dataset_version": "2026.04",
                },
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    def fake_materialize(root: Path, entry: object) -> list[str]:
        return [str(root / "data" / "raw" / "repos" / "a" / "src" / "a.c")]

    def fake_transport_builder(**kwargs: object) -> Transport:
        return lambda payload: ProviderExecutionResult(
            raw_output={
                "response": "sample transport",
                "findings": [],
            },
            duration_ms=0,
            failure_mode=None,
        )

    with patch(
        "src.benchmark.sample.materialize_entry_checkout",
        side_effect=fake_materialize,
    ), patch(
        "src.benchmark.sample.build_codex_cli_transport",
        side_effect=fake_transport_builder,
    ):
        result_root = run_sample_benchmark(project_root, seed=7, sample_size=1)

    summary = json.loads((result_root / "summary.json").read_text(encoding="utf-8"))
    records = json.loads((result_root / "run_records.json").read_text(encoding="utf-8"))
    sampled_entries = json.loads(
        (result_root / "sampled_entries.json").read_text(encoding="utf-8")
    )

    assert summary["sample_size"] == 1
    assert summary["record_count"] == 1
    assert summary["materialized_files"]["entry-a"][0].endswith("src/a.c")
    assert len(records) == 1
    assert records[0]["status"] == "completed"
    assert records[0]["score"]["outcome"] == "false_negative"
    assert sampled_entries[0]["entry_id"] == "entry-a"


def test_app_supports_benchmark_sample_command() -> None:
    with patch("src.app.run_sample_benchmark", return_value=PROJECT_ROOT):
        assert main(["benchmark", "sample"]) == 0


def test_materialize_entry_checkout_rejects_entries_without_fixed_commit() -> None:
    from src.dataset.schema import DatasetEntry

    entry = DatasetEntry(
        entry_id="entry-b",
        source_report_section="B",
        product_name="Fixture B",
        repository_url="https://example.com/b",
        clone_url="https://example.com/b.git",
        repository_kind="git",
        local_checkout_path="data/raw/repos/b",
        language="Rust",
        cve_id=None,
        cwe_ids=[],
        vuln_type="type confusion",
        severity="high",
        introduced_commit=None,
        fixed_commit=None,
        affected_files=["src/b.rs"],
        affected_line_ranges=[],
        description="B",
        source_urls=["https://example.com/b"],
        code_snippet_ref="src/b.rs",
        dataset_version="2026.04",
    )

    try:
        materialize_entry_checkout(PROJECT_ROOT, entry)
    except ValueError as exc:
        assert "fixed commit" in str(exc)
    else:
        raise AssertionError("Expected materialize_entry_checkout to reject the entry")
