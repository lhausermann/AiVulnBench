from __future__ import annotations

import json
from pathlib import Path
from typing import cast
from unittest.mock import patch

from src.app import main
from src.benchmark.checkout import materialize_entry_checkout
from src.benchmark.harness import ProviderExecutionResult, Transport
from src.benchmark.sample import run_full_benchmark, run_sample_benchmark
from src.benchmark.scoring import JudgeExecutionResult, JudgeMetadata, ScoreResult

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

    class FakeJudge:
        def judge(self, *, case: object, findings: list[object]) -> JudgeExecutionResult:
            return JudgeExecutionResult(
                score=ScoreResult(
                    outcome="false_negative",
                    matched=False,
                    partial=False,
                    false_positive=False,
                    false_negative=True,
                    matched_locations=[],
                ),
                rationale="No findings were returned.",
                duration_ms=3,
                failure_mode=None,
                raw_output={"rationale": "No findings were returned."},
            )

        def metadata(self) -> JudgeMetadata:
            return JudgeMetadata(
                provider="codex",
                model="gpt-5-codex-judge",
                model_version="judge-fixture-1",
            )

    with patch(
        "src.benchmark.sample.materialize_entry_checkout",
        side_effect=fake_materialize,
    ), patch(
        "src.benchmark.sample.build_codex_cli_transport",
        side_effect=fake_transport_builder,
    ), patch(
        "src.benchmark.sample.CodexCliScoreJudge",
        return_value=FakeJudge(),
    ):
        result_root = run_sample_benchmark(
            project_root,
            seed="s260411120000",
            sample_size=1,
        )

    summary = json.loads((result_root / "summary.json").read_text(encoding="utf-8"))
    records = json.loads((result_root / "run_records.json").read_text(encoding="utf-8"))
    sampled_entries = json.loads(
        (result_root / "sampled_entries.json").read_text(encoding="utf-8")
    )

    assert summary["sample_size"] == 1
    assert summary["record_count"] == 1
    assert summary["seed"] == "s260411120000"
    assert summary["materialized_files"]["entry-a"][0].endswith("src/a.c")
    assert len(records) == 1
    assert records[0]["status"] == "completed"
    assert records[0]["score"]["outcome"] == "false_negative"
    assert sampled_entries[0]["entry_id"] == "entry-a"


def test_run_sample_benchmark_supports_hard_prompt_mode(tmp_path: Path) -> None:
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
                }
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    requested_prompt_modes: list[object] = []

    def fake_materialize(root: Path, entry: object) -> list[str]:
        return [str(root / "data" / "raw" / "repos" / "a" / "src" / "a.c")]

    def fake_transport_builder(**kwargs: object) -> Transport:
        requested_prompt_modes.append(kwargs["prompt_mode"])
        return lambda payload: ProviderExecutionResult(
            raw_output={"response": "sample transport", "findings": []},
            duration_ms=0,
            failure_mode=None,
        )

    class FakeJudge:
        def judge(self, *, case: object, findings: list[object]) -> JudgeExecutionResult:
            return JudgeExecutionResult(
                score=ScoreResult(
                    outcome="false_negative",
                    matched=False,
                    partial=False,
                    false_positive=False,
                    false_negative=True,
                    matched_locations=[],
                ),
                rationale="No findings were returned.",
                duration_ms=3,
                failure_mode=None,
                raw_output={"rationale": "No findings were returned."},
            )

        def metadata(self) -> JudgeMetadata:
            return JudgeMetadata(
                provider="codex",
                model="gpt-5-codex-judge",
                model_version="judge-fixture-1",
            )

    with patch(
        "src.benchmark.sample.materialize_entry_checkout",
        side_effect=fake_materialize,
    ), patch(
        "src.benchmark.sample.build_codex_cli_transport",
        side_effect=fake_transport_builder,
    ), patch(
        "src.benchmark.sample.CodexCliScoreJudge",
        return_value=FakeJudge(),
    ):
        result_root = run_sample_benchmark(
            project_root,
            seed="s260411120001",
            sample_size=1,
            prompt_mode="hard",
        )

    summary = json.loads((result_root / "summary.json").read_text(encoding="utf-8"))

    assert requested_prompt_modes == ["hard"]
    assert summary["prompt_mode"] == "hard"
    assert result_root.name == "sample_mode_hard_s260411120001"


def test_app_supports_benchmark_sample_command() -> None:
    with patch("src.app.run_sample_benchmark", return_value=PROJECT_ROOT):
        assert main(["benchmark", "sample"]) == 0


def test_app_supports_benchmark_sample_hard_mode_command() -> None:
    with patch("src.app.run_sample_benchmark", return_value=PROJECT_ROOT) as run_sample:
        assert main(["benchmark", "sample", "--hard"]) == 0

    run_sample.assert_called_once_with(PROJECT_ROOT, prompt_mode="hard")


def test_run_full_benchmark_writes_runnable_results_and_skipped_entries(
    tmp_path: Path,
) -> None:
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
            raw_output={"response": "full transport", "findings": []},
            duration_ms=0,
            failure_mode=None,
        )

    class FakeJudge:
        def judge(self, *, case: object, findings: list[object]) -> JudgeExecutionResult:
            return JudgeExecutionResult(
                score=ScoreResult(
                    outcome="false_negative",
                    matched=False,
                    partial=False,
                    false_positive=False,
                    false_negative=True,
                    matched_locations=[],
                ),
                rationale="No findings were returned.",
                duration_ms=3,
                failure_mode=None,
                raw_output={"rationale": "No findings were returned."},
            )

        def metadata(self) -> JudgeMetadata:
            return JudgeMetadata(
                provider="codex",
                model="gpt-5-codex-judge",
                model_version="judge-fixture-1",
            )

    with patch(
        "src.benchmark.sample.materialize_entry_checkout",
        side_effect=fake_materialize,
    ), patch(
        "src.benchmark.sample.build_codex_cli_transport",
        side_effect=fake_transport_builder,
    ), patch(
        "src.benchmark.sample.CodexCliScoreJudge",
        return_value=FakeJudge(),
    ):
        result_root = run_full_benchmark(project_root, stamp="s260411120002")

    summary = json.loads((result_root / "summary.json").read_text(encoding="utf-8"))
    records = json.loads((result_root / "run_records.json").read_text(encoding="utf-8"))
    skipped_entries = json.loads(
        (result_root / "skipped_entries.json").read_text(encoding="utf-8")
    )

    assert result_root.name == "benchmark_run_s260411120002"
    assert summary["total_entry_count"] == 2
    assert summary["runnable_entry_count"] == 1
    assert summary["skipped_entry_count"] == 1
    assert len(records) == 1
    assert skipped_entries[0]["entry_id"] == "entry-b"
    assert "fixed_commit" in skipped_entries[0]["reason"]


def test_app_supports_benchmark_run_command() -> None:
    with patch("src.app.run_full_benchmark", return_value=PROJECT_ROOT):
        assert main(["benchmark", "run"]) == 0


def test_app_supports_benchmark_run_hard_mode_command() -> None:
    with patch("src.app.run_full_benchmark", return_value=PROJECT_ROOT) as run_full:
        assert main(["benchmark", "run", "--hard"]) == 0

    run_full.assert_called_once_with(PROJECT_ROOT, prompt_mode="hard")


def test_app_supports_view_command(tmp_path: Path) -> None:
    result_root = tmp_path / "results" / "run-a"
    result_root.mkdir(parents=True)

    with patch("src.app.render_result_view", return_value=result_root / "index.html"):
        assert main(["view", str(result_root)]) == 0


def test_run_full_benchmark_maps_case_files_by_entry_id_not_list_position(
    tmp_path: Path,
) -> None:
    project_root = tmp_path
    (project_root / "data").mkdir(parents=True)
    (project_root / "data" / "vulnerability_dataset.json").write_text(
        json.dumps(
            [
                {
                    "entry_id": "z-entry",
                    "source_report_section": "Z",
                    "product_name": "Fixture Z",
                    "repository_url": "https://example.com/z",
                    "clone_url": "https://example.com/z.git",
                    "repository_kind": "git",
                    "local_checkout_path": "data/raw/repos/z",
                    "language": "C",
                    "cve_id": None,
                    "cwe_ids": [],
                    "vuln_type": "overflow",
                    "severity": "high",
                    "introduced_commit": None,
                    "fixed_commit": "deadbeef",
                    "affected_files": ["src/z.c"],
                    "affected_line_ranges": [],
                    "description": "Z",
                    "source_urls": ["https://example.com/z"],
                    "code_snippet_ref": "src/z.c",
                    "dataset_version": "2026.04",
                },
                {
                    "entry_id": "a-entry",
                    "source_report_section": "A",
                    "product_name": "Fixture A",
                    "repository_url": "https://example.com/a",
                    "clone_url": "https://example.com/a.git",
                    "repository_kind": "git",
                    "local_checkout_path": "data/raw/repos/a",
                    "language": "C",
                    "cve_id": None,
                    "cwe_ids": [],
                    "vuln_type": "type confusion",
                    "severity": "high",
                    "introduced_commit": None,
                    "fixed_commit": "feedface",
                    "affected_files": ["src/a.c"],
                    "affected_line_ranges": [],
                    "description": "A",
                    "source_urls": ["https://example.com/a"],
                    "code_snippet_ref": "src/a.c",
                    "dataset_version": "2026.04",
                },
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    def fake_materialize(root: Path, entry: object) -> list[str]:
        entry_id = getattr(entry, "entry_id")
        file_name = "a.c" if entry_id == "a-entry" else "z.c"
        repo_name = "a" if entry_id == "a-entry" else "z"
        return [str(root / "data" / "raw" / "repos" / repo_name / "src" / file_name)]

    captured_files_by_case: dict[str, list[str]] = {}

    def fake_transport_builder(**kwargs: object) -> Transport:
        captured_files_by_case.update(
            cast(dict[str, list[str]], kwargs["materialized_files_by_case"])
        )
        return lambda payload: ProviderExecutionResult(
            raw_output={"response": "full transport", "findings": []},
            duration_ms=0,
            failure_mode=None,
        )

    class FakeJudge:
        def judge(self, *, case: object, findings: list[object]) -> JudgeExecutionResult:
            return JudgeExecutionResult(
                score=ScoreResult(
                    outcome="false_negative",
                    matched=False,
                    partial=False,
                    false_positive=False,
                    false_negative=True,
                    matched_locations=[],
                ),
                rationale="No findings were returned.",
                duration_ms=3,
                failure_mode=None,
                raw_output={"rationale": "No findings were returned."},
            )

        def metadata(self) -> JudgeMetadata:
            return JudgeMetadata(
                provider="codex",
                model="gpt-5-codex-judge",
                model_version="judge-fixture-1",
            )

    with patch(
        "src.benchmark.sample.materialize_entry_checkout",
        side_effect=fake_materialize,
    ), patch(
        "src.benchmark.sample.build_codex_cli_transport",
        side_effect=fake_transport_builder,
    ), patch(
        "src.benchmark.sample.CodexCliScoreJudge",
        return_value=FakeJudge(),
    ):
        run_full_benchmark(project_root, stamp="s260411120003")

    assert captured_files_by_case["a-entry:full-v1"][0].endswith("src/a.c")
    assert captured_files_by_case["z-entry:full-v1"][0].endswith("src/z.c")


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
