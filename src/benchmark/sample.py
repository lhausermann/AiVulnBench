from __future__ import annotations

import json
import random
from datetime import datetime
from pathlib import Path
from typing import Any

from src.benchmark.checkout import materialize_entry_checkout
from src.benchmark.codex_cli import (
    CodexCliScoreJudge,
    PromptMode,
    build_codex_cli_transport,
)
from src.benchmark.contracts import PromptTemplate, build_benchmark_cases
from src.benchmark.harness import CodexHarnessAdapter
from src.benchmark.runner import ExperimentRunner
from src.dataset.schema import DatasetEntry
from src.dataset.storage import load_dataset_entries_json


def run_sample_benchmark(
    project_root: Path,
    *,
    seed: str | None = None,
    sample_size: int = 1,
    prompt_mode: PromptMode = "normal",
) -> Path:
    sample_stamp = seed or _sample_stamp()
    dataset_path = project_root / "data" / "vulnerability_dataset.json"
    entries = load_dataset_entries_json(dataset_path)
    runnable_entries, skipped_entries = _partition_entries(entries)

    if sample_size <= 0:
        raise ValueError("sample_size must be greater than 0")
    if len(runnable_entries) < sample_size:
        raise ValueError("sample_size cannot exceed the runnable dataset size")

    sampled_entries = random.Random(sample_stamp).sample(runnable_entries, sample_size)
    result_root = (
        project_root
        / "data"
        / "results"
        / _sample_result_dir(seed=sample_stamp, prompt_mode=prompt_mode)
    )
    return _run_dataset_entries(
        project_root=project_root,
        entries=sampled_entries,
        result_root=result_root,
        prompt_mode=prompt_mode,
        template=PromptTemplate(
            template_id="sample-v1",
            system_instructions=(
                "Run a one-case sample benchmark for pipeline validation."
            ),
            prompt_version="2026.04",
        ),
        selected_entries_path=result_root / "sampled_entries.json",
        summary_payload={
            "seed": sample_stamp,
            "sample_size": sample_size,
            "prompt_mode": prompt_mode,
            "runnable_entry_count": len(runnable_entries),
            "skipped_entry_count": len(skipped_entries),
        },
    )


def run_full_benchmark(
    project_root: Path,
    *,
    stamp: str | None = None,
    prompt_mode: PromptMode = "normal",
) -> Path:
    benchmark_stamp = stamp or _sample_stamp()
    dataset_path = project_root / "data" / "vulnerability_dataset.json"
    entries = load_dataset_entries_json(dataset_path)
    runnable_entries, skipped_entries = _partition_entries(entries)

    if not runnable_entries:
        raise ValueError(
            "No runnable entries are available in the vulnerability dataset"
        )

    result_root = (
        project_root
        / "data"
        / "results"
        / _benchmark_result_dir(stamp=benchmark_stamp, prompt_mode=prompt_mode)
    )
    return _run_dataset_entries(
        project_root=project_root,
        entries=runnable_entries,
        result_root=result_root,
        prompt_mode=prompt_mode,
        template=PromptTemplate(
            template_id="full-v1",
            system_instructions="Run the full real-world vulnerability benchmark.",
            prompt_version="2026.04",
        ),
        selected_entries_path=result_root / "executed_entries.json",
        skipped_entries=skipped_entries,
        summary_payload={
            "seed": benchmark_stamp,
            "prompt_mode": prompt_mode,
            "total_entry_count": len(entries),
            "runnable_entry_count": len(runnable_entries),
            "skipped_entry_count": len(skipped_entries),
        },
    )


def _run_dataset_entries(
    *,
    project_root: Path,
    entries: list[DatasetEntry],
    result_root: Path,
    prompt_mode: PromptMode,
    template: PromptTemplate,
    selected_entries_path: Path,
    summary_payload: dict[str, Any],
    skipped_entries: list[dict[str, str]] | None = None,
) -> Path:
    cases = build_benchmark_cases(entries, template=template)
    entries_by_id = {entry.entry_id: entry for entry in entries}
    materialized_files = {
        entry.entry_id: materialize_entry_checkout(project_root, entry)
        for entry in entries
    }
    checkout_root_by_case = {
        case.case_id: project_root
        / _checkout_path_for_entry(entries_by_id[case.entry_id])
        for case in cases
    }
    materialized_files_by_case = {
        case.case_id: materialized_files[case.entry_id] for case in cases
    }
    runner = ExperimentRunner(
        result_root=result_root,
        judge=CodexCliScoreJudge(output_root=result_root / "judge"),
    )
    adapter = CodexHarnessAdapter(
        transport=build_codex_cli_transport(
            checkout_root_by_case=checkout_root_by_case,
            materialized_files_by_case=materialized_files_by_case,
            output_root=result_root / "codex_cli",
            prompt_mode=prompt_mode,
        ),
        model="gpt-5-codex-cli",
        model_version=f"gpt-5-codex-cli-{template.template_id}-{prompt_mode}-2026-04-10",
    )
    records = runner.run_cases(
        cases,
        adapter=adapter,
        dataset_version=entries[0].dataset_version,
        prompt_version=template.prompt_version,
    )

    result_root.mkdir(parents=True, exist_ok=True)
    selected_entries_path.write_text(
        json.dumps([entry.to_dict() for entry in entries], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    if skipped_entries is not None:
        (result_root / "skipped_entries.json").write_text(
            json.dumps(skipped_entries, indent=2, sort_keys=True),
            encoding="utf-8",
        )
    (result_root / "summary.json").write_text(
        json.dumps(
            {
                **summary_payload,
                "case_ids": [case.case_id for case in cases],
                "record_count": len(records),
                "materialized_files": materialized_files,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return result_root


def _partition_entries(
    entries: list[DatasetEntry],
) -> tuple[list[DatasetEntry], list[dict[str, str]]]:
    runnable_entries: list[DatasetEntry] = []
    skipped_entries: list[dict[str, str]] = []
    for entry in entries:
        reason = _runnability_reason(entry)
        if reason is None:
            runnable_entries.append(entry)
            continue
        skipped_entries.append({"entry_id": entry.entry_id, "reason": reason})

    return runnable_entries, skipped_entries


def _runnability_reason(entry: DatasetEntry) -> str | None:
    missing_fields: list[str] = []
    if not entry.clone_url:
        missing_fields.append("clone_url")
    if not entry.local_checkout_path:
        missing_fields.append("local_checkout_path")
    if not entry.fixed_commit:
        missing_fields.append("fixed_commit")
    if not entry.affected_files:
        missing_fields.append("affected_files")

    if not missing_fields:
        return None
    return "Missing required runner metadata: " + ", ".join(missing_fields)


def _sample_result_dir(*, seed: str, prompt_mode: PromptMode) -> str:
    if prompt_mode == "normal":
        return f"sample_mode_{seed}"

    return f"sample_mode_{prompt_mode}_{seed}"


def _benchmark_result_dir(*, stamp: str, prompt_mode: PromptMode) -> str:
    if prompt_mode == "normal":
        return f"benchmark_run_{stamp}"

    return f"benchmark_run_{prompt_mode}_{stamp}"


def _sample_stamp(now: datetime | None = None) -> str:
    current = now or datetime.now().astimezone()
    return current.strftime("s%y%m%d%H%M%S")


def _checkout_path_for_entry(entry: DatasetEntry) -> str:
    if not entry.local_checkout_path:
        raise ValueError("entry is missing a local checkout path")

    return entry.local_checkout_path
