from __future__ import annotations

import json
import random
from datetime import datetime
from pathlib import Path

from src.benchmark.checkout import materialize_entry_checkout
from src.benchmark.codex_cli import (
    CodexCliScoreJudge,
    PromptMode,
    build_codex_cli_transport,
)
from src.benchmark.contracts import PromptTemplate, build_benchmark_cases
from src.benchmark.harness import CodexHarnessAdapter
from src.benchmark.runner import ExperimentRunner
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
    result_root = (
        project_root
        / "data"
        / "results"
        / _sample_result_dir(seed=sample_stamp, prompt_mode=prompt_mode)
    )
    entries = load_dataset_entries_json(dataset_path)
    runnable_entries = [entry for entry in entries if _is_runnable_sample_entry(entry)]

    if sample_size <= 0:
        raise ValueError("sample_size must be greater than 0")
    if len(runnable_entries) < sample_size:
        raise ValueError("sample_size cannot exceed the runnable dataset size")

    sampled_entries = random.Random(sample_stamp).sample(runnable_entries, sample_size)
    template = PromptTemplate(
        template_id="sample-v1",
        system_instructions="Run a one-case sample benchmark for pipeline validation.",
        prompt_version="2026.04",
    )
    cases = build_benchmark_cases(sampled_entries, template=template)
    materialized_files = {
        entry.entry_id: materialize_entry_checkout(project_root, entry)
        for entry in sampled_entries
    }
    checkout_root_by_case = {
        case.case_id: project_root / _checkout_path_for_sample(sampled_entries[index])
        for index, case in enumerate(cases)
    }
    materialized_files_by_case = {
        case.case_id: materialized_files[sampled_entries[index].entry_id]
        for index, case in enumerate(cases)
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
        model_version=f"gpt-5-codex-cli-sample-{prompt_mode}-2026-04-10",
    )
    records = runner.run_cases(
        cases,
        adapter=adapter,
        dataset_version=sampled_entries[0].dataset_version,
        prompt_version=template.prompt_version,
    )

    result_root.mkdir(parents=True, exist_ok=True)
    (result_root / "sampled_entries.json").write_text(
        json.dumps(
            [entry.to_dict() for entry in sampled_entries],
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (result_root / "summary.json").write_text(
        json.dumps(
            {
                "seed": sample_stamp,
                "sample_size": sample_size,
                "case_ids": [case.case_id for case in cases],
                "record_count": len(records),
                "materialized_files": materialized_files,
                "prompt_mode": prompt_mode,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return result_root


def _is_runnable_sample_entry(entry: object) -> bool:
    from src.dataset.schema import DatasetEntry

    if not isinstance(entry, DatasetEntry):
        return False

    return bool(
        entry.clone_url
        and entry.local_checkout_path
        and entry.fixed_commit
        and entry.affected_files
    )


def _sample_result_dir(*, seed: str, prompt_mode: PromptMode) -> str:
    if prompt_mode == "normal":
        return f"sample_mode_{seed}"

    return f"sample_mode_{prompt_mode}_{seed}"


def _sample_stamp(now: datetime | None = None) -> str:
    current = now or datetime.now().astimezone()
    return current.strftime("s%y%m%d%H%M%S")


def _checkout_path_for_sample(entry: object) -> str:
    from src.dataset.schema import DatasetEntry

    if not isinstance(entry, DatasetEntry) or not entry.local_checkout_path:
        raise ValueError("sample entry is missing a local checkout path")

    return entry.local_checkout_path
