from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from src.benchmark.contracts import BenchmarkCase
from src.benchmark.harness import CodexHarnessAdapter, ProviderExecutionResult
from src.benchmark.runner import ExperimentRunner
from src.benchmark.scoring import (
    BaseScoreJudge,
    Finding,
    JudgeExecutionResult,
    JudgeMetadata,
    ScoreResult,
)


def _case(case_id: str) -> BenchmarkCase:
    return BenchmarkCase(
        case_id=case_id,
        entry_id=case_id.split(":")[0],
        prompt_template_id="codex-v1",
        prompt_text="Audit this file for a stack buffer overflow.",
        input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        expected_vuln_type="stack buffer overflow",
        expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
        scoring_mode="exact-location-or-overlap",
    )


def test_experiment_runner_persists_scored_results_and_raw_output(
    tmp_path: Path,
) -> None:
    case = _case("freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1")
    adapter = CodexHarnessAdapter(
        transport=lambda payload: ProviderExecutionResult(
            raw_output={
                "response": "Potential stack overflow in RPC credential parsing",
                "findings": [
                    {
                        "file_path": "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
                        "line_range": "148-188",
                        "vuln_type": "stack buffer overflow",
                        "explanation": "oa_length crosses the fixed buffer boundary",
                    }
                ],
            },
            duration_ms=512,
            failure_mode=None,
        )
    )
    runner = ExperimentRunner(result_root=tmp_path / "results")

    records = runner.run_cases(
        [case],
        adapter=adapter,
        dataset_version="2026.04",
        prompt_version="2026.04",
    )

    assert len(records) == 1
    assert records[0].score["outcome"] == "true_positive"
    judge_payload = cast(dict[str, str], records[0].score["judge"])
    assert judge_payload["provider"] == "heuristic"
    assert records[0].failure_mode is None
    assert Path(records[0].raw_output_ref).exists()

    persisted = json.loads((tmp_path / "results" / "run_records.json").read_text())
    assert persisted[0]["case_id"] == case.case_id


def test_experiment_runner_skips_completed_cases_on_resume(tmp_path: Path) -> None:
    case = _case("freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1")
    calls = {"count": 0}

    def transport(payload: dict[str, object]) -> ProviderExecutionResult:
        calls["count"] += 1
        return ProviderExecutionResult(
            raw_output={"response": "ok", "findings": []},
            duration_ms=100,
            failure_mode=None,
        )

    runner = ExperimentRunner(result_root=tmp_path / "results")
    adapter = CodexHarnessAdapter(transport=transport)

    first = runner.run_cases(
        [case], adapter=adapter, dataset_version="2026.04", prompt_version="2026.04"
    )
    second = runner.run_cases(
        [case], adapter=adapter, dataset_version="2026.04", prompt_version="2026.04"
    )

    assert calls["count"] == 1
    assert first[0].status == "completed"
    assert second[0].status == "skipped"


def test_experiment_runner_retries_failed_cases_when_requested(tmp_path: Path) -> None:
    case = _case("freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1")
    responses = iter(
        [
            ProviderExecutionResult(
                raw_output={"response": "", "findings": []},
                duration_ms=3000,
                failure_mode="timeout",
            ),
            ProviderExecutionResult(
                raw_output={
                    "response": "Likely stack overflow",
                    "findings": [
                        {
                            "file_path": "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
                            "line_range": "160-172",
                            "vuln_type": "stack buffer overflow",
                            "explanation": "The copy is inside the vulnerable block",
                        }
                    ],
                },
                duration_ms=600,
                failure_mode=None,
            ),
        ]
    )
    runner = ExperimentRunner(result_root=tmp_path / "results")
    adapter = CodexHarnessAdapter(transport=lambda payload: next(responses))

    first = runner.run_cases(
        [case], adapter=adapter, dataset_version="2026.04", prompt_version="2026.04"
    )
    second = runner.run_cases(
        [case],
        adapter=adapter,
        dataset_version="2026.04",
        prompt_version="2026.04",
        retry_failures=True,
    )

    assert first[0].status == "failed"
    assert first[0].failure_mode == "timeout"
    assert second[0].status == "completed"
    assert second[0].score["outcome"] == "partial_match"


def test_experiment_runner_can_use_an_llm_judge(tmp_path: Path) -> None:
    class FakeJudge(BaseScoreJudge):
        def metadata(self) -> JudgeMetadata:
            return JudgeMetadata(
                provider="codex",
                model="gpt-5-codex-judge",
                model_version="judge-fixture-1",
            )

        def judge(
            self,
            *,
            case: BenchmarkCase,
            findings: list[Finding],
        ) -> JudgeExecutionResult:
            assert case.case_id == "freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1"
            assert len(findings) == 1
            return JudgeExecutionResult(
                score=ScoreResult(
                    outcome="true_positive",
                    matched=True,
                    partial=False,
                    false_positive=False,
                    false_negative=False,
                    matched_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
                ),
                rationale=(
                    "The judge accepted 'Stack buffer overflow' as equivalent to "
                    "'stack buffer overflow'."
                ),
                duration_ms=125,
                failure_mode=None,
                raw_output={"rationale": "accepted synonym"},
            )

    case = _case("freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1")
    adapter = CodexHarnessAdapter(
        transport=lambda payload: ProviderExecutionResult(
            raw_output={
                "response": "Potential stack overflow in RPC credential parsing",
                "findings": [
                    {
                        "file_path": "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
                        "line_range": "148-188",
                        "vuln_type": "Stack buffer overflow",
                        "explanation": "oa_length crosses the fixed buffer boundary",
                    }
                ],
            },
            duration_ms=512,
            failure_mode=None,
        )
    )
    runner = ExperimentRunner(result_root=tmp_path / "results", judge=FakeJudge())

    records = runner.run_cases(
        [case],
        adapter=adapter,
        dataset_version="2026.04",
        prompt_version="2026.04",
    )

    assert records[0].score["outcome"] == "true_positive"
    llm_judge_payload = cast(dict[str, str], records[0].score["judge"])
    assert llm_judge_payload["model_version"] == "judge-fixture-1"
    assert "equivalent" in str(records[0].score["judge_rationale"])
