from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from src.benchmark.contracts import BenchmarkCase
from src.benchmark.harness import BaseHarnessAdapter, serialize_raw_output
from src.benchmark.scoring import BaseScoreJudge, Finding, HeuristicScoreJudge


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    case_id: str
    provider: str
    model: str
    model_version: str
    prompt_template_id: str
    raw_output_ref: str
    normalized_findings: list[dict[str, str]]
    score: dict[str, object]
    failure_mode: str | None
    duration_ms: int
    timestamp: str
    status: str
    dataset_version: str
    prompt_version: str
    language: str | None
    vuln_type: str


class ExperimentRunner:
    def __init__(
        self,
        *,
        result_root: Path,
        judge: BaseScoreJudge | None = None,
    ) -> None:
        self._result_root = result_root
        self._result_root.mkdir(parents=True, exist_ok=True)
        self._judge = judge or HeuristicScoreJudge()

    def run_cases(
        self,
        cases: list[BenchmarkCase],
        *,
        adapter: BaseHarnessAdapter,
        dataset_version: str,
        prompt_version: str,
        retry_failures: bool = False,
    ) -> list[RunRecord]:
        metadata = adapter.metadata()
        run_id = (
            f"{metadata.provider}-{dataset_version}-{prompt_version}-"
            f"{metadata.model_version}"
        )
        existing_records = self._load_records()
        latest_by_case = {
            (record.case_id, record.provider, record.model_version): record
            for record in existing_records
        }

        emitted_records: list[RunRecord] = []
        for case in cases:
            key = (case.case_id, metadata.provider, metadata.model_version)
            previous = latest_by_case.get(key)
            if previous and previous.status == "completed":
                emitted_records.append(
                    self._skipped_record(previous, dataset_version, prompt_version)
                )
                continue
            if previous and previous.status == "failed" and not retry_failures:
                emitted_records.append(
                    self._skipped_record(previous, dataset_version, prompt_version)
                )
                continue

            payload = adapter.prepare(case)
            execution = adapter.execute(payload)
            findings = adapter.normalize(execution)
            score = self._score(case, findings, execution.failure_mode)
            raw_output_ref = self._write_raw_output(
                run_id, case.case_id, execution.raw_output
            )
            record = RunRecord(
                run_id=run_id,
                case_id=case.case_id,
                provider=metadata.provider,
                model=metadata.model,
                model_version=metadata.model_version,
                prompt_template_id=case.prompt_template_id,
                raw_output_ref=str(raw_output_ref),
                normalized_findings=[asdict(finding) for finding in findings],
                score=score,
                failure_mode=execution.failure_mode,
                duration_ms=execution.duration_ms,
                timestamp=datetime.now(UTC).isoformat(),
                status="failed" if execution.failure_mode else "completed",
                dataset_version=dataset_version,
                prompt_version=prompt_version,
                language=None,
                vuln_type=case.expected_vuln_type,
            )
            existing_records.append(record)
            latest_by_case[key] = record
            emitted_records.append(record)

        self._write_records(existing_records)
        return emitted_records

    def _score(
        self,
        case: BenchmarkCase,
        findings: list[Finding],
        failure_mode: str | None,
    ) -> dict[str, object]:
        if failure_mode:
            return {
                "outcome": "execution_failure",
                "matched": False,
                "partial": False,
                "false_positive": False,
                "false_negative": False,
                "matched_locations": [],
            }

        judgment = self._judge.judge(case=case, findings=findings)
        return {
            **asdict(judgment.score),
            "judge": asdict(self._judge.metadata()),
            "judge_rationale": judgment.rationale,
            "judge_duration_ms": judgment.duration_ms,
            "judge_failure_mode": judgment.failure_mode,
        }

    def _write_raw_output(
        self, run_id: str, case_id: str, raw_output: dict[str, object]
    ) -> Path:
        raw_output_dir = self._result_root / "raw" / run_id
        raw_output_dir.mkdir(parents=True, exist_ok=True)
        raw_output_path = raw_output_dir / f"{_safe_name(case_id)}.json"
        raw_output_path.write_text(serialize_raw_output(raw_output), encoding="utf-8")
        return raw_output_path

    def _load_records(self) -> list[RunRecord]:
        records_path = self._result_root / "run_records.json"
        if not records_path.exists():
            return []

        payload = json.loads(records_path.read_text(encoding="utf-8"))
        return [RunRecord(**record) for record in payload]

    def _write_records(self, records: list[RunRecord]) -> None:
        records_path = self._result_root / "run_records.json"
        records_path.write_text(
            json.dumps([asdict(record) for record in records], indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _skipped_record(
        self, previous: RunRecord, dataset_version: str, prompt_version: str
    ) -> RunRecord:
        return RunRecord(
            run_id=previous.run_id,
            case_id=previous.case_id,
            provider=previous.provider,
            model=previous.model,
            model_version=previous.model_version,
            prompt_template_id=previous.prompt_template_id,
            raw_output_ref=previous.raw_output_ref,
            normalized_findings=previous.normalized_findings,
            score=previous.score,
            failure_mode=previous.failure_mode,
            duration_ms=0,
            timestamp=datetime.now(UTC).isoformat(),
            status="skipped",
            dataset_version=dataset_version,
            prompt_version=prompt_version,
            language=previous.language,
            vuln_type=previous.vuln_type,
        )


def _safe_name(value: str) -> str:
    return value.replace("/", "_").replace(":", "__")
