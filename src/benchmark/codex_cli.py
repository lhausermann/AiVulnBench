from __future__ import annotations

import json
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from typing import Literal, TypedDict

from src.benchmark.contracts import BenchmarkCase
from src.benchmark.harness import ProviderExecutionResult, Transport
from src.benchmark.scoring import (
    BaseScoreJudge,
    Finding,
    JudgeExecutionResult,
    JudgeMetadata,
    ScoreResult,
    score_case_findings,
)

PromptMode = Literal["normal", "hard"]


class _NormalizedResponse(TypedDict):
    response: str
    findings: list[dict[str, str]]


class _JudgeResponse(TypedDict):
    outcome: str
    matched: bool
    partial: bool
    false_positive: bool
    false_negative: bool
    matched_locations: list[str]
    rationale: str


class CodexCliScoreJudge(BaseScoreJudge):
    def __init__(
        self,
        *,
        output_root: Path,
        model: str = "gpt-5-codex-judge",
        model_version: str = "gpt-5-codex-judge-2026-04-11",
    ) -> None:
        self._output_root = output_root
        self._metadata = JudgeMetadata(
            provider="codex",
            model=model,
            model_version=model_version,
        )

    def metadata(self) -> JudgeMetadata:
        return self._metadata

    def judge(
        self,
        *,
        case: BenchmarkCase,
        findings: list[Finding],
    ) -> JudgeExecutionResult:
        started = time.monotonic()
        self._output_root.mkdir(parents=True, exist_ok=True)
        schema_path = self._output_root / "codex_judge_schema.json"
        artifacts = _artifact_paths(self._output_root, case.case_id)
        execution_log = [
            f"case_id={case.case_id}",
            f"entry_id={case.entry_id}",
            f"schema_path={schema_path}",
            f"prompt_path={artifacts['prompt']}",
            f"pretty_result_path={artifacts['pretty']}",
            f"stdout_log_path={artifacts['stdout']}",
            f"stderr_log_path={artifacts['stderr']}",
        ]
        _write_judge_schema(schema_path)
        prompt = _build_judge_prompt(case=case, findings=findings)
        _write_text(artifacts["prompt"], prompt)
        execution_log.append("prompt_written=true")

        output_path = self._output_root / f"{_safe_name(case.case_id)}.json"
        completed = subprocess.run(
            [
                "codex",
                "exec",
                "--skip-git-repo-check",
                "--output-schema",
                str(schema_path),
                "-o",
                str(output_path),
                prompt,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        _write_text(artifacts["stdout"], completed.stdout)
        _write_text(artifacts["stderr"], completed.stderr)
        execution_log.extend(
            [
                f"codex_exec_return_code={completed.returncode}",
                "stdout_log_written=true",
                "stderr_log_written=true",
            ]
        )

        if completed.returncode != 0:
            return self._fallback_result(
                case=case,
                findings=findings,
                output_path=artifacts["pretty"],
                log_path=artifacts["log"],
                execution_log=execution_log,
                stdout=completed.stdout,
                stderr=completed.stderr,
                failure_mode=f"codex_judge_exit_{completed.returncode}",
                duration_ms=_elapsed_ms(started),
            )

        try:
            response_text = output_path.read_text(encoding="utf-8").strip()
            payload = _parse_judge_response(response_text)
            score = ScoreResult(
                outcome=str(payload["outcome"]),
                matched=bool(payload["matched"]),
                partial=bool(payload["partial"]),
                false_positive=bool(payload["false_positive"]),
                false_negative=bool(payload["false_negative"]),
                matched_locations=[str(value) for value in payload["matched_locations"]],
            )
            rationale = str(payload["rationale"])
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raw_response = (
                output_path.read_text(encoding="utf-8") if output_path.exists() else ""
            )
            return self._fallback_result(
                case=case,
                findings=findings,
                output_path=artifacts["pretty"],
                log_path=artifacts["log"],
                execution_log=execution_log
                + [f"parse_error={type(exc).__name__}: {exc}"],
                stdout=completed.stdout,
                stderr=completed.stderr,
                failure_mode="codex_judge_invalid_json",
                duration_ms=_elapsed_ms(started),
                response=raw_response,
            )

        raw_output = {
            "response": response_text,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "rationale": rationale,
            **asdict(score),
        }
        duration_ms = _elapsed_ms(started)
        _write_pretty_result(
            artifacts["pretty"],
            raw_output=raw_output,
            failure_mode=None,
            duration_ms=duration_ms,
            prompt_mode="judge",
        )
        execution_log.extend(
            [
                "failure_mode=null",
                f"outcome={score.outcome}",
                f"duration_ms={duration_ms}",
            ]
        )
        _write_execution_log(artifacts["log"], execution_log)
        return JudgeExecutionResult(
            score=score,
            rationale=rationale,
            duration_ms=duration_ms,
            failure_mode=None,
            raw_output=raw_output,
        )

    def _fallback_result(
        self,
        *,
        case: BenchmarkCase,
        findings: list[Finding],
        output_path: Path,
        log_path: Path,
        execution_log: list[str],
        stdout: str,
        stderr: str,
        failure_mode: str,
        duration_ms: int,
        response: str = "",
    ) -> JudgeExecutionResult:
        score = score_case_findings(case, findings)
        rationale = (
            "Fell back to heuristic scoring because the Codex judge did not return "
            f"a usable decision ({failure_mode})."
        )
        raw_output = {
            "response": response,
            "stdout": stdout,
            "stderr": stderr,
            "rationale": rationale,
            **asdict(score),
        }
        _write_pretty_result(
            output_path,
            raw_output=raw_output,
            failure_mode=failure_mode,
            duration_ms=duration_ms,
            prompt_mode="judge",
        )
        execution_log.extend(
            [
                f"failure_mode={failure_mode}",
                f"fallback_outcome={score.outcome}",
                f"duration_ms={duration_ms}",
            ]
        )
        _write_execution_log(log_path, execution_log)
        return JudgeExecutionResult(
            score=score,
            rationale=rationale,
            duration_ms=duration_ms,
            failure_mode=failure_mode,
            raw_output=raw_output,
        )


def build_codex_cli_transport(
    *,
    checkout_root_by_case: dict[str, Path],
    materialized_files_by_case: dict[str, list[str]],
    output_root: Path,
    prompt_mode: PromptMode = "normal",
) -> Transport:
    def transport(payload: dict[str, object]) -> ProviderExecutionResult:
        started = time.monotonic()
        case_id = str(payload["case_id"])
        checkout_root = checkout_root_by_case[case_id]
        materialized_files = materialized_files_by_case[case_id]
        output_root.mkdir(parents=True, exist_ok=True)
        output_path = output_root / f"{_safe_name(case_id)}.json"
        schema_path = output_root / "codex_output_schema.json"
        artifacts = _artifact_paths(output_root, case_id)
        execution_log = [
            f"case_id={case_id}",
            f"checkout_root={checkout_root}",
            f"materialized_files={json.dumps(materialized_files, sort_keys=True)}",
            f"schema_path={schema_path}",
            f"response_path={output_path}",
            f"prompt_path={artifacts['prompt']}",
            f"pretty_result_path={artifacts['pretty']}",
            f"stdout_log_path={artifacts['stdout']}",
            f"stderr_log_path={artifacts['stderr']}",
            f"prompt_mode={prompt_mode}",
        ]
        _write_output_schema(schema_path)
        prompt = _build_prompt(
            payload,
            materialized_files,
            prompt_mode=prompt_mode,
        )
        _write_text(artifacts["prompt"], prompt)
        execution_log.append("prompt_written=true")

        completed = subprocess.run(
            [
                "codex",
                "exec",
                "-C",
                str(checkout_root),
                "--skip-git-repo-check",
                "--output-schema",
                str(schema_path),
                "-o",
                str(output_path),
                prompt,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        _write_text(artifacts["stdout"], completed.stdout)
        _write_text(artifacts["stderr"], completed.stderr)
        execution_log.extend(
            [
                f"codex_exec_return_code={completed.returncode}",
                "stdout_log_written=true",
                "stderr_log_written=true",
            ]
        )
        if completed.returncode != 0:
            raw_output: dict[str, object] = {
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "response": "",
                "findings": [],
            }
            duration_ms = _elapsed_ms(started)
            failure_mode = f"codex_exec_exit_{completed.returncode}"
            _write_pretty_result(
                artifacts["pretty"],
                raw_output=raw_output,
                failure_mode=failure_mode,
                duration_ms=duration_ms,
                prompt_mode=prompt_mode,
            )
            execution_log.extend(
                [
                    f"failure_mode={failure_mode}",
                    f"duration_ms={duration_ms}",
                ]
            )
            _write_execution_log(artifacts["log"], execution_log)
            return ProviderExecutionResult(
                raw_output=raw_output,
                duration_ms=duration_ms,
                failure_mode=failure_mode,
            )

        try:
            response_text = output_path.read_text(encoding="utf-8").strip()
            normalized = _parse_response(response_text)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raw_response = (
                output_path.read_text(encoding="utf-8") if output_path.exists() else ""
            )
            raw_output = {
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "response": raw_response,
                "findings": [],
            }
            duration_ms = _elapsed_ms(started)
            failure_mode = "codex_exec_invalid_json"
            _write_pretty_result(
                artifacts["pretty"],
                raw_output=raw_output,
                failure_mode=failure_mode,
                duration_ms=duration_ms,
                prompt_mode=prompt_mode,
            )
            execution_log.extend(
                [
                    f"failure_mode={failure_mode}",
                    f"parse_error={type(exc).__name__}: {exc}",
                    f"duration_ms={duration_ms}",
                ]
            )
            _write_execution_log(artifacts["log"], execution_log)
            return ProviderExecutionResult(
                raw_output=raw_output,
                duration_ms=duration_ms,
                failure_mode=failure_mode,
            )

        raw_output = {
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "response": normalized["response"],
            "findings": normalized["findings"],
        }
        duration_ms = _elapsed_ms(started)
        _write_pretty_result(
            artifacts["pretty"],
            raw_output=raw_output,
            failure_mode=None,
            duration_ms=duration_ms,
            prompt_mode=prompt_mode,
        )
        execution_log.extend(
            [
                "failure_mode=null",
                f"normalized_findings_count={len(normalized['findings'])}",
                f"duration_ms={duration_ms}",
            ]
        )
        _write_execution_log(artifacts["log"], execution_log)
        return ProviderExecutionResult(
            raw_output=raw_output,
            duration_ms=duration_ms,
            failure_mode=None,
        )

    return transport


def _build_prompt(
    payload: dict[str, object],
    materialized_files: list[str],
    *,
    prompt_mode: PromptMode,
) -> str:
    files_block = "\n".join(
        f"- {Path(file_path).name}: {file_path}" for file_path in materialized_files
    )
    if prompt_mode == "hard":
        return (
            "Review the provided source file(s) for security vulnerabilities.\n"
            "Only inspect the provided materialized files.\n"
            f"Files:\n{files_block}\n"
            "If you identify a vulnerability, report the repo-relative file path and"
            " the narrowest line range you can justify from the visible code.\n"
            "Respond with valid JSON only using the provided output schema.\n"
            "If you do not find a vulnerability, return an empty findings array."
        )

    return (
        "Analyze the checked-out source file(s) for the expected vulnerability.\n"
        f"Case ID: {payload['case_id']}\n"
        f"Expected vulnerability type hint: {payload['expected_vuln_type']}\n"
        "Only inspect the provided materialized files.\n"
        f"Files:\n{files_block}\n"
        f"Benchmark prompt:\n{payload['prompt_text']}\n"
        "If you identify the vulnerability, report the repo-relative file path and the"
        " narrowest line range you can justify from the visible code.\n"
        "Respond with valid JSON only using the provided output schema.\n"
        "If you do not find the vulnerability, return an empty findings array."
    )


def _parse_response(response_text: str) -> _NormalizedResponse:
    payload = json.loads(_extract_json_object(response_text))
    response = str(payload["response"])
    findings_payload = payload["findings"]
    if not isinstance(findings_payload, list):
        raise ValueError("findings must be a list")

    findings: list[dict[str, str]] = []
    for finding in findings_payload:
        if not isinstance(finding, dict):
            raise ValueError("finding must be an object")
        findings.append(
            {
                "file_path": str(finding["file_path"]),
                "line_range": str(finding["line_range"]),
                "vuln_type": str(finding["vuln_type"]),
                "explanation": str(finding["explanation"]),
            }
        )

    return {"response": response, "findings": findings}


def _write_output_schema(schema_path: Path) -> None:
    schema_path.write_text(
        json.dumps(
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["response", "findings"],
                "properties": {
                    "response": {"type": "string"},
                    "findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": [
                                "file_path",
                                "line_range",
                                "vuln_type",
                                "explanation",
                            ],
                            "properties": {
                                "file_path": {"type": "string"},
                                "line_range": {"type": "string"},
                                "vuln_type": {"type": "string"},
                                "explanation": {"type": "string"},
                            },
                        },
                    },
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_judge_schema(schema_path: Path) -> None:
    schema_path.write_text(
        json.dumps(
            {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "outcome",
                    "matched",
                    "partial",
                    "false_positive",
                    "false_negative",
                    "matched_locations",
                    "rationale",
                ],
                "properties": {
                    "outcome": {
                        "type": "string",
                        "enum": [
                            "true_positive",
                            "partial_match",
                            "false_positive",
                            "false_negative",
                        ],
                    },
                    "matched": {"type": "boolean"},
                    "partial": {"type": "boolean"},
                    "false_positive": {"type": "boolean"},
                    "false_negative": {"type": "boolean"},
                    "matched_locations": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "rationale": {"type": "string"},
                },
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _artifact_paths(output_root: Path, case_id: str) -> dict[str, Path]:
    safe_case_id = _safe_name(case_id)
    return {
        "prompt": output_root / "prompts" / f"{safe_case_id}.txt",
        "log": output_root / "logs" / f"{safe_case_id}.log",
        "pretty": output_root / "pretty" / f"{safe_case_id}.json",
        "stdout": output_root / "stdout" / f"{safe_case_id}.log",
        "stderr": output_root / "stderr" / f"{safe_case_id}.log",
    }


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_pretty_result(
    path: Path,
    *,
    raw_output: dict[str, object],
    failure_mode: str | None,
    duration_ms: int,
    prompt_mode: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                **raw_output,
                "failure_mode": failure_mode,
                "duration_ms": duration_ms,
                "prompt_mode": prompt_mode,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _write_execution_log(path: Path, lines: list[str]) -> None:
    _write_text(path, "\n".join(lines) + "\n")


def _build_judge_prompt(*, case: BenchmarkCase, findings: list[Finding]) -> str:
    findings_payload = [asdict(finding) for finding in findings]
    return (
        "You are scoring a vulnerability-detection benchmark result.\n"
        "Decide whether the model output should be scored as true_positive, "
        "partial_match, false_positive, or false_negative.\n"
        "Treat close vulnerability-type synonyms as equivalent when they clearly "
        "describe the same underlying bug class.\n"
        "Treat an overlapping line range in the correct file as a partial match.\n"
        f"Expected vulnerability type: {case.expected_vuln_type}\n"
        f"Expected locations: {json.dumps(case.expected_locations, sort_keys=True)}\n"
        f"Reported findings: {json.dumps(findings_payload, indent=2, sort_keys=True)}\n"
        "Return valid JSON only using the provided schema, including a short rationale."
    )


def _parse_judge_response(response_text: str) -> _JudgeResponse:
    payload = json.loads(_extract_json_object(response_text))
    required_keys = {
        "outcome",
        "matched",
        "partial",
        "false_positive",
        "false_negative",
        "matched_locations",
        "rationale",
    }
    missing = required_keys.difference(payload)
    if missing:
        raise ValueError(f"judge response is missing keys: {sorted(missing)}")
    if not isinstance(payload["matched_locations"], list):
        raise ValueError("matched_locations must be a list")
    return _JudgeResponse(
        outcome=str(payload["outcome"]),
        matched=bool(payload["matched"]),
        partial=bool(payload["partial"]),
        false_positive=bool(payload["false_positive"]),
        false_negative=bool(payload["false_negative"]),
        matched_locations=[str(value) for value in payload["matched_locations"]],
        rationale=str(payload["rationale"]),
    )


def _extract_json_object(response_text: str) -> str:
    stripped = response_text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            return "\n".join(lines[1:-1]).strip()
    return stripped


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _safe_name(value: str) -> str:
    return value.replace("/", "_").replace(":", "__")
