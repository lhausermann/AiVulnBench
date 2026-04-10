from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from src.benchmark.harness import ProviderExecutionResult, Transport


def build_codex_cli_transport(
    *,
    checkout_root_by_case: dict[str, Path],
    materialized_files_by_case: dict[str, list[str]],
    output_root: Path,
) -> Transport:
    def transport(payload: dict[str, object]) -> ProviderExecutionResult:
        started = time.monotonic()
        case_id = str(payload["case_id"])
        checkout_root = checkout_root_by_case[case_id]
        materialized_files = materialized_files_by_case[case_id]
        output_root.mkdir(parents=True, exist_ok=True)
        output_path = output_root / f"{_safe_name(case_id)}.json"
        schema_path = output_root / "codex_output_schema.json"
        _write_output_schema(schema_path)
        prompt = _build_prompt(payload, materialized_files)

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
        if completed.returncode != 0:
            return ProviderExecutionResult(
                raw_output={
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "response": "",
                    "findings": [],
                },
                duration_ms=_elapsed_ms(started),
                failure_mode=f"codex_exec_exit_{completed.returncode}",
            )

        try:
            response_text = output_path.read_text(encoding="utf-8").strip()
            normalized = _parse_response(response_text)
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
            return ProviderExecutionResult(
                raw_output={
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "response": output_path.read_text(encoding="utf-8")
                    if output_path.exists()
                    else "",
                    "findings": [],
                },
                duration_ms=_elapsed_ms(started),
                failure_mode="codex_exec_invalid_json",
            )

        return ProviderExecutionResult(
            raw_output={
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "response": normalized["response"],
                "findings": normalized["findings"],
            },
            duration_ms=_elapsed_ms(started),
            failure_mode=None,
        )

    return transport


def _build_prompt(payload: dict[str, object], materialized_files: list[str]) -> str:
    files_block = "\n".join(
        f"- {Path(file_path).name}: {file_path}" for file_path in materialized_files
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


def _parse_response(response_text: str) -> dict[str, object]:
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
