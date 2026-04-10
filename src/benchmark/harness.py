from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable

from src.benchmark.contracts import BenchmarkCase
from src.benchmark.scoring import Finding

Transport = Callable[[dict[str, object]], "ProviderExecutionResult"]


@dataclass(frozen=True)
class ProviderMetadata:
    provider: str
    model: str
    model_version: str


@dataclass(frozen=True)
class ProviderExecutionResult:
    raw_output: dict[str, Any]
    duration_ms: int
    failure_mode: str | None


class BaseHarnessAdapter:
    def __init__(
        self,
        *,
        provider: str,
        model: str,
        model_version: str,
        transport: Transport,
    ) -> None:
        self._provider = provider
        self._model = model
        self._model_version = model_version
        self._transport = transport

    def prepare(self, case: BenchmarkCase) -> dict[str, object]:
        return {
            "case_id": case.case_id,
            "entry_id": case.entry_id,
            "prompt_template_id": case.prompt_template_id,
            "prompt_text": case.prompt_text,
            "input_files": case.input_files,
            "expected_vuln_type": case.expected_vuln_type,
            "expected_locations": case.expected_locations,
            "scoring_mode": case.scoring_mode,
        }

    def execute(self, payload: dict[str, object]) -> ProviderExecutionResult:
        return self._transport(payload)

    def normalize(self, result: ProviderExecutionResult) -> list[Finding]:
        finding_payloads = result.raw_output.get("findings", [])
        if not isinstance(finding_payloads, list):
            return []

        findings: list[Finding] = []
        for payload in finding_payloads:
            if not isinstance(payload, dict):
                continue
            findings.append(
                Finding(
                    file_path=str(payload["file_path"]),
                    line_range=str(payload["line_range"]),
                    vuln_type=str(payload["vuln_type"]),
                    explanation=str(payload["explanation"]),
                )
            )
        return findings

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider=self._provider,
            model=self._model,
            model_version=self._model_version,
        )


class CodexHarnessAdapter(BaseHarnessAdapter):
    def __init__(
        self,
        transport: Transport,
        *,
        model: str = "gpt-5-codex",
        model_version: str = "gpt-5-codex-2026-04-09",
    ) -> None:
        super().__init__(
            provider="codex",
            model=model,
            model_version=model_version,
            transport=transport,
        )


class GeminiCliHarnessAdapter(BaseHarnessAdapter):
    def __init__(
        self,
        transport: Transport,
        *,
        model: str = "gemini-cli",
        model_version: str = "gemini-cli-2026-04-09",
    ) -> None:
        super().__init__(
            provider="gemini-cli",
            model=model,
            model_version=model_version,
            transport=transport,
        )


def serialize_raw_output(raw_output: dict[str, Any]) -> str:
    return json.dumps(raw_output, indent=2, sort_keys=True)
