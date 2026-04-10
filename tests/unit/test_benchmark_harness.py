from __future__ import annotations

from src.benchmark.contracts import BenchmarkCase
from src.benchmark.harness import (
    CodexHarnessAdapter,
    GeminiCliHarnessAdapter,
    ProviderExecutionResult,
)


def _case() -> BenchmarkCase:
    return BenchmarkCase(
        case_id="freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1",
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        prompt_template_id="codex-v1",
        prompt_text=(
            "Audit the provided FreeBSD source file for a stack buffer overflow."
        ),
        input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        expected_vuln_type="stack buffer overflow",
        expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
        scoring_mode="exact-location-or-overlap",
    )


def test_provider_adapters_prepare_shared_case_shape() -> None:
    case = _case()
    codex_adapter = CodexHarnessAdapter(
        transport=lambda payload: ProviderExecutionResult(
            raw_output=payload,
            duration_ms=0,
            failure_mode=None,
        )
    )
    gemini_adapter = GeminiCliHarnessAdapter(
        transport=lambda payload: ProviderExecutionResult(
            raw_output=payload,
            duration_ms=0,
            failure_mode=None,
        )
    )

    codex_payload = codex_adapter.prepare(case)
    gemini_payload = gemini_adapter.prepare(case)

    assert codex_payload["case_id"] == case.case_id
    assert gemini_payload["case_id"] == case.case_id
    assert codex_payload["input_files"] == case.input_files
    assert gemini_payload["input_files"] == case.input_files
    assert codex_adapter.metadata().provider == "codex"
    assert gemini_adapter.metadata().provider == "gemini-cli"


def test_provider_adapters_capture_raw_output_and_normalized_findings() -> None:
    case = _case()

    def codex_transport(payload: dict[str, object]) -> ProviderExecutionResult:
        assert payload["prompt_text"] == case.prompt_text
        return ProviderExecutionResult(
            raw_output={
                "response": "Likely stack buffer overflow in svc_rpcsec_gss.c",
                "findings": [
                    {
                        "file_path": "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
                        "line_range": "148-188",
                        "vuln_type": "stack buffer overflow",
                        "explanation": "oa_length can overrun the fixed stack buffer",
                    }
                ],
            },
            duration_ms=241,
            failure_mode=None,
        )

    adapter = CodexHarnessAdapter(transport=codex_transport)

    raw_result = adapter.execute(adapter.prepare(case))
    findings = adapter.normalize(raw_result)

    assert raw_result.failure_mode is None
    assert raw_result.duration_ms == 241
    assert findings[0].file_path == "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"
    assert findings[0].line_range == "148-188"
    assert findings[0].vuln_type == "stack buffer overflow"


def test_provider_adapters_preserve_structured_failures() -> None:
    case = _case()
    adapter = GeminiCliHarnessAdapter(
        transport=lambda payload: ProviderExecutionResult(
            raw_output={"response": "", "findings": []},
            duration_ms=3000,
            failure_mode="timeout",
        )
    )

    result = adapter.execute(adapter.prepare(case))
    findings = adapter.normalize(result)

    assert result.failure_mode == "timeout"
    assert findings == []
