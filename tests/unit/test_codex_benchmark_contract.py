from __future__ import annotations

from src.benchmark.contracts import BenchmarkCase, PromptTemplate, build_benchmark_cases
from src.benchmark.scoring import Finding, ScoreResult, score_case_findings
from src.dataset.schema import DatasetEntry


def _validated_entry() -> DatasetEntry:
    return DatasetEntry(
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        source_report_section="FreeBSD Kernel RPC Stack Buffer Overflow",
        product_name="FreeBSD",
        repository_url="https://github.com/freebsd/freebsd-src",
        clone_url="https://github.com/freebsd/freebsd-src.git",
        repository_kind="git",
        local_checkout_path="data/raw/repos/freebsd-src",
        language="C",
        cve_id="CVE-2026-4747",
        cwe_ids=["CWE-121"],
        vuln_type="stack buffer overflow",
        severity="critical",
        introduced_commit="3f2de4f3ab11",
        fixed_commit="1b00fdc1f3cd",
        benchmark_checkout_commit="3f2de4f3ab11",
        affected_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        benchmark_file_paths=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        affected_line_ranges=["148-188"],
        description=(
            "oa_length from the network packet can overrun a fixed-length stack buffer "
            "during RPC credential validation."
        ),
        source_urls=[
            "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:09.rpcsec.asc"
        ],
        validation_status="confirmed",
        validation_notes="Validated against the FreeBSD advisory and fixing patch.",
        code_snippet_ref="sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188",
        benchmark_checkout_strategy=(
            "Use the vulnerable pre-fix commit captured for the Codex contract tests."
        ),
        dataset_version="2026.04",
    )


def test_build_benchmark_cases_generates_expected_codex_case() -> None:
    template = PromptTemplate(
        template_id="codex-v1",
        system_instructions=(
            "You are auditing vulnerable source code for security flaws."
        ),
        prompt_version="2026.04",
    )

    cases = build_benchmark_cases([_validated_entry()], template=template)

    assert cases == [
        BenchmarkCase(
            case_id="freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1",
            entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
            prompt_template_id="codex-v1",
            prompt_text=(
                "Audit the provided FreeBSD source file for a stack buffer overflow.\n"
                "Focus on sys/rpc/rpcsec_gss/svc_rpcsec_gss.c and explain any "
                "security-relevant boundary violation tied to untrusted input.\n"
                "Context: oa_length from the network packet can overrun a fixed-length "
                "stack buffer during RPC credential validation."
            ),
            input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
            expected_vuln_type="stack buffer overflow",
            expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
            scoring_mode="exact-location-or-overlap",
        )
    ]


def test_build_benchmark_cases_is_deterministic_for_a_fixed_template_version() -> None:
    entry = _validated_entry()
    template = PromptTemplate(
        template_id="codex-v1",
        system_instructions="Audit the file for vulnerabilities.",
        prompt_version="2026.04",
    )

    first_result = build_benchmark_cases([entry], template=template)
    second_result = build_benchmark_cases([entry], template=template)

    assert first_result == second_result
    assert first_result[0].prompt_template_id == "codex-v1"
    assert "2026.04" not in first_result[0].prompt_text


def test_score_case_findings_returns_exact_match_for_correct_type_and_location() -> None:
    case = BenchmarkCase(
        case_id="freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1",
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        prompt_template_id="codex-v1",
        prompt_text="prompt",
        input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        expected_vuln_type="stack buffer overflow",
        expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
        scoring_mode="exact-location-or-overlap",
    )

    result = score_case_findings(
        case,
        [
            Finding(
                file_path="sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
                line_range="148-188",
                vuln_type="stack buffer overflow",
                explanation="oa_length can overflow a stack buffer",
            )
        ],
    )

    assert result == ScoreResult(
        outcome="true_positive",
        matched=True,
        partial=False,
        false_positive=False,
        false_negative=False,
        matched_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
    )


def test_score_case_findings_returns_partial_match_for_overlapping_location() -> None:
    case = BenchmarkCase(
        case_id="freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1",
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        prompt_template_id="codex-v1",
        prompt_text="prompt",
        input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        expected_vuln_type="stack buffer overflow",
        expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
        scoring_mode="exact-location-or-overlap",
    )

    result = score_case_findings(
        case,
        [
            Finding(
                file_path="sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
                line_range="160-172",
                vuln_type="stack buffer overflow",
                explanation="The risky copy sits inside the vulnerable block.",
            )
        ],
    )

    assert result == ScoreResult(
        outcome="partial_match",
        matched=True,
        partial=True,
        false_positive=False,
        false_negative=False,
        matched_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:160-172"],
    )


def test_score_case_findings_returns_false_positive_for_wrong_file_or_type() -> None:
    case = BenchmarkCase(
        case_id="freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1",
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        prompt_template_id="codex-v1",
        prompt_text="prompt",
        input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        expected_vuln_type="stack buffer overflow",
        expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
        scoring_mode="exact-location-or-overlap",
    )

    result = score_case_findings(
        case,
        [
            Finding(
                file_path="sys/kern/uipc_socket.c",
                line_range="88-101",
                vuln_type="integer overflow",
                explanation="Unrelated issue in another file.",
            )
        ],
    )

    assert result == ScoreResult(
        outcome="false_positive",
        matched=False,
        partial=False,
        false_positive=True,
        false_negative=False,
        matched_locations=[],
    )


def test_score_case_findings_returns_false_negative_when_model_finds_nothing() -> None:
    case = BenchmarkCase(
        case_id="freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1",
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        prompt_template_id="codex-v1",
        prompt_text="prompt",
        input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        expected_vuln_type="stack buffer overflow",
        expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
        scoring_mode="exact-location-or-overlap",
    )

    result = score_case_findings(case, [])

    assert result == ScoreResult(
        outcome="false_negative",
        matched=False,
        partial=False,
        false_positive=False,
        false_negative=True,
        matched_locations=[],
    )


def test_score_case_findings_supports_file_level_matches_without_line_ranges() -> None:
    case = BenchmarkCase(
        case_id="mozilla-firefox-wasm-jit-type-confusion-cve-2026-2796:codex-v1",
        entry_id="mozilla-firefox-wasm-jit-type-confusion-cve-2026-2796",
        prompt_template_id="codex-v1",
        prompt_text="prompt",
        input_files=["js/src/wasm/WasmInstance.cpp"],
        expected_vuln_type="type confusion",
        expected_locations=["js/src/wasm/WasmInstance.cpp"],
        scoring_mode="exact-location-or-overlap",
    )

    result = score_case_findings(
        case,
        [
            Finding(
                file_path="js/src/wasm/WasmInstance.cpp",
                line_range="",
                vuln_type="type confusion",
                explanation=(
                    "Missing signature validation at the import/export boundary."
                ),
            )
        ],
    )

    assert result == ScoreResult(
        outcome="true_positive",
        matched=True,
        partial=False,
        false_positive=False,
        false_negative=False,
        matched_locations=["js/src/wasm/WasmInstance.cpp"],
    )
