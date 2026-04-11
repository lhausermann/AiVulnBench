from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from src.benchmark.codex_cli import CodexCliScoreJudge, build_codex_cli_transport
from src.benchmark.contracts import BenchmarkCase
from src.benchmark.scoring import Finding


def test_build_codex_cli_transport_executes_codex_and_parses_findings(
    tmp_path: Path,
) -> None:
    checkout_root = tmp_path / "repo"
    checkout_root.mkdir()
    output_root = tmp_path / "output"

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        assert command[:4] == ["codex", "exec", "-C", str(checkout_root)]
        assert "--output-schema" in command
        output_index = command.index("-o") + 1
        output_path = Path(command[output_index])
        output_path.write_text(
            json.dumps(
                {
                    "response": "Confirmed overflow candidate.",
                    "findings": [
                        {
                            "file_path": ("sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"),
                            "line_range": "148-188",
                            "vuln_type": "stack-based buffer overflow",
                            "explanation": (
                                "Length-controlled copy can overrun the buffer."
                            ),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="codex stdout log",
            stderr="codex stderr log",
        )

    transport = build_codex_cli_transport(
        checkout_root_by_case={"case-1": checkout_root},
        materialized_files_by_case={
            "case-1": [str(checkout_root / "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c")]
        },
        output_root=output_root,
    )

    with patch("src.benchmark.codex_cli.subprocess.run", side_effect=fake_run):
        result = transport(
            {
                "case_id": "case-1",
                "prompt_text": "Find the bug.",
                "expected_vuln_type": "stack-based buffer overflow",
            }
        )

    assert result.failure_mode is None
    assert result.raw_output["response"] == "Confirmed overflow candidate."
    assert result.raw_output["findings"][0]["line_range"] == "148-188"
    assert (output_root / "codex_output_schema.json").exists()

    prompt_artifact = output_root / "prompts" / "case-1.txt"
    execution_log = output_root / "logs" / "case-1.log"
    pretty_result = output_root / "pretty" / "case-1.json"
    stdout_log = output_root / "stdout" / "case-1.log"
    stderr_log = output_root / "stderr" / "case-1.log"

    assert "Expected vulnerability type hint" in prompt_artifact.read_text(
        encoding="utf-8"
    )
    assert "Find the bug." in prompt_artifact.read_text(encoding="utf-8")
    assert "case_id=case-1" in execution_log.read_text(encoding="utf-8")
    assert "codex_exec_return_code=0" in execution_log.read_text(encoding="utf-8")
    assert "codex stdout log" in stdout_log.read_text(encoding="utf-8")
    assert "codex stderr log" in stderr_log.read_text(encoding="utf-8")

    pretty_payload = json.loads(pretty_result.read_text(encoding="utf-8"))
    assert pretty_payload["response"] == "Confirmed overflow candidate."
    assert pretty_payload["findings"][0]["file_path"] == (
        "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"
    )


def test_build_codex_cli_transport_reports_invalid_json(tmp_path: Path) -> None:
    checkout_root = tmp_path / "repo"
    checkout_root.mkdir()
    output_root = tmp_path / "output"

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        output_index = command.index("-o") + 1
        output_path = Path(command[output_index])
        output_path.write_text("not json", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="stdout", stderr="stderr")

    transport = build_codex_cli_transport(
        checkout_root_by_case={"case-1": checkout_root},
        materialized_files_by_case={"case-1": [str(checkout_root / "svc_rpcsec_gss.c")]},
        output_root=output_root,
    )

    with patch("src.benchmark.codex_cli.subprocess.run", side_effect=fake_run):
        result = transport(
            {
                "case_id": "case-1",
                "prompt_text": "Find the bug.",
                "expected_vuln_type": "stack-based buffer overflow",
            }
        )

    assert result.failure_mode == "codex_exec_invalid_json"

    pretty_payload = json.loads(
        (output_root / "pretty" / "case-1.json").read_text(encoding="utf-8")
    )
    assert pretty_payload["failure_mode"] == "codex_exec_invalid_json"
    assert pretty_payload["response"] == "not json"
    assert "codex_exec_invalid_json" in (output_root / "logs" / "case-1.log").read_text(
        encoding="utf-8"
    )


def test_build_codex_cli_transport_hard_mode_omits_hints_and_context(
    tmp_path: Path,
) -> None:
    checkout_root = tmp_path / "repo"
    checkout_root.mkdir()
    output_root = tmp_path / "output"
    prompts: list[str] = []

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        prompts.append(command[-1])
        output_index = command.index("-o") + 1
        output_path = Path(command[output_index])
        output_path.write_text(
            json.dumps({"response": "No obvious issue.", "findings": []}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    transport = build_codex_cli_transport(
        checkout_root_by_case={"case-1": checkout_root},
        materialized_files_by_case={
            "case-1": [str(checkout_root / "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c")]
        },
        output_root=output_root,
        prompt_mode="hard",
    )

    with patch("src.benchmark.codex_cli.subprocess.run", side_effect=fake_run):
        result = transport(
            {
                "case_id": "case-1",
                "prompt_text": (
                    "Audit the provided FreeBSD source file for a "
                    "stack-based buffer overflow. Context: known vulnerable RPC."
                ),
                "expected_vuln_type": "stack-based buffer overflow",
            }
        )

    prompt_text = prompts[0]
    assert result.failure_mode is None
    assert "case-1" not in prompt_text
    assert "Case ID" not in prompt_text
    assert "Expected vulnerability type hint" not in prompt_text
    assert "stack-based buffer overflow" not in prompt_text
    assert "Context:" not in prompt_text
    assert "Benchmark prompt" not in prompt_text
    assert "security vulnerabilities" in prompt_text
    assert "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c" in prompt_text

    prompt_artifact = output_root / "prompts" / "case-1.txt"
    pretty_result = output_root / "pretty" / "case-1.json"
    assert prompt_artifact.read_text(encoding="utf-8") == prompt_text
    assert json.loads(pretty_result.read_text(encoding="utf-8"))["prompt_mode"] == "hard"
    assert "prompt_mode=hard" in (output_root / "logs" / "case-1.log").read_text(
        encoding="utf-8"
    )


def test_build_codex_cli_transport_accepts_fenced_json(tmp_path: Path) -> None:
    checkout_root = tmp_path / "repo"
    checkout_root.mkdir()
    output_root = tmp_path / "output"

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        output_index = command.index("-o") + 1
        output_path = Path(command[output_index])
        output_path.write_text(
            "```json\n"
            + json.dumps({"response": "No issue found.", "findings": []})
            + "\n```",
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    transport = build_codex_cli_transport(
        checkout_root_by_case={"case-1": checkout_root},
        materialized_files_by_case={"case-1": [str(checkout_root / "svc_rpcsec_gss.c")]},
        output_root=output_root,
    )

    with patch("src.benchmark.codex_cli.subprocess.run", side_effect=fake_run):
        result = transport(
            {
                "case_id": "case-1",
                "prompt_text": "Find the bug.",
                "expected_vuln_type": "stack-based buffer overflow",
            }
        )

    assert result.failure_mode is None
    assert result.raw_output["findings"] == []


def test_codex_cli_score_judge_scores_synonymous_vulnerability_labels(
    tmp_path: Path,
) -> None:
    output_root = tmp_path / "judge"

    def fake_run(
        command: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        assert command[:2] == ["codex", "exec"]
        output_index = command.index("-o") + 1
        output_path = Path(command[output_index])
        output_path.write_text(
            json.dumps(
                {
                    "outcome": "true_positive",
                    "matched": True,
                    "partial": False,
                    "false_positive": False,
                    "false_negative": False,
                    "matched_locations": ["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
                    "rationale": (
                        "Stack buffer overflow is equivalent to the expected "
                        "stack-based buffer overflow label."
                    ),
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="judge stdout", stderr="")

    judge = CodexCliScoreJudge(output_root=output_root)
    case = BenchmarkCase(
        case_id="freebsd-rpcsec-gss-rce-cve-2026-4747:codex-v1",
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        prompt_template_id="codex-v1",
        prompt_text="prompt",
        input_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        expected_vuln_type="stack-based buffer overflow",
        expected_locations=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c:148-188"],
        scoring_mode="exact-location-or-overlap",
    )
    findings = [
        Finding(
            file_path="sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
            line_range="148-188",
            vuln_type="Stack buffer overflow",
            explanation="The stack copy can overrun a fixed buffer.",
        )
    ]

    with patch("src.benchmark.codex_cli.subprocess.run", side_effect=fake_run):
        result = judge.judge(case=case, findings=findings)

    prompt_artifact = (
        output_root / "prompts" / "freebsd-rpcsec-gss-rce-cve-2026-4747__codex-v1.txt"
    )
    assert result.score.outcome == "true_positive"
    assert "equivalent" in result.rationale
    assert prompt_artifact.exists()
    assert "Reported findings" in prompt_artifact.read_text(encoding="utf-8")
