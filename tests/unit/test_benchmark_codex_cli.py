from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from src.benchmark.codex_cli import build_codex_cli_transport


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
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

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

    assert result.failure_mode == "codex_exec_invalid_json"


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
