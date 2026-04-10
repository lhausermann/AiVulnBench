from __future__ import annotations

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from src.benchmark.checkout import materialize_entry_checkout
from src.dataset.schema import DatasetEntry


def _entry() -> DatasetEntry:
    return DatasetEntry(
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        source_report_section="fixture",
        product_name="FreeBSD",
        repository_url="https://github.com/freebsd/freebsd-src",
        clone_url="https://github.com/freebsd/freebsd-src.git",
        repository_kind="git",
        local_checkout_path="data/raw/repos/freebsd-src",
        language="C",
        cve_id="CVE-2026-4747",
        cwe_ids=["CWE-121"],
        vuln_type="stack-based buffer overflow",
        severity="critical",
        introduced_commit=None,
        fixed_commit="1b00fdc1f3cd",
        affected_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        affected_line_ranges=[],
        description="fixture",
        source_urls=["https://example.com"],
        code_snippet_ref="sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
        dataset_version="2026.04",
    )


def test_materialize_entry_checkout_clones_fetches_and_checks_out_target_file(
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> CompletedProcess[str]:
        commands.append(command)
        return CompletedProcess(command, 0, stdout="fixture-content", stderr="")

    with patch("src.benchmark.checkout.subprocess.run", side_effect=fake_run):
        materialized = materialize_entry_checkout(tmp_path, _entry())

    assert commands[0] == [
        "git",
        "clone",
        "https://github.com/freebsd/freebsd-src.git",
        str(tmp_path / "data/raw/repos/freebsd-src"),
    ]
    assert commands[1] == [
        "git",
        "-C",
        str(tmp_path / "data/raw/repos/freebsd-src"),
        "fetch",
        "origin",
        "1b00fdc1f3cd",
    ]
    assert commands[2] == [
        "git",
        "-C",
        str(tmp_path / "data/raw/repos/freebsd-src"),
        "rev-parse",
        "--verify",
        "1b00fdc1f3cd^",
    ]
    assert commands[3] == [
        "git",
        "-C",
        str(tmp_path / "data/raw/repos/freebsd-src"),
        "show",
        "1b00fdc1f3cd^:sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
    ]
    materialized_path = (
        tmp_path / "data/raw/repos/freebsd-src/sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"
    )
    assert materialized == [str(materialized_path)]
    assert materialized_path.read_text(encoding="utf-8") == "fixture-content"


def test_materialize_entry_checkout_falls_back_to_base_commit_when_parent_missing(
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> CompletedProcess[str]:
        commands.append(command)
        if command[-2:] == ["--verify", "1b00fdc1f3cd^"]:
            from subprocess import CalledProcessError

            raise CalledProcessError(128, command)
        return CompletedProcess(command, 0, stdout="fixture-content", stderr="")

    with patch("src.benchmark.checkout.subprocess.run", side_effect=fake_run):
        materialize_entry_checkout(tmp_path, _entry())

    assert commands[-1] == [
        "git",
        "-C",
        str(tmp_path / "data/raw/repos/freebsd-src"),
        "show",
        "1b00fdc1f3cd:sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
    ]


def test_materialize_entry_checkout_reuses_existing_clone(tmp_path: Path) -> None:
    commands: list[list[str]] = []
    checkout_path = tmp_path / "data/raw/repos/freebsd-src"
    checkout_path.mkdir(parents=True)

    def fake_run(
        command: list[str],
        *,
        check: bool,
        capture_output: bool,
        text: bool,
    ) -> CompletedProcess[str]:
        commands.append(command)
        return CompletedProcess(command, 0, stdout="fixture-content", stderr="")

    with patch("src.benchmark.checkout.subprocess.run", side_effect=fake_run):
        materialize_entry_checkout(tmp_path, _entry())

    assert all(command[:2] != ["git", "clone"] for command in commands)
    assert commands[0] == [
        "git",
        "-C",
        str(tmp_path / "data/raw/repos/freebsd-src"),
        "fetch",
        "origin",
        "1b00fdc1f3cd",
    ]
