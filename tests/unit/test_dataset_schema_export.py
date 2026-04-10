from __future__ import annotations

import json
from pathlib import Path

from src.dataset.schema import DatasetEntry
from src.dataset.storage import export_dataset_entries, load_dataset_entries_json


def build_entry() -> DatasetEntry:
    return DatasetEntry(
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        source_report_section=(
            "FreeBSD RPCSEC_GSS Remote Kernel Code Execution (CVE-2026-4747)"
        ),
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
        benchmark_checkout_commit="1b00fdc1f3cd^",
        affected_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        benchmark_file_paths=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
        affected_line_ranges=[],
        description="Kernel RPCSEC_GSS stack overflow in svc_rpc_gss_validate.",
        source_urls=[
            "https://www.freebsd.org/security/advisories/FreeBSD-SA-26:08.rpcsec_gss.asc"
        ],
        validation_status="confirmed",
        validation_notes="Confirmed by FreeBSD advisory in report citations.",
        code_snippet_ref=None,
        benchmark_checkout_strategy=(
            "Check out the parent of the fixing commit to approximate the vulnerable "
            "pre-patch snapshot for benchmarking."
        ),
        dataset_version="2026.04",
    )


def test_dataset_entry_round_trips_through_json() -> None:
    entry = build_entry()

    payload = entry.to_dict()
    restored = DatasetEntry.from_dict(payload)

    assert restored == entry


def test_export_dataset_entries_writes_expected_json(tmp_path: Path) -> None:
    entry = build_entry()
    json_path = tmp_path / "dataset.json"

    export_dataset_entries([entry], json_path=json_path)

    json_payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert json_payload[0]["entry_id"] == entry.entry_id
    assert json_payload[0]["fixed_commit"] == "1b00fdc1f3cd"
    assert json_payload[0]["clone_url"] == "https://github.com/freebsd/freebsd-src.git"
    assert json_payload[0]["benchmark_checkout_commit"] == "1b00fdc1f3cd^"

    assert json_payload[0]["repository_url"] == "https://github.com/freebsd/freebsd-src"
    assert json_payload[0]["local_checkout_path"] == "data/raw/repos/freebsd-src"
    assert json_payload[0]["validation_status"] == "confirmed"


def test_load_dataset_entries_json_restores_exported_entries(tmp_path: Path) -> None:
    entry = build_entry()
    json_path = tmp_path / "dataset.json"

    export_dataset_entries([entry], json_path=json_path)
    restored = load_dataset_entries_json(json_path)

    assert restored == [entry]
