from __future__ import annotations

import json
from pathlib import Path

from src.app import main
from src.dataset.report import extract_source_registry_entries
from src.dataset.resolution import resolve_source_registry_entries
from src.dataset.validation import validate_dataset_entries

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = PROJECT_ROOT / "docs" / "REPORT.md"


def test_validate_dataset_entries_assigns_expected_states() -> None:
    source_entries = extract_source_registry_entries(
        REPORT_PATH.read_text(encoding="utf-8")
    )
    resolved_entries = resolve_source_registry_entries(source_entries)

    validated_entries = validate_dataset_entries(resolved_entries)
    by_id = {entry.entry_id: entry for entry in validated_entries}

    assert by_id["freebsd-rpcsec-gss-rce-cve-2026-4747"].validation_status == "confirmed"
    assert (
        by_id["mozilla-firefox-wasm-jit-type-confusion-cve-2026-2796"].validation_status
        == "confirmed"
    )
    assert by_id["openbsd-tcp-sack-denial-of-service"].validation_status == (
        "partially_confirmed"
    )
    assert by_id["ffmpeg-h264-codec-memory-corruption"].validation_status == (
        "partially_confirmed"
    )
    assert (
        by_id[
            "linux-kernel-race-conditions-and-memory-safe-vmm-escapes"
        ].validation_status
        == "unresolved"
    )


def test_app_build_dataset_writes_validated_artifacts() -> None:
    assert main(["build-dataset"]) == 0

    json_path = PROJECT_ROOT / "data" / "validated" / "vulnerability_dataset.json"
    csv_path = PROJECT_ROOT / "data" / "validated" / "vulnerability_dataset.csv"

    assert json_path.exists()
    assert csv_path.exists()

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert len(payload) == 5
    assert payload[0]["validation_status"] in {
        "confirmed",
        "partially_confirmed",
        "unresolved",
    }
