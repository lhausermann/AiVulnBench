from __future__ import annotations

from pathlib import Path

from src.dataset.report import extract_source_registry_entries
from src.dataset.resolution import resolve_source_registry_entries

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = PROJECT_ROOT / "docs" / "REPORT.md"


def test_resolve_source_registry_entries_maps_known_repositories() -> None:
    entries = extract_source_registry_entries(REPORT_PATH.read_text(encoding="utf-8"))

    resolved_entries = resolve_source_registry_entries(entries)
    by_id = {entry.entry_id: entry for entry in resolved_entries}

    freebsd_entry = by_id["freebsd-rpcsec-gss-rce-cve-2026-4747"]
    assert freebsd_entry.repository_url == "https://github.com/freebsd/freebsd-src"
    assert freebsd_entry.repository_kind == "git"
    assert freebsd_entry.language == "C"
    assert freebsd_entry.fixed_commit == "1b00fdc1f3cd"
    assert freebsd_entry.validation_status == "unvalidated"

    firefox_entry = by_id["mozilla-firefox-wasm-jit-type-confusion-cve-2026-2796"]
    assert firefox_entry.repository_url == "https://github.com/mozilla/gecko-dev"
    assert firefox_entry.fixed_commit is None
    assert firefox_entry.affected_files == ["js/src/wasm/WasmInstance.cpp"]


def test_resolve_source_registry_entries_preserves_unresolved_provenance() -> None:
    entries = extract_source_registry_entries(REPORT_PATH.read_text(encoding="utf-8"))

    resolved_entries = resolve_source_registry_entries(entries)
    by_id = {entry.entry_id: entry for entry in resolved_entries}

    openbsd_entry = by_id["openbsd-tcp-sack-denial-of-service"]
    assert openbsd_entry.repository_url is None
    assert openbsd_entry.fixed_commit is None
    assert "errata 025" in openbsd_entry.validation_notes.lower()

    linux_entry = by_id["linux-kernel-race-conditions-and-memory-safe-vmm-escapes"]
    assert linux_entry.repository_url == "https://github.com/torvalds/linux"
    assert linux_entry.fixed_commit is None
    assert "sha-3 commitments" in linux_entry.validation_notes.lower()
