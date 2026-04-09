from __future__ import annotations

from pathlib import Path

from src.dataset.report import (
    extract_source_registry_entries,
    parse_vulnerability_sections,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPORT_PATH = PROJECT_ROOT / "docs" / "REPORT.md"


def test_parse_vulnerability_sections_finds_report_sections() -> None:
    report_text = REPORT_PATH.read_text(encoding="utf-8")

    sections = parse_vulnerability_sections(report_text)

    assert [section.title for section in sections] == [
        "FreeBSD RPCSEC_GSS Remote Kernel Code Execution (CVE-2026-4747)",
        "Mozilla Firefox WebAssembly JIT Type Confusion (CVE-2026-2796)",
        "OpenBSD TCP SACK Denial of Service",
        "FFmpeg H.264 Codec Memory Corruption",
        "Linux Kernel Race Conditions and Memory-Safe VMM Escapes",
    ]


def test_extract_source_registry_entries_normalizes_known_fields() -> None:
    report_text = REPORT_PATH.read_text(encoding="utf-8")

    entries = extract_source_registry_entries(report_text)

    assert len(entries) == 5

    freebsd_entry = entries[0]
    assert freebsd_entry.entry_id == "freebsd-rpcsec-gss-rce-cve-2026-4747"
    assert freebsd_entry.product_name == "FreeBSD"
    assert freebsd_entry.cve_ids == ["CVE-2026-4747"]
    assert freebsd_entry.vuln_type == "stack-based buffer overflow"
    assert freebsd_entry.affected_files == [
        "sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
    ]
    assert freebsd_entry.source_urls
    assert freebsd_entry.confidence == "high"

    firefox_entry = entries[1]
    assert firefox_entry.product_name == "Mozilla Firefox"
    assert firefox_entry.cve_ids == [
        "CVE-2026-2796",
        "CVE-2026-2797",
        "CVE-2026-2765",
        "CVE-2026-2766",
    ]
    assert "js/src/wasm/WasmInstance.cpp" in firefox_entry.affected_files


def test_extract_source_registry_entries_preserves_unresolved_items() -> None:
    report_text = REPORT_PATH.read_text(encoding="utf-8")

    entries = extract_source_registry_entries(report_text)
    by_product = {entry.product_name: entry for entry in entries}

    openbsd_entry = by_product["OpenBSD"]
    assert openbsd_entry.cve_ids == []
    assert openbsd_entry.confidence == "medium"
    assert openbsd_entry.affected_files == ["sys/netinet/tcp_input.c"]

    ffmpeg_entry = by_product["FFmpeg"]
    assert ffmpeg_entry.cve_ids == []
    assert ffmpeg_entry.vuln_type == "heap memory corruption"

    linux_entry = by_product["Linux Kernel"]
    assert linux_entry.cve_ids == []
    assert linux_entry.vuln_type == "race condition / memory corruption chain"
