from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CuratedSectionMetadata:
    entry_id: str
    product_name: str
    vuln_type: str
    source_urls: list[str]
    confidence: str
    affected_files: list[str]


@dataclass(frozen=True)
class CuratedResolutionMetadata:
    repository_url: str | None
    repository_kind: str | None
    language: str | None
    cwe_ids: list[str]
    severity: str | None
    introduced_commit: str | None
    fixed_commit: str | None
    affected_line_ranges: list[str]
    code_snippet_ref: str | None
    resolution_notes: str


FREEBSD_SECTION = "FreeBSD RPCSEC_GSS Remote Kernel Code Execution (CVE-2026-4747)"
FIREFOX_SECTION = "Mozilla Firefox WebAssembly JIT Type Confusion (CVE-2026-2796)"
OPENBSD_SECTION = "OpenBSD TCP SACK Denial of Service"
FFMPEG_SECTION = "FFmpeg H.264 Codec Memory Corruption"
LINUX_SECTION = "Linux Kernel Race Conditions and Memory-Safe VMM Escapes"


CURATED_SECTION_METADATA: dict[str, CuratedSectionMetadata] = {
    FREEBSD_SECTION: CuratedSectionMetadata(
        entry_id="freebsd-rpcsec-gss-rce-cve-2026-4747",
        product_name="FreeBSD",
        vuln_type="stack-based buffer overflow",
        source_urls=[
            (
                "https://www.freebsd.org/security/advisories/"
                "FreeBSD-SA-26:08.rpcsec_gss.asc"
            ),
            (
                "https://github.com/califio/publications/blob/main/"
                "MADBugs/CVE-2026-4747/write-up.md"
            ),
        ],
        confidence="high",
        affected_files=["sys/rpc/rpcsec_gss/svc_rpcsec_gss.c"],
    ),
    FIREFOX_SECTION: CuratedSectionMetadata(
        entry_id="mozilla-firefox-wasm-jit-type-confusion-cve-2026-2796",
        product_name="Mozilla Firefox",
        vuln_type="type confusion",
        source_urls=[
            "https://nvd.nist.gov/vuln/detail/CVE-2026-2796",
            "https://red.anthropic.com/2026/exploit/",
        ],
        confidence="high",
        affected_files=["js/src/wasm/WasmInstance.cpp"],
    ),
    OPENBSD_SECTION: CuratedSectionMetadata(
        entry_id="openbsd-tcp-sack-denial-of-service",
        product_name="OpenBSD",
        vuln_type="integer overflow",
        source_urls=[
            "https://news.hada.io/topic?id=28130",
        ],
        confidence="medium",
        affected_files=["sys/netinet/tcp_input.c"],
    ),
    FFMPEG_SECTION: CuratedSectionMetadata(
        entry_id="ffmpeg-h264-codec-memory-corruption",
        product_name="FFmpeg",
        vuln_type="heap memory corruption",
        source_urls=[
            "https://red.anthropic.com/2026/mythos-preview/",
        ],
        confidence="medium",
        affected_files=[],
    ),
    LINUX_SECTION: CuratedSectionMetadata(
        entry_id="linux-kernel-race-conditions-and-memory-safe-vmm-escapes",
        product_name="Linux Kernel",
        vuln_type="race condition / memory corruption chain",
        source_urls=[
            "https://red.anthropic.com/2026/mythos-preview/",
        ],
        confidence="medium",
        affected_files=[],
    ),
}


CURATED_RESOLUTION_METADATA: dict[str, CuratedResolutionMetadata] = {
    FREEBSD_SECTION: CuratedResolutionMetadata(
        repository_url="https://github.com/freebsd/freebsd-src",
        repository_kind="git",
        language="C",
        cwe_ids=["CWE-121"],
        severity="critical",
        introduced_commit=None,
        fixed_commit="1b00fdc1f3cd",
        affected_line_ranges=[],
        code_snippet_ref="sys/rpc/rpcsec_gss/svc_rpcsec_gss.c",
        resolution_notes=(
            "Resolved to the FreeBSD source repository. The report includes a "
            "stable/15 patch commit and additional branch-specific fixes."
        ),
    ),
    FIREFOX_SECTION: CuratedResolutionMetadata(
        repository_url="https://github.com/mozilla/gecko-dev",
        repository_kind="git",
        language="C++",
        cwe_ids=["CWE-843"],
        severity="high",
        introduced_commit=None,
        fixed_commit=None,
        affected_line_ranges=[],
        code_snippet_ref="js/src/wasm/WasmInstance.cpp",
        resolution_notes=(
            "Resolved to gecko-dev and the WasmInstance.cpp path, but the "
            "report only gives Bugzilla references and version boundaries."
        ),
    ),
    OPENBSD_SECTION: CuratedResolutionMetadata(
        repository_url=None,
        repository_kind=None,
        language="C",
        cwe_ids=["CWE-190"],
        severity="high",
        introduced_commit=None,
        fixed_commit=None,
        affected_line_ranges=[],
        code_snippet_ref="sys/netinet/tcp_input.c",
        resolution_notes=(
            "The report references OpenBSD 7.8 errata 025 and a patch "
            "signature, but does not provide a concrete public Git commit."
        ),
    ),
    FFMPEG_SECTION: CuratedResolutionMetadata(
        repository_url="https://github.com/FFmpeg/FFmpeg",
        repository_kind="git",
        language="C",
        cwe_ids=["CWE-787"],
        severity="high",
        introduced_commit=None,
        fixed_commit=None,
        affected_line_ranges=[],
        code_snippet_ref=None,
        resolution_notes=(
            "Resolved to the FFmpeg repository and the 8.0/8.1 version "
            "boundary only; the report does not identify a fixing commit."
        ),
    ),
    LINUX_SECTION: CuratedResolutionMetadata(
        repository_url="https://github.com/torvalds/linux",
        repository_kind="git",
        language="C",
        cwe_ids=["CWE-362"],
        severity="high",
        introduced_commit=None,
        fixed_commit=None,
        affected_line_ranges=[],
        code_snippet_ref=None,
        resolution_notes=(
            "Resolved to the Linux kernel repository at the product level. "
            "The report provides SHA-3 commitments for unpatched findings "
            "rather than public commit hashes."
        ),
    ),
}
