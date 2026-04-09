from __future__ import annotations

import re

from .curation import CURATED_SECTION_METADATA
from .models import SourceRegistryEntry, VulnerabilitySection

SECTION_HEADER_RE = re.compile(r"^### \*\*(?P<title>.+?)\*\*$", re.MULTILINE)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
FILE_RE = re.compile(r"\b(?:[A-Za-z0-9_-]+/)+(?:[A-Za-z0-9_.-]+)\b")
SOURCE_FILE_RE = re.compile(
    r"\b(?:[A-Za-z0-9_-]+/)+(?:[A-Za-z0-9_.-]+\.(?:c|cc|cpp|cxx|h|hpp|md))\b"
)
DESCRIPTION_RE = re.compile(r"\n\n(?P<paragraph>.+?)(?:\n\n#### |\Z)", re.DOTALL)


def _clean_markdown_text(value: str) -> str:
    return value.replace(r"\_", "_").replace(r"\-", "-").strip()


def parse_vulnerability_sections(report_text: str) -> list[VulnerabilitySection]:
    matches = list(SECTION_HEADER_RE.finditer(report_text))
    sections: list[VulnerabilitySection] = []

    for index, match in enumerate(matches):
        start = match.end()
        if index + 1 < len(matches):
            end = matches[index + 1].start()
        else:
            end = report_text.find(
                "## **Vulnerabilities in the Artificial Intelligence Supply Chain**",
                start,
            )
        if end == -1:
            end = len(report_text)

        title = _clean_markdown_text(match.group("title"))
        body = report_text[start:end].strip()
        sections.append(VulnerabilitySection(title=title, body=body))

    return sections


def _extract_description(section_body: str) -> str:
    match = DESCRIPTION_RE.search(f"\n\n{section_body}")
    if match is None:
        return section_body.splitlines()[0].strip()

    return " ".join(match.group("paragraph").split())


def _extract_affected_files(section: VulnerabilitySection) -> list[str]:
    curated = CURATED_SECTION_METADATA[section.title]
    discovered = [
        candidate
        for candidate in FILE_RE.findall(section.body)
        if SOURCE_FILE_RE.fullmatch(candidate) is not None
    ]
    combined = curated.affected_files + discovered

    unique_files: list[str] = []
    for path in combined:
        if path not in unique_files:
            unique_files.append(path)

    return unique_files


def extract_source_registry_entries(report_text: str) -> list[SourceRegistryEntry]:
    entries: list[SourceRegistryEntry] = []

    for section in parse_vulnerability_sections(report_text):
        curated = CURATED_SECTION_METADATA[section.title]
        cve_ids = list(
            dict.fromkeys(CVE_RE.findall(section.title + "\n" + section.body))
        )
        entries.append(
            SourceRegistryEntry(
                entry_id=curated.entry_id,
                source_report_section=section.title,
                product_name=curated.product_name,
                cve_ids=cve_ids,
                vuln_type=curated.vuln_type,
                description=_extract_description(section.body),
                affected_files=_extract_affected_files(section),
                source_urls=curated.source_urls,
                confidence=curated.confidence,
            )
        )

    return entries
