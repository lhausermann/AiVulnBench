from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class VulnerabilitySection:
    """A single vulnerability-focused section extracted from the report."""

    title: str
    body: str


@dataclass(frozen=True)
class SourceRegistryEntry:
    """Normalized source-registry entry extracted from the report."""

    entry_id: str
    source_report_section: str
    product_name: str
    cve_ids: list[str]
    vuln_type: str
    description: str
    affected_files: list[str]
    source_urls: list[str]
    confidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
