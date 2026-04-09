from __future__ import annotations

from .curation import CURATED_RESOLUTION_METADATA
from .models import SourceRegistryEntry
from .schema import DatasetEntry

DATASET_VERSION = "2026.04"


def resolve_source_registry_entries(
    entries: list[SourceRegistryEntry],
) -> list[DatasetEntry]:
    resolved_entries: list[DatasetEntry] = []

    for entry in entries:
        metadata = CURATED_RESOLUTION_METADATA[entry.source_report_section]
        cve_id = entry.cve_ids[0] if entry.cve_ids else None
        resolved_entries.append(
            DatasetEntry(
                entry_id=entry.entry_id,
                source_report_section=entry.source_report_section,
                product_name=entry.product_name,
                repository_url=metadata.repository_url,
                repository_kind=metadata.repository_kind,
                language=metadata.language,
                cve_id=cve_id,
                cwe_ids=metadata.cwe_ids,
                vuln_type=entry.vuln_type,
                severity=metadata.severity,
                introduced_commit=metadata.introduced_commit,
                fixed_commit=metadata.fixed_commit,
                affected_files=entry.affected_files,
                affected_line_ranges=metadata.affected_line_ranges,
                description=entry.description,
                source_urls=entry.source_urls,
                validation_status="unvalidated",
                validation_notes=metadata.resolution_notes,
                code_snippet_ref=metadata.code_snippet_ref,
                dataset_version=DATASET_VERSION,
            )
        )

    return resolved_entries
