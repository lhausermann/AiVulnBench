from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class DatasetEntry:
    entry_id: str
    source_report_section: str
    product_name: str
    repository_url: str | None
    repository_kind: str | None
    language: str | None
    cve_id: str | None
    cwe_ids: list[str]
    vuln_type: str
    severity: str | None
    introduced_commit: str | None
    fixed_commit: str | None
    affected_files: list[str]
    affected_line_ranges: list[str]
    description: str
    source_urls: list[str]
    validation_status: str
    validation_notes: str
    code_snippet_ref: str | None
    dataset_version: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "DatasetEntry":
        return cls(
            entry_id=str(payload["entry_id"]),
            source_report_section=str(payload["source_report_section"]),
            product_name=str(payload["product_name"]),
            repository_url=_string_or_none(payload["repository_url"]),
            repository_kind=_string_or_none(payload["repository_kind"]),
            language=_string_or_none(payload["language"]),
            cve_id=_string_or_none(payload["cve_id"]),
            cwe_ids=[str(item) for item in payload["cwe_ids"]],
            vuln_type=str(payload["vuln_type"]),
            severity=_string_or_none(payload["severity"]),
            introduced_commit=_string_or_none(payload["introduced_commit"]),
            fixed_commit=_string_or_none(payload["fixed_commit"]),
            affected_files=[str(item) for item in payload["affected_files"]],
            affected_line_ranges=[str(item) for item in payload["affected_line_ranges"]],
            description=str(payload["description"]),
            source_urls=[str(item) for item in payload["source_urls"]],
            validation_status=str(payload["validation_status"]),
            validation_notes=str(payload["validation_notes"]),
            code_snippet_ref=_string_or_none(payload["code_snippet_ref"]),
            dataset_version=str(payload["dataset_version"]),
        )


def _string_or_none(value: Any) -> str | None:
    if value is None or value == "":
        return None

    return str(value)
