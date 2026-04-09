from __future__ import annotations

import csv
import json
from pathlib import Path

from .schema import DatasetEntry

FIELDNAMES = [
    "entry_id",
    "source_report_section",
    "product_name",
    "repository_url",
    "repository_kind",
    "language",
    "cve_id",
    "cwe_ids",
    "vuln_type",
    "severity",
    "introduced_commit",
    "fixed_commit",
    "affected_files",
    "affected_line_ranges",
    "description",
    "source_urls",
    "validation_status",
    "validation_notes",
    "code_snippet_ref",
    "dataset_version",
]


def export_dataset_entries(
    entries: list[DatasetEntry], *, json_path: Path, csv_path: Path
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(
        json.dumps([entry.to_dict() for entry in entries], indent=2),
        encoding="utf-8",
    )

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for entry in entries:
            row = entry.to_dict()
            writer.writerow(_encode_csv_row(row))


def load_dataset_entries_json(json_path: Path) -> list[DatasetEntry]:
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    return [DatasetEntry.from_dict(entry) for entry in payload]


def _encode_csv_row(row: dict[str, object]) -> dict[str, str]:
    encoded: dict[str, str] = {}
    for field in FIELDNAMES:
        value = row[field]
        if isinstance(value, list):
            encoded[field] = json.dumps(value)
        elif value is None:
            encoded[field] = ""
        else:
            encoded[field] = str(value)

    return encoded
