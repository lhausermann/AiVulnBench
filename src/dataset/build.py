from __future__ import annotations

import json
from pathlib import Path

from .report import extract_source_registry_entries
from .resolution import resolve_source_registry_entries
from .storage import export_dataset_entries
from .validation import validate_dataset_entries


def build_dataset_artifacts(project_root: Path) -> None:
    report_path = project_root / "docs" / "REPORT.md"
    report_text = report_path.read_text(encoding="utf-8")

    source_entries = extract_source_registry_entries(report_text)
    resolved_entries = resolve_source_registry_entries(source_entries)
    validated_entries = validate_dataset_entries(resolved_entries)

    normalized_dir = project_root / "data" / "normalized"
    validated_dir = project_root / "data" / "validated"

    normalized_dir.mkdir(parents=True, exist_ok=True)
    validated_dir.mkdir(parents=True, exist_ok=True)

    (normalized_dir / "source_registry.json").write_text(
        json.dumps([entry.to_dict() for entry in source_entries], indent=2),
        encoding="utf-8",
    )
    export_dataset_entries(
        resolved_entries,
        json_path=normalized_dir / "resolved_dataset.json",
        csv_path=normalized_dir / "resolved_dataset.csv",
    )
    export_dataset_entries(
        validated_entries,
        json_path=validated_dir / "vulnerability_dataset.json",
        csv_path=validated_dir / "vulnerability_dataset.csv",
    )
