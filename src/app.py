"""Application entrypoint for the AIVulnBench project."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from src.dataset.build import build_dataset_artifacts
from src.dataset.report import extract_source_registry_entries

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    """Run the application."""
    args = argv if argv is not None else sys.argv[1:]

    if not args:
        return 0

    if args == ["build-source-registry"]:
        report_path = PROJECT_ROOT / "docs" / "REPORT.md"
        entries = extract_source_registry_entries(
            report_path.read_text(encoding="utf-8")
        )
        output_path = PROJECT_ROOT / "data" / "normalized" / "source_registry.json"
        output_path.write_text(
            json.dumps([entry.to_dict() for entry in entries], indent=2),
            encoding="utf-8",
        )
        return 0

    if args == ["build-dataset"]:
        build_dataset_artifacts(PROJECT_ROOT)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
