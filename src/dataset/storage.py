from __future__ import annotations

import json
from pathlib import Path

from .schema import DatasetEntry


def export_dataset_entries(entries: list[DatasetEntry], *, json_path: Path) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(
        json.dumps([entry.to_dict() for entry in entries], indent=2),
        encoding="utf-8",
    )


def load_dataset_entries_json(json_path: Path) -> list[DatasetEntry]:
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    return [DatasetEntry.from_dict(entry) for entry in payload]
