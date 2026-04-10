from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_bootstrap_layout_exists() -> None:
    expected_paths = [
        PROJECT_ROOT / "src",
        PROJECT_ROOT / "tests" / "unit",
        PROJECT_ROOT / "data" / "raw",
        PROJECT_ROOT / "data" / "validated",
        PROJECT_ROOT / "docs" / "IMPLEMENTATION_SUMMARY.md",
        PROJECT_ROOT / "Makefile",
        PROJECT_ROOT / "requirements.txt",
    ]

    missing = [
        str(path.relative_to(PROJECT_ROOT))
        for path in expected_paths
        if not path.exists()
    ]

    assert missing == []


def test_makefile_exposes_required_targets() -> None:
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")

    for target in [
        "install:",
        "init-tasks:",
        "test:",
        "lint:",
        "format:",
        "run:",
        "verify-beads:",
    ]:
        assert target in makefile


def test_application_entrypoint_is_importable() -> None:
    from src.app import main

    assert main() == 0
