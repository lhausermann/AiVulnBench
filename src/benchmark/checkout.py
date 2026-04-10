from __future__ import annotations

import subprocess
from pathlib import Path

from src.dataset.schema import DatasetEntry


def materialize_entry_checkout(project_root: Path, entry: DatasetEntry) -> list[str]:
    if not entry.clone_url or not entry.local_checkout_path:
        raise ValueError(f"{entry.entry_id} does not define clone metadata")
    if not entry.fixed_commit:
        raise ValueError(f"{entry.entry_id} does not define a fixed commit")
    if not entry.affected_files:
        raise ValueError(f"{entry.entry_id} does not define affected files")

    checkout_path = project_root / entry.local_checkout_path
    checkout_path.parent.mkdir(parents=True, exist_ok=True)

    if not checkout_path.exists():
        _run(["git", "clone", entry.clone_url, str(checkout_path)])

    checkout_expression = _vulnerable_checkout_expression(entry.fixed_commit)
    fetch_target = _fetch_target(checkout_expression)
    _run(
        [
            "git",
            "-C",
            str(checkout_path),
            "fetch",
            "origin",
            fetch_target,
        ]
    )
    checkout_revision = _resolve_checkout_revision(checkout_path, checkout_expression)
    for file_path in entry.affected_files:
        file_output = _run_output(
            [
                "git",
                "-C",
                str(checkout_path),
                "show",
                f"{checkout_revision}:{file_path}",
            ]
        )
        target_path = checkout_path / file_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(file_output, encoding="utf-8")

    return [str(checkout_path / file_path) for file_path in entry.affected_files]


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True, capture_output=True, text=True)


def _run_output(command: list[str]) -> str:
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return completed.stdout


def _fetch_target(commit_expr: str) -> str:
    if commit_expr.endswith("^"):
        return commit_expr[:-1]

    return commit_expr


def _vulnerable_checkout_expression(fixed_commit: str) -> str:
    return f"{fixed_commit}^"


def _resolve_checkout_revision(checkout_path: Path, commit_expr: str) -> str:
    if not commit_expr.endswith("^"):
        return commit_expr

    try:
        _run(
            [
                "git",
                "-C",
                str(checkout_path),
                "rev-parse",
                "--verify",
                commit_expr,
            ]
        )
        return commit_expr
    except subprocess.CalledProcessError:
        return commit_expr[:-1]
