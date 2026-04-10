"""Application entrypoint for the AIVulnBench project."""

from __future__ import annotations

import sys
from pathlib import Path

from src.benchmark.sample import run_sample_benchmark

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    """Run the application."""
    args = argv if argv is not None else sys.argv[1:]

    if args == ["benchmark", "sample"]:
        run_sample_benchmark(PROJECT_ROOT)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
