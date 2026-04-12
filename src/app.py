"""Application entrypoint for the AIVulnBench project."""

from __future__ import annotations

import sys
from pathlib import Path

from src.benchmark.sample import run_full_benchmark, run_sample_benchmark
from src.benchmark.viewer import render_result_view

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    """Run the application."""
    args = argv if argv is not None else sys.argv[1:]

    if args == ["benchmark", "sample"]:
        run_sample_benchmark(PROJECT_ROOT)
        return 0
    if args == ["benchmark", "sample", "--hard"]:
        run_sample_benchmark(PROJECT_ROOT, prompt_mode="hard")
        return 0
    if args == ["benchmark", "run"]:
        run_full_benchmark(PROJECT_ROOT)
        return 0
    if args == ["benchmark", "run", "--hard"]:
        run_full_benchmark(PROJECT_ROOT, prompt_mode="hard")
        return 0
    if len(args) == 2 and args[0] == "view":
        target_path = Path(args[1])
        if not target_path.is_absolute():
            target_path = (PROJECT_ROOT / target_path).resolve()
        html_path = render_result_view(target_path)
        print(html_path)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
