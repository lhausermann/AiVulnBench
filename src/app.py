"""Application entrypoint for the AIVulnBench project."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    """Run the application."""
    _ = argv if argv is not None else sys.argv[1:]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
