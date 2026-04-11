# Implementation Summary

## Bootstrap

The repository uses a minimal Python scaffold with:

- `src/` for application code
- `tests/unit/` for unit tests
- `data/raw/` for persistent repo checkouts
- `data/vulnerability_dataset.json` for the checked-in dataset
- `Makefile` targets for install, test, lint, format, run, init-tasks, and verify-beads

This document is the central place for implementation notes and will be updated
alongside code changes.

## Dataset Model

The dataset layer is intentionally small and runner-focused:

- `schema.py` defines the checked-in benchmark dataset shape
- `storage.py` loads and writes JSON dataset artifacts used by the runner

The repository no longer treats extraction, normalization, or validation as
runtime responsibilities. The checked-in dataset JSON at
`data/vulnerability_dataset.json` serves as the source of truth for benchmark
execution.

The dataset schema carries only runner-facing repository metadata:

- `clone_url` for the canonical clone endpoint
- `local_checkout_path` for the expected workspace-relative checkout location
- `fixed_commit` for entries where the runner can derive a vulnerable pre-fix
  checkout using the parent revision
- `affected_files` for the repo-relative files that should be materialized

## Codex Benchmark Contract

The first benchmark layer now lives in `src/benchmark/` and is deliberately
small:

- `contracts.py` defines prompt-template metadata and deterministic
  benchmark-case generation from dataset entries
- `scoring.py` defines a normalized finding shape plus the scoring contract for
  exact matches, overlapping-location partial matches, false positives, and
  false negatives

The current Codex prompt contract uses stable case IDs in the form
`<entry_id>:<prompt_template_id>`, carries forward the expected vulnerable file
locations from the dataset schema, and avoids embedding version metadata into
the prompt body so prompt text stays reproducible for a fixed template version.

## Harnesses And Runner

The benchmark execution layer now includes:

- `harness.py` for provider-neutral preparation, execution, normalization, and
  metadata capture
- `runner.py` for reproducible run IDs, raw-output persistence, scored result
  records, and resume/retry semantics

The first concrete adapters are `CodexHarnessAdapter` and
`GeminiCliHarnessAdapter`. Both consume the same benchmark-case contract and
normalize provider output into the shared finding shape used by scoring.

Codex CLI sample runs now write reviewer-facing artifacts under
`data/results/<run>/codex_cli/`:

- `prompts/<case>.txt` for the exact prompt sent to Codex
- `logs/<case>.log` for major execution steps, paths, return code, and duration
- `stdout/<case>.log` and `stderr/<case>.log` for raw Codex CLI process logs
- `pretty/<case>.json` for the parsed result, findings, failure mode, duration,
  and captured stdout/stderr

Sample mode also supports `python -m src.app benchmark sample --hard`, which
uses the same checkout and artifact flow but sends a sparse prompt containing
only the materialized files and a generic vulnerability-audit request. Hard mode
intentionally omits the case ID, vulnerability type hint, benchmark prompt, and
report-derived context from the prompt sent to Codex.

## Analysis And Reporting

The benchmark analysis/reporting layer now includes:

- `analysis.py` for provider-level summary metrics and slices by vulnerability
  class and language
- `reporting.py` for rendering a reproducible Codex benchmark report in
  Markdown

The current repository includes the reporting workflow and a baseline report
template, but it does not claim that a live Codex benchmark run has already
been executed in this checkout. Any published findings should distinguish dry
run/framework validation from real provider-evaluation results.
