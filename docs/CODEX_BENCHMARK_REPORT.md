# Codex Benchmark Report

## Methodology

The repository now contains a deterministic benchmark workflow for evaluating
Codex-style vulnerability auditing against the validated dataset built from
`docs/REPORT.md`. The workflow is structured as:

1. Convert validated dataset entries into benchmark cases with stable case IDs,
   prompt template IDs, expected vulnerable locations, and reproducible prompt
   text.
2. Execute those cases through a provider adapter that preserves raw output,
   provider/model metadata, normalized findings, and failure modes.
3. Score the normalized findings against ground truth using exact-match,
   overlap-based partial-match, false-positive, and false-negative semantics.
4. Aggregate the resulting run records by provider, vulnerability class, and
   language.

## Findings

The codebase now supports end-to-end benchmark execution, analysis, and report
generation for Codex-style runs. The implemented contracts are exercised by unit
tests covering:

- deterministic benchmark-case generation
- provider-neutral harness behavior
- reproducible result capture with resume/retry semantics
- analysis summaries by provider, vulnerability class, and language
- Markdown report generation

No live Codex run artifacts are committed in this checkout, so this report does
not claim empirical Codex detection rates yet. The current state should be read
as benchmark infrastructure completion plus framework-level validation rather
than a completed model-performance study.

## Limitations

- Live provider execution still depends on an external Codex transport and any
  required credentials or runtime access.
- The repository currently validates the benchmark stack with deterministic test
  fixtures rather than with committed real-model outputs.
- Comparative claims versus other providers should not be made until actual run
  artifacts are generated and analyzed through the same workflow.

## Reproducibility

- Run `make clean`, `make test`, and `make lint` to validate the implemented
  benchmark stack.
- Use `src/benchmark/codex/contract.py`, `src/benchmark/harness.py`, and
  `src/benchmark/runner.py` as the operational path for generating cases and
  capturing run records.
- Use `src/benchmark/analysis.py` and `src/benchmark/reporting.py` to summarize
  stored run records and render future benchmark findings into Markdown.
