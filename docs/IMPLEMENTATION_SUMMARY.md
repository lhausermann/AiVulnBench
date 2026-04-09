# Implementation Summary

## Bootstrap

The repository uses a minimal Python scaffold with:

- `src/` for application code
- `tests/unit/` for unit tests
- `data/raw/`, `data/normalized/`, and `data/validated/` for dataset stages
- `Makefile` targets for install, test, lint, format, run, init-tasks, and verify-beads

This document is the central place for implementation notes and will be updated
alongside code changes.

## Dataset Extraction

The dataset logic now lives in `src/dataset/` and currently includes:

- `models.py` for normalized report-section and source-registry dataclasses
- `report.py` for parsing vulnerability sections from `docs/REPORT.md`
- `curation.py` for deterministic metadata needed to normalize the five report
  findings into a stable source registry

The extraction stage preserves unresolved entries rather than dropping them.
OpenBSD, FFmpeg, and Linux kernel findings remain part of the registry even when
they do not have a single public CVE or a fully resolved repository state.

## Resolution Policy

Repository and commit resolution are intentionally evidence-bound:

- FreeBSD is resolved to `freebsd/freebsd-src` with a concrete stable/15 fix
  commit from the report.
- Firefox is resolved to `mozilla/gecko-dev` and the affected file path, but
  patch provenance remains version/Bugzilla-based rather than commit-based.
- OpenBSD is preserved with unresolved repository and commit coordinates because
  the report references errata material rather than a concrete public Git commit.
- FFmpeg and Linux kernel are resolved at the repository level when the report
  clearly identifies the upstream project, while unresolved commit provenance is
  carried forward in notes.

## Validation And Artifacts

Validation is currently deterministic and report-driven:

- `confirmed` is used when the report cites a concrete public advisory or NVD
  reference tied to the finding.
- `partially_confirmed` is used when the report provides strong product/version
  or errata evidence without a complete public commit trail.
- `unresolved` is used when the report references undisclosed findings or
  commitments without a public patch/advisory.

`python -m src.app build-dataset` now emits:

- `data/normalized/source_registry.json`
- `data/normalized/resolved_dataset.json`
- `data/normalized/resolved_dataset.csv`
- `data/validated/vulnerability_dataset.json`
- `data/validated/vulnerability_dataset.csv`
