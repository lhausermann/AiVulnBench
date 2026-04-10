from __future__ import annotations

from collections import defaultdict

from src.benchmark.runner import RunRecord
from src.dataset.schema import DatasetEntry


def summarize_run_records(
    records: list[RunRecord], *, entries_by_id: dict[str, DatasetEntry]
) -> dict[str, object]:
    provider_buckets: dict[str, dict[str, float]] = {}
    by_vuln_type: dict[str, dict[str, int]] = defaultdict(_outcome_counter)
    by_language: dict[str, dict[str, int]] = defaultdict(_outcome_counter)

    grouped: dict[str, list[RunRecord]] = defaultdict(list)
    for record in records:
        grouped[record.provider].append(record)

        entry_id = record.case_id.split(":", maxsplit=1)[0]
        entry = entries_by_id[entry_id]
        outcome = str(record.score["outcome"])
        by_vuln_type[entry.vuln_type][outcome] += 1
        language = entry.language or "unknown"
        by_language[language][outcome] += 1

    for provider, provider_records in grouped.items():
        completed = [
            record for record in provider_records if record.status == "completed"
        ]
        total = len(completed)
        if total == 0:
            provider_buckets[provider] = {
                "completed_runs": 0,
                "detection_rate": 0.0,
                "exact_match_rate": 0.0,
                "partial_match_rate": 0.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
            }
            continue

        provider_buckets[provider] = {
            "completed_runs": total,
            "detection_rate": _rate(completed, {"true_positive", "partial_match"}),
            "exact_match_rate": _rate(completed, {"true_positive"}),
            "partial_match_rate": _rate(completed, {"partial_match"}),
            "false_positive_rate": _rate(completed, {"false_positive"}),
            "false_negative_rate": _rate(completed, {"false_negative"}),
        }

    return {
        "providers": provider_buckets,
        "by_vuln_type": dict(by_vuln_type),
        "by_language": dict(by_language),
    }


def _outcome_counter() -> dict[str, int]:
    return {
        "true_positive": 0,
        "partial_match": 0,
        "false_positive": 0,
        "false_negative": 0,
    }


def _rate(records: list[RunRecord], matching_outcomes: set[str]) -> float:
    total = len(records)
    if total == 0:
        return 0.0
    matched = sum(
        1 for record in records if record.score["outcome"] in matching_outcomes
    )
    return matched / total
