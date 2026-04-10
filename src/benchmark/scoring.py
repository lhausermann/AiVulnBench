from __future__ import annotations

from dataclasses import dataclass

from src.benchmark.contracts import BenchmarkCase


@dataclass(frozen=True)
class Finding:
    file_path: str
    line_range: str
    vuln_type: str
    explanation: str


@dataclass(frozen=True)
class ScoreResult:
    outcome: str
    matched: bool
    partial: bool
    false_positive: bool
    false_negative: bool
    matched_locations: list[str]


def score_case_findings(case: BenchmarkCase, findings: list[Finding]) -> ScoreResult:
    if not findings:
        return ScoreResult(
            outcome="false_negative",
            matched=False,
            partial=False,
            false_positive=False,
            false_negative=True,
            matched_locations=[],
        )

    for finding in findings:
        if finding.vuln_type != case.expected_vuln_type:
            continue

        matched_location = _match_location(
            finding, expected_locations=case.expected_locations
        )
        if matched_location is None:
            continue

        if _is_exact_location(finding, matched_location):
            return ScoreResult(
                outcome="true_positive",
                matched=True,
                partial=False,
                false_positive=False,
                false_negative=False,
                matched_locations=[matched_location],
            )

        return ScoreResult(
            outcome="partial_match",
            matched=True,
            partial=True,
            false_positive=False,
            false_negative=False,
            matched_locations=[f"{finding.file_path}:{finding.line_range}"],
        )

    return ScoreResult(
        outcome="false_positive",
        matched=False,
        partial=False,
        false_positive=True,
        false_negative=False,
        matched_locations=[],
    )


def _match_location(finding: Finding, *, expected_locations: list[str]) -> str | None:
    for expected_location in expected_locations:
        if ":" not in expected_location:
            if finding.file_path == expected_location:
                return expected_location
            continue

        expected_file, expected_range = _split_location(expected_location)
        if finding.file_path != expected_file:
            continue
        if finding.line_range == expected_range:
            return expected_location
        if _ranges_overlap(finding.line_range, expected_range):
            return expected_location

    return None


def _is_exact_location(finding: Finding, expected_location: str) -> bool:
    if ":" not in expected_location:
        return finding.file_path == expected_location

    expected_file, expected_range = _split_location(expected_location)
    return finding.file_path == expected_file and finding.line_range == expected_range


def _split_location(location: str) -> tuple[str, str]:
    file_path, line_range = location.rsplit(":", maxsplit=1)
    return file_path, line_range


def _ranges_overlap(left: str, right: str) -> bool:
    left_start, left_end = _parse_line_range(left)
    right_start, right_end = _parse_line_range(right)
    return max(left_start, right_start) <= min(left_end, right_end)


def _parse_line_range(line_range: str) -> tuple[int, int]:
    if "-" not in line_range:
        line_number = int(line_range)
        return line_number, line_number

    start_text, end_text = line_range.split("-", maxsplit=1)
    return int(start_text), int(end_text)
