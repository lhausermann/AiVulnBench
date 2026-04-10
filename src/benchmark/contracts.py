from __future__ import annotations

from dataclasses import dataclass

from src.dataset.schema import DatasetEntry


@dataclass(frozen=True)
class PromptTemplate:
    template_id: str
    system_instructions: str
    prompt_version: str


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    entry_id: str
    prompt_template_id: str
    prompt_text: str
    input_files: list[str]
    expected_vuln_type: str
    expected_locations: list[str]
    scoring_mode: str


def build_benchmark_cases(
    entries: list[DatasetEntry], *, template: PromptTemplate
) -> list[BenchmarkCase]:
    ordered_entries = sorted(entries, key=lambda entry: entry.entry_id)
    return [
        BenchmarkCase(
            case_id=f"{entry.entry_id}:{template.template_id}",
            entry_id=entry.entry_id,
            prompt_template_id=template.template_id,
            prompt_text=_render_prompt(entry),
            input_files=list(entry.affected_files),
            expected_vuln_type=entry.vuln_type,
            expected_locations=_expected_locations(entry),
            scoring_mode="exact-location-or-overlap",
        )
        for entry in ordered_entries
    ]


def _render_prompt(entry: DatasetEntry) -> str:
    if entry.affected_files:
        target_file = entry.affected_files[0]
    else:
        target_file = "the provided file"
    return (
        f"Audit the provided {entry.product_name} source file "
        f"for a {entry.vuln_type}.\n"
        f"Focus on {target_file} and explain any security-relevant boundary violation "
        f"tied to untrusted input.\n"
        f"Context: {entry.description}"
    )


def _expected_locations(entry: DatasetEntry) -> list[str]:
    if entry.code_snippet_ref:
        return [entry.code_snippet_ref]

    return [
        f"{file_path}:{line_range}"
        for file_path, line_range in zip(
            entry.affected_files, entry.affected_line_ranges, strict=True
        )
    ]
