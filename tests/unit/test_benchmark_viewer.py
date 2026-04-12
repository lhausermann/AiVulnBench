from __future__ import annotations

import json
from pathlib import Path

from src.benchmark.viewer import render_result_view


def test_render_result_view_writes_html_dashboard(tmp_path: Path) -> None:
    result_root = tmp_path / "data" / "results" / "benchmark_run_hard_s260412140000"
    result_root.mkdir(parents=True)
    (result_root / "summary.json").write_text(
        json.dumps(
            {
                "seed": "s260412140000",
                "prompt_mode": "hard",
                "record_count": 1,
                "materialized_files": {"entry-a": ["data/raw/repos/a/src/a.c"]},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (result_root / "run_records.json").write_text(
        json.dumps(
            [
                {
                    "case_id": "entry-a:full-v1",
                    "status": "completed",
                    "duration_ms": 1234,
                    "model_version": "gpt-5-codex-cli-full-v1-hard-2026-04-10",
                    "vuln_type": "overflow",
                    "raw_output_ref": "/tmp/raw.json",
                    "normalized_findings": [{"file_path": "src/a.c"}],
                    "score": {
                        "outcome": "true_positive",
                        "judge_rationale": (
                            "Matches expected file and vulnerability type."
                        ),
                    },
                }
            ],
            indent=2,
        ),
        encoding="utf-8",
    )
    (result_root / "skipped_entries.json").write_text(
        json.dumps(
            [{"entry_id": "entry-b", "reason": "Missing fixed_commit"}],
            indent=2,
        ),
        encoding="utf-8",
    )
    (result_root / "executed_entries.json").write_text(
        json.dumps(
            [{"entry_id": "entry-a", "product_name": "Fixture A"}],
            indent=2,
        ),
        encoding="utf-8",
    )

    html_path = render_result_view(result_root)
    html = html_path.read_text(encoding="utf-8")

    assert html_path == result_root / "index.html"
    assert "AIVulnBench result viewer" in html
    assert "Benchmark Result Viewer" in html
    assert "entry-a:full-v1" in html
    assert "Matches expected file and vulnerability type." in html
    assert "Missing fixed_commit" in html
