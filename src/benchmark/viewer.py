from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any


def render_result_view(result_root: Path) -> Path:
    summary = _load_optional_json(result_root / "summary.json")
    records = _load_optional_json(result_root / "run_records.json")
    skipped_entries = _load_optional_json(result_root / "skipped_entries.json")
    selected_entries = _load_selected_entries(result_root)

    html_path = result_root / "index.html"
    html_path.write_text(
        _build_html(
            result_root=result_root,
            summary=summary,
            records=records,
            skipped_entries=skipped_entries,
            selected_entries=selected_entries,
        ),
        encoding="utf-8",
    )
    return html_path


def _load_selected_entries(result_root: Path) -> list[dict[str, Any]] | None:
    for file_name in ("executed_entries.json", "sampled_entries.json"):
        payload = _load_optional_json(result_root / file_name)
        if isinstance(payload, list):
            return payload

    return None


def _load_optional_json(path: Path) -> Any:
    if not path.exists():
        return None

    return json.loads(path.read_text(encoding="utf-8"))


def _build_html(
    *,
    result_root: Path,
    summary: dict[str, Any] | None,
    records: list[dict[str, Any]] | None,
    skipped_entries: list[dict[str, Any]] | None,
    selected_entries: list[dict[str, Any]] | None,
) -> str:
    case_sections = (
        "\n".join(_render_case_card(record) for record in (records or []))
        or "<p>No run records were found.</p>"
    )
    skipped_section = _render_json_section(
        title="Skipped Entries",
        payload=skipped_entries,
        empty_message="No skipped entries were recorded.",
    )
    selected_section = _render_json_section(
        title="Dataset Entries",
        payload=selected_entries,
        empty_message="No executed or sampled entries were recorded.",
    )
    summary_section = _render_json_section(
        title="Run Summary",
        payload=summary,
        empty_message="No summary.json file was found.",
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AIVulnBench result viewer</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f3eb;
      --panel: #fffdf7;
      --ink: #202124;
      --muted: #5e6472;
      --accent: #0d6b6b;
      --border: #d8d2c4;
      --ok: #1c7c54;
      --warn: #9b6b00;
      --bad: #a0342c;
      --shadow: 0 12px 30px rgba(32, 33, 36, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
      background:
        radial-gradient(circle at top left, rgba(13, 107, 107, 0.12), transparent 32%),
        linear-gradient(180deg, #fcfaf4 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 20px 80px;
    }}
    .hero, .panel, .case-card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: var(--shadow);
    }}
    .hero {{
      padding: 24px;
      margin-bottom: 24px;
    }}
    .hero h1 {{
      margin: 0 0 8px;
      font-size: 2rem;
    }}
    .hero p {{
      margin: 0;
      color: var(--muted);
      overflow-wrap: anywhere;
    }}
    .grid {{
      display: grid;
      gap: 20px;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      margin-bottom: 24px;
    }}
    .panel {{
      padding: 18px;
    }}
    h2 {{
      margin-top: 0;
      font-size: 1.2rem;
    }}
    .case-list {{
      display: grid;
      gap: 18px;
    }}
    .case-card {{
      padding: 18px;
    }}
    .case-card h3 {{
      margin: 0 0 8px;
      font-size: 1.05rem;
      overflow-wrap: anywhere;
    }}
    .meta {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }}
    .pill {{
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 0.9rem;
      border: 1px solid var(--border);
      background: #f7f2e7;
    }}
    .pill.ok {{ color: var(--ok); border-color: rgba(28, 124, 84, 0.25); }}
    .pill.bad {{ color: var(--bad); border-color: rgba(160, 52, 44, 0.25); }}
    .pill.warn {{ color: var(--warn); border-color: rgba(155, 107, 0, 0.25); }}
    dl {{
      display: grid;
      grid-template-columns: 160px 1fr;
      gap: 6px 14px;
      margin: 0 0 14px;
    }}
    dt {{
      font-weight: 700;
      color: var(--muted);
    }}
    dd {{
      margin: 0;
      overflow-wrap: anywhere;
    }}
    pre {{
      margin: 0;
      padding: 14px;
      border-radius: 12px;
      background: #17191d;
      color: #f7f4ed;
      overflow: auto;
      font-size: 0.88rem;
      line-height: 1.4;
    }}
    details {{
      margin-top: 12px;
    }}
    summary {{
      cursor: pointer;
      font-weight: 700;
      color: var(--accent);
    }}
    .section-stack {{
      display: grid;
      gap: 20px;
    }}
    @media (max-width: 720px) {{
      dl {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Benchmark Result Viewer</h1>
      <p>{escape(str(result_root))}</p>
    </section>
    <section class="grid">
      <article class="panel">
        <h2>Run Summary</h2>
        {_render_summary_list(summary)}
      </article>
      <article class="panel">
        <h2>Counts</h2>
        {_render_counts(summary, records, skipped_entries, selected_entries)}
      </article>
    </section>
    <section class="section-stack">
      <article class="panel">
        <h2>Case Results</h2>
        <div class="case-list">
          {case_sections}
        </div>
      </article>
      <article class="panel">
        {summary_section}
      </article>
      <article class="panel">
        {skipped_section}
      </article>
      <article class="panel">
        {selected_section}
      </article>
    </section>
  </main>
</body>
</html>
"""


def _render_summary_list(summary: dict[str, Any] | None) -> str:
    if not summary:
        return "<p>No summary metadata was found.</p>"

    keys = [
        "seed",
        "prompt_mode",
        "total_entry_count",
        "runnable_entry_count",
        "skipped_entry_count",
        "record_count",
    ]
    lines = []
    for key in keys:
        if key in summary:
            lines.append(f"<dt>{escape(key)}</dt><dd>{escape(str(summary[key]))}</dd>")
    if not lines:
        return "<p>No standard summary fields were found.</p>"

    return f"<dl>{''.join(lines)}</dl>"


def _render_counts(
    summary: dict[str, Any] | None,
    records: list[dict[str, Any]] | None,
    skipped_entries: list[dict[str, Any]] | None,
    selected_entries: list[dict[str, Any]] | None,
) -> str:
    rows = [
        ("records", len(records or [])),
        ("skipped entries", len(skipped_entries or [])),
        ("selected entries", len(selected_entries or [])),
    ]
    if summary and "materialized_files" in summary:
        rows.append(("materialized entry roots", len(summary["materialized_files"])))
    return (
        "<dl>"
        + "".join(
            f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>"
            for label, value in rows
        )
        + "</dl>"
    )


def _render_case_card(record: dict[str, Any]) -> str:
    score = record.get("score", {})
    outcome = str(score.get("outcome", "unknown"))
    badge_class = "ok" if outcome == "true_positive" else "bad"
    if outcome in {"partial_match", "execution_failure"}:
        badge_class = "warn"
    return f"""
    <section class="case-card">
      <h3>{escape(str(record.get("case_id", "unknown case")))}</h3>
      <div class="meta">
        <span class="pill {badge_class}">{escape(outcome)}</span>
        <span class="pill">{escape(str(record.get("status", "unknown")))}</span>
        <span class="pill">{escape(str(record.get("duration_ms", 0)))} ms</span>
      </div>
      <dl>
        <dt>Model</dt><dd>{escape(str(record.get("model_version", "")))}</dd>
        <dt>Vulnerability Type</dt><dd>{escape(str(record.get("vuln_type", "")))}</dd>
        <dt>Raw Output</dt><dd>{escape(str(record.get("raw_output_ref", "")))}</dd>
        <dt>Judge Rationale</dt><dd>{escape(str(score.get("judge_rationale", "")))}</dd>
      </dl>
      <details>
        <summary>Normalized Findings</summary>
        <pre>{escape(
            json.dumps(
                record.get("normalized_findings", []),
                indent=2,
                sort_keys=True,
            )
        )}</pre>
      </details>
      <details>
        <summary>Full Run Record</summary>
        <pre>{escape(json.dumps(record, indent=2, sort_keys=True))}</pre>
      </details>
    </section>
    """


def _render_json_section(
    *,
    title: str,
    payload: Any,
    empty_message: str,
) -> str:
    if payload is None:
        return f"<h2>{escape(title)}</h2><p>{escape(empty_message)}</p>"

    return (
        f"<h2>{escape(title)}</h2>"
        f"<pre>{escape(json.dumps(payload, indent=2, sort_keys=True))}</pre>"
    )
