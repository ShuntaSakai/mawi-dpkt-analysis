#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import csv
import html
import mimetypes
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_SUMMARY_COLUMNS = [
    "flow_count",
    "short_flow_ratio",
    "tiny_flow_ratio",
    "rst_observed_flow_ratio",
    "syn_only_like_flow_ratio",
    "tcp_ratio",
    "udp_ratio",
    "duration_median",
    "packet_count_median",
    "byte_count_median",
    "avg_packet_size_median",
    "low_flow_count_warning",
]
DEFAULT_IMAGE_ORDER = [
    "flow_inter_arrival_time_compare.png",
    "duration_compare.png",
    "packet_count_compare.png",
    "byte_count_compare.png",
    "avg_packet_size_compare.png",
    "behavioral_indicators_compare.png",
    "histograms/flow_inter_arrival_time_hist_compare.png",
    "histograms/duration_hist_compare.png",
    "histograms/packet_count_hist_compare.png",
    "histograms/byte_count_hist_compare.png",
    "histograms/pps_hist_compare.png",
    "histograms/bps_hist_compare.png",
    "histograms/avg_packet_size_hist_compare.png",
]


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a static HTML report from prefix comparison summary and PNG plots.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--dataset",
        help="Dataset name under results/comparison/<dataset>.",
    )
    source.add_argument(
        "--comparison-dir",
        type=Path,
        help="Comparison result directory containing comparison_summary.csv and plots/.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output HTML path. Defaults to results/reports/<dataset>/analysis_report.html.",
    )
    parser.add_argument(
        "--prefix",
        action="append",
        default=[],
        help="Target prefix directory/name to include. Can be specified multiple times.",
    )
    parser.add_argument(
        "--all-prefixes",
        action="store_true",
        help="Include all prefixes. This is the default when --prefix is not specified.",
    )
    parser.add_argument(
        "--features",
        nargs="+",
        default=None,
        help="Feature names to include, such as duration packet_count byte_count.",
    )
    parser.add_argument(
        "--no-histograms",
        action="store_true",
        help="Exclude PNG files under each prefix histograms/ directory.",
    )
    parser.add_argument(
        "--embed-images",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Embed PNG images as base64 data URIs. Use --no-embed-images "
            "to reference PNG files by relative path instead."
        ),
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on missing plot directories or missing expected PNG files.",
    )
    return parser.parse_args(argv)


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def require_dataset_name(dataset: str) -> str:
    path = Path(dataset)
    if dataset in {"", ".", ".."} or path.name != dataset or any(part == ".." for part in path.parts):
        raise ValueError(f"dataset must be a single directory name: {dataset!r}")
    return dataset


def default_comparison_dir(dataset: str) -> Path:
    return REPO_ROOT / "results" / "comparison" / require_dataset_name(dataset)


def default_output_path(dataset: str) -> Path:
    return REPO_ROOT / "results" / "reports" / require_dataset_name(dataset) / "analysis_report.html"


def read_summary_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            if reader.fieldnames is None:
                raise ValueError("CSV has no header")
            rows = list(reader)
    except csv.Error as exc:
        raise ValueError(f"failed to parse CSV: {path}") from exc

    if "target" not in reader.fieldnames:
        raise ValueError(f"required column 'target' is missing: {path}")
    if not rows:
        raise ValueError(f"CSV has no data rows: {path}")
    return list(reader.fieldnames), rows


def html_escape(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def format_cell(value: str) -> str:
    if value == "":
        return ""
    try:
        parsed = float(value)
    except ValueError:
        return value
    if parsed.is_integer() and abs(parsed) < 1_000_000_000:
        return str(int(parsed))
    return f"{parsed:.6g}"


def selected_summary_columns(fieldnames: list[str]) -> list[str]:
    cols = [col for col in DEFAULT_SUMMARY_COLUMNS if col in fieldnames]
    if not cols:
        return [col for col in fieldnames if col != "target"]
    return cols


def target_rows(rows: list[dict[str, str]], selected_prefixes: set[str]) -> tuple[dict[str, str] | None, list[dict[str, str]]]:
    overall = next((row for row in rows if row.get("target") == "overall"), None)
    prefixes = [row for row in rows if row.get("target") != "overall"]
    if selected_prefixes:
        prefixes = [row for row in prefixes if row.get("target", "") in selected_prefixes]
    return overall, prefixes


def feature_matches(path: Path, selected_features: set[str] | None) -> bool:
    if selected_features is None:
        return True

    stem = path.stem
    for feature in selected_features:
        if stem == feature or stem.startswith(f"{feature}_"):
            return True
    return False


def expected_images(include_histograms: bool, selected_features: set[str] | None) -> list[Path]:
    paths: list[Path] = []
    for name in DEFAULT_IMAGE_ORDER:
        rel = Path(name)
        if not include_histograms and "histograms" in rel.parts:
            continue
        if feature_matches(rel, selected_features):
            paths.append(rel)
    return paths


def collect_images(
    prefix_dir: Path,
    include_histograms: bool,
    selected_features: set[str] | None,
) -> list[Path]:
    expected = expected_images(include_histograms, selected_features)
    ordered = [prefix_dir / rel for rel in expected if (prefix_dir / rel).is_file()]
    known = {path.resolve() for path in ordered}

    discovered: list[Path] = []
    for path in prefix_dir.rglob("*.png"):
        if not include_histograms and "histograms" in path.relative_to(prefix_dir).parts:
            continue
        if path.resolve() in known:
            continue
        if feature_matches(path, selected_features):
            discovered.append(path)
    return ordered + sorted(discovered, key=lambda p: str(p.relative_to(prefix_dir)))


def missing_expected_images(
    prefix_dir: Path,
    include_histograms: bool,
    selected_features: set[str] | None,
) -> list[Path]:
    return [
        prefix_dir / rel
        for rel in expected_images(include_histograms, selected_features)
        if not (prefix_dir / rel).is_file()
    ]


def image_src(image_path: Path, output_path: Path, embed_images: bool) -> str:
    if not embed_images:
        rel = os.path.relpath(image_path.resolve(), output_path.parent.resolve())
        return Path(rel).as_posix()

    mime_type = mimetypes.guess_type(image_path.name)[0] or "image/png"
    data = base64.b64encode(image_path.read_bytes()).decode("ascii")
    return f"data:{mime_type};base64,{data}"


def relative_path_text(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def render_summary_table(title: str, row: dict[str, str] | None, columns: list[str]) -> str:
    if row is None:
        return f"<section class=\"summary\"><h2>{html_escape(title)}</h2><p class=\"warning\">summary row is missing.</p></section>"

    cells = "\n".join(
        f"<tr><th>{html_escape(col)}</th><td>{html_escape(format_cell(row.get(col, '')))}</td></tr>"
        for col in columns
    )
    return (
        "<section class=\"summary\">"
        f"<h2>{html_escape(title)}</h2>"
        f"<table><tbody>{cells}</tbody></table>"
        "</section>"
    )


def signal_notes(row: dict[str, str]) -> list[str]:
    notes: list[str] = []

    def as_float(key: str) -> float | None:
        try:
            return float(row.get(key, ""))
        except ValueError:
            return None

    if row.get("low_flow_count_warning", "").lower() == "true":
        notes.append("low_flow_count_warning が True のため、分布の解釈には小標本の影響を考慮する必要があります。")
    short_ratio = as_float("short_flow_ratio")
    tiny_ratio = as_float("tiny_flow_ratio")
    rst_ratio = as_float("rst_observed_flow_ratio")
    tcp_ratio = as_float("tcp_ratio")
    udp_ratio = as_float("udp_ratio")

    if short_ratio is not None and tiny_ratio is not None and short_ratio >= 0.8 and tiny_ratio >= 0.8:
        notes.append("短命 flow と tiny flow が多く、scan 的または試行的な通信と整合的な可能性があります。")
    if rst_ratio is not None and rst_ratio >= 0.2:
        notes.append("RST observed ratio が高めで、接続失敗や途中終了が多い通信と整合的な可能性があります。")
    if tcp_ratio is not None and tcp_ratio >= 0.8:
        notes.append("TCP 中心の prefix として解釈できます。")
    if udp_ratio is not None and udp_ratio >= 0.8:
        notes.append("UDP 中心の prefix として解釈できます。")
    return notes


def render_prefix_section(
    row: dict[str, str],
    columns: list[str],
    plot_base_dir: Path,
    output_path: Path,
    include_histograms: bool,
    selected_features: set[str] | None,
    embed_images: bool,
    strict: bool,
    warnings: list[str],
) -> str:
    target = row.get("target", "")
    prefix_dir = plot_base_dir / target
    section: list[str] = [f"<section class=\"prefix\" id=\"{html_escape(target)}\">"]
    section.append(f"<h2>{html_escape(target)}</h2>")

    cells = "\n".join(
        f"<tr><th>{html_escape(col)}</th><td>{html_escape(format_cell(row.get(col, '')))}</td></tr>"
        for col in columns
    )
    section.append(f"<table class=\"compact\"><tbody>{cells}</tbody></table>")

    notes = signal_notes(row)
    if notes:
        items = "".join(f"<li>{html_escape(note)}</li>" for note in notes)
        section.append(f"<ul class=\"notes\">{items}</ul>")

    if not prefix_dir.is_dir():
        message = f"plot directory is missing for {target}: {relative_path_text(prefix_dir)}"
        if strict:
            raise FileNotFoundError(message)
        warnings.append(message)
        section.append(f"<p class=\"warning\">{html_escape(message)}</p></section>")
        return "\n".join(section)

    missing = missing_expected_images(prefix_dir, include_histograms, selected_features)
    if missing:
        message = f"{target}: {len(missing)} expected PNG file(s) are missing"
        if strict:
            raise FileNotFoundError(message)
        warnings.append(message)
        missing_items = "".join(f"<li>{html_escape(relative_path_text(path))}</li>" for path in missing)
        section.append(f"<details class=\"warning\"><summary>{html_escape(message)}</summary><ul>{missing_items}</ul></details>")

    images = collect_images(prefix_dir, include_histograms, selected_features)
    if not images:
        section.append("<p class=\"warning\">No PNG images found for this prefix.</p>")
    else:
        section.append("<div class=\"figures\">")
        for path in images:
            rel_label = path.relative_to(prefix_dir).as_posix()
            try:
                src = image_src(path, output_path, embed_images)
            except OSError as exc:
                message = f"failed to read image {relative_path_text(path)}: {exc}"
                if strict:
                    raise
                warnings.append(message)
                section.append(f"<p class=\"warning\">{html_escape(message)}</p>")
                continue
            section.append(
                "<figure>"
                f"<img src=\"{html_escape(src)}\" alt=\"{html_escape(target)} {html_escape(rel_label)}\" loading=\"lazy\">"
                f"<figcaption>{html_escape(rel_label)}</figcaption>"
                "</figure>"
            )
        section.append("</div>")

    section.append("</section>")
    return "\n".join(section)


def render_html(
    dataset: str,
    fieldnames: list[str],
    rows: list[dict[str, str]],
    comparison_dir: Path,
    output_path: Path,
    prefixes: list[dict[str, str]],
    overall: dict[str, str] | None,
    include_histograms: bool,
    selected_features: set[str] | None,
    embed_images: bool,
    strict: bool,
    warnings: list[str],
) -> str:
    columns = selected_summary_columns(fieldnames)
    plot_base_dir = comparison_dir / "plots"
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    feature_text = "all" if selected_features is None else ", ".join(sorted(selected_features))

    prefix_links = "\n".join(
        f"<li><a href=\"#{html_escape(row.get('target', ''))}\">{html_escape(row.get('target', ''))}</a></li>"
        for row in prefixes
    )
    sections = [
        render_prefix_section(
            row,
            columns,
            plot_base_dir,
            output_path,
            include_histograms,
            selected_features,
            embed_images,
            strict,
            warnings,
        )
        for row in prefixes
    ]

    warning_block = ""
    if warnings:
        warning_items = "".join(f"<li>{html_escape(warning)}</li>" for warning in warnings)
        warning_block = f"<section class=\"warnings\"><h2>Warnings</h2><ul>{warning_items}</ul></section>"

    return f"""<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MAWI Prefix Analysis Report - {html_escape(dataset)}</title>
  <style>
    :root {{
      color-scheme: light;
      --fg: #202124;
      --muted: #5f6368;
      --line: #d9dee3;
      --soft: #f6f8fa;
      --warn: #8a4b00;
    }}
    body {{
      margin: 0;
      color: var(--fg);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.55;
      background: #fff;
    }}
    header, main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 24px;
    }}
    header {{
      border-bottom: 1px solid var(--line);
    }}
    h1, h2, h3 {{
      line-height: 1.25;
      margin: 0 0 14px;
    }}
    h1 {{
      font-size: 28px;
    }}
    h2 {{
      font-size: 22px;
      margin-top: 10px;
    }}
    p, ul {{
      margin-top: 0;
    }}
    .meta {{
      color: var(--muted);
      font-size: 14px;
    }}
    section {{
      margin: 28px 0;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      margin: 10px 0 16px;
      font-size: 14px;
    }}
    th, td {{
      border: 1px solid var(--line);
      padding: 7px 9px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      width: 260px;
      background: var(--soft);
      font-weight: 600;
    }}
    .compact {{
      max-width: 760px;
    }}
    .figures {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 18px;
      align-items: start;
    }}
    figure {{
      margin: 0;
      border: 1px solid var(--line);
      background: #fff;
    }}
    img {{
      display: block;
      width: 100%;
      height: auto;
    }}
    figcaption {{
      border-top: 1px solid var(--line);
      padding: 8px 10px;
      color: var(--muted);
      font-size: 13px;
      overflow-wrap: anywhere;
    }}
    .notes {{
      max-width: 860px;
      color: #2f4f4f;
      background: #f2f7f6;
      border: 1px solid #cddfdb;
      padding: 10px 16px 10px 28px;
    }}
    .warning, .warnings {{
      color: var(--warn);
    }}
    details.warning {{
      margin: 12px 0;
    }}
    .toc ul {{
      columns: 2;
      padding-left: 22px;
    }}
    a {{
      color: #0b57d0;
    }}
    @media (max-width: 720px) {{
      header, main {{
        padding: 18px;
      }}
      .figures {{
        grid-template-columns: 1fr;
      }}
      .toc ul {{
        columns: 1;
      }}
      th {{
        width: 42%;
      }}
    }}
    @media print {{
      @page {{
        size: A4 landscape;
        margin: 12mm;
      }}
      body {{
        background: #fff;
      }}
      header, main {{
        max-width: none;
        padding: 0;
      }}
      section.prefix {{
        break-before: page;
        page-break-before: always;
      }}
      table, figure, .notes, details {{
        break-inside: avoid;
        page-break-inside: avoid;
      }}
      .figures {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 12px;
      }}
      figure {{
        border-color: #c7cdd3;
      }}
      img {{
        max-height: 92mm;
        object-fit: contain;
      }}
      a {{
        color: inherit;
        text-decoration: none;
      }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>MAWI Prefix Analysis Report</h1>
    <p class="meta">dataset: {html_escape(dataset)} / generated_at_utc: {html_escape(generated_at)}</p>
    <p class="meta">input: {html_escape(relative_path_text(comparison_dir / "comparison_summary.csv"))} / image_mode: {html_escape("embed" if embed_images else "relative")} / features: {html_escape(feature_text)}</p>
  </header>
  <main>
    {render_summary_table("Overall Summary", overall, columns)}
    <section class="toc">
      <h2>Prefixes</h2>
      <ul>
        {prefix_links}
      </ul>
    </section>
    {warning_block}
    {"".join(sections)}
  </main>
</body>
</html>
"""


def ensure_output_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def validate_args(args: argparse.Namespace) -> tuple[str, Path, Path]:
    if args.prefix and args.all_prefixes:
        raise ValueError("--prefix and --all-prefixes should not be used together")

    if args.dataset:
        dataset = require_dataset_name(args.dataset)
        comparison_dir = default_comparison_dir(dataset)
    else:
        comparison_dir = resolve_from_repo_root(args.comparison_dir).resolve()
        dataset = comparison_dir.name

    output_path = resolve_from_repo_root(args.output).resolve() if args.output else default_output_path(dataset)
    return dataset, comparison_dir.resolve(), output_path.resolve()


def write_report(args: argparse.Namespace) -> Path:
    dataset, comparison_dir, output_path = validate_args(args)
    summary_path = comparison_dir / "comparison_summary.csv"
    plot_dir = comparison_dir / "plots"

    if not comparison_dir.is_dir():
        raise FileNotFoundError(f"comparison directory does not exist: {comparison_dir}")
    if not summary_path.is_file():
        raise FileNotFoundError(f"comparison_summary.csv does not exist: {summary_path}")
    if not plot_dir.is_dir() and args.strict:
        raise FileNotFoundError(f"plots directory does not exist: {plot_dir}")

    fieldnames, rows = read_summary_csv(summary_path)
    selected_prefixes = set(args.prefix)
    overall, prefixes = target_rows(rows, selected_prefixes)
    if selected_prefixes:
        found = {row.get("target", "") for row in prefixes}
        missing = sorted(selected_prefixes - found)
        if missing:
            raise ValueError(f"requested prefix(es) not found in summary CSV: {', '.join(missing)}")
    if not prefixes:
        raise ValueError("no prefix rows selected")

    warnings: list[str] = []
    if not plot_dir.is_dir():
        warnings.append(f"plots directory does not exist: {relative_path_text(plot_dir)}")

    selected_features = set(args.features) if args.features else None
    html_text = render_html(
        dataset=dataset,
        fieldnames=fieldnames,
        rows=rows,
        comparison_dir=comparison_dir,
        output_path=output_path,
        prefixes=prefixes,
        overall=overall,
        include_histograms=not args.no_histograms,
        selected_features=selected_features,
        embed_images=args.embed_images,
        strict=args.strict,
        warnings=warnings,
    )
    ensure_output_parent(output_path)
    output_path.write_text(html_text, encoding="utf-8")
    return output_path


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        output_path = write_report(args)
    except (OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] wrote {relative_path_text(output_path)}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
