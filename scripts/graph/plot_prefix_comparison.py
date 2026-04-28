#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import textwrap
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
matplotlib = None
plt = None


def require_matplotlib() -> tuple[Any, Any]:
    global matplotlib, plt
    if plt is None:
        import matplotlib as matplotlib_module

        matplotlib_module.use("Agg")
        import matplotlib.pyplot as pyplot

        matplotlib = matplotlib_module
        plt = pyplot
    return matplotlib, plt

COMPARE_FEATURES = [
    "flow_inter_arrival_time",
    "duration",
    "packet_count",
    "byte_count",
    "avg_packet_size",
]

BEHAVIORAL_KEY_ALIASES = {
    "short_flow_ratio": ("short_flow_ratio", "short_flow_ratio_le_1s"),
    "tiny_flow_ratio": ("tiny_flow_ratio", "tiny_flow_ratio_le_3packets"),
    "rst_observed_flow_ratio": ("rst_observed_flow_ratio",),
    "syn_only_like_flow_ratio": ("syn_only_like_flow_ratio",),
}

PROTOCOL_ALIASES = {
    "tcp": {"6", "TCP"},
    "udp": {"17", "UDP"},
}

LOW_FLOW_COUNT_THRESHOLD = 30


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compare overall flow features.json against per-prefix features.json files.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_args = parser.add_argument_group("required arguments")
    optional_args = parser.add_argument_group("options")
    required_args.add_argument("--overall", required=True, type=Path, help="Overall features.json path.")
    required_args.add_argument(
        "--prefix-dir",
        required=True,
        type=Path,
        help="Directory containing prefix *_features.json files.",
    )
    optional_args.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for summary CSV and plots. Defaults to results/comparison/<dataset_name>.",
    )
    return parser.parse_args()


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"top-level JSON must be an object: {path}")
    return data


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def default_output_dir(overall_path: Path, overall_json: dict[str, Any]) -> Path:
    scope = overall_json.get("scope", {})
    if isinstance(scope, dict):
        dataset_name = scope.get("dataset_name")
        if isinstance(dataset_name, str) and dataset_name.strip():
            return REPO_ROOT / "results" / "comparison" / dataset_name.strip()

    stem = overall_path.stem
    if stem.endswith("_features"):
        stem = stem[: -len("_features")]
    return REPO_ROOT / "results" / "comparison" / stem


def prefix_name_from_path(path: Path) -> str:
    name = path.stem
    if name.endswith("_features"):
        name = name[: -len("_features")]
    return name


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in name)


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def get_feature_block(features_json: dict[str, Any], feature_name: str) -> dict[str, Any] | None:
    features = features_json.get("features")
    if not isinstance(features, dict):
        return None
    feature = features.get(feature_name)
    return feature if isinstance(feature, dict) else None


def get_flow_count(features_json: dict[str, Any]) -> int:
    totals = features_json.get("totals", {})
    if isinstance(totals, dict) and "valid_flow_count" in totals:
        return int(totals["valid_flow_count"])

    feature = get_feature_block(features_json, "duration")
    if feature:
        stats = feature.get("stats", {})
        if isinstance(stats, dict) and "count" in stats:
            return int(stats["count"])

    return 0


def get_behavioral_indicators(features_json: dict[str, Any]) -> dict[str, float]:
    raw = features_json.get("behavioral_indicators", {})
    if not isinstance(raw, dict):
        raw = {}

    indicators: dict[str, float] = {}
    for output_key, aliases in BEHAVIORAL_KEY_ALIASES.items():
        value = 0.0
        for alias in aliases:
            if alias in raw:
                value = float(raw[alias])
                break
        indicators[output_key] = value
    return indicators


def get_protocol_ratios(features_json: dict[str, Any]) -> dict[str, float]:
    summary = features_json.get("protocol_summary", {})
    if not isinstance(summary, dict):
        return {
            "tcp_ratio": 0.0,
            "udp_ratio": 0.0,
            "tcp_flow_ratio": 0.0,
            "udp_flow_ratio": 0.0,
        }

    ratios = {"tcp": 0.0, "udp": 0.0}
    for proto_key, proto_summary in summary.items():
        if not isinstance(proto_summary, dict):
            continue

        key = str(proto_key).upper()
        flow_ratio = float(proto_summary.get("flow_ratio", proto_summary.get("ratio", 0.0)))

        if key in PROTOCOL_ALIASES["tcp"]:
            ratios["tcp"] = flow_ratio
        elif key in PROTOCOL_ALIASES["udp"]:
            ratios["udp"] = flow_ratio

    return {
        "tcp_ratio": ratios["tcp"],
        "udp_ratio": ratios["udp"],
        "tcp_flow_ratio": ratios["tcp"],
        "udp_flow_ratio": ratios["udp"],
    }


def get_stat(features_json: dict[str, Any], feature_name: str, stat_name: str) -> float:
    feature = get_feature_block(features_json, feature_name)
    if not feature:
        return 0.0

    stats = feature.get("stats", {})
    if not isinstance(stats, dict):
        return 0.0

    value = stats.get(stat_name, 0.0)
    return float(value) if value is not None else 0.0


def extract_summary_row(name: str, features_json: dict[str, Any]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "target": name,
        "flow_count": get_flow_count(features_json),
    }
    row.update(get_behavioral_indicators(features_json))
    row.update(get_protocol_ratios(features_json))

    for feature_name in COMPARE_FEATURES:
        row[f"{feature_name}_mean"] = get_stat(features_json, feature_name, "mean")
        row[f"{feature_name}_median"] = get_stat(features_json, feature_name, "median")

    row["low_flow_count_warning"] = row["flow_count"] < LOW_FLOW_COUNT_THRESHOLD
    return row


def pick_histogram(feature_block: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    if feature_block.get("log_scale_recommended") and feature_block.get("log_histogram"):
        hist = feature_block["log_histogram"]
        if isinstance(hist, dict):
            return "log_histogram", hist

    hist = feature_block.get("histogram")
    if isinstance(hist, dict):
        return "histogram", hist

    log_hist = feature_block.get("log_histogram")
    if isinstance(log_hist, dict):
        return "log_histogram", log_hist

    return None


def histogram_edges(hist_type: str, hist: dict[str, Any]) -> list[float] | None:
    edge_key = "linear_edges" if hist_type == "log_histogram" else "edges"
    raw_edges = hist.get(edge_key)
    if raw_edges is None and "bins" in hist and isinstance(hist["bins"], list):
        raw_edges = hist["bins"]

    if not isinstance(raw_edges, list):
        return None

    try:
        return [float(v) for v in raw_edges]
    except (TypeError, ValueError):
        return None


def histogram_counts(hist: dict[str, Any]) -> list[float] | None:
    raw_counts = hist.get("counts")
    if not isinstance(raw_counts, list):
        return None
    try:
        return [float(v) for v in raw_counts]
    except (TypeError, ValueError):
        return None


def histogram_centers(edges: list[float], count_len: int) -> list[float] | None:
    if len(edges) == count_len + 1:
        return [(edges[i] + edges[i + 1]) / 2.0 for i in range(count_len)]
    if len(edges) == count_len:
        return list(edges)
    return None


def normalize_counts(counts: list[float]) -> list[float]:
    total = sum(counts)
    if total <= 0:
        return [0.0 for _ in counts]
    return [value / total for value in counts]


def normalize_histogram(
    hist_type: str,
    hist: dict[str, Any],
) -> tuple[list[float], list[float], list[float]] | None:
    edges = histogram_edges(hist_type, hist)
    counts = histogram_counts(hist)
    if edges is None or counts is None or not counts:
        return None

    centers = histogram_centers(edges, len(counts))
    if centers is None:
        return None

    return edges, centers, normalize_counts(counts)


def compact_title(prefix_name: str, max_width: int = 48) -> str:
    return "\n".join(textwrap.wrap(prefix_name, width=max_width)) or prefix_name


def feature_axis_label(feature_name: str, hist_type: str, feature_block: dict[str, Any]) -> str:
    unit = feature_block.get("unit", "")
    label = feature_name.replace("_", " ")
    if unit:
        label = f"{label} ({unit})"
    if hist_type == "log_histogram":
        label += " [log x-scale]"
    return label


def add_small_sample_note(ax: plt.Axes, flow_count: int) -> None:
    if flow_count < LOW_FLOW_COUNT_THRESHOLD:
        ax.text(
            0.99,
            0.98,
            f"small sample: n={flow_count}",
            transform=ax.transAxes,
            ha="right",
            va="top",
            fontsize=9,
            color="dimgray",
        )


def add_bin_mismatch_note(ax: plt.Axes, overall_edges: list[float], prefix_edges: list[float]) -> None:
    if len(overall_edges) != len(prefix_edges):
        mismatch = True
    else:
        mismatch = any(not math.isclose(a, b, rel_tol=1e-9, abs_tol=1e-12) for a, b in zip(overall_edges, prefix_edges))

    if mismatch:
        ax.text(
            0.01,
            0.02,
            "note: overall/prefix histograms use independent bins",
            transform=ax.transAxes,
            ha="left",
            va="bottom",
            fontsize=8.5,
            color="dimgray",
        )


def plot_histogram_compare(
    overall_json: dict[str, Any],
    prefix_json: dict[str, Any],
    prefix_name: str,
    feature_name: str,
    out_path: Path,
) -> bool:
    _, plt_module = require_matplotlib()
    overall_feature = get_feature_block(overall_json, feature_name)
    prefix_feature = get_feature_block(prefix_json, feature_name)

    if not overall_feature or not prefix_feature:
        warn(f"missing feature block for {feature_name}: {prefix_name}")
        return False

    overall_choice = pick_histogram(overall_feature)
    prefix_choice = pick_histogram(prefix_feature)
    if overall_choice is None or prefix_choice is None:
        warn(f"missing histogram for {feature_name}: {prefix_name}")
        return False

    overall_hist_type, overall_hist = overall_choice
    prefix_hist_type, prefix_hist = prefix_choice

    if overall_hist_type != prefix_hist_type:
        shared_type = "histogram"
        if overall_feature.get(shared_type) and prefix_feature.get(shared_type):
            overall_hist_type = shared_type
            prefix_hist_type = shared_type
            overall_hist = overall_feature[shared_type]
            prefix_hist = prefix_feature[shared_type]
        else:
            shared_type = "log_histogram"
            if overall_feature.get(shared_type) and prefix_feature.get(shared_type):
                overall_hist_type = shared_type
                prefix_hist_type = shared_type
                overall_hist = overall_feature[shared_type]
                prefix_hist = prefix_feature[shared_type]

    overall_norm = normalize_histogram(overall_hist_type, overall_hist)
    prefix_norm = normalize_histogram(prefix_hist_type, prefix_hist)
    if overall_norm is None or prefix_norm is None:
        warn(f"invalid histogram format for {feature_name}: {prefix_name}")
        return False

    overall_edges, overall_x, overall_y = overall_norm
    prefix_edges, prefix_x, prefix_y = prefix_norm

    fig, ax = plt_module.subplots(figsize=(9.5, 5.8))
    ax.plot(overall_x, overall_y, label=f"overall (n={get_flow_count(overall_json)})", linewidth=2.0)
    ax.plot(prefix_x, prefix_y, label=f"{prefix_name} (n={get_flow_count(prefix_json)})", linewidth=2.0)

    if overall_hist_type == "log_histogram" and prefix_hist_type == "log_histogram":
        ax.set_xscale("log")

    ax.set_xlabel(feature_axis_label(feature_name, overall_hist_type, overall_feature))
    ax.set_ylabel("Normalized frequency")
    ax.set_title(f"{feature_name.replace('_', ' ')}: overall vs prefix\n{compact_title(prefix_name)}")
    ax.legend()
    ax.grid(alpha=0.25, linewidth=0.5)
    add_small_sample_note(ax, get_flow_count(prefix_json))
    add_bin_mismatch_note(ax, overall_edges, prefix_edges)
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt_module.close(fig)
    return True


def plot_behavioral_compare(
    overall_json: dict[str, Any],
    prefix_json: dict[str, Any],
    prefix_name: str,
    out_path: Path,
) -> bool:
    _, plt_module = require_matplotlib()
    overall_values = get_behavioral_indicators(overall_json)
    prefix_values = get_behavioral_indicators(prefix_json)

    labels = [
        "short<=1s",
        "tiny<=3pkts",
        "rst observed",
        "syn-only-like",
    ]
    keys = list(BEHAVIORAL_KEY_ALIASES.keys())
    x = range(len(keys))
    width = 0.38

    fig, ax = plt_module.subplots(figsize=(10.5, 5.8))
    overall_y = [overall_values[key] for key in keys]
    prefix_y = [prefix_values[key] for key in keys]

    ax.bar([i - width / 2 for i in x], overall_y, width=width, label=f"overall (n={get_flow_count(overall_json)})")
    ax.bar([i + width / 2 for i in x], prefix_y, width=width, label=f"{prefix_name} (n={get_flow_count(prefix_json)})")
    ax.set_xticks(list(x), labels, rotation=20, ha="right")
    ax.set_ylabel("Ratio")
    ax.set_ylim(0, 1)
    ax.set_title(f"Behavioral indicators: overall vs prefix\n{compact_title(prefix_name)}")
    ax.legend()
    ax.grid(axis="y", alpha=0.25, linewidth=0.5)
    add_small_sample_note(ax, get_flow_count(prefix_json))
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt_module.close(fig)
    return True


def write_summary_csv(rows: list[dict[str, Any]], out_path: Path) -> None:
    fieldnames = [
        "target",
        "flow_count",
        "short_flow_ratio",
        "tiny_flow_ratio",
        "rst_observed_flow_ratio",
        "syn_only_like_flow_ratio",
        "tcp_ratio",
        "udp_ratio",
        "tcp_flow_ratio",
        "udp_flow_ratio",
        "duration_mean",
        "duration_median",
        "flow_inter_arrival_time_mean",
        "flow_inter_arrival_time_median",
        "packet_count_mean",
        "packet_count_median",
        "byte_count_mean",
        "byte_count_median",
        "avg_packet_size_mean",
        "avg_packet_size_median",
        "low_flow_count_warning",
    ]

    with out_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def validate_overall_json(features_json: dict[str, Any], path: Path) -> None:
    missing: list[str] = []
    if get_flow_count(features_json) <= 0:
        missing.append("totals.valid_flow_count")

    for feature_name in COMPARE_FEATURES:
        if get_feature_block(features_json, feature_name) is None:
            missing.append(f"features.{feature_name}")

    if missing:
        raise ValueError(f"overall features.json is missing required keys in {path}: {', '.join(missing)}")


def process_prefix_file(
    overall_json: dict[str, Any],
    prefix_path: Path,
    plots_dir: Path,
) -> tuple[dict[str, Any] | None, list[str]]:
    warnings: list[str] = []
    prefix_name = prefix_name_from_path(prefix_path)

    try:
        prefix_json = load_json(prefix_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        warnings.append(f"skip {prefix_path.name}: failed to load JSON ({exc})")
        return None, warnings

    if get_flow_count(prefix_json) <= 0:
        warnings.append(f"skip {prefix_path.name}: valid_flow_count is missing or zero")
        return None, warnings

    summary_row = extract_summary_row(prefix_name, prefix_json)
    prefix_plot_dir = plots_dir / sanitize_filename(prefix_name)
    safe_mkdir(prefix_plot_dir)

    for feature_name in COMPARE_FEATURES:
        created = plot_histogram_compare(
            overall_json=overall_json,
            prefix_json=prefix_json,
            prefix_name=prefix_name,
            feature_name=feature_name,
            out_path=prefix_plot_dir / f"{feature_name}_compare.png",
        )
        if not created:
            warnings.append(f"{prefix_name}: failed to create {feature_name}_compare.png")

    created = plot_behavioral_compare(
        overall_json=overall_json,
        prefix_json=prefix_json,
        prefix_name=prefix_name,
        out_path=prefix_plot_dir / "behavioral_indicators_compare.png",
    )
    if not created:
        warnings.append(f"{prefix_name}: failed to create behavioral_indicators_compare.png")

    return summary_row, warnings


def main() -> int:
    args = parse_args()
    overall_path = resolve_from_repo_root(args.overall)
    prefix_dir = resolve_from_repo_root(args.prefix_dir)

    if not overall_path.exists():
        raise FileNotFoundError(f"overall features.json not found: {overall_path}")
    if not prefix_dir.exists():
        raise FileNotFoundError(f"prefix directory not found: {prefix_dir}")
    if not prefix_dir.is_dir():
        raise NotADirectoryError(f"prefix directory is not a directory: {prefix_dir}")

    overall_json = load_json(overall_path)
    validate_overall_json(overall_json, overall_path)
    out_dir = (
        resolve_from_repo_root(args.out_dir)
        if args.out_dir is not None
        else default_output_dir(overall_path, overall_json)
    )

    safe_mkdir(out_dir)
    plots_dir = out_dir / "plots"
    safe_mkdir(plots_dir)

    prefix_paths = sorted(prefix_dir.glob("*_features.json"))
    if not prefix_paths:
        warn(f"no prefix feature files found in {prefix_dir}")
        return 0

    summary_rows = [extract_summary_row("overall", overall_json)]
    warning_messages: list[str] = []

    for prefix_path in prefix_paths:
        row, warnings = process_prefix_file(overall_json, prefix_path, plots_dir)
        warning_messages.extend(warnings)
        if row is not None:
            summary_rows.append(row)

    summary_path = out_dir / "comparison_summary.csv"
    write_summary_csv(summary_rows, summary_path)

    for message in warning_messages:
        warn(message)

    print(f"[DONE] summary: {summary_path}")
    print(f"[DONE] plots:   {plots_dir}")
    print(f"[DONE] compared_prefixes: {max(len(summary_rows) - 1, 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
