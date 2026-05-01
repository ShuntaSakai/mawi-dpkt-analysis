#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import textwrap
from bisect import bisect_right
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

HISTOGRAM_COMPARE_FEATURES = [
    "flow_inter_arrival_time",
    "duration",
    "packet_count",
    "byte_count",
    "pps",
    "bps",
    "avg_packet_size",
    "packets_from_src_ratio",
    "bytes_from_src_ratio",
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


FeatureValues = dict[str, list[float]]


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


def parse_float_strict(value: str, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} is not a float: {value!r}") from exc

    if not math.isfinite(parsed):
        raise ValueError(f"{field_name} is not finite: {value!r}")
    return parsed


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


def get_dataset_name(features_json: dict[str, Any], fallback: str = "unknown") -> str:
    scope = features_json.get("scope", {})
    if isinstance(scope, dict):
        dataset_name = scope.get("dataset_name")
        if isinstance(dataset_name, str) and dataset_name.strip():
            return dataset_name.strip()
    return fallback


def get_input_file_path(features_json: dict[str, Any]) -> Path | None:
    meta = features_json.get("meta", {})
    if not isinstance(meta, dict):
        return None

    input_file = meta.get("input_file")
    if not isinstance(input_file, str) or not input_file.strip():
        return None

    return resolve_from_repo_root(Path(input_file))


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


def histogram_bin_count(feature_block: dict[str, Any], hist_key: str = "histogram", default: int = 20) -> int:
    hist = feature_block.get(hist_key)
    if isinstance(hist, dict):
        bins = hist.get("bins")
        if isinstance(bins, int) and bins > 0:
            return bins

        counts = hist.get("counts")
        if isinstance(counts, list) and counts:
            return len(counts)

    return default


def build_common_edges(values_a: list[float], values_b: list[float], bins: int) -> list[float] | None:
    values = values_a + values_b
    if not values:
        return None

    value_min = min(values)
    value_max = max(values)
    if value_min == value_max:
        return [value_min, value_max]

    width = (value_max - value_min) / bins
    return [value_min + width * i for i in range(bins + 1)]


def build_common_log_edges(values_a: list[float], values_b: list[float], bins: int) -> list[float] | None:
    positive_values = [value for value in values_a + values_b if value > 0]
    if not positive_values:
        return None

    log_min = math.log10(min(positive_values))
    log_max = math.log10(max(positive_values))
    if log_min == log_max:
        value = 10 ** log_min
        return [value, value]

    width = (log_max - log_min) / bins
    return [10 ** (log_min + width * i) for i in range(bins + 1)]


def count_values_in_edges(values: list[float], edges: list[float]) -> list[float] | None:
    if len(edges) < 2:
        return None

    counts = [0.0 for _ in range(len(edges) - 1)]
    if len(edges) == 2 and edges[0] == edges[1]:
        counts[0] = float(sum(1 for value in values if value == edges[0]))
        return counts

    if edges[-1] <= edges[0]:
        return None

    for value in values:
        if value < edges[0] or value > edges[-1]:
            continue
        index = bisect_right(edges, value) - 1
        if index == len(counts):
            index -= 1
        if index < 0:
            continue
        counts[index] += 1.0

    return counts


def count_log_values_in_edges(values: list[float], edges: list[float]) -> tuple[list[float] | None, int]:
    positive_values = [value for value in values if value > 0]
    non_positive_count = len(values) - len(positive_values)
    return count_values_in_edges(positive_values, edges), non_positive_count


def common_histogram(values: list[float], edges: list[float]) -> dict[str, Any] | None:
    counts = count_values_in_edges(values, edges)
    if counts is None:
        return None
    return {
        "bins": len(counts),
        "edges": edges,
        "counts": counts,
    }


def common_log_histogram(values: list[float], edges: list[float]) -> dict[str, Any] | None:
    counts, non_positive_count = count_log_values_in_edges(values, edges)
    if counts is None:
        return None
    return {
        "bins": len(counts),
        "linear_edges": edges,
        "counts": counts,
        "non_positive_count": non_positive_count,
    }


def common_histograms_for_feature(
    overall_feature: dict[str, Any],
    prefix_feature: dict[str, Any],
    overall_values: list[float],
    prefix_values: list[float],
    hist_type: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not overall_values or not prefix_values:
        return None

    bins = max(
        histogram_bin_count(overall_feature, hist_type),
        histogram_bin_count(prefix_feature, hist_type),
    )

    if hist_type == "log_histogram":
        common_edges = build_common_log_edges(overall_values, prefix_values, bins)
        if common_edges is None:
            return None
        overall_hist = common_log_histogram(overall_values, common_edges)
        prefix_hist = common_log_histogram(prefix_values, common_edges)
    else:
        common_edges = build_common_edges(overall_values, prefix_values, bins)
        if common_edges is None:
            return None
        overall_hist = common_histogram(overall_values, common_edges)
        prefix_hist = common_histogram(prefix_values, common_edges)

    if overall_hist is None or prefix_hist is None:
        return None
    return overall_hist, prefix_hist


def flow_csv_feature_values(csv_path: Path) -> FeatureValues:
    values: FeatureValues = {feature_name: [] for feature_name in HISTOGRAM_COMPARE_FEATURES}
    start_times: list[float] = []

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("CSV header is missing")

        for row in reader:
            try:
                start_time = parse_float_strict(row["start_time"], "start_time")
                end_time = parse_float_strict(row["end_time"], "end_time")
                duration = parse_float_strict(row["duration"], "duration")
                packet_count = parse_float_strict(row["packet_count"], "packet_count")
                byte_count = parse_float_strict(row["byte_count"], "byte_count")
                packets_from_src = parse_float_strict(row["packets_from_src"], "packets_from_src")
                bytes_from_src = parse_float_strict(row["bytes_from_src"], "bytes_from_src")
                if end_time < start_time or duration < 0 or packet_count < 0 or byte_count < 0:
                    raise ValueError("invalid flow row")

                start_times.append(start_time)
                values["duration"].append(duration)
                values["packet_count"].append(packet_count)
                values["byte_count"].append(byte_count)
                values["pps"].append(parse_float_strict(row["pps"], "pps"))
                values["bps"].append(parse_float_strict(row["bps"], "bps"))
                values["avg_packet_size"].append(byte_count / packet_count if packet_count > 0 else 0.0)
                values["packets_from_src_ratio"].append(
                    packets_from_src / packet_count if packet_count > 0 else 0.0
                )
                values["bytes_from_src_ratio"].append(
                    bytes_from_src / byte_count if byte_count > 0 else 0.0
                )
            except (KeyError, ValueError):
                continue

    sorted_start_times = sorted(start_times)
    values["flow_inter_arrival_time"] = [
        sorted_start_times[i] - sorted_start_times[i - 1]
        for i in range(1, len(sorted_start_times))
    ]
    return values


def load_flow_feature_values(features_json: dict[str, Any], label: str) -> FeatureValues | None:
    input_file_path = get_input_file_path(features_json)
    if input_file_path is None:
        warn(f"{label}: meta.input_file is missing; skip strict common-bin histograms")
        return None
    if not input_file_path.exists():
        warn(f"{label}: flow CSV not found: {input_file_path}; skip strict common-bin histograms")
        return None

    try:
        return flow_csv_feature_values(input_file_path)
    except (OSError, ValueError) as exc:
        warn(f"{label}: failed to load flow CSV for strict common-bin histograms ({exc})")
        return None


def cumulative_ratios(counts: list[float]) -> list[float]:
    total = sum(counts)
    if total <= 0:
        return [0.0 for _ in counts]

    cumulative = 0.0
    ratios: list[float] = []
    for value in counts:
        cumulative += value
        ratios.append(cumulative / total)
    return ratios


def cdf_from_histogram(
    hist_type: str,
    hist: dict[str, Any],
) -> tuple[list[float], list[float], list[float]] | None:
    edges = histogram_edges(hist_type, hist)
    counts = histogram_counts(hist)
    if edges is None or counts is None or not counts:
        return None

    y = cumulative_ratios(counts)
    if len(edges) == len(counts) + 1:
        x = [edges[0]]
        step_y = [0.0]
        previous_ratio = 0.0
        for upper_edge, ratio in zip(edges[1:], y):
            x.extend([upper_edge, upper_edge])
            step_y.extend([previous_ratio, ratio])
            previous_ratio = ratio
        y = step_y
    elif len(edges) == len(counts):
        x = edges
    else:
        return None

    return edges, x, y


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


def add_log_exclusion_note(ax: plt.Axes, histogram: dict[str, Any]) -> None:
    non_positive_count = histogram.get("non_positive_count", 0)
    try:
        count = int(non_positive_count)
    except (TypeError, ValueError):
        count = 0

    if count > 0:
        ax.text(
            0.99,
            0.86,
            f"excluded non-positive values: {count}",
            transform=ax.transAxes,
            ha="right",
            va="top",
            fontsize=8.5,
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


def histogram_data(hist_type: str, hist: dict[str, Any]) -> tuple[list[float], list[float]] | None:
    edges = histogram_edges(hist_type, hist)
    counts = histogram_counts(hist)
    if edges is None or counts is None or not counts or len(edges) != len(counts) + 1:
        return None
    return edges, counts


def plot_histogram_panel(
    ax: plt.Axes,
    feature_name: str,
    feature_block: dict[str, Any],
    hist_type: str,
    histogram: dict[str, Any],
    features_json: dict[str, Any],
    dataset_label: str,
    prefix_name: str,
    target_label: str,
) -> bool:
    data = histogram_data(hist_type, histogram)
    if data is None:
        return False

    edges, counts = data
    left_edges = edges[:-1]
    widths = [edges[i + 1] - edges[i] for i in range(len(counts))]

    if len(widths) == 1 and math.isclose(widths[0], 0.0, rel_tol=0.0, abs_tol=1e-12):
        center = left_edges[0]
        width = abs(center) * 0.1 if center else 1.0
        left_edges = [center - width / 2]
        widths = [width]

    ax.bar(left_edges, counts, width=widths, align="edge", edgecolor="black", linewidth=0.35)

    if hist_type == "log_histogram":
        ax.set_xscale("log")
        add_log_exclusion_note(ax, histogram)

    flow_count = get_flow_count(features_json)
    ax.set_xlabel(feature_axis_label(feature_name, hist_type, feature_block))
    ax.set_ylabel("Flow count")
    ax.set_title(
        "\n".join(
            [
                f"{feature_name} {target_label}",
                f"dataset: {dataset_label}",
                f"prefix: {prefix_name}",
                f"flow count: {flow_count}",
            ]
        ),
        fontsize=10,
    )
    ax.grid(axis="y", alpha=0.25, linewidth=0.5)
    add_small_sample_note(ax, flow_count)
    return True


def should_plot_histogram_compare(feature_name: str, overall_feature: dict[str, Any], prefix_feature: dict[str, Any]) -> bool:
    if overall_feature.get("unit") == "ratio" or prefix_feature.get("unit") == "ratio":
        return False

    return (
        isinstance(overall_feature.get("histogram"), dict)
        and isinstance(prefix_feature.get("histogram"), dict)
        and isinstance(overall_feature.get("log_histogram"), dict)
        and isinstance(prefix_feature.get("log_histogram"), dict)
    )


def plot_histogram_compare(
    overall_json: dict[str, Any],
    prefix_json: dict[str, Any],
    overall_feature_values: FeatureValues,
    prefix_feature_values: FeatureValues,
    prefix_name: str,
    feature_name: str,
    out_path: Path,
) -> bool | None:
    _, plt_module = require_matplotlib()
    overall_feature = get_feature_block(overall_json, feature_name)
    prefix_feature = get_feature_block(prefix_json, feature_name)

    if not overall_feature or not prefix_feature:
        return None

    if not should_plot_histogram_compare(feature_name, overall_feature, prefix_feature):
        return None

    overall_values = overall_feature_values.get(feature_name, [])
    prefix_values = prefix_feature_values.get(feature_name, [])
    if not overall_values or not prefix_values:
        return None

    common_histograms = common_histograms_for_feature(
        overall_feature,
        prefix_feature,
        overall_values,
        prefix_values,
        "histogram",
    )
    common_log_histograms = common_histograms_for_feature(
        overall_feature,
        prefix_feature,
        overall_values,
        prefix_values,
        "log_histogram",
    )
    if common_histograms is None or common_log_histograms is None:
        return None

    overall_hist, prefix_hist = common_histograms
    overall_log_hist, prefix_log_hist = common_log_histograms

    fig, axes = plt_module.subplots(2, 2, figsize=(13.5, 8.8), constrained_layout=True)
    overall_dataset = get_dataset_name(overall_json)

    panels = [
        (
            axes[0][0],
            overall_feature,
            "histogram",
            overall_hist,
            overall_json,
            overall_dataset,
            prefix_name,
            "all / histogram",
        ),
        (
            axes[0][1],
            overall_feature,
            "log_histogram",
            overall_log_hist,
            overall_json,
            overall_dataset,
            prefix_name,
            "all / log histogram",
        ),
        (
            axes[1][0],
            prefix_feature,
            "histogram",
            prefix_hist,
            prefix_json,
            overall_dataset,
            prefix_name,
            "prefix / histogram",
        ),
        (
            axes[1][1],
            prefix_feature,
            "log_histogram",
            prefix_log_hist,
            prefix_json,
            overall_dataset,
            prefix_name,
            "prefix / log histogram",
        ),
    ]

    for ax, feature_block, hist_type, histogram, features_json, dataset_label, panel_prefix, target_label in panels:
        created = plot_histogram_panel(
            ax=ax,
            feature_name=feature_name,
            feature_block=feature_block,
            hist_type=hist_type,
            histogram=histogram,
            features_json=features_json,
            dataset_label=dataset_label,
            prefix_name=panel_prefix,
            target_label=target_label,
        )
        if not created:
            plt_module.close(fig)
            warn(f"invalid histogram format for histogram {feature_name}: {prefix_name}")
            return False

    fig.suptitle(
        f"{feature_name.replace('_', ' ')} histogram comparison: all vs prefix\n{compact_title(prefix_name)}",
        fontsize=13,
    )
    fig.savefig(out_path, dpi=150)
    plt_module.close(fig)
    return True


def plot_cdf_compare(
    overall_json: dict[str, Any],
    prefix_json: dict[str, Any],
    overall_feature_values: FeatureValues | None,
    prefix_feature_values: FeatureValues | None,
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

    overall_hist_type: str
    prefix_hist_type: str
    overall_hist: dict[str, Any]
    prefix_hist: dict[str, Any]
    using_common_bins = False

    if overall_feature_values is not None and prefix_feature_values is not None:
        overall_values = overall_feature_values.get(feature_name, [])
        prefix_values = prefix_feature_values.get(feature_name, [])
        preferred_hist_type = (
            "log_histogram"
            if overall_feature.get("log_scale_recommended")
            and prefix_feature.get("log_scale_recommended")
            and isinstance(overall_feature.get("log_histogram"), dict)
            and isinstance(prefix_feature.get("log_histogram"), dict)
            else "histogram"
        )
        common_histograms = common_histograms_for_feature(
            overall_feature,
            prefix_feature,
            overall_values,
            prefix_values,
            preferred_hist_type,
        )
        if common_histograms is not None:
            overall_hist_type = preferred_hist_type
            prefix_hist_type = preferred_hist_type
            overall_hist, prefix_hist = common_histograms
            using_common_bins = True

    if not using_common_bins:
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

    overall_cdf = cdf_from_histogram(overall_hist_type, overall_hist)
    prefix_cdf = cdf_from_histogram(prefix_hist_type, prefix_hist)
    if overall_cdf is None or prefix_cdf is None:
        warn(f"invalid histogram format for {feature_name}: {prefix_name}")
        return False

    overall_edges, overall_x, overall_y = overall_cdf
    prefix_edges, prefix_x, prefix_y = prefix_cdf

    fig, ax = plt_module.subplots(figsize=(9.5, 5.8))
    ax.plot(overall_x, overall_y, label=f"overall (n={get_flow_count(overall_json)})", linewidth=2.0)
    ax.plot(prefix_x, prefix_y, label=f"{prefix_name} (n={get_flow_count(prefix_json)})", linewidth=2.0)

    if overall_hist_type == "log_histogram" and prefix_hist_type == "log_histogram":
        ax.set_xscale("log")

    ax.set_xlabel(feature_axis_label(feature_name, overall_hist_type, overall_feature))
    ax.set_ylabel("Cumulative flow ratio")
    ax.set_ylim(0, 1.02)
    ax.set_title(f"{feature_name.replace('_', ' ')} CDF: overall vs prefix\n{compact_title(prefix_name)}")
    ax.legend()
    ax.grid(alpha=0.25, linewidth=0.5)
    add_small_sample_note(ax, get_flow_count(prefix_json))
    if not using_common_bins:
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
    overall_feature_values: FeatureValues | None,
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
    histogram_plot_dir = prefix_plot_dir / "histograms"
    safe_mkdir(histogram_plot_dir)
    prefix_feature_values = load_flow_feature_values(prefix_json, prefix_name)

    for feature_name in COMPARE_FEATURES:
        created = plot_cdf_compare(
            overall_json=overall_json,
            prefix_json=prefix_json,
            overall_feature_values=overall_feature_values,
            prefix_feature_values=prefix_feature_values,
            prefix_name=prefix_name,
            feature_name=feature_name,
            out_path=prefix_plot_dir / f"{feature_name}_compare.png",
        )
        if not created:
            warnings.append(f"{prefix_name}: failed to create {feature_name}_compare.png")

    if overall_feature_values is not None and prefix_feature_values is not None:
        for feature_name in HISTOGRAM_COMPARE_FEATURES:
            created = plot_histogram_compare(
                overall_json=overall_json,
                prefix_json=prefix_json,
                overall_feature_values=overall_feature_values,
                prefix_feature_values=prefix_feature_values,
                prefix_name=prefix_name,
                feature_name=feature_name,
                out_path=histogram_plot_dir / f"{feature_name}_hist_compare.png",
            )
            if created is False:
                warnings.append(f"{prefix_name}: skipped {feature_name}_hist_compare.png")

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
    overall_feature_values = load_flow_feature_values(overall_json, "overall")
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
        row, warnings = process_prefix_file(overall_json, overall_feature_values, prefix_path, plots_dir)
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
