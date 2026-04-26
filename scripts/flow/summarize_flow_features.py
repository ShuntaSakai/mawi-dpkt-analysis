#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from heapq import nlargest
from pathlib import Path
from statistics import mean, median, pvariance, pstdev
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent.parent


REQUIRED_COLUMNS = {
    "flow_id",
    "start_time",
    "end_time",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "duration",
    "packet_count",
    "byte_count",
    "pps",
    "bps",
    "packets_from_src",
    "packets_from_dst",
    "bytes_from_src",
    "bytes_from_dst",
    "syn_count",
    "syn_ack_count",
    "ack_count",
    "fin_count",
    "rst_count",
}


FEATURE_SPECS = {
    "flow_inter_arrival_time": {
        "unit": "seconds",
        "description": "全フローを開始時刻でソートしたときの隣接フロー開始間隔",
        "log_scale_recommended": True,
    },
    "duration": {
        "unit": "seconds",
        "description": "各フローの継続時間",
        "log_scale_recommended": True,
    },
    "packet_count": {
        "unit": "packets",
        "description": "各フローのパケット数",
        "log_scale_recommended": True,
    },
    "byte_count": {
        "unit": "bytes",
        "description": "各フローのバイト数",
        "log_scale_recommended": True,
    },
    "pps": {
        "unit": "packets_per_second",
        "description": "各フローの packets/sec",
        "log_scale_recommended": True,
    },
    "bps": {
        "unit": "bytes_per_second",
        "description": "各フローの bytes/sec",
        "log_scale_recommended": True,
    },
    "avg_packet_size": {
        "unit": "bytes_per_packet",
        "description": "byte_count / packet_count",
        "log_scale_recommended": True,
    },
    "packets_from_src_ratio": {
        "unit": "ratio",
        "description": "packet_count に対する src->dst パケット比率",
        "log_scale_recommended": False,
    },
    "bytes_from_src_ratio": {
        "unit": "ratio",
        "description": "byte_count に対する src->dst バイト比率",
        "log_scale_recommended": False,
    },
}


TOP_KEYS = [
    "packet_count",
    "byte_count",
    "duration",
    "pps",
    "bps",
]


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def default_output_dir_for_input(input_path: Path) -> Path:
    try:
        relative_input = input_path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return REPO_ROOT / "results/features/all"

    if relative_input.parts[:3] == ("results", "flows", "prefix"):
        prefix_parts = relative_input.parts[3:-1]
        if prefix_parts:
            return REPO_ROOT / "results" / "features" / "prefix" / Path(*prefix_parts)
        return REPO_ROOT / "results/features/prefix"

    return REPO_ROOT / "results/features/all"


def parse_float_strict(value: str, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} is not a float: {value!r}") from exc

    if not math.isfinite(parsed):
        raise ValueError(f"{field_name} is not finite: {value!r}")

    return parsed


def parse_int_strict(value: str, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} is not an int: {value!r}") from exc


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0

    sorted_values = sorted(values)
    k = (len(sorted_values) - 1) * (p / 100.0)
    lower = math.floor(k)
    upper = math.ceil(k)

    if lower == upper:
        return sorted_values[int(k)]

    weight = k - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def build_histogram(values: list[float], bins: int) -> dict[str, Any]:
    if not values:
        return {
            "bins": bins,
            "edges": [],
            "counts": [],
        }

    value_min = min(values)
    value_max = max(values)

    if value_min == value_max:
        return {
            "bins": 1,
            "edges": [value_min, value_max],
            "counts": [len(values)],
        }

    width = (value_max - value_min) / bins
    counts = [0 for _ in range(bins)]
    edges = [value_min + width * i for i in range(bins + 1)]

    for value in values:
        index = int((value - value_min) / width)
        if index == bins:
            index -= 1
        counts[index] += 1

    return {
        "bins": bins,
        "edges": edges,
        "counts": counts,
    }


def build_log_histogram(values: list[float], bins: int) -> dict[str, Any] | None:
    positive_values = [value for value in values if value > 0]
    if not positive_values:
        return None

    log_values = [math.log10(value) for value in positive_values]
    histogram = build_histogram(log_values, bins)

    # 元の値域に戻した境界も残しておくと、後続の可視化で再利用しやすい。
    return {
        "bins": histogram["bins"],
        "log10_edges": histogram["edges"],
        "linear_edges": [10 ** edge for edge in histogram["edges"]],
        "counts": histogram["counts"],
        "non_positive_count": len(values) - len(positive_values),
    }


def summarize_numeric(values: list[float], bins: int) -> dict[str, Any]:
    if not values:
        return {
            "stats": {
                "count": 0,
                "min": 0.0,
                "max": 0.0,
                "mean": 0.0,
                "population_variance": 0.0,
                "population_stddev": 0.0,
                "median": 0.0,
                "p01": 0.0,
                "p05": 0.0,
                "p25": 0.0,
                "p75": 0.0,
                "p90": 0.0,
                "p95": 0.0,
                "p99": 0.0,
            },
            "histogram": build_histogram(values, bins),
            "log_histogram": build_log_histogram(values, bins),
        }

    return {
        "stats": {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "mean": mean(values),
            "population_variance": pvariance(values),
            "population_stddev": pstdev(values),
            "median": median(values),
            "p01": percentile(values, 1),
            "p05": percentile(values, 5),
            "p25": percentile(values, 25),
            "p75": percentile(values, 75),
            "p90": percentile(values, 90),
            "p95": percentile(values, 95),
            "p99": percentile(values, 99),
        },
        "histogram": build_histogram(values, bins),
        "log_histogram": build_log_histogram(values, bins),
    }


def validate_csv_header(fieldnames: list[str] | None) -> None:
    if fieldnames is None:
        raise ValueError("CSV header is missing")

    missing = sorted(REQUIRED_COLUMNS - set(fieldnames))
    if missing:
        raise ValueError(f"missing required columns: {', '.join(missing)}")


def parse_flow_row(row: dict[str, str]) -> dict[str, Any]:
    packet_count = parse_int_strict(row["packet_count"], "packet_count")
    byte_count = parse_int_strict(row["byte_count"], "byte_count")
    packets_from_src = parse_int_strict(row["packets_from_src"], "packets_from_src")
    bytes_from_src = parse_int_strict(row["bytes_from_src"], "bytes_from_src")

    flow = {
        "flow_id": parse_int_strict(row["flow_id"], "flow_id"),
        "start_time": parse_float_strict(row["start_time"], "start_time"),
        "end_time": parse_float_strict(row["end_time"], "end_time"),
        "src_ip": row["src_ip"],
        "src_port": parse_int_strict(row["src_port"], "src_port"),
        "dst_ip": row["dst_ip"],
        "dst_port": parse_int_strict(row["dst_port"], "dst_port"),
        "protocol": parse_int_strict(row["protocol"], "protocol"),
        "duration": parse_float_strict(row["duration"], "duration"),
        "packet_count": packet_count,
        "byte_count": byte_count,
        "pps": parse_float_strict(row["pps"], "pps"),
        "bps": parse_float_strict(row["bps"], "bps"),
        "packets_from_src": packets_from_src,
        "packets_from_dst": parse_int_strict(row["packets_from_dst"], "packets_from_dst"),
        "bytes_from_src": bytes_from_src,
        "bytes_from_dst": parse_int_strict(row["bytes_from_dst"], "bytes_from_dst"),
        "syn_count": parse_int_strict(row["syn_count"], "syn_count"),
        "syn_ack_count": parse_int_strict(row["syn_ack_count"], "syn_ack_count"),
        "ack_count": parse_int_strict(row["ack_count"], "ack_count"),
        "fin_count": parse_int_strict(row["fin_count"], "fin_count"),
        "rst_count": parse_int_strict(row["rst_count"], "rst_count"),
    }

    if flow["end_time"] < flow["start_time"]:
        raise ValueError("end_time is earlier than start_time")
    if flow["duration"] < 0:
        raise ValueError("duration is negative")
    if packet_count < 0 or byte_count < 0:
        raise ValueError("packet_count or byte_count is negative")

    # 後続の比較や可視化で再利用しやすいよう、派生特徴量をここで明示的に持つ。
    flow["avg_packet_size"] = byte_count / packet_count if packet_count > 0 else 0.0
    flow["packets_from_src_ratio"] = (
        packets_from_src / packet_count if packet_count > 0 else 0.0
    )
    flow["bytes_from_src_ratio"] = (
        bytes_from_src / byte_count if byte_count > 0 else 0.0
    )

    return flow


def load_flows(csv_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    invalid_row_examples: list[dict[str, Any]] = []
    invalid_row_count = 0

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        validate_csv_header(reader.fieldnames)

        for row_number, row in enumerate(reader, start=2):
            try:
                flows.append(parse_flow_row(row))
            except ValueError as exc:
                invalid_row_count += 1

                # すべての不正行を保持すると大規模データで JSON が肥大化するため、
                # 代表例だけを数件残し、件数は別で保持する。
                if len(invalid_row_examples) < 20:
                    invalid_row_examples.append(
                        {
                            "row_number": row_number,
                            "reason": str(exc),
                        }
                    )

    return flows, {
        "invalid_row_count": invalid_row_count,
        "invalid_row_examples": invalid_row_examples,
    }


def calc_flow_inter_arrival_times(flows: list[dict[str, Any]]) -> list[float]:
    start_times = sorted(flow["start_time"] for flow in flows)
    return [
        start_times[i] - start_times[i - 1]
        for i in range(1, len(start_times))
    ]


def top_records(
    flows: list[dict[str, Any]],
    key: str,
    limit: int,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    for flow in nlargest(limit, flows, key=lambda item: item[key]):
        records.append(
            {
                "flow_id": flow["flow_id"],
                "src_ip": flow["src_ip"],
                "src_port": flow["src_port"],
                "dst_ip": flow["dst_ip"],
                "dst_port": flow["dst_port"],
                "protocol": flow["protocol"],
                key: flow[key],
                "duration": flow["duration"],
                "packet_count": flow["packet_count"],
                "byte_count": flow["byte_count"],
                "avg_packet_size": flow["avg_packet_size"],
                "packets_from_src_ratio": flow["packets_from_src_ratio"],
                "bytes_from_src_ratio": flow["bytes_from_src_ratio"],
            }
        )

    return records


def summarize_protocols(flows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for flow in flows:
        grouped[flow["protocol"]].append(flow)

    summary: dict[str, Any] = {}
    total_flows = len(flows)

    for proto, proto_flows in sorted(grouped.items()):
        packet_total = sum(flow["packet_count"] for flow in proto_flows)
        byte_total = sum(flow["byte_count"] for flow in proto_flows)
        summary[str(proto)] = {
            "flow_count": len(proto_flows),
            "flow_ratio": (len(proto_flows) / total_flows) if total_flows > 0 else 0.0,
            "packet_total": packet_total,
            "byte_total": byte_total,
            "duration": summarize_numeric(
                [flow["duration"] for flow in proto_flows],
                bins=20,
            )["stats"],
        }

    return summary


def summarize_behavioral_indicators(flows: list[dict[str, Any]]) -> dict[str, Any]:
    total_flows = len(flows)
    if total_flows == 0:
        return {
            "short_flow_ratio_le_1s": 0.0,
            "tiny_flow_ratio_le_3packets": 0.0,
            "rst_observed_flow_ratio": 0.0,
            "syn_only_like_flow_ratio": 0.0,
        }

    short_flow_count = sum(1 for flow in flows if flow["duration"] <= 1.0)
    tiny_flow_count = sum(1 for flow in flows if flow["packet_count"] <= 3)
    rst_flow_count = sum(1 for flow in flows if flow["rst_count"] > 0)
    syn_only_like_count = sum(
        1
        for flow in flows
        if flow["syn_count"] > 0
        and flow["ack_count"] == 0
        and flow["byte_count"] == 0
    )

    return {
        "short_flow_ratio_le_1s": short_flow_count / total_flows,
        "tiny_flow_ratio_le_3packets": tiny_flow_count / total_flows,
        "rst_observed_flow_ratio": rst_flow_count / total_flows,
        "syn_only_like_flow_ratio": syn_only_like_count / total_flows,
    }


def summarize_flows(
    flows: list[dict[str, Any]],
    input_path: Path,
    top_n: int,
    bins: int,
    invalid_info: dict[str, Any],
) -> dict[str, Any]:
    inter_arrival_times = calc_flow_inter_arrival_times(flows)
    packet_total = sum(flow["packet_count"] for flow in flows)
    byte_total = sum(flow["byte_count"] for flow in flows)
    start_times = [flow["start_time"] for flow in flows]
    end_times = [flow["end_time"] for flow in flows]

    tcp_flag_totals = {
        "syn_count": sum(flow["syn_count"] for flow in flows),
        "syn_ack_count": sum(flow["syn_ack_count"] for flow in flows),
        "ack_count": sum(flow["ack_count"] for flow in flows),
        "fin_count": sum(flow["fin_count"] for flow in flows),
        "rst_count": sum(flow["rst_count"] for flow in flows),
    }

    total_flows = len(flows)
    tcp_flag_rates_per_flow = {
        key.replace("_count", "_per_flow"): (
            value / total_flows if total_flows > 0 else 0.0
        )
        for key, value in tcp_flag_totals.items()
    }

    summary: dict[str, Any] = {
        "meta": {
            "schema_version": "2.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "script": str(Path(__file__).resolve()),
            "input_file": str(input_path),
        },
        "scope": {
            "dataset_name": input_path.stem,
            "flow_definition": "bidirectional 5-tuple flow",
            "flow_inter_arrival_time_definition": (
                "difference between adjacent flow start times after global sort"
            ),
            "feature_units": {
                feature_name: spec["unit"]
                for feature_name, spec in FEATURE_SPECS.items()
            },
        },
        "totals": {
            "valid_flow_count": total_flows,
            "invalid_row_count": invalid_info["invalid_row_count"],
            "packet_total": packet_total,
            "byte_total": byte_total,
            "first_start_time": min(start_times) if start_times else None,
            "last_end_time": max(end_times) if end_times else None,
            "capture_span_seconds": (
                max(end_times) - min(start_times) if start_times and end_times else 0.0
            ),
        },
        "invalid_rows": invalid_info,
        "features": {},
        "protocol_summary": summarize_protocols(flows),
        "behavioral_indicators": summarize_behavioral_indicators(flows),
        "tcp_flag_totals": tcp_flag_totals,
        "tcp_flag_rates_per_flow": tcp_flag_rates_per_flow,
        "top": {},
    }

    feature_values = {
        "flow_inter_arrival_time": inter_arrival_times,
        "duration": [flow["duration"] for flow in flows],
        "packet_count": [float(flow["packet_count"]) for flow in flows],
        "byte_count": [float(flow["byte_count"]) for flow in flows],
        "pps": [flow["pps"] for flow in flows],
        "bps": [flow["bps"] for flow in flows],
        "avg_packet_size": [flow["avg_packet_size"] for flow in flows],
        "packets_from_src_ratio": [flow["packets_from_src_ratio"] for flow in flows],
        "bytes_from_src_ratio": [flow["bytes_from_src_ratio"] for flow in flows],
    }

    for feature_name, values in feature_values.items():
        summary["features"][feature_name] = {
            "unit": FEATURE_SPECS[feature_name]["unit"],
            "description": FEATURE_SPECS[feature_name]["description"],
            "log_scale_recommended": FEATURE_SPECS[feature_name]["log_scale_recommended"],
            **summarize_numeric(values, bins),
        }

    protocol_counter = Counter(flow["protocol"] for flow in flows)
    summary["protocol_counts"] = {
        str(proto): count
        for proto, count in sorted(protocol_counter.items())
    }

    for key in TOP_KEYS:
        summary["top"][f"by_{key}"] = top_records(flows, key, top_n)

    return summary


def save_json(obj: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def print_short_summary(summary: dict[str, Any]) -> None:
    print(f"valid_flow_count = {summary['totals']['valid_flow_count']}")
    print(f"invalid_row_count = {summary['totals']['invalid_row_count']}")

    for feature_name, feature_summary in summary["features"].items():
        stats = feature_summary["stats"]
        print(
            f"{feature_name}: "
            f"count={stats['count']} "
            f"min={stats['min']:.6f} "
            f"median={stats['median']:.6f} "
            f"mean={stats['mean']:.6f} "
            f"p95={stats['p95']:.6f} "
            f"max={stats['max']:.6f}"
        )

    print("tcp_flag_totals:")
    for key, value in summary["tcp_flag_totals"].items():
        print(f"  {key} = {value}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Summarize flow-level features from flow CSV.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_args = parser.add_argument_group("required arguments")
    optional_args = parser.add_argument_group("options")
    required_args.add_argument(
        "--input",
        type=Path,
        required=True,
        help="input flow CSV path",
    )
    optional_args.add_argument(
        "--output",
        type=Path,
        default=None,
        help="output summary JSON path",
    )
    optional_args.add_argument(
        "--top-n",
        type=int,
        default=20,
        help="number of top flows to include",
    )
    optional_args.add_argument(
        "--hist-bins",
        type=int,
        default=20,
        help="number of histogram bins to include in JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    input_path = resolve_from_repo_root(args.input)

    if args.output is None:
        output_dir = default_output_dir_for_input(input_path)
        output_path = output_dir / f"{input_path.stem}_features.json"
    else:
        output_path = resolve_from_repo_root(args.output)

    if args.hist_bins <= 0:
        print("[error] --hist-bins must be > 0")
        return 1

    if not input_path.exists():
        print(f"[error] input not found: {input_path}")
        return 1

    try:
        flows, invalid_info = load_flows(input_path)
        summary = summarize_flows(
            flows=flows,
            input_path=input_path,
            top_n=args.top_n,
            bins=args.hist_bins,
            invalid_info=invalid_info,
        )
    except ValueError as exc:
        print(f"[error] {exc}")
        return 1

    save_json(summary, output_path)
    print_short_summary(summary)
    print(f"[done] saved: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
