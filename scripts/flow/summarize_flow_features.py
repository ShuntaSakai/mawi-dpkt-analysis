#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
from array import array
from collections import Counter, defaultdict
from datetime import datetime, timezone
from heapq import heappush, heapreplace
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


TOP_RECORD_FIELDS = (
    "flow_id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "duration",
    "packet_count",
    "byte_count",
    "avg_packet_size",
    "packets_from_src_ratio",
    "bytes_from_src_ratio",
)


class TopNTracker:
    def __init__(self, key: str, limit: int) -> None:
        self.key = key
        self.limit = limit
        self._heap: list[tuple[float, int, dict[str, Any]]] = []

    def add(self, flow: dict[str, Any]) -> None:
        record = {field: flow[field] for field in TOP_RECORD_FIELDS}
        record[self.key] = flow[self.key]
        item = (float(flow[self.key]), int(flow["flow_id"]), record)

        if len(self._heap) < self.limit:
            heappush(self._heap, item)
            return

        if item > self._heap[0]:
            heapreplace(self._heap, item)

    def records_desc(self) -> list[dict[str, Any]]:
        return [
            record
            for _, _, record in sorted(
                self._heap,
                key=lambda item: (item[0], item[1]),
                reverse=True,
            )
        ]


class OnlineStats:
    def __init__(self) -> None:
        self.count = 0
        self.min_value = 0.0
        self.max_value = 0.0
        self.mean_value = 0.0
        self.m2 = 0.0

    def add(self, value: float) -> None:
        self.count += 1
        if self.count == 1:
            self.min_value = value
            self.max_value = value
            self.mean_value = value
            self.m2 = 0.0
            return

        if value < self.min_value:
            self.min_value = value
        if value > self.max_value:
            self.max_value = value

        delta = value - self.mean_value
        self.mean_value += delta / self.count
        delta2 = value - self.mean_value
        self.m2 += delta * delta2

    def basic_stats(self) -> dict[str, float | int]:
        if self.count == 0:
            return {
                "count": 0,
                "min": 0.0,
                "max": 0.0,
                "mean": 0.0,
                "population_variance": 0.0,
                "population_stddev": 0.0,
            }

        variance = self.m2 / self.count
        return {
            "count": self.count,
            "min": self.min_value,
            "max": self.max_value,
            "mean": self.mean_value,
            "population_variance": variance,
            "population_stddev": math.sqrt(variance),
        }


class FeatureCollector:
    def __init__(self) -> None:
        self.values = array("d")
        self.stats = OnlineStats()

    def add(self, value: float) -> None:
        self.values.append(value)
        self.stats.add(value)

    def summarize(self, bins: int) -> dict[str, Any]:
        values = self.values
        if not values:
            return {
                "stats": {
                    **self.stats.basic_stats(),
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


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def default_output_dir_for_input(input_path: Path) -> Path:
    try:
        relative_input = input_path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return REPO_ROOT / "results" / "features" / "all" / input_path.stem

    if relative_input.parts[:3] == ("results", "flows", "all"):
        dataset_parts = relative_input.parts[3:-1]
        if dataset_parts:
            return REPO_ROOT / "results" / "features" / "all" / Path(*dataset_parts)
        return REPO_ROOT / "results" / "features" / "all" / input_path.stem

    if relative_input.parts[:3] == ("results", "flows", "prefix"):
        prefix_parts = relative_input.parts[3:-1]
        if prefix_parts:
            return REPO_ROOT / "results" / "features" / "prefix" / Path(*prefix_parts)
        return REPO_ROOT / "results/features/prefix"

    return REPO_ROOT / "results" / "features" / "all" / input_path.stem


def default_output_filename_for_input(input_path: Path) -> str:
    try:
        relative_input = input_path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return "features.json"

    if relative_input.parts[:3] == ("results", "flows", "all"):
        return "features.json"

    if relative_input.parts[:3] == ("results", "flows", "prefix"):
        return f"{input_path.stem}_features.json"

    return "features.json"


def infer_dataset_name(input_path: Path) -> str:
    try:
        relative_input = input_path.resolve().relative_to(REPO_ROOT.resolve())
    except ValueError:
        return input_path.stem

    if relative_input.parts[:3] == ("results", "flows", "all") and len(relative_input.parts) >= 5:
        return relative_input.parts[3]

    return input_path.stem


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


def summarize_csv(
    csv_path: Path,
    input_path: Path,
    dataset_name: str,
    top_n: int,
    bins: int,
) -> dict[str, Any]:
    invalid_row_examples: list[dict[str, Any]] = []
    invalid_row_count = 0
    total_flows = 0
    packet_total = 0
    byte_total = 0
    first_start_time: float | None = None
    last_end_time: float | None = None

    feature_collectors: dict[str, FeatureCollector] = {
        "duration": FeatureCollector(),
        "packet_count": FeatureCollector(),
        "byte_count": FeatureCollector(),
        "pps": FeatureCollector(),
        "bps": FeatureCollector(),
        "avg_packet_size": FeatureCollector(),
        "packets_from_src_ratio": FeatureCollector(),
        "bytes_from_src_ratio": FeatureCollector(),
    }
    start_times = array("d")
    protocol_counter: Counter[int] = Counter()
    protocol_packet_totals: Counter[int] = Counter()
    protocol_byte_totals: Counter[int] = Counter()
    protocol_duration_collectors: dict[int, FeatureCollector] = defaultdict(FeatureCollector)
    tcp_flag_totals = {
        "syn_count": 0,
        "syn_ack_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
    }
    short_flow_count = 0
    tiny_flow_count = 0
    rst_flow_count = 0
    syn_only_like_count = 0
    top_trackers = {
        key: TopNTracker(key=key, limit=top_n)
        for key in TOP_KEYS
    }

    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        validate_csv_header(reader.fieldnames)

        for row_number, row in enumerate(reader, start=2):
            try:
                flow = parse_flow_row(row)
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

                continue

            total_flows += 1
            packet_total += flow["packet_count"]
            byte_total += flow["byte_count"]

            start_time = flow["start_time"]
            end_time = flow["end_time"]
            start_times.append(start_time)
            first_start_time = start_time if first_start_time is None else min(first_start_time, start_time)
            last_end_time = end_time if last_end_time is None else max(last_end_time, end_time)

            for feature_name, collector in feature_collectors.items():
                collector.add(float(flow[feature_name]))

            proto = flow["protocol"]
            protocol_counter[proto] += 1
            protocol_packet_totals[proto] += flow["packet_count"]
            protocol_byte_totals[proto] += flow["byte_count"]
            protocol_duration_collectors[proto].add(flow["duration"])

            for key in tcp_flag_totals:
                tcp_flag_totals[key] += flow[key]

            if flow["duration"] <= 1.0:
                short_flow_count += 1
            if flow["packet_count"] <= 3:
                tiny_flow_count += 1
            if flow["rst_count"] > 0:
                rst_flow_count += 1
            if (
                flow["syn_count"] > 0
                and flow["ack_count"] == 0
                and flow["byte_count"] == 0
            ):
                syn_only_like_count += 1

            for tracker in top_trackers.values():
                tracker.add(flow)

    inter_arrival_times = [
        sorted_start_times[i] - sorted_start_times[i - 1]
        for sorted_start_times in [sorted(start_times)]
        for i in range(1, len(sorted_start_times))
    ]

    tcp_flag_rates_per_flow = {
        key.replace("_count", "_per_flow"): (
            value / total_flows if total_flows > 0 else 0.0
        )
        for key, value in tcp_flag_totals.items()
    }

    protocol_summary: dict[str, Any] = {}
    for proto in sorted(protocol_counter):
        protocol_summary[str(proto)] = {
            "flow_count": protocol_counter[proto],
            "flow_ratio": (protocol_counter[proto] / total_flows) if total_flows > 0 else 0.0,
            "packet_total": protocol_packet_totals[proto],
            "byte_total": protocol_byte_totals[proto],
            "duration": protocol_duration_collectors[proto].summarize(bins=20)["stats"],
        }

    behavioral_indicators = {
        "short_flow_ratio_le_1s": short_flow_count / total_flows if total_flows > 0 else 0.0,
        "tiny_flow_ratio_le_3packets": tiny_flow_count / total_flows if total_flows > 0 else 0.0,
        "rst_observed_flow_ratio": rst_flow_count / total_flows if total_flows > 0 else 0.0,
        "syn_only_like_flow_ratio": syn_only_like_count / total_flows if total_flows > 0 else 0.0,
    }

    summary: dict[str, Any] = {
        "meta": {
            "schema_version": "2.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "script": str(Path(__file__).resolve()),
            "input_file": str(input_path),
        },
        "scope": {
            "dataset_name": dataset_name,
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
            "invalid_row_count": invalid_row_count,
            "packet_total": packet_total,
            "byte_total": byte_total,
            "first_start_time": first_start_time,
            "last_end_time": last_end_time,
            "capture_span_seconds": (
                (last_end_time - first_start_time)
                if first_start_time is not None and last_end_time is not None
                else 0.0
            ),
        },
        "invalid_rows": {
            "invalid_row_count": invalid_row_count,
            "invalid_row_examples": invalid_row_examples,
        },
        "features": {},
        "protocol_summary": protocol_summary,
        "behavioral_indicators": behavioral_indicators,
        "tcp_flag_totals": tcp_flag_totals,
        "tcp_flag_rates_per_flow": tcp_flag_rates_per_flow,
        "top": {},
    }

    inter_arrival_collector = FeatureCollector()
    for value in inter_arrival_times:
        inter_arrival_collector.add(value)

    combined_feature_collectors = {
        "flow_inter_arrival_time": inter_arrival_collector,
        **feature_collectors,
    }

    for feature_name, collector in combined_feature_collectors.items():
        summary["features"][feature_name] = {
            "unit": FEATURE_SPECS[feature_name]["unit"],
            "description": FEATURE_SPECS[feature_name]["description"],
            "log_scale_recommended": FEATURE_SPECS[feature_name]["log_scale_recommended"],
            **collector.summarize(bins),
        }

    summary["protocol_counts"] = {
        str(proto): count
        for proto, count in sorted(protocol_counter.items())
    }

    for key, tracker in top_trackers.items():
        summary["top"][f"by_{key}"] = tracker.records_desc()

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
        output_path = output_dir / default_output_filename_for_input(input_path)
    else:
        output_path = resolve_from_repo_root(args.output)

    if args.hist_bins <= 0:
        print("[error] --hist-bins must be > 0")
        return 1

    if not input_path.exists():
        print(f"[error] input not found: {input_path}")
        return 1

    try:
        dataset_name = infer_dataset_name(input_path)
        summary = summarize_csv(
            csv_path=input_path,
            input_path=input_path,
            dataset_name=dataset_name,
            top_n=args.top_n,
            bins=args.hist_bins,
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
