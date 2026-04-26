#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from cli_output import format_tagged

DEFAULT_CONFIG_PATH = REPO_ROOT / "config/prefix_selection.yaml"
pd = None
yaml = None


def require_pandas() -> Any:
    global pd
    if pd is None:
        import pandas as pandas_module

        pd = pandas_module
    return pd


def require_yaml() -> Any:
    global yaml
    if yaml is None:
        import yaml as yaml_module

        yaml = yaml_module
    return yaml


def parse_scalar_yaml_value(raw: str) -> Any:
    text = raw.strip()
    if not text:
        return ""
    if text.lower() in {"true", "false"}:
        return text.lower() == "true"
    try:
        if any(char in text for char in (".", "e", "E")):
            return float(text)
        return int(text)
    except ValueError:
        return text


def load_yaml_mapping_file(path: Path) -> dict[str, Any]:
    try:
        yaml_module = require_yaml()
    except ModuleNotFoundError:
        yaml_module = None

    with path.open("r", encoding="utf-8") as handle:
        if yaml_module is not None:
            config = yaml_module.safe_load(handle)
        else:
            root: dict[str, Any] = {}
            nested_key: str | None = None
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.rstrip("\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if line.startswith((" ", "\t")):
                    if nested_key is None:
                        raise ValueError(f"Invalid nested YAML at line {line_number}: {line}")
                    child_text = stripped
                    if ":" not in child_text:
                        raise ValueError(f"Invalid YAML mapping at line {line_number}: {line}")
                    child_key, child_value = child_text.split(":", 1)
                    nested = root.setdefault(nested_key, {})
                    if not isinstance(nested, dict):
                        raise ValueError(f"Invalid YAML structure near line {line_number}: {line}")
                    nested[child_key.strip()] = parse_scalar_yaml_value(child_value)
                    continue

                if ":" not in stripped:
                    raise ValueError(f"Invalid YAML mapping at line {line_number}: {line}")
                key, value = stripped.split(":", 1)
                key = key.strip()
                if value.strip() == "":
                    root[key] = {}
                    nested_key = key
                else:
                    root[key] = parse_scalar_yaml_value(value)
                    nested_key = None
            config = root

    if not isinstance(config, dict):
        raise ValueError("Config file must contain a YAML mapping.")
    return config

REQUIRED_CONFIG_KEYS = {
    "prefix_len",
    "min_flows",
    "min_packets",
    "min_bytes",
    "max_short_flow_ratio",
    "max_tiny_flow_ratio",
    "max_syn_only_like_ratio",
    "max_rst_observed_ratio",
    "short_duration_threshold",
    "tiny_packet_threshold",
    "top_k",
    "score_weights",
}

REQUIRED_SCORE_WEIGHT_KEYS = {
    "flow_count",
    "packet_count",
    "byte_count",
    "low_short_flow_ratio",
    "low_tiny_flow_ratio",
    "low_syn_only_like_ratio",
}

REQUIRED_FLOW_COLUMNS = {
    "dst_ip",
    "protocol",
    "duration",
    "packet_count",
    "byte_count",
    "packets_from_src",
    "packets_from_dst",
    "bytes_from_src",
    "bytes_from_dst",
}

OPTIONAL_NUMERIC_FLOW_COLUMNS = {
    "syn_count",
    "ack_count",
    "rst_count",
}

REQUIRED_AGURI_COLUMNS = {
    "aggregate_id",
    "src_prefix",
    "dst_prefix",
    "bytes",
    "byte_ratio",
    "packets",
    "packet_ratio",
    "protocol_breakdown",
}

OPTIONAL_AGURI_COLUMNS = {
    "tcp_byte_ratio",
    "tcp_packet_ratio",
    "udp_byte_ratio",
    "udp_packet_ratio",
}

OUTPUT_COLUMNS = [
    "aggregate_id",
    "src_prefix",
    "dst_prefix",
    "normalized_dst_prefix",
    "match_status",
    "ip_version",
    "prefix_length",
    "prefix_is_host",
    "prefix_is_broader_than_target",
    "prefix_specificity_ratio",
    "aguri_bytes",
    "aguri_byte_ratio",
    "aguri_packets",
    "aguri_packet_ratio",
    "aguri_tcp_byte_ratio",
    "aguri_tcp_packet_ratio",
    "aguri_udp_byte_ratio",
    "aguri_udp_packet_ratio",
    "flow_count",
    "packet_count",
    "byte_count",
    "tcp_flow_ratio",
    "udp_flow_ratio",
    "other_flow_ratio",
    "dominant_l4_flow_ratio",
    "avg_duration",
    "median_duration",
    "avg_packet_size",
    "short_flow_ratio",
    "tiny_flow_ratio",
    "syn_only_like_ratio",
    "rst_observed_ratio",
    "avg_packets_from_src_ratio",
    "avg_bytes_from_src_ratio",
    "scan_candidate",
    "passes_filters",
    "score",
    "protocol_breakdown",
]


@dataclass(frozen=True)
class PrefixInfo:
    original: str
    normalized: str
    network: ipaddress.IPv4Network | ipaddress.IPv6Network

    @property
    def ip_version(self) -> int:
        return self.network.version

    @property
    def prefix_length(self) -> int:
        return self.network.prefixlen

    @property
    def is_host(self) -> bool:
        return self.network.prefixlen == self.network.max_prefixlen


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def default_output_dir(aguri_path: Path) -> Path:
    name = aguri_path.name
    suffix = ".aguri_candidates.csv"
    stem = name[: -len(suffix)] if name.endswith(suffix) else aguri_path.stem
    return REPO_ROOT / "results/prefix" / stem


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate aguri prefix candidates using flow CSV.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_args = parser.add_argument_group("required arguments")
    optional_args = parser.add_argument_group("options")
    required_args.add_argument("--flows", required=True, type=Path, help="Input flow CSV.")
    required_args.add_argument("--aguri", required=True, type=Path, help="Input aguri_candidates.csv.")
    optional_args.add_argument(
        "--config",
        type=Path,
        default=Path("config/prefix_selection.yaml"),
        help=f"prefix_selection.yaml path; if omitted, use {DEFAULT_CONFIG_PATH}",
    )
    optional_args.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory. If omitted, use results/prefix/<aguri_dataset_name>.",
    )
    return parser.parse_args()


def ensure_file_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"{label} is not a file: {path}")


def load_config(path: Path) -> tuple[dict[str, Any], list[str]]:
    ensure_file_exists(path, "Config file")
    config = load_yaml_mapping_file(path)

    missing_keys = sorted(REQUIRED_CONFIG_KEYS - set(config))
    if missing_keys:
        raise ValueError(f"Config is missing required keys: {', '.join(missing_keys)}")

    if not isinstance(config["score_weights"], dict):
        raise ValueError("Config key 'score_weights' must be a mapping.")

    missing_weight_keys = sorted(REQUIRED_SCORE_WEIGHT_KEYS - set(config["score_weights"]))
    if missing_weight_keys:
        raise ValueError(
            "Config score_weights is missing required keys: "
            + ", ".join(missing_weight_keys)
        )

    warnings: list[str] = []
    int_keys = ["prefix_len", "min_flows", "min_packets", "min_bytes", "tiny_packet_threshold", "top_k"]
    float_keys = [
        "max_short_flow_ratio",
        "max_tiny_flow_ratio",
        "max_syn_only_like_ratio",
        "max_rst_observed_ratio",
        "short_duration_threshold",
    ]

    for key in int_keys:
        try:
            config[key] = int(config[key])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Config key '{key}' must be an integer.") from exc

    for key in float_keys:
        try:
            config[key] = float(config[key])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Config key '{key}' must be a float.") from exc

    if config["prefix_len"] < 0:
        raise ValueError("Config key 'prefix_len' must be >= 0.")
    if config["top_k"] <= 0:
        raise ValueError("Config key 'top_k' must be > 0.")
    if config["tiny_packet_threshold"] < 0:
        raise ValueError("Config key 'tiny_packet_threshold' must be >= 0.")

    for key in (
        "max_short_flow_ratio",
        "max_tiny_flow_ratio",
        "max_syn_only_like_ratio",
        "max_rst_observed_ratio",
    ):
        if not 0.0 <= config[key] <= 1.0:
            raise ValueError(f"Config key '{key}' must be between 0.0 and 1.0.")

    weights = {}
    for key, value in config["score_weights"].items():
        try:
            weights[key] = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Score weight '{key}' must be numeric.") from exc

    negative_weights = sorted(key for key, value in weights.items() if value < 0.0)
    if negative_weights:
        raise ValueError(
            "Score weights must be non-negative. Invalid keys: "
            + ", ".join(negative_weights)
        )

    weight_sum = sum(weights.values())
    if weight_sum <= 0.0:
        raise ValueError("Score weights must sum to a positive value.")
    if not math.isclose(weight_sum, 1.0, rel_tol=1e-6, abs_tol=1e-6):
        warnings.append(
            f"score_weights sum to {weight_sum:.6f}; weights were normalized to 1.0."
        )
        weights = {key: value / weight_sum for key, value in weights.items()}

    config["score_weights"] = weights
    return config, warnings


def load_csv(path: Path, label: str) -> pd.DataFrame:
    pd_module = require_pandas()
    ensure_file_exists(path, label)
    try:
        return pd_module.read_csv(path)
    except Exception as exc:  # pragma: no cover - pandas exception type is broad
        raise ValueError(f"Failed to read {label}: {path}") from exc


def validate_columns(df: pd.DataFrame, required: set[str], label: str) -> None:
    missing = sorted(required - set(df.columns))
    if missing:
        raise ValueError(f"{label} is missing required columns: {', '.join(missing)}")


def parse_prefix(prefix: str) -> PrefixInfo | None:
    text = str(prefix).strip()
    if not text or text == "*" or text.lower() == "nan":
        return None

    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None

    return PrefixInfo(original=text, normalized=str(network), network=network)


def prepare_flows(flows: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    validate_columns(flows, REQUIRED_FLOW_COLUMNS, "Flow CSV")

    prepared = flows.copy()
    warnings: list[str] = []

    for column in REQUIRED_FLOW_COLUMNS | OPTIONAL_NUMERIC_FLOW_COLUMNS:
        if column in prepared.columns and column != "dst_ip" and column != "protocol":
            prepared[column] = pd.to_numeric(prepared[column], errors="coerce")

    numeric_with_nulls = [
        column
        for column in (REQUIRED_FLOW_COLUMNS - {"dst_ip", "protocol"})
        if prepared[column].isna().any()
    ]
    if numeric_with_nulls:
        raise ValueError(
            "Flow CSV contains non-numeric values in required columns: "
            + ", ".join(sorted(numeric_with_nulls))
        )

    for column in OPTIONAL_NUMERIC_FLOW_COLUMNS:
        if column not in prepared.columns:
            prepared[column] = 0
        prepared[column] = prepared[column].fillna(0)

    prepared["_dst_ip_obj"] = prepared["dst_ip"].map(parse_ip_address)
    invalid_ip_count = int(prepared["_dst_ip_obj"].isna().sum())
    if invalid_ip_count:
        warnings.append(
            f"Flow CSV contains {invalid_ip_count} rows with invalid dst_ip; those rows will never match."
        )

    total_packets = prepared["packets_from_src"] + prepared["packets_from_dst"]
    total_bytes = prepared["bytes_from_src"] + prepared["bytes_from_dst"]
    prepared["packets_from_src_ratio"] = (
        prepared["packets_from_src"] / total_packets.where(total_packets > 0, other=1)
    )
    prepared["bytes_from_src_ratio"] = (
        prepared["bytes_from_src"] / total_bytes.where(total_bytes > 0, other=1)
    )
    return prepared, warnings


def prepare_aguri(aguri: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    validate_columns(aguri, REQUIRED_AGURI_COLUMNS, "aguri CSV")

    prepared = aguri.copy()
    warnings: list[str] = []

    for column in ["aggregate_id", "src_prefix", "dst_prefix", "protocol_breakdown"]:
        prepared[column] = prepared[column].astype(str)

    numeric_columns = list((REQUIRED_AGURI_COLUMNS | OPTIONAL_AGURI_COLUMNS) - {"aggregate_id", "src_prefix", "dst_prefix", "protocol_breakdown"})
    for column in numeric_columns:
        if column not in prepared.columns:
            prepared[column] = 0.0
        prepared[column] = pd.to_numeric(prepared[column], errors="coerce")

    invalid_numeric = [column for column in numeric_columns if prepared[column].isna().any()]
    if invalid_numeric:
        raise ValueError(
            "aguri CSV contains non-numeric values in required columns: "
            + ", ".join(sorted(invalid_numeric))
        )

    prepared["_prefix_info"] = prepared["dst_prefix"].map(parse_prefix)
    invalid_prefix_count = int(prepared["_prefix_info"].isna().sum())
    if invalid_prefix_count:
        warnings.append(
            f"aguri CSV contains {invalid_prefix_count} invalid or wildcard dst_prefix values; those rows were skipped."
        )

    return prepared, warnings


def parse_ip_address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def flow_match_mask(
    flows: pd.DataFrame,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> pd.Series:
    if network.prefixlen == network.max_prefixlen:
        return flows["dst_ip"].astype(str) == str(network.network_address)

    def matcher(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> bool:
        return ip_obj is not None and ip_obj.version == network.version and ip_obj in network

    return flows["_dst_ip_obj"].map(matcher)


def safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator) / float(denominator)


def evaluate_prefix_metrics(
    flows: pd.DataFrame,
    prefix_info: PrefixInfo,
    config: dict[str, Any],
) -> dict[str, Any] | None:
    matched = flows.loc[flow_match_mask(flows, prefix_info.network)].copy()
    if matched.empty:
        return None

    short_duration_threshold = config["short_duration_threshold"]
    tiny_packet_threshold = config["tiny_packet_threshold"]
    target_prefix_len = config["prefix_len"]

    matched["is_short_flow"] = matched["duration"] <= short_duration_threshold
    matched["is_tiny_flow"] = matched["packet_count"] <= tiny_packet_threshold
    matched["is_syn_only_like"] = (
        (matched["protocol"].astype(str) == "6")
        & (matched["syn_count"] > 0)
        & (matched["ack_count"] == 0)
        & (matched["packet_count"] <= tiny_packet_threshold)
    )
    matched["has_rst"] = matched["rst_count"] > 0

    protocol_text = matched["protocol"].astype(str).str.upper()
    tcp_mask = protocol_text.isin(["6", "TCP"])
    udp_mask = protocol_text.isin(["17", "UDP"])

    flow_count = int(len(matched))
    packet_count = int(matched["packet_count"].sum())
    byte_count = int(matched["byte_count"].sum())

    prefix_is_broader_than_target = (
        prefix_info.ip_version == 4
        and not prefix_info.is_host
        and prefix_info.prefix_length < target_prefix_len
    )
    prefix_specificity_ratio = 1.0
    if prefix_info.ip_version == 4 and not prefix_info.is_host and target_prefix_len > 0:
        prefix_specificity_ratio = min(prefix_info.prefix_length / target_prefix_len, 1.0)

    return {
        "normalized_dst_prefix": prefix_info.normalized,
        "match_status": "matched",
        "ip_version": prefix_info.ip_version,
        "prefix_length": prefix_info.prefix_length,
        "prefix_is_host": prefix_info.is_host,
        "prefix_is_broader_than_target": prefix_is_broader_than_target,
        "prefix_specificity_ratio": prefix_specificity_ratio,
        "flow_count": flow_count,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "tcp_flow_ratio": safe_ratio(int(tcp_mask.sum()), flow_count),
        "udp_flow_ratio": safe_ratio(int(udp_mask.sum()), flow_count),
        "other_flow_ratio": safe_ratio(int((~(tcp_mask | udp_mask)).sum()), flow_count),
        "dominant_l4_flow_ratio": max(
            safe_ratio(int(tcp_mask.sum()), flow_count),
            safe_ratio(int(udp_mask.sum()), flow_count),
        ),
        "avg_duration": float(matched["duration"].mean()),
        "median_duration": float(matched["duration"].median()),
        "avg_packet_size": safe_ratio(byte_count, packet_count),
        "short_flow_ratio": float(matched["is_short_flow"].mean()),
        "tiny_flow_ratio": float(matched["is_tiny_flow"].mean()),
        "syn_only_like_ratio": float(matched["is_syn_only_like"].mean()),
        "rst_observed_ratio": float(matched["has_rst"].mean()),
        "avg_packets_from_src_ratio": float(matched["packets_from_src_ratio"].mean()),
        "avg_bytes_from_src_ratio": float(matched["bytes_from_src_ratio"].mean()),
        "scan_candidate": bool(
            matched["is_syn_only_like"].mean() > config["max_syn_only_like_ratio"]
            or matched["is_tiny_flow"].mean() > config["max_tiny_flow_ratio"]
            or matched["is_short_flow"].mean() > config["max_short_flow_ratio"]
        ),
    }


def build_evaluation_rows(
    flows: pd.DataFrame,
    aguri: pd.DataFrame,
    config: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    metrics_cache: dict[str, dict[str, Any] | None] = {}

    for _, aguri_row in aguri.iterrows():
        prefix_info = aguri_row["_prefix_info"]
        if prefix_info is None:
            continue

        cache_key = prefix_info.normalized
        if cache_key not in metrics_cache:
            metrics_cache[cache_key] = evaluate_prefix_metrics(flows, prefix_info, config)

        metrics = metrics_cache[cache_key]
        row = {
            "aggregate_id": aguri_row["aggregate_id"],
            "src_prefix": aguri_row["src_prefix"],
            "dst_prefix": aguri_row["dst_prefix"],
            "aguri_bytes": int(aguri_row["bytes"]),
            "aguri_byte_ratio": float(aguri_row["byte_ratio"]),
            "aguri_packets": int(aguri_row["packets"]),
            "aguri_packet_ratio": float(aguri_row["packet_ratio"]),
            "aguri_tcp_byte_ratio": float(aguri_row.get("tcp_byte_ratio", 0.0)),
            "aguri_tcp_packet_ratio": float(aguri_row.get("tcp_packet_ratio", 0.0)),
            "aguri_udp_byte_ratio": float(aguri_row.get("udp_byte_ratio", 0.0)),
            "aguri_udp_packet_ratio": float(aguri_row.get("udp_packet_ratio", 0.0)),
            "protocol_breakdown": aguri_row.get("protocol_breakdown", ""),
        }
        if metrics is None:
            warnings.append(
                f"No flows matched dst_prefix={prefix_info.original} (normalized={prefix_info.normalized})."
            )
            row.update(
                {
                    "normalized_dst_prefix": prefix_info.normalized,
                    "match_status": "no_matching_flows",
                    "ip_version": prefix_info.ip_version,
                    "prefix_length": prefix_info.prefix_length,
                    "prefix_is_host": prefix_info.is_host,
                    "prefix_is_broader_than_target": (
                        prefix_info.ip_version == 4
                        and not prefix_info.is_host
                        and prefix_info.prefix_length < config["prefix_len"]
                    ),
                    "prefix_specificity_ratio": (
                        min(prefix_info.prefix_length / config["prefix_len"], 1.0)
                        if prefix_info.ip_version == 4
                        and not prefix_info.is_host
                        and config["prefix_len"] > 0
                        else 1.0
                    ),
                    "flow_count": 0,
                    "packet_count": 0,
                    "byte_count": 0,
                    "tcp_flow_ratio": 0.0,
                    "udp_flow_ratio": 0.0,
                    "other_flow_ratio": 0.0,
                    "dominant_l4_flow_ratio": 0.0,
                    "avg_duration": 0.0,
                    "median_duration": 0.0,
                    "avg_packet_size": 0.0,
                    "short_flow_ratio": 0.0,
                    "tiny_flow_ratio": 0.0,
                    "syn_only_like_ratio": 0.0,
                    "rst_observed_ratio": 0.0,
                    "avg_packets_from_src_ratio": 0.0,
                    "avg_bytes_from_src_ratio": 0.0,
                    "scan_candidate": False,
                }
            )
        else:
            row.update(metrics)
        rows.append(row)

    return rows, warnings


def add_score(df: pd.DataFrame, config: dict[str, Any]) -> pd.DataFrame:
    if df.empty:
        scored = df.copy()
        scored["score"] = pd.Series(dtype=float)
        return scored

    weights = config["score_weights"]
    scored = df.copy()
    scored["score"] = (
        scored["flow_count"].rank(method="average", pct=True) * weights["flow_count"]
        + scored["packet_count"].rank(method="average", pct=True) * weights["packet_count"]
        + scored["byte_count"].rank(method="average", pct=True) * weights["byte_count"]
        + (1.0 - scored["short_flow_ratio"]) * weights["low_short_flow_ratio"]
        + (1.0 - scored["tiny_flow_ratio"]) * weights["low_tiny_flow_ratio"]
        + (1.0 - scored["syn_only_like_ratio"]) * weights["low_syn_only_like_ratio"]
    )
    scored["score"] = scored["score"].fillna(0.0)
    return scored.sort_values(["score", "flow_count", "packet_count", "byte_count"], ascending=False)


def apply_filters(df: pd.DataFrame, config: dict[str, Any]) -> pd.DataFrame:
    if df.empty:
        filtered = df.copy()
        filtered["passes_filters"] = pd.Series(dtype=bool)
        return filtered

    passes = (
        (df["flow_count"] >= config["min_flows"])
        & (df["packet_count"] >= config["min_packets"])
        & (df["byte_count"] >= config["min_bytes"])
        & (df["short_flow_ratio"] <= config["max_short_flow_ratio"])
        & (df["tiny_flow_ratio"] <= config["max_tiny_flow_ratio"])
        & (df["syn_only_like_ratio"] <= config["max_syn_only_like_ratio"])
        & (df["rst_observed_ratio"] <= config["max_rst_observed_ratio"])
        & (~df["prefix_is_broader_than_target"])
    )

    filtered = df.copy()
    filtered["passes_filters"] = passes
    return filtered


def finalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    finalized = df.copy()
    for column in OUTPUT_COLUMNS:
        if column not in finalized.columns:
            finalized[column] = pd.Series(dtype=float)

    string_columns = [
        "src_prefix",
        "dst_prefix",
        "normalized_dst_prefix",
        "match_status",
        "protocol_breakdown",
    ]
    for column in string_columns:
        if column in finalized.columns:
            finalized[column] = finalized[column].fillna("").astype(str)

    numeric_columns = [
        "aguri_byte_ratio",
        "aguri_packet_ratio",
        "aguri_tcp_byte_ratio",
        "aguri_tcp_packet_ratio",
        "aguri_udp_byte_ratio",
        "aguri_udp_packet_ratio",
        "tcp_flow_ratio",
        "udp_flow_ratio",
        "other_flow_ratio",
        "dominant_l4_flow_ratio",
        "avg_duration",
        "median_duration",
        "avg_packet_size",
        "short_flow_ratio",
        "tiny_flow_ratio",
        "syn_only_like_ratio",
        "rst_observed_ratio",
        "avg_packets_from_src_ratio",
        "avg_bytes_from_src_ratio",
        "prefix_specificity_ratio",
        "score",
    ]
    for column in numeric_columns:
        if column in finalized.columns:
            finalized[column] = pd.to_numeric(finalized[column], errors="coerce").fillna(0.0)

    boolean_columns = [
        "prefix_is_host",
        "prefix_is_broader_than_target",
        "scan_candidate",
        "passes_filters",
    ]
    for column in boolean_columns:
        if column in finalized.columns:
            finalized[column] = finalized[column].map(
                lambda value: value if isinstance(value, bool) else str(value).strip().lower() == "true"
            )

    int_columns = [
        "aggregate_id",
        "ip_version",
        "prefix_length",
        "aguri_bytes",
        "aguri_packets",
        "flow_count",
        "packet_count",
        "byte_count",
    ]
    for column in int_columns:
        if column in finalized.columns:
            finalized[column] = pd.to_numeric(finalized[column], errors="coerce").fillna(0).astype(int)

    return finalized.loc[:, OUTPUT_COLUMNS]


def write_outputs(
    evaluation: pd.DataFrame,
    selected: pd.DataFrame,
    out_dir: Path,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    evaluation_path = out_dir / "prefix_evaluation.csv"
    selected_path = out_dir / "selected_prefixes.csv"
    evaluation.to_csv(evaluation_path, index=False)
    selected.to_csv(selected_path, index=False)
    return evaluation_path, selected_path


def main() -> int:
    args = parse_args()
    flows_path = resolve_from_repo_root(args.flows.expanduser())
    aguri_path = resolve_from_repo_root(args.aguri.expanduser())
    config_path = resolve_from_repo_root(args.config.expanduser())
    out_dir = (
        resolve_from_repo_root(args.out_dir.expanduser())
        if args.out_dir is not None
        else default_output_dir(aguri_path)
    )

    try:
        config, config_warnings = load_config(config_path)
        flows_raw = load_csv(flows_path, "Flow CSV")
        aguri_raw = load_csv(aguri_path, "aguri CSV")
        flows, flow_warnings = prepare_flows(flows_raw)
        aguri, aguri_warnings = prepare_aguri(aguri_raw)
        rows, evaluation_warnings = build_evaluation_rows(flows, aguri, config)
    except (FileNotFoundError, ValueError) as exc:
        print(format_tagged("Error:", str(exc), "red", stream=sys.stderr), file=sys.stderr)
        return 1

    warnings = config_warnings + flow_warnings + aguri_warnings + evaluation_warnings

    evaluation = finalize_columns(add_score(pd.DataFrame(rows), config))
    evaluation_with_flags = finalize_columns(apply_filters(evaluation, config))
    selected = finalize_columns(
        evaluation_with_flags.loc[evaluation_with_flags["passes_filters"]].head(config["top_k"])
    )

    if evaluation["score"].isna().any():
        print(format_tagged("Error:", "score calculation produced NaN.", "red", stream=sys.stderr), file=sys.stderr)
        return 1

    evaluation_path, selected_path = write_outputs(evaluation_with_flags, selected, out_dir)

    for warning in warnings:
        print(format_tagged("[WARN]", warning, "yellow", stream=sys.stderr), file=sys.stderr)

    if evaluation_with_flags.empty:
        print(
            format_tagged("[WARN]", "No valid prefix candidates were evaluated.", "yellow", stream=sys.stderr),
            file=sys.stderr,
        )
    if selected.empty:
        print(
            format_tagged("[WARN]", "No prefixes passed the configured filters.", "yellow", stream=sys.stderr),
            file=sys.stderr,
        )

    print(format_tagged("[DONE]", f"evaluated prefixes: {len(evaluation_with_flags)}", "green"))
    print(format_tagged("[DONE]", f"selected prefixes: {len(selected)}", "green"))
    print(f"evaluation: {evaluation_path}")
    print(f"selected:   {selected_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
