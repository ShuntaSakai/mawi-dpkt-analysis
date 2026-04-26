#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from typing import Any

import pandas as pd


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
REQUIRED_FLOW_COLUMN = "dst_ip"
REQUIRED_SELECTED_COLUMN = "normalized_dst_prefix"
COMBINED_OUTPUT_NAME = "selected_prefix_flows.csv"
INTERNAL_DST_IP_COLUMN = "_dst_ip_obj"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Filter flow CSV by selected destination prefixes."
    )
    parser.add_argument(
        "--flows",
        required=True,
        type=Path,
        help="Input full flow CSV.",
    )
    parser.add_argument(
        "--selected",
        required=True,
        type=Path,
        help="Input selected_prefixes.csv.",
    )
    parser.add_argument(
        "--out-dir",
        default=None,
        type=Path,
        help="Output directory. Defaults to results/flows/prefix/<flow_dataset_name>/",
    )
    parser.add_argument(
        "--write-separate",
        dest="write_separate",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Write one CSV per selected prefix. Default: enabled.",
    )
    parser.add_argument(
        "--write-combined",
        dest="write_combined",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Write a combined CSV for all selected prefixes. Default: disabled.",
    )
    return parser.parse_args()


def ensure_file_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"{label} is not a file: {path}")


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def default_output_dir(flows_path: Path) -> Path:
    return REPO_ROOT / "results" / "flows" / "prefix" / flows_path.stem


def warn(message: str) -> None:
    print(f"[WARN] {message}", file=sys.stderr)


def parse_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def parse_network(
    value: Any,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(str(value).strip(), strict=False)


def prefix_to_filename(prefix: str) -> str:
    return prefix.replace("/", "_").replace(":", "_")


def load_csv(path: Path, label: str) -> pd.DataFrame:
    ensure_file_exists(path, label)
    return pd.read_csv(path)


def add_dst_ip_cache(flows: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    cached = flows.copy()
    cached[INTERNAL_DST_IP_COLUMN] = cached[REQUIRED_FLOW_COLUMN].map(parse_ip)
    invalid_count = int(cached[INTERNAL_DST_IP_COLUMN].isna().sum())
    return cached, invalid_count


def build_match_mask(
    flows: pd.DataFrame,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> pd.Series:
    return flows[INTERNAL_DST_IP_COLUMN].map(
        lambda ip: ip is not None and ip.version == network.version and ip in network
    )


def build_combined_rows(
    flows: pd.DataFrame,
    selected: pd.DataFrame,
    write_separate: bool,
    out_dir: Path,
) -> tuple[list[pd.DataFrame], int]:
    combined_rows: list[pd.DataFrame] = []
    matched_prefix_count = 0

    for _, row in selected.iterrows():
        raw_prefix = row.get(REQUIRED_SELECTED_COLUMN)
        prefix = str(raw_prefix).strip()

        if not prefix or prefix.lower() == "nan":
            warn("skipped empty normalized_dst_prefix")
            continue

        try:
            network = parse_network(prefix)
        except ValueError:
            warn(f"skipped invalid prefix: {prefix}")
            continue

        mask = build_match_mask(flows, network)
        matched_base = (
            flows.loc[mask].drop(columns=[INTERNAL_DST_IP_COLUMN], errors="ignore").copy()
        )

        if matched_base.empty:
            warn(f"no flows matched prefix: {prefix}")
            continue

        matched_prefix_count += 1
        matched = matched_base.copy()
        matched["matched_prefix"] = prefix
        matched["aggregate_id"] = row["aggregate_id"] if "aggregate_id" in row.index else pd.NA
        if "prefix_score" in row.index:
            matched["prefix_score"] = row["prefix_score"]
        elif "score" in row.index:
            matched["prefix_score"] = row["score"]
        else:
            matched["prefix_score"] = pd.NA
        matched["scan_candidate"] = (
            row["scan_candidate"] if "scan_candidate" in row.index else pd.NA
        )
        matched["passes_filters"] = (
            row["passes_filters"] if "passes_filters" in row.index else pd.NA
        )
        combined_rows.append(matched)

        if write_separate:
            output_path = out_dir / f"dst_{prefix_to_filename(prefix)}.csv"
            matched_base.to_csv(output_path, index=False)
            print(f"[DONE] {prefix}: {len(matched_base)} flows -> {output_path}")

    return combined_rows, matched_prefix_count


def main() -> int:
    args = parse_args()
    flows_path = resolve_from_repo_root(args.flows.expanduser())
    selected_path = resolve_from_repo_root(args.selected.expanduser())
    out_dir = (
        resolve_from_repo_root(args.out_dir.expanduser())
        if args.out_dir is not None
        else default_output_dir(flows_path)
    )

    try:
        flows = load_csv(flows_path, "Flow CSV")
        selected = load_csv(selected_path, "selected_prefixes.csv")
    except (FileNotFoundError, pd.errors.EmptyDataError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if REQUIRED_FLOW_COLUMN not in flows.columns:
        print(f"Error: Flow CSV must contain '{REQUIRED_FLOW_COLUMN}' column.", file=sys.stderr)
        return 1

    if REQUIRED_SELECTED_COLUMN not in selected.columns:
        print(
            f"Error: selected_prefixes.csv must contain '{REQUIRED_SELECTED_COLUMN}' column.",
            file=sys.stderr,
        )
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    if selected.empty:
        warn("selected_prefixes.csv is empty. No prefix flow CSV was created.")
        return 0

    flows_with_cache, invalid_dst_ip_count = add_dst_ip_cache(flows)
    if invalid_dst_ip_count > 0:
        warn(
            f"found {invalid_dst_ip_count} invalid dst_ip value(s); those rows were excluded from matching."
        )

    combined_rows, matched_prefix_count = build_combined_rows(
        flows=flows_with_cache,
        selected=selected,
        write_separate=args.write_separate,
        out_dir=out_dir,
    )

    if matched_prefix_count == 0:
        warn("no selected prefixes matched any flow.")

    if args.write_combined and combined_rows:
        combined = pd.concat(combined_rows, ignore_index=True)
        combined_output_path = out_dir / COMBINED_OUTPUT_NAME
        combined.to_csv(combined_output_path, index=False)
        print(f"[DONE] combined: {len(combined)} flows -> {combined_output_path}")
    elif args.write_combined:
        warn("combined CSV was not written because no flows matched any selected prefix.")

    if args.write_separate:
        print(f"[DONE] wrote {matched_prefix_count} prefix flow CSV file(s)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
