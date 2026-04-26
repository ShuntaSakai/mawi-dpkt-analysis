#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SUPPORTED_CAPTURE_SUFFIXES: tuple[str, ...] = (
    ".pcapng.gz",
    ".pcap.gz",
    ".pcapng",
    ".pcap",
)
DEFAULT_CONFIG_PATH = Path("config/prefix_selection.yaml")
PREFIX_FLOW_GLOB = "dst_*.csv"


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def infer_dataset_name(pcap_path: Path) -> str:
    filename = pcap_path.name
    for suffix in SUPPORTED_CAPTURE_SUFFIXES:
        if filename.endswith(suffix):
            return filename[: -len(suffix)]
    return pcap_path.stem


def flow_csv_path(dataset: str) -> Path:
    return REPO_ROOT / "results" / "flows" / "all" / dataset / "flows.csv"


def overall_features_path(dataset: str) -> Path:
    return REPO_ROOT / "results" / "features" / "all" / dataset / "features.json"


def aguri_output_dir(dataset: str) -> Path:
    return REPO_ROOT / "results" / "aguri" / dataset


def aguri_agr_path(dataset: str) -> Path:
    return aguri_output_dir(dataset) / f"{dataset}.agr"


def agurim_txt_path(dataset: str) -> Path:
    return aguri_output_dir(dataset) / f"{dataset}.agurim.txt"


def aguri_candidates_path(dataset: str) -> Path:
    return aguri_output_dir(dataset) / f"{dataset}.aguri_candidates.csv"


def prefix_output_dir(dataset: str) -> Path:
    return REPO_ROOT / "results" / "prefix" / dataset


def prefix_evaluation_path(dataset: str) -> Path:
    return prefix_output_dir(dataset) / "prefix_evaluation.csv"


def selected_prefixes_path(dataset: str) -> Path:
    return prefix_output_dir(dataset) / "selected_prefixes.csv"


def prefix_flow_dir(dataset: str) -> Path:
    return REPO_ROOT / "results" / "flows" / "prefix" / dataset


def prefix_feature_dir(dataset: str) -> Path:
    return REPO_ROOT / "results" / "features" / "prefix" / dataset


def comparison_output_dir(dataset: str) -> Path:
    return REPO_ROOT / "results" / "comparison" / dataset


def prefix_feature_path(prefix_flow_path: Path) -> Path:
    return prefix_feature_dir(prefix_flow_path.parent.name) / f"{prefix_flow_path.stem}_features.json"


def prefix_to_filename(prefix: str) -> str:
    return prefix.replace("/", "_").replace(":", "_")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the full prefix analysis pipeline for a pcap/pcapng capture.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_args = parser.add_argument_group("required arguments")
    optional_args = parser.add_argument_group("options")
    required_args.add_argument(
        "--pcap",
        required=True,
        type=Path,
        help="Input pcap / pcap.gz / pcapng / pcapng.gz path.",
    )
    optional_args.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Dataset name. If omitted, infer it from the pcap filename.",
    )
    optional_args.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="prefix_selection.yaml path.",
    )
    optional_args.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files and re-run all steps.",
    )
    optional_args.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned commands without executing them.",
    )
    return parser


def parse_args() -> argparse.Namespace:
    return build_parser().parse_args()


def print_step(step_no: int, description: str) -> None:
    print(f"[STEP {step_no}] {description}")


def print_done(message: str) -> None:
    print(f"[DONE] {message}")


def print_warn(message: str) -> None:
    print(f"[WARN] {message}")


def ensure_file_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    if not path.is_file():
        raise FileNotFoundError(f"{label} is not a file: {path}")


def ensure_can_write(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise FileExistsError(
            f"Output file already exists: {path}\n"
            "Re-run with --force to overwrite."
        )


def run_step(
    step_no: int,
    description: str,
    cmd: list[str],
    *,
    dry_run: bool,
) -> None:
    print_step(step_no, description)
    print(f"[RUN] {shlex.join(cmd)}")

    if dry_run:
        print_done("dry-run only")
        return

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"Step {step_no} failed: {description}\n"
            f"Command: {shlex.join(cmd)}\n"
            f"Exit code: {exc.returncode}"
        ) from exc


def count_data_rows(csv_path: Path) -> int:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return sum(1 for _ in reader)


def load_selected_prefixes(csv_path: Path) -> list[str]:
    prefixes: list[str] = []
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            prefix = str(row.get("normalized_dst_prefix", "")).strip()
            if prefix and prefix.lower() != "nan":
                prefixes.append(prefix)
    return prefixes


def load_prefix_evaluation_rows(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_scalar_yaml_value(raw: str) -> str | int | float | bool:
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


def explain_filter_failures(row: dict[str, str], config: dict[str, float | int]) -> list[str]:
    reasons: list[str] = []

    def int_value(key: str) -> int:
        return int(float(str(row.get(key, "0") or "0")))

    def float_value(key: str) -> float:
        return float(str(row.get(key, "0") or "0"))

    if row.get("match_status") == "no_matching_flows":
        reasons.append("no flows matched this destination prefix in flow CSV")
        return reasons

    flow_count = int_value("flow_count")
    packet_count = int_value("packet_count")
    byte_count = int_value("byte_count")
    short_flow_ratio = float_value("short_flow_ratio")
    tiny_flow_ratio = float_value("tiny_flow_ratio")
    syn_only_like_ratio = float_value("syn_only_like_ratio")
    rst_observed_ratio = float_value("rst_observed_ratio")
    prefix_is_broader_than_target = str(row.get("prefix_is_broader_than_target", "")).strip().lower() == "true"

    if flow_count < int(config["min_flows"]):
        reasons.append(f"flow_count {flow_count} < min_flows {config['min_flows']}")
    if packet_count < int(config["min_packets"]):
        reasons.append(f"packet_count {packet_count} < min_packets {config['min_packets']}")
    if byte_count < int(config["min_bytes"]):
        reasons.append(f"byte_count {byte_count} < min_bytes {config['min_bytes']}")
    if short_flow_ratio > float(config["max_short_flow_ratio"]):
        reasons.append(
            f"short_flow_ratio {short_flow_ratio:.3f} > max_short_flow_ratio {config['max_short_flow_ratio']}"
        )
    if tiny_flow_ratio > float(config["max_tiny_flow_ratio"]):
        reasons.append(
            f"tiny_flow_ratio {tiny_flow_ratio:.3f} > max_tiny_flow_ratio {config['max_tiny_flow_ratio']}"
        )
    if syn_only_like_ratio > float(config["max_syn_only_like_ratio"]):
        reasons.append(
            "syn_only_like_ratio "
            f"{syn_only_like_ratio:.3f} > max_syn_only_like_ratio {config['max_syn_only_like_ratio']}"
        )
    if rst_observed_ratio > float(config["max_rst_observed_ratio"]):
        reasons.append(
            f"rst_observed_ratio {rst_observed_ratio:.3f} > max_rst_observed_ratio {config['max_rst_observed_ratio']}"
        )
    if prefix_is_broader_than_target:
        reasons.append("prefix is broader than target prefix_len")

    return reasons


def load_selection_config(config_path: Path) -> dict[str, float | int]:
    with config_path.open("r", encoding="utf-8") as handle:
        root: dict[str, float | int | dict[str, float | int] | str | bool] = {}
        nested_key: str | None = None
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\n")
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if line.startswith((" ", "\t")):
                if nested_key is None:
                    raise RuntimeError(f"Invalid nested YAML at line {line_number}: {line}")
                child_text = stripped
                if ":" not in child_text:
                    raise RuntimeError(f"Invalid YAML mapping at line {line_number}: {line}")
                child_key, child_value = child_text.split(":", 1)
                nested = root.setdefault(nested_key, {})
                if not isinstance(nested, dict):
                    raise RuntimeError(f"Invalid YAML structure near line {line_number}: {line}")
                nested[child_key.strip()] = parse_scalar_yaml_value(child_value)
                continue

            if ":" not in stripped:
                raise RuntimeError(f"Invalid YAML mapping at line {line_number}: {line}")
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
        raise RuntimeError(f"Config file must contain a YAML mapping: {config_path}")
    return config


def list_prefix_flow_files(dataset: str) -> list[Path]:
    return sorted(
        path
        for path in prefix_flow_dir(dataset).glob(PREFIX_FLOW_GLOB)
        if path.is_file()
    )


def cleanup_force_outputs(dataset: str) -> None:
    for path in (
        prefix_flow_dir(dataset),
        prefix_feature_dir(dataset),
        comparison_output_dir(dataset),
    ):
        if path.exists():
            shutil.rmtree(path)


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        return 2

    args = parse_args()
    pcap_path = resolve_from_repo_root(args.pcap.expanduser())
    dataset = args.dataset or infer_dataset_name(pcap_path)
    config_path = resolve_from_repo_root(args.config.expanduser())

    try:
        ensure_file_exists(pcap_path, "Input pcap")
        ensure_file_exists(config_path, "Config file")
        ensure_can_write(flow_csv_path(dataset), args.force)
        ensure_can_write(overall_features_path(dataset), args.force)
        ensure_can_write(aguri_agr_path(dataset), args.force)
        ensure_can_write(agurim_txt_path(dataset), args.force)
        ensure_can_write(aguri_candidates_path(dataset), args.force)
        ensure_can_write(prefix_evaluation_path(dataset), args.force)
        ensure_can_write(selected_prefixes_path(dataset), args.force)
    except (FileExistsError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    flow_csv = flow_csv_path(dataset)
    overall_features = overall_features_path(dataset)
    agurim_txt = agurim_txt_path(dataset)
    aguri_candidates = aguri_candidates_path(dataset)
    selected_prefixes = selected_prefixes_path(dataset)
    prefix_flows_out_dir = prefix_flow_dir(dataset)
    prefix_features_out_dir = prefix_feature_dir(dataset)

    try:
        if args.force and not args.dry_run:
            cleanup_force_outputs(dataset)

        run_step(
            1,
            "Aggregate packets into bidirectional flows",
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "flow" / "pcap_to_flow.py"),
                "--input",
                str(pcap_path),
                "--output",
                str(flow_csv),
            ],
            dry_run=args.dry_run,
        )
        print_done(str(flow_csv))

        run_step(
            2,
            "Summarize overall flow features",
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "flow" / "summarize_flow_features.py"),
                "--input",
                str(flow_csv),
                "--output",
                str(overall_features),
            ],
            dry_run=args.dry_run,
        )
        print_done(str(overall_features))

        run_step(
            3,
            "Run aguri3/agurim",
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "aguri" / "run_aguri.py"),
                "--pcap",
                str(pcap_path),
                "--dataset",
                dataset,
                "--force",
            ],
            dry_run=args.dry_run,
        )
        print_done(f"{aguri_agr_path(dataset)}, {agurim_txt}")

        run_step(
            4,
            "Parse agurim output into prefix candidates CSV",
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "aguri" / "parse_agurim.py"),
                "--input",
                str(agurim_txt),
                "--output",
                str(aguri_candidates),
                "--force",
            ],
            dry_run=args.dry_run,
        )
        print_done(str(aguri_candidates))

        run_step(
            5,
            "Evaluate prefix candidates using flow features",
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "prefix" / "evaluate_prefixes.py"),
                "--flows",
                str(flow_csv),
                "--aguri",
                str(aguri_candidates),
                "--config",
                str(config_path),
                "--out-dir",
                str(prefix_output_dir(dataset)),
            ],
            dry_run=args.dry_run,
        )
        print_done(f"{prefix_evaluation_path(dataset)}, {selected_prefixes}")

        if args.dry_run:
            run_step(
                6,
                "Extract flows for each selected prefix",
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "prefix" / "filter_flows_by_prefix.py"),
                    "--flows",
                    str(flow_csv),
                    "--selected",
                    str(selected_prefixes),
                    "--out-dir",
                    str(prefix_flows_out_dir),
                ],
                dry_run=True,
            )

            if selected_prefixes.exists():
                for prefix in load_selected_prefixes(selected_prefixes):
                    predicted_prefix_flow = prefix_flows_out_dir / f"dst_{prefix_to_filename(prefix)}.csv"
                    run_step(
                        7,
                        f"Summarize prefix flow features: {predicted_prefix_flow.name}",
                        [
                            sys.executable,
                            str(REPO_ROOT / "scripts" / "flow" / "summarize_flow_features.py"),
                            "--input",
                            str(predicted_prefix_flow),
                            "--output",
                            str(prefix_feature_path(predicted_prefix_flow)),
                        ],
                        dry_run=True,
                    )
            else:
                print_warn(
                    "selected_prefixes.csv does not exist yet, so step 7 prefix-specific commands cannot be expanded in dry-run."
                )

            run_step(
                8,
                "Plot overall vs prefix feature comparisons",
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "graph" / "plot_prefix_comparison.py"),
                    "--overall",
                    str(overall_features),
                    "--prefix-dir",
                    str(prefix_features_out_dir),
                    "--out-dir",
                    str(comparison_output_dir(dataset)),
                ],
                dry_run=True,
            )
            return 0

        selected_count = count_data_rows(selected_prefixes)
        if selected_count == 0:
            print_warn(f"selected_prefixes.csv is empty: {selected_prefixes}")
            print_warn(f"prefix evaluation is available for inspection: {prefix_evaluation_path(dataset)}")
            print_warn(f"selection config used: {config_path}")
            try:
                config = load_selection_config(config_path)
                for row in load_prefix_evaluation_rows(prefix_evaluation_path(dataset)):
                    prefix = row.get("normalized_dst_prefix", row.get("dst_prefix", "(unknown)"))
                    reasons = explain_filter_failures(row, config)
                    if reasons:
                        print_warn(f"{prefix}: {'; '.join(reasons)}")
            except (OSError, RuntimeError, ValueError) as exc:
                print_warn(f"Failed to summarize prefix filter reasons: {exc}")
            print_warn(
                "Downstream prefix-specific flow extraction, prefix features, and comparison plots were skipped."
            )
            print_warn(
                "If this is a small sample pcap, re-run with --config config/prefix_selection.sample.yaml."
            )
            return 0

        selected_prefix_list = load_selected_prefixes(selected_prefixes)
        predicted_prefix_flow_paths = [
            prefix_flows_out_dir / f"dst_{prefix_to_filename(prefix)}.csv"
            for prefix in selected_prefix_list
        ]

        for prefix in selected_prefix_list:
            predicted_prefix_flow = prefix_flows_out_dir / f"dst_{prefix_to_filename(prefix)}.csv"
            ensure_can_write(predicted_prefix_flow, args.force)
            ensure_can_write(prefix_feature_path(predicted_prefix_flow), args.force)

        ensure_can_write(comparison_output_dir(dataset) / "comparison_summary.csv", args.force)

        run_step(
            6,
            "Extract flows for each selected prefix",
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "prefix" / "filter_flows_by_prefix.py"),
                "--flows",
                str(flow_csv),
                "--selected",
                str(selected_prefixes),
                "--out-dir",
                str(prefix_flows_out_dir),
            ],
            dry_run=False,
        )
        print_done(str(prefix_flows_out_dir))

        prefix_flow_files = [path for path in predicted_prefix_flow_paths if path.exists()]
        if not prefix_flow_files:
            print_warn("No prefix flow CSV was generated. Stopping before prefix feature summary.")
            return 0

        for prefix_flow_path in prefix_flow_files:
            prefix_feature_output = prefix_feature_path(prefix_flow_path)
            ensure_can_write(prefix_feature_output, args.force)
            run_step(
                7,
                f"Summarize prefix flow features: {prefix_flow_path.name}",
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "flow" / "summarize_flow_features.py"),
                    "--input",
                    str(prefix_flow_path),
                    "--output",
                    str(prefix_feature_output),
                ],
                dry_run=False,
            )
            print_done(str(prefix_feature_output))

        run_step(
            8,
            "Plot overall vs prefix feature comparisons",
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "graph" / "plot_prefix_comparison.py"),
                "--overall",
                str(overall_features),
                "--prefix-dir",
                str(prefix_features_out_dir),
                "--out-dir",
                str(comparison_output_dir(dataset)),
            ],
            dry_run=False,
        )
        print_done(str(comparison_output_dir(dataset)))
    except (FileExistsError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
