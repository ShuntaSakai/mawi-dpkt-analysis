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
            print_warn("selected_prefixes.csv is empty. No prefix flow CSV was created.")
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
