#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from cli_output import format_tagged

DEFAULT_OUTPUT_ROOT = REPO_ROOT / "results" / "aguri"
AGURIM_SRC_DIR = REPO_ROOT / "scripts" / "aguri" / "agurim" / "src"
DEFAULT_AGURI3_BIN = AGURIM_SRC_DIR / "aguri3"
DEFAULT_AGURIM_BIN = AGURIM_SRC_DIR / "agurim"
SUPPORTED_CAPTURE_SUFFIXES: tuple[str, ...] = (
    ".pcapng.gz",
    ".pcap.gz",
    ".pcapng",
    ".pcap",
)


def print_run(message: str) -> None:
    print(format_tagged("[RUN]", message, "cyan"))


def print_warn(message: str) -> None:
    print(format_tagged("[WARN]", message, "yellow", stream=sys.stderr), file=sys.stderr)


def print_done(message: str = "") -> None:
    print(format_tagged("[DONE]", message, "green"))


def print_info(message: str) -> None:
    print(format_tagged("[INFO]", message, "blue"))


def print_error(message: str) -> None:
    print(format_tagged("Error:", message, "red", stream=sys.stderr), file=sys.stderr)


def infer_dataset_name(pcap_path: Path) -> str:
    filename = pcap_path.name
    for suffix in SUPPORTED_CAPTURE_SUFFIXES:
        if filename.endswith(suffix):
            return filename[: -len(suffix)]
    return pcap_path.stem


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def resolve_output_dir(dataset: str, out_dir: Path | None) -> Path:
    if out_dir is not None:
        return resolve_from_repo_root(out_dir)
    return DEFAULT_OUTPUT_ROOT / dataset


def ensure_input_exists(pcap_path: Path) -> None:
    if not pcap_path.exists():
        raise FileNotFoundError(f"Input pcap not found: {pcap_path}")
    if not pcap_path.is_file():
        raise FileNotFoundError(f"Input pcap is not a file: {pcap_path}")


def ensure_outputs_writable(agr_path: Path, agurim_txt_path: Path, force: bool) -> None:
    if force:
        return

    existing_paths = [path for path in (agr_path, agurim_txt_path) if path.exists()]
    if not existing_paths:
        return

    joined = "\n".join(f"  - {path}" for path in existing_paths)
    raise FileExistsError(
        "Output file already exists. Re-run with --force to overwrite:\n"
        f"{joined}"
    )


def resolve_command(command: str | None, default_path: Path, fallback_name: str) -> str:
    if command is not None:
        return str(resolve_from_repo_root(Path(command).expanduser()))
    if default_path.exists():
        return str(default_path)
    return fallback_name


def ensure_command_available(command: str, flag_name: str, default_path: Path) -> None:
    command_path = Path(command).expanduser()
    if command_path.parent != Path("."):
        if command_path.exists():
            return
    elif shutil.which(command) is not None:
        return

    raise FileNotFoundError(
        f"Required command not found: {command}\n"
        f"Expected bundled binary location: {default_path}\n"
        "Build aguri3/agurim first, for example:\n"
        "  cd scripts/aguri/agurim/src\n"
        "  make\n"
        "Then either add the built binaries to PATH or pass an explicit path with "
        f"{flag_name}."
    )


def prepare_input_capture(pcap_path: Path) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if pcap_path.suffix != ".gz":
        return pcap_path, None

    suffix = Path(pcap_path.stem).suffix
    temp_dir = tempfile.TemporaryDirectory(prefix="run-aguri-")
    decompressed_path = Path(temp_dir.name) / f"{pcap_path.stem}"

    print_info(f"Decompressing {pcap_path} -> {decompressed_path}")
    with gzip.open(pcap_path, "rb") as src, decompressed_path.open("wb") as dst:
        shutil.copyfileobj(src, dst)

    if suffix not in {".pcap", ".pcapng"}:
        print_warn(f"Decompressed input has unexpected suffix: {decompressed_path.name}")

    return decompressed_path, temp_dir


def run_command(cmd: list[str]) -> None:
    printable = shlex.join(cmd)
    print_run(printable)
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            "Command failed with a non-zero exit status.\n"
            f"Command: {printable}\n"
            f"Exit code: {exc.returncode}"
        ) from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run aguri3 and agurim for a capture file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_args = parser.add_argument_group("required arguments")
    optional_args = parser.add_argument_group("options")
    required_args.add_argument(
        "--pcap",
        required=True,
        type=Path,
        help="Input pcap / pcap.gz / pcapng / pcapng.gz path (relative paths are resolved from the repo root).",
    )
    optional_args.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Dataset name. If omitted, infer it from the pcap filename.",
    )
    optional_args.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (relative paths are resolved from the repo root). If omitted, use results/aguri/<dataset>.",
    )
    optional_args.add_argument(
        "--aguri3-bin",
        type=str,
        default=None,
        help="Path to aguri3 command. If omitted, use scripts/aguri/agurim/src/aguri3 when present, otherwise aguri3 on PATH.",
    )
    optional_args.add_argument(
        "--agurim-bin",
        type=str,
        default=None,
        help="Path to agurim command. If omitted, use scripts/aguri/agurim/src/agurim when present, otherwise agurim on PATH.",
    )
    optional_args.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files if they already exist.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    pcap_path = resolve_from_repo_root(args.pcap.expanduser())
    dataset = args.dataset or infer_dataset_name(pcap_path)
    out_dir = resolve_output_dir(dataset, args.out_dir)
    agr_path = out_dir / f"{dataset}.agr"
    agurim_txt_path = out_dir / f"{dataset}.agurim.txt"
    aguri3_bin = resolve_command(args.aguri3_bin, DEFAULT_AGURI3_BIN, "aguri3")
    agurim_bin = resolve_command(args.agurim_bin, DEFAULT_AGURIM_BIN, "agurim")
    prepared_pcap_path: Path | None = None
    temp_dir: tempfile.TemporaryDirectory[str] | None = None

    try:
        ensure_input_exists(pcap_path)
        ensure_command_available(aguri3_bin, "--aguri3-bin", DEFAULT_AGURI3_BIN)
        ensure_command_available(agurim_bin, "--agurim-bin", DEFAULT_AGURIM_BIN)
        ensure_outputs_writable(agr_path, agurim_txt_path, args.force)
        prepared_pcap_path, temp_dir = prepare_input_capture(pcap_path)
    except (FileExistsError, FileNotFoundError) as exc:
        print_error(str(exc))
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        run_command(
            [
                aguri3_bin,
                "-r",
                str(prepared_pcap_path),
                "-w",
                str(agr_path),
            ]
        )
        run_command(
            [
                agurim_bin,
                "-w",
                str(agurim_txt_path),
                str(agr_path),
            ]
        )
    except RuntimeError as exc:
        print_error(str(exc))
        return 1
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()

    print_done()
    print(f"AGR: {agr_path}")
    print(f"TXT: {agurim_txt_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
