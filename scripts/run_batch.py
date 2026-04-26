#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
JST = timezone(timedelta(hours=9))
yaml = None


def require_yaml() -> object:
    global yaml
    if yaml is None:
        import yaml as yaml_module

        yaml = yaml_module
    return yaml


def now_iso() -> str:
    return datetime.now(JST).isoformat()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the legacy MAWI batch download/analyze pipeline.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    optional_args = parser.add_argument_group("options")
    optional_args.add_argument(
        "--config",
        type=Path,
        default=Path("config/settings.yaml"),
        help="settings YAML path",
    )
    return parser


def load_config(config_path: Path) -> dict:
    yaml_module = require_yaml()
    with config_path.open("r", encoding="utf-8") as f:
        return yaml_module.safe_load(f)


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def load_state(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())


def append_state(path: Path, value: str) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(value + "\n")


def generate_timestamps(start: str, end: str, interval: int) -> list[str]:
    fmt = "%Y%m%d%H%M"
    t = datetime.strptime(start, fmt)
    end_t = datetime.strptime(end, fmt)

    result = []
    while t <= end_t:
        result.append(t.strftime(fmt))
        t += timedelta(minutes=interval)
    return result


def build_url(base_url: str, ts: str) -> str:
    return f"{base_url}/{ts}.pcap.gz"


def write_jsonl(log_path: Path, record: dict) -> None:
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def log_event(log_path: Path, event: str, **kwargs) -> None:
    record = {
        "time": now_iso(),
        "event": event,
        **kwargs,
    }
    write_jsonl(log_path, record)


def run_cmd(cmd: list[str]) -> subprocess.CompletedProcess:
    print("[cmd]", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True)


def get_free_bytes(path: Path) -> int:
    usage = shutil.disk_usage(path)
    return usage.free


def bytes_to_gib(num_bytes: int) -> float:
    return num_bytes / (1024 ** 3)


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        return 2

    args = parser.parse_args()
    config_path = args.config if args.config.is_absolute() else REPO_ROOT / args.config
    config = load_config(config_path)

    raw_dir = REPO_ROOT / config["paths"]["raw_dir"]
    json_dir = REPO_ROOT / config["paths"]["json_dir"]
    plot_dir = REPO_ROOT / config["paths"]["plot_dir"]
    state_dir = REPO_ROOT / config["paths"]["state_dir"]
    log_dir = REPO_ROOT / config["paths"]["log_dir"]

    safe_mkdir(raw_dir)
    safe_mkdir(json_dir)
    safe_mkdir(plot_dir)
    safe_mkdir(state_dir)
    safe_mkdir(log_dir)

    processed_file = state_dir / "processed.txt"
    failed_file = state_dir / "failed.txt"
    retained_file = state_dir / "retained.txt"

    processed = load_state(processed_file)

    run_id = datetime.now(JST).strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"run_batch_{run_id}.jsonl"

    timestamps = generate_timestamps(
        config["mawi"]["start"],
        config["mawi"]["end"],
        config["mawi"]["interval_minutes"],
    )

    # 空き容量しきい値（GiB）
    min_free_gib = config["run"].get("min_free_gib_before_download", 10)
    min_free_bytes = int(min_free_gib * (1024 ** 3))

    log_event(
        log_path,
        "batch_start",
        total_targets=len(timestamps),
        raw_dir=str(raw_dir),
        json_dir=str(json_dir),
        plot_dir=str(plot_dir),
        delete_raw_after_success=config["run"]["delete_raw_after_success"],
        generate_plots=config["run"]["generate_plots"],
        min_free_gib_before_download=min_free_gib,
    )

    for ts in timestamps:
        filename = f"{ts}.pcap.gz"

        if filename in processed:
            print(f"[skip] already processed: {filename}")
            log_event(log_path, "skip_processed", filename=filename)
            continue

        url = build_url(config["mawi"]["base_url"], ts)
        raw_path = raw_dir / filename
        json_path = json_dir / f"{ts}.json"

        print(f"\n[info] processing {filename}")
        log_event(log_path, "job_start", filename=filename, url=url)

        # 空き容量チェック
        free_bytes = get_free_bytes(raw_dir)
        free_gib = bytes_to_gib(free_bytes)

        log_event(
            log_path,
            "disk_check",
            filename=filename,
            free_bytes=free_bytes,
            free_gib=round(free_gib, 3),
        )

        if free_bytes < min_free_bytes:
            print(f"[error] not enough disk space before download: {free_gib:.2f} GiB free")
            append_state(failed_file, filename)
            log_event(
                log_path,
                "disk_space_insufficient",
                filename=filename,
                free_bytes=free_bytes,
                free_gib=round(free_gib, 3),
                threshold_gib=min_free_gib,
            )
            continue

        # --- download ---
        result = run_cmd([
            sys.executable,
            str(REPO_ROOT / "scripts/download_one.py"),
            "--url", url,
            "--outdir", str(raw_dir),
        ])

        log_event(
            log_path,
            "download_finished",
            filename=filename,
            returncode=result.returncode,
            stdout=result.stdout[-4000:],
            stderr=result.stderr[-4000:],
        )

        if result.returncode != 0:
            print(f"[error] download failed: {filename}")
            append_state(failed_file, filename)
            log_event(log_path, "download_failed", filename=filename)
            continue

        if not raw_path.exists():
            print(f"[error] raw file not found after download: {filename}")
            append_state(failed_file, filename)
            log_event(log_path, "download_missing_output", filename=filename)
            continue

        raw_size = raw_path.stat().st_size
        log_event(
            log_path,
            "download_success",
            filename=filename,
            raw_path=str(raw_path),
            raw_size_bytes=raw_size,
            raw_size_gib=round(bytes_to_gib(raw_size), 3),
        )

        # --- analyze ---
        analyze_cmd = [
            sys.executable,
            str(REPO_ROOT / "scripts/analyze_one.py"),
            "--input", str(raw_path),
            "--outdir", str(json_dir),
            "--progress-every", str(config["run"]["progress_every"]),
        ]
        max_packets = config["run"].get("max_packets")
        if max_packets is not None:
            analyze_cmd.extend(["--max-packets", str(max_packets)])

        result = run_cmd(analyze_cmd)

        log_event(
            log_path,
            "analyze_finished",
            filename=filename,
            returncode=result.returncode,
            stdout=result.stdout[-4000:],
            stderr=result.stderr[-4000:],
        )

        if result.returncode != 0:
            print(f"[error] analyze failed: {filename}")
            append_state(failed_file, filename)
            log_event(log_path, "analyze_failed", filename=filename)
            continue

        if not json_path.exists():
            print(f"[error] json output not found: {json_path}")
            append_state(failed_file, filename)
            log_event(log_path, "analyze_missing_output", filename=filename, json_path=str(json_path))
            continue

        log_event(
            log_path,
            "analyze_success",
            filename=filename,
            json_path=str(json_path),
            json_size_bytes=json_path.stat().st_size,
        )

        # --- plot ---
        plot_success = True
        if config["run"]["generate_plots"]:
            result = run_cmd([
                sys.executable,
                str(REPO_ROOT / "scripts/graph/plot_from_json.py"),
                "--input", str(json_path),
                "--outdir", str(plot_dir),
                "--graph", config["run"]["graph_type"],
            ])

            log_event(
                log_path,
                "plot_finished",
                filename=filename,
                returncode=result.returncode,
                stdout=result.stdout[-4000:],
                stderr=result.stderr[-4000:],
            )

            if result.returncode != 0:
                print(f"[warn] plot failed: {filename}")
                plot_success = False
                log_event(log_path, "plot_failed", filename=filename)
            else:
                log_event(log_path, "plot_success", filename=filename, plot_dir=str(plot_dir))

        # --- success ---
        append_state(processed_file, filename)
        log_event(log_path, "marked_processed", filename=filename)

        # --- delete raw ---
        if config["run"]["delete_raw_after_success"] and plot_success:
            try:
                raw_path.unlink()
                print(f"[info] deleted raw: {filename}")
                log_event(log_path, "delete_raw_success", filename=filename, raw_path=str(raw_path))
            except Exception as e:
                print(f"[warn] failed to delete raw: {e}")
                append_state(retained_file, filename)
                log_event(
                    log_path,
                    "delete_raw_failed",
                    filename=filename,
                    raw_path=str(raw_path),
                    error=str(e),
                )
        else:
            append_state(retained_file, filename)
            log_event(
                log_path,
                "raw_retained",
                filename=filename,
                reason="delete_disabled_or_plot_failed",
            )

        # --- sleep ---
        sleep_sec = config["run"]["sleep_seconds_between_jobs"]
        log_event(log_path, "sleep", seconds=sleep_sec, filename=filename)
        time.sleep(sleep_sec)

    log_event(log_path, "batch_end")
    print(f"\n[done] batch completed")
    print(f"[info] log file: {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
