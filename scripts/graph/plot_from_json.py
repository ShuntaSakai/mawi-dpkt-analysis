#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTDIR = REPO_ROOT / "results/plots/all"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def resolve_from_repo_root(path: Path) -> Path:
    """相対パスをリポジトリルート基準の絶対パスに変換する。"""
    return path if path.is_absolute() else REPO_ROOT / path


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)


def plot_tcp_flag_distribution(data: dict, outdir: Path) -> Path:
    """TCPフラグ分布を棒グラフで描画する。"""
    records = data.get("tcp_flag_counts", [])
    if not records:
        raise ValueError("tcp_flag_counts が JSON にありません。")

    labels = [r["flag"] for r in records]
    values = [r["packets"] for r in records]

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values)
    plt.xlabel("TCP flags")
    plt.ylabel("Packets")
    plt.title("TCP Flag Distribution")
    plt.tight_layout()

    outpath = outdir / "tcp_flag_distribution.png"
    plt.savefig(outpath, dpi=150)
    plt.close()
    return outpath


def plot_top_flows(data: dict, outdir: Path, top_n: int = 10) -> Path:
    """
    Topフローランキングを横棒グラフで描画する。

    現状のJSONでは packets ベース。
    将来 flow_bytes が入れば bytes ベースに差し替え可能。
    """
    records = data.get("top_flows", [])
    if not records:
        raise ValueError("top_flows が JSON にありません。")

    records = records[:top_n]
    labels = [r["flow"] for r in records]
    values = [r["packets"] for r in records]

    plt.figure(figsize=(12, 6))
    plt.barh(labels[::-1], values[::-1])
    plt.xlabel("Packets")
    plt.ylabel("Flow")
    plt.title(f"Top {len(records)} Flows by Packets")
    plt.tight_layout()

    outpath = outdir / "top_flows_packets.png"
    plt.savefig(outpath, dpi=150)
    plt.close()
    return outpath


def plot_flow_size_distribution(data: dict, outdir: Path) -> Path:
    """
    フローサイズ分布をヒストグラムで描画する。

    注意:
    現状のJSONでは top_flows の packets のみを使う簡易版。
    全フロー分布ではない。
    """
    records = data.get("top_flows", [])
    if not records:
        raise ValueError("top_flows が JSON にありません。")

    sizes = [r["packets"] for r in records]
    if not sizes:
        raise ValueError("top_flows に packets がありません。")

    plt.figure(figsize=(8, 5))
    plt.hist(sizes, bins=min(10, max(1, len(sizes))))
    plt.xlabel("Flow size (packets)")
    plt.ylabel("Frequency")
    plt.title("Flow Size Distribution (from top_flows only)")
    plt.tight_layout()

    outpath = outdir / "flow_size_distribution_packets.png"
    plt.savefig(outpath, dpi=150)
    plt.close()
    return outpath


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate graphs from analysis JSON."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="input JSON path",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=DEFAULT_OUTDIR,
        help=f"output directory for plots (default: {DEFAULT_OUTDIR})",
    )
    parser.add_argument(
        "--graph",
        choices=["tcp_flags", "top_flows", "flow_size_distribution", "all"],
        default="all",
        help="which graph to generate",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="number of top flows to plot for top_flows graph",
    )
    args = parser.parse_args()

    data = load_json(args.input)
    outdir = resolve_from_repo_root(args.outdir)
    safe_mkdir(outdir)

    created: list[Path] = []

    if args.graph in ("tcp_flags", "all"):
        created.append(plot_tcp_flag_distribution(data, outdir))

    if args.graph in ("top_flows", "all"):
        created.append(plot_top_flows(data, outdir, top_n=args.top_n))

    if args.graph in ("flow_size_distribution", "all"):
        created.append(plot_flow_size_distribution(data, outdir))

    print("[done] created plots:")
    for path in created:
        print(f"  - {path}")
        
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
