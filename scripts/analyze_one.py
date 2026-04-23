#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import json
import socket
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import dpkt

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data/raw/202604080000.pcap.gz"
DEFAULT_OUTDIR = REPO_ROOT / "results/json"


def inet_to_str(addr: bytes) -> str:
    """IPアドレスのバイト列を文字列表記に変換する。

    4バイトならIPv4、16バイトならIPv6として解釈する。変換できない場合は、
    解析を止めないために元のバイト列を16進文字列として返す。
    """
    try:
        if len(addr) == 4:
            return socket.inet_ntop(socket.AF_INET, addr)
        if len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except OSError:
        pass
    return addr.hex()


def safe_mkdir(path: Path) -> None:
    """指定されたディレクトリを、親ディレクトリも含めて存在する状態にする。"""
    path.mkdir(parents=True, exist_ok=True)


def resolve_from_repo_root(path: Path) -> Path:
    """相対パスをリポジトリルート基準の絶対パスに変換する。"""
    return path if path.is_absolute() else REPO_ROOT / path


def analyze_pcap_gz(
    input_path: Path,
    progress_every: int = 1_000_000,
    max_packets: int | None = None,
) -> dict[str, Any]:
    """gzip圧縮されたpcapファイルを読み込み、通信統計を集計する。

    Ethernetフレームを順に解析し、総パケット数、総バイト数、IPv4/IPv6、
    TCP/UDP/ICMP/ARP、上位ポート、上位IPアドレス、分単位のパケット数などを
    辞書として返す。``progress_every`` が正の値なら指定パケット数ごとに
    進捗を表示し、``max_packets`` が指定されている場合はその件数で解析を
    打ち切る。
    """
    stats: dict[str, Any] = {
        "file": str(input_path),
        "started_at_epoch": time.time(),
        "packets_total": 0,
        "bytes_total": 0,
        "non_ip": 0,
        "ipv4": 0,
        "ipv6": 0,
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "arp": 0,
        "ethernet_parse_error": 0,
        "ip_parse_error": 0,
        "first_timestamp": None,
        "last_timestamp": None,
    }

    dport_counter: Counter[int] = Counter()
    sport_counter: Counter[int] = Counter()
    src_ip_counter: Counter[str] = Counter()
    dst_ip_counter: Counter[str] = Counter()
    l4_proto_counter: Counter[str] = Counter()
    packets_per_minute: Counter[str] = Counter()

    started = time.time()

    with gzip.open(input_path, "rb") as fp:
        pcap = dpkt.pcap.Reader(fp)

        for i, (ts, buf) in enumerate(pcap, start=1):
            if max_packets is not None and i > max_packets:
                break

            stats["packets_total"] += 1
            stats["bytes_total"] += len(buf)

            if stats["first_timestamp"] is None:
                stats["first_timestamp"] = ts
            stats["last_timestamp"] = ts

            minute_bucket = time.strftime("%Y-%m-%d %H:%M", time.gmtime(ts))
            packets_per_minute[minute_bucket] += 1

            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                stats["ethernet_parse_error"] += 1
                continue

            if isinstance(eth.data, dpkt.arp.ARP):
                stats["arp"] += 1
                continue

            ip = eth.data

            if isinstance(ip, dpkt.ip.IP):
                stats["ipv4"] += 1
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)
            elif isinstance(ip, dpkt.ip6.IP6):
                stats["ipv6"] += 1
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)
            else:
                stats["non_ip"] += 1
                continue

            src_ip_counter[src_ip] += 1
            dst_ip_counter[dst_ip] += 1

            try:
                if isinstance(ip.data, dpkt.tcp.TCP):
                    stats["tcp"] += 1
                    l4_proto_counter["TCP"] += 1
                    sport_counter[ip.data.sport] += 1
                    dport_counter[ip.data.dport] += 1

                elif isinstance(ip.data, dpkt.udp.UDP):
                    stats["udp"] += 1
                    l4_proto_counter["UDP"] += 1
                    sport_counter[ip.data.sport] += 1
                    dport_counter[ip.data.dport] += 1

                elif isinstance(ip.data, dpkt.icmp.ICMP):
                    stats["icmp"] += 1
                    l4_proto_counter["ICMP"] += 1

                elif isinstance(ip.data, dpkt.icmp6.ICMP6):
                    stats["icmp"] += 1
                    l4_proto_counter["ICMPv6"] += 1

                else:
                    proto_name = type(ip.data).__name__
                    l4_proto_counter[proto_name] += 1

            except Exception:
                stats["ip_parse_error"] += 1
                continue

            if progress_every > 0 and i % progress_every == 0:
                elapsed = time.time() - started
                rate = i / elapsed if elapsed > 0 else 0.0
                print(
                    f"[progress] packets={i:,} elapsed={elapsed:.1f}s rate={rate:,.0f} pkt/s",
                    flush=True,
                )

    elapsed_total = time.time() - started
    stats["elapsed_seconds"] = elapsed_total
    stats["packets_per_second"] = (
        stats["packets_total"] / elapsed_total if elapsed_total > 0 else 0.0
    )

    stats["top_destination_ports"] = dport_counter.most_common(20)
    stats["top_source_ports"] = sport_counter.most_common(20)
    stats["top_source_ips"] = src_ip_counter.most_common(20)
    stats["top_destination_ips"] = dst_ip_counter.most_common(20)
    stats["layer4_protocols"] = l4_proto_counter.most_common()
    stats["packets_per_minute_top20"] = packets_per_minute.most_common(20)
    stats["finished_at_epoch"] = time.time()

    return stats


def save_json(obj: dict[str, Any], outpath: Path) -> None:
    """解析結果の辞書をJSONファイルとして保存する。

    保存先ディレクトリが存在しない場合は作成し、日本語などをそのまま
    読めるように ``ensure_ascii=False`` で書き出す。
    """
    safe_mkdir(outpath.parent)
    with outpath.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def parse_args() -> argparse.Namespace:
    """解析スクリプトのコマンドライン引数を解析する。"""
    parser = argparse.ArgumentParser(
        description="Analyze one .pcap.gz file with dpkt."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"input .pcap.gz path (default: {DEFAULT_INPUT})",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=DEFAULT_OUTDIR,
        help=f"output directory (default: {DEFAULT_OUTDIR})",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1_000_000,
        help="show progress every N packets (default: 1000000)",
    )
    parser.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="stop after reading this many packets (for quick testing)",
    )
    return parser.parse_args()


def main() -> int:
    """コマンドライン処理を実行し、プロセスの終了コードを返す。"""
    args = parse_args()
    input_path = args.input
    outdir = resolve_from_repo_root(args.outdir)

    if not input_path.exists():
        print(f"[error] input not found: {input_path}", file=sys.stderr)
        return 1

    outpath = outdir / f"{input_path.name.replace('.pcap.gz', '')}.json"

    try:
        print(f"[info] analyzing: {input_path}")
        stats = analyze_pcap_gz(
            input_path,
            progress_every=args.progress_every,
            max_packets=args.max_packets,
        )
        save_json(stats, outpath)
        print(f"[done] result saved to: {outpath}")
        print(
            f"[summary] packets={stats['packets_total']:,} "
            f"bytes={stats['bytes_total']:,} "
            f"elapsed={stats['elapsed_seconds']:.1f}s "
            f"rate={stats['packets_per_second']:,.0f} pkt/s"
        )
        return 0
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
