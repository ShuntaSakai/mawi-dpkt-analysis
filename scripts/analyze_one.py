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

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "data/raw/202604080000.pcap.gz"
DEFAULT_OUTDIR = REPO_ROOT / "results/json/all"
dpkt = None


def require_dpkt() -> Any:
    global dpkt
    if dpkt is None:
        import dpkt as dpkt_module

        dpkt = dpkt_module
    return dpkt


def inet_to_str(addr: bytes) -> str:
    """
    IPアドレスのバイト列を文字列表記に変換する。

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


def counter_to_port_records(counter: Counter[int], key_name: str = "port") -> list[dict[str, Any]]:
    """ポート番号のCounterをJSON向けの上位20件レコードに変換する。"""
    return [{key_name: k, "packets": v} for k, v in counter.most_common(20)]


def counter_to_ip_records(counter: Counter[str], key_name: str = "ip") -> list[dict[str, Any]]:
    """IPアドレスのCounterをJSON向けの上位20件レコードに変換する。"""
    return [{key_name: k, "packets": v} for k, v in counter.most_common(20)]


def counter_to_endpoint_records(counter: Counter[str], key_name: str = "endpoint") -> list[dict[str, Any]]:
    """エンドポイントやフローのCounterをJSON向けの上位20件レコードに変換する。"""
    return [{key_name: k, "packets": v} for k, v in counter.most_common(20)]


def counter_to_proto_records(counter: Counter[str]) -> list[dict[str, Any]]:
    """プロトコル名のCounterをJSON向けレコードに変換する。"""
    return [{"protocol": k, "packets": v} for k, v in counter.most_common()]


def counter_to_time_records(counter: Counter[str]) -> list[dict[str, Any]]:
    """分単位の時刻バケットCounterをJSON向けの上位20件レコードに変換する。"""
    return [{"minute": k, "packets": v} for k, v in counter.most_common(20)]


def counter_to_flag_records(counter: Counter[str]) -> list[dict[str, Any]]:
    """TCPフラグ名や組み合わせのCounterをJSON向けレコードに変換する。"""
    return [{"flag": k, "packets": v} for k, v in counter.most_common()]


def tcp_flags_to_names(flags: int) -> list[str]:
    """TCPフラグ整数値を、人が読みやすいフラグ名の配列に変換する。"""
    dpkt_module = require_dpkt()
    names: list[str] = []
    if flags & dpkt_module.tcp.TH_FIN:
        names.append("FIN")
    if flags & dpkt_module.tcp.TH_SYN:
        names.append("SYN")
    if flags & dpkt_module.tcp.TH_RST:
        names.append("RST")
    if flags & dpkt_module.tcp.TH_PUSH:
        names.append("PSH")
    if flags & dpkt_module.tcp.TH_ACK:
        names.append("ACK")
    if flags & dpkt_module.tcp.TH_URG:
        names.append("URG")
    if flags & dpkt_module.tcp.TH_ECE:
        names.append("ECE")
    if flags & dpkt_module.tcp.TH_CWR:
        names.append("CWR")
    if not names:
        names.append("NONE")
    return names


def analyze_pcap_gz(
    input_path: Path,
    progress_every: int = 1_000_000,
    max_packets: int | None = None,
) -> dict[str, Any]:
    """
    gzip圧縮されたpcapファイルを読み込み、通信統計を集計する。

    Ethernetフレームを順に解析し、総パケット数、総バイト数、IPv4/IPv6、
    TCP/UDP/ICMP/ARP、上位ポート、上位IPアドレス、上位エンドポイント、
    上位フロー、分単位のパケット数などを、JSONで扱いやすいレコード形式の
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
        "tcp_syn": 0,
        "tcp_ack": 0,
        "tcp_fin": 0,
        "tcp_rst": 0,
    }

    dport_counter: Counter[int] = Counter()
    sport_counter: Counter[int] = Counter()
    src_ip_counter: Counter[str] = Counter()
    dst_ip_counter: Counter[str] = Counter()
    src_endpoint_counter: Counter[str] = Counter()
    dst_endpoint_counter: Counter[str] = Counter()
    flow_counter: Counter[str] = Counter()
    syn_flow_counter: Counter[str] = Counter()
    l4_proto_counter: Counter[str] = Counter()
    packets_per_minute: Counter[str] = Counter()
    tcp_flag_counter: Counter[str] = Counter()
    tcp_flag_combo_counter: Counter[str] = Counter()

    started = time.time()

    dpkt_module = require_dpkt()

    with gzip.open(input_path, "rb") as fp:
        pcap = dpkt_module.pcap.Reader(fp)

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
                eth = dpkt_module.ethernet.Ethernet(buf)
            except Exception:
                stats["ethernet_parse_error"] += 1
                continue

            if isinstance(eth.data, dpkt_module.arp.ARP):
                stats["arp"] += 1
                continue

            ip = eth.data

            if isinstance(ip, dpkt_module.ip.IP):
                stats["ipv4"] += 1
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)
            elif isinstance(ip, dpkt_module.ip6.IP6):
                stats["ipv6"] += 1
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)
            else:
                stats["non_ip"] += 1
                continue

            src_ip_counter[src_ip] += 1
            dst_ip_counter[dst_ip] += 1

            try:
                if isinstance(ip.data, dpkt_module.tcp.TCP):
                    tcp = ip.data
                    stats["tcp"] += 1
                    l4_proto_counter["TCP"] += 1

                    sport_counter[tcp.sport] += 1
                    dport_counter[tcp.dport] += 1

                    src_endpoint = f"{src_ip}:{tcp.sport}"
                    dst_endpoint = f"{dst_ip}:{tcp.dport}"
                    flow = f"TCP {src_ip}:{tcp.sport} -> {dst_ip}:{tcp.dport}"

                    src_endpoint_counter[src_endpoint] += 1
                    dst_endpoint_counter[dst_endpoint] += 1
                    flow_counter[flow] += 1

                    flags = tcp.flags
                    flag_names = tcp_flags_to_names(flags)
                    flag_combo = "|".join(flag_names)

                    tcp_flag_combo_counter[flag_combo] += 1
                    for name in flag_names:
                        tcp_flag_counter[name] += 1

                    if flags & dpkt_module.tcp.TH_SYN:
                        stats["tcp_syn"] += 1
                        syn_flow_counter[flow] += 1
                    if flags & dpkt_module.tcp.TH_ACK:
                        stats["tcp_ack"] += 1
                    if flags & dpkt_module.tcp.TH_FIN:
                        stats["tcp_fin"] += 1
                    if flags & dpkt_module.tcp.TH_RST:
                        stats["tcp_rst"] += 1

                elif isinstance(ip.data, dpkt_module.udp.UDP):
                    udp = ip.data
                    stats["udp"] += 1
                    l4_proto_counter["UDP"] += 1

                    sport_counter[udp.sport] += 1
                    dport_counter[udp.dport] += 1

                    src_endpoint = f"{src_ip}:{udp.sport}"
                    dst_endpoint = f"{dst_ip}:{udp.dport}"
                    flow = f"UDP {src_ip}:{udp.sport} -> {dst_ip}:{udp.dport}"

                    src_endpoint_counter[src_endpoint] += 1
                    dst_endpoint_counter[dst_endpoint] += 1
                    flow_counter[flow] += 1

                elif isinstance(ip.data, dpkt_module.icmp.ICMP):
                    stats["icmp"] += 1
                    l4_proto_counter["ICMP"] += 1

                elif isinstance(ip.data, dpkt_module.icmp6.ICMP6):
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

    stats["top_destination_ports"] = counter_to_port_records(dport_counter, "port")
    stats["top_source_ports"] = counter_to_port_records(sport_counter, "port")
    stats["top_source_ips"] = counter_to_ip_records(src_ip_counter, "ip")
    stats["top_destination_ips"] = counter_to_ip_records(dst_ip_counter, "ip")
    stats["top_source_endpoints"] = counter_to_endpoint_records(src_endpoint_counter, "endpoint")
    stats["top_destination_endpoints"] = counter_to_endpoint_records(dst_endpoint_counter, "endpoint")
    stats["top_flows"] = counter_to_endpoint_records(flow_counter, "flow")
    stats["top_syn_flows"] = counter_to_endpoint_records(syn_flow_counter, "flow")
    stats["layer4_protocols"] = counter_to_proto_records(l4_proto_counter)
    stats["packets_per_minute_top20"] = counter_to_time_records(packets_per_minute)
    stats["tcp_flag_counts"] = counter_to_flag_records(tcp_flag_counter)
    stats["top_tcp_flag_combinations"] = counter_to_flag_records(tcp_flag_combo_counter)
    stats["finished_at_epoch"] = time.time()

    return stats


def save_json(obj: dict[str, Any], outpath: Path) -> None:
    """
    解析結果の辞書をJSONファイルとして保存する。

    保存先ディレクトリが存在しない場合は作成し、日本語などをそのまま
    読めるように ``ensure_ascii=False`` で書き出す。
    """
    safe_mkdir(outpath.parent)
    with outpath.open("w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def build_parser() -> argparse.ArgumentParser:
    """解析スクリプトのコマンドライン引数を解析する。"""
    parser = argparse.ArgumentParser(
        description="Analyze one .pcap.gz file with dpkt.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    optional_args = parser.add_argument_group("options")
    optional_args.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help="input .pcap.gz path",
    )
    optional_args.add_argument(
        "--outdir",
        type=Path,
        default=DEFAULT_OUTDIR,
        help="output directory",
    )
    optional_args.add_argument(
        "--progress-every",
        type=int,
        default=1_000_000,
        help="show progress every N packets",
    )
    optional_args.add_argument(
        "--max-packets",
        type=int,
        default=None,
        help="stop after reading this many packets (for quick testing)",
    )
    return parser


def parse_args() -> argparse.Namespace:
    return build_parser().parse_args()


def main() -> int:
    """コマンドライン処理を実行し、プロセスの終了コードを返す。"""
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        return 2

    args = parser.parse_args()
    input_path = resolve_from_repo_root(args.input)
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
