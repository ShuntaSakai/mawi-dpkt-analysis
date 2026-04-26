#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results/flows/all"
DEFAULT_OUTPUT_FILENAME = "flows.csv"
PROTOCOLS: tuple[int, ...] = (6, 17)
dpkt = None


def require_dpkt() -> Any:
    global dpkt
    if dpkt is None:
        import dpkt as dpkt_module

        dpkt = dpkt_module
    return dpkt


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int


@dataclass(frozen=True)
class FlowKey:
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    protocol: int


@dataclass
class Flow:
    flow_id: int
    start_time: float
    end_time: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    packet_count: int = 0
    byte_count: int = 0
    packets_from_src: int = 0
    packets_from_dst: int = 0
    bytes_from_src: int = 0
    bytes_from_dst: int = 0
    syn_count: int = 0
    syn_ack_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    def update(
        self,
        timestamp: float,
        packet_byte: int,
        is_from_src: bool,
        tcp_flags: int | None,
    ) -> None:
        self.end_time = timestamp
        self.packet_count += 1
        # byte_count は pcap に記録された Ethernet フレーム長 len(buf) ベースで集計する。
        self.byte_count += packet_byte

        if is_from_src:
            self.packets_from_src += 1
            self.bytes_from_src += packet_byte
        else:
            self.packets_from_dst += 1
            self.bytes_from_dst += packet_byte

        if tcp_flags is None:
            return

        dpkt_module = require_dpkt()

        if tcp_flags & dpkt_module.tcp.TH_SYN:
            self.syn_count += 1
        if (tcp_flags & dpkt_module.tcp.TH_SYN) and (tcp_flags & dpkt_module.tcp.TH_ACK):
            self.syn_ack_count += 1
        if tcp_flags & dpkt_module.tcp.TH_ACK:
            self.ack_count += 1
        if tcp_flags & dpkt_module.tcp.TH_FIN:
            self.fin_count += 1
        if tcp_flags & dpkt_module.tcp.TH_RST:
            self.rst_count += 1

    def duration(self) -> float:
        return self.end_time - self.start_time

    def pps(self) -> float:
        duration = self.duration()
        return self.packet_count / duration if duration > 0 else 0.0

    def bps(self) -> float:
        duration = self.duration()
        return self.byte_count / duration if duration > 0 else 0.0


@dataclass
class Stats:
    total_packets: int = 0
    skipped_non_ip: int = 0
    skipped_non_tcp_udp: int = 0
    parse_errors: int = 0


def inet_to_str(addr: bytes) -> str:
    try:
        if len(addr) == 4:
            return socket.inet_ntop(socket.AF_INET, addr)
        if len(addr) == 16:
            return socket.inet_ntop(socket.AF_INET6, addr)
    except OSError:
        pass
    return addr.hex()


def open_input_file(input_path: Path) -> BinaryIO:
    if input_path.suffix == ".gz":
        return gzip.open(input_path, "rb")
    return input_path.open("rb")


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def build_default_output_path(input_path: Path) -> Path:
    filename = input_path.name
    for suffix in (".pcapng.gz", ".pcap.gz", ".pcapng", ".pcap"):
        if filename.endswith(suffix):
            filename = filename[: -len(suffix)]
            break
    return DEFAULT_OUTPUT_DIR / filename / DEFAULT_OUTPUT_FILENAME


def open_packet_reader(fp: BinaryIO) -> Iterator[tuple[float, bytes]]:
    dpkt_module = require_dpkt()
    try:
        return dpkt_module.pcap.Reader(fp)
    except ValueError:
        fp.seek(0)
        try:
            return dpkt_module.pcapng.Reader(fp)
        except ValueError as exc:
            raise ValueError(f"unsupported capture format: {exc}") from exc


def get_ip_protocol(ip: dpkt.ip.IP | dpkt.ip6.IP6) -> int:
    dpkt_module = require_dpkt()
    if isinstance(ip, dpkt_module.ip.IP):
        return ip.p
    return ip.nxt


def get_transport_layer(ip: dpkt.ip.IP | dpkt.ip6.IP6) -> dpkt.tcp.TCP | dpkt.udp.UDP:
    dpkt_module = require_dpkt()
    transport = ip.data
    if isinstance(transport, (dpkt_module.tcp.TCP, dpkt_module.udp.UDP)):
        return transport
    raise TypeError("unsupported transport protocol")


def normalize_flow_key(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: int,
) -> FlowKey:
    # 双方向フローとして集約するため、A->B と B->A が同じキーになるように正規化する。
    endpoint_src = Endpoint(src_ip, src_port)
    endpoint_dst = Endpoint(dst_ip, dst_port)
    endpoint_a, endpoint_b = sorted((endpoint_src, endpoint_dst), key=lambda ep: (ep.ip, ep.port))
    return FlowKey(endpoint_a=endpoint_a, endpoint_b=endpoint_b, protocol=protocol)


def is_packet_from_initial_src(flow: Flow, src_ip: str, src_port: int) -> bool:
    return flow.src_ip == src_ip and flow.src_port == src_port


def write_csv(output_path: Path, flows: list[Flow]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
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
            ]
        )

        for flow in flows:
            writer.writerow(
                [
                    flow.flow_id,
                    f"{flow.start_time:.6f}",
                    f"{flow.end_time:.6f}",
                    flow.src_ip,
                    flow.src_port,
                    flow.dst_ip,
                    flow.dst_port,
                    flow.protocol,
                    f"{flow.duration():.6f}",
                    flow.packet_count,
                    flow.byte_count,
                    f"{flow.pps():.6f}",
                    f"{flow.bps():.6f}",
                    flow.packets_from_src,
                    flow.packets_from_dst,
                    flow.bytes_from_src,
                    flow.bytes_from_dst,
                    flow.syn_count,
                    flow.syn_ack_count,
                    flow.ack_count,
                    flow.fin_count,
                    flow.rst_count,
                ]
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aggregate TCP/UDP packets from pcap/pcapng into bidirectional flows.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    required_args = parser.add_argument_group("required arguments")
    required_inputs = required_args.add_mutually_exclusive_group(required=True)
    optional_args = parser.add_argument_group("options")
    required_inputs.add_argument("--input", dest="input", type=Path, help="input capture path")
    required_inputs.add_argument("--input_path", dest="input_path", type=Path, help="legacy input path")
    optional_args.add_argument(
        "--output",
        dest="output",
        type=Path,
        help=f"output CSV path; if omitted, write {DEFAULT_OUTPUT_DIR}/<input_name>/{DEFAULT_OUTPUT_FILENAME}",
    )
    optional_args.add_argument("--output_path", dest="output_path", type=Path, help="legacy output path")
    optional_args.add_argument(
        "--progress-every",
        type=int,
        default=1_000_000,
        help="show progress every N packets; 0 disables progress output",
    )
    return parser


def parse_args() -> argparse.Namespace:
    return build_parser().parse_args()


def resolve_cli_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    input_arg = args.input or args.input_path
    if input_arg is None:
        raise ValueError("--input or --input_path is required")

    input_path = resolve_from_repo_root(input_arg)
    output_arg = args.output or args.output_path
    output_path = (
        resolve_from_repo_root(output_arg)
        if output_arg is not None
        else build_default_output_path(input_path)
    )
    return input_path, output_path


def aggregate_flows(
    input_path: Path,
    progress_every: int,
) -> tuple[list[Flow], Stats]:
    flow_dict: dict[FlowKey, Flow] = {}
    stats = Stats()
    next_flow_id = 1
    started = time.perf_counter()

    with open_input_file(input_path) as fp:
        packet_reader = open_packet_reader(fp)

        # タイムアウトは設けず、フローはキャプチャ全体を通して集約し EOF で確定する。
        for ts, buf in packet_reader:
            stats.total_packets += 1

            if progress_every > 0 and stats.total_packets % progress_every == 0:
                elapsed = time.perf_counter() - started
                rate = stats.total_packets / elapsed if elapsed > 0 else 0.0
                print(
                    f"[progress] packets={stats.total_packets:,} elapsed={elapsed:.1f}s rate={rate:,.0f} pkt/s",
                    flush=True,
                )

            dpkt_module = require_dpkt()

            try:
                eth = dpkt_module.ethernet.Ethernet(buf)
            except Exception:
                stats.parse_errors += 1
                continue

            if not isinstance(eth.data, (dpkt_module.ip.IP, dpkt_module.ip6.IP6)):
                stats.skipped_non_ip += 1
                continue
            ip = eth.data

            proto = get_ip_protocol(ip)
            if proto not in PROTOCOLS:
                stats.skipped_non_tcp_udp += 1
                continue

            try:
                src_ip = inet_to_str(ip.src)
                dst_ip = inet_to_str(ip.dst)
                transport = get_transport_layer(ip)
                src_port = int(getattr(transport, "sport"))
                dst_port = int(getattr(transport, "dport"))
            except Exception:
                stats.parse_errors += 1
                continue

            flow_key = normalize_flow_key(src_ip, dst_ip, src_port, dst_port, proto)
            flow = flow_dict.get(flow_key)

            if flow is None:
                # 出力用の src/dst はソート順ではなく、最初に観測されたパケット方向で固定する。
                flow = Flow(
                    flow_id=next_flow_id,
                    start_time=ts,
                    end_time=ts,
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=proto,
                )
                flow_dict[flow_key] = flow
                next_flow_id += 1

            packet_byte = len(buf)
            tcp_flags = transport.flags if isinstance(transport, dpkt_module.tcp.TCP) else None
            flow.update(
                timestamp=ts,
                packet_byte=packet_byte,
                is_from_src=is_packet_from_initial_src(flow, src_ip, src_port),
                tcp_flags=tcp_flags,
            )

    flows = sorted(flow_dict.values(), key=lambda flow: flow.flow_id)
    return flows, stats


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        return 2

    args = parser.parse_args()

    try:
        input_path, output_path = resolve_cli_paths(args)
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    if not input_path.exists():
        print(f"[error] input not found: {input_path}", file=sys.stderr)
        return 1

    start_timer = time.perf_counter()
    print(f"Processing: {input_path}")

    try:
        flows, stats = aggregate_flows(input_path, progress_every=args.progress_every)
        write_csv(output_path, flows)
    except Exception as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1

    process_time = time.perf_counter() - start_timer

    print(f"total_packets = {stats.total_packets}")
    print(f"skipped_non_ip = {stats.skipped_non_ip}")
    print(f"skipped_non_tcp_udp = {stats.skipped_non_tcp_udp}")
    print(f"parse_errors = {stats.parse_errors}")
    print(f"flow_num = {len(flows)}")
    print(f"process_time = {process_time:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
