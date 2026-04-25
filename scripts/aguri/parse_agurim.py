#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent.parent

AGGREGATE_RE = re.compile(
    r"^\[\s*(?P<id>\d+)\]\s+"
    r"(?P<src>\S+)\s+"
    r"(?P<dst>\S+):\s+"
    r"(?P<bytes>[\d,]+)\s+\((?P<byte_ratio>\d+(?:\.\d+)?)%\)\s+"
    r"(?P<packets>[\d,]+)\s+\((?P<packet_ratio>\d+(?:\.\d+)?)%\)\s*$"
)

PROTOCOL_ENTRY_RE = re.compile(
    r"\[(?P<protocol>\d+):(?P<port_a>[^:\]]+):(?P<port_b>[^\]]+)\]\s+"
    r"(?P<byte_ratio>\d+(?:\.\d+)?)%\s+"
    r"(?P<packet_ratio>\d+(?:\.\d+)?)%"
)

OUTPUT_FIELDS = [
    "aggregate_id",
    "src_prefix",
    "dst_prefix",
    "bytes",
    "byte_ratio",
    "packets",
    "packet_ratio",
    "tcp_byte_ratio",
    "tcp_packet_ratio",
    "udp_byte_ratio",
    "udp_packet_ratio",
    "protocol_breakdown",
]


@dataclass
class AggregateRecord:
    aggregate_id: str
    src_prefix: str
    dst_prefix: str
    bytes: str
    byte_ratio: str
    packets: str
    packet_ratio: str
    protocol_breakdown_parts: list[str] = field(default_factory=list)

    @property
    def protocol_breakdown(self) -> str:
        return " ".join(part.strip() for part in self.protocol_breakdown_parts if part.strip())

    def protocol_totals(self) -> dict[int, tuple[float, float]]:
        totals: dict[int, list[float]] = {}
        for match in PROTOCOL_ENTRY_RE.finditer(self.protocol_breakdown):
            protocol = int(match.group("protocol"))
            byte_ratio = float(match.group("byte_ratio"))
            packet_ratio = float(match.group("packet_ratio"))
            if protocol not in totals:
                totals[protocol] = [0.0, 0.0]
            totals[protocol][0] += byte_ratio
            totals[protocol][1] += packet_ratio
        return {protocol: (values[0], values[1]) for protocol, values in totals.items()}

    def to_csv_row(self) -> dict[str, str]:
        protocol_totals = self.protocol_totals()
        tcp_byte_ratio, tcp_packet_ratio = protocol_totals.get(6, (0.0, 0.0))
        udp_byte_ratio, udp_packet_ratio = protocol_totals.get(17, (0.0, 0.0))

        return {
            "aggregate_id": self.aggregate_id,
            "src_prefix": self.src_prefix,
            "dst_prefix": self.dst_prefix,
            "bytes": self.bytes,
            "byte_ratio": self.byte_ratio,
            "packets": self.packets,
            "packet_ratio": self.packet_ratio,
            "tcp_byte_ratio": f"{tcp_byte_ratio:.2f}",
            "tcp_packet_ratio": f"{tcp_packet_ratio:.2f}",
            "udp_byte_ratio": f"{udp_byte_ratio:.2f}",
            "udp_packet_ratio": f"{udp_packet_ratio:.2f}",
            "protocol_breakdown": self.protocol_breakdown,
        }


@dataclass
class ParseResult:
    rows: list[AggregateRecord]
    warnings: list[str]


def normalize_count(value: str) -> str:
    return value.replace(",", "")


def default_output_path(input_path: Path) -> Path:
    if input_path.name.endswith(".agurim.txt"):
        stem = input_path.name[: -len(".agurim.txt")]
    else:
        stem = input_path.stem
    return input_path.with_name(f"{stem}.aguri_candidates.csv")


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def build_record(match: re.Match[str]) -> AggregateRecord:
    return AggregateRecord(
        aggregate_id=match.group("id"),
        src_prefix=match.group("src"),
        dst_prefix=match.group("dst"),
        bytes=normalize_count(match.group("bytes")),
        byte_ratio=match.group("byte_ratio"),
        packets=normalize_count(match.group("packets")),
        packet_ratio=match.group("packet_ratio"),
    )


def parse_agurim_lines(
    lines: Iterable[str],
    *,
    strict: bool = False,
) -> ParseResult:
    rows: list[AggregateRecord] = []
    warnings: list[str] = []
    current: AggregateRecord | None = None

    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\n")
        stripped = line.strip()

        if not stripped or stripped.startswith("%"):
            continue

        aggregate_match = AGGREGATE_RE.match(stripped)
        if aggregate_match:
            if current is not None:
                rows.append(current)
            current = build_record(aggregate_match)
            continue

        if current is not None and line[:1].isspace():
            current.protocol_breakdown_parts.append(stripped)
            continue

        message = f"Unparsed line {line_number}: {line}"
        if strict:
            raise ValueError(message)
        warnings.append(message)

    if current is not None:
        rows.append(current)

    return ParseResult(rows=rows, warnings=warnings)


def parse_agurim_txt(input_path: Path, *, strict: bool = False) -> ParseResult:
    with input_path.open("r", encoding="utf-8") as handle:
        return parse_agurim_lines(handle, strict=strict)


def ensure_input_exists(input_path: Path) -> None:
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")
    if not input_path.is_file():
        raise FileNotFoundError(f"Input path is not a file: {input_path}")


def ensure_output_writable(output_path: Path, force: bool) -> None:
    if output_path.exists() and not force:
        raise FileExistsError(
            f"Output file already exists: {output_path}\n"
            "Re-run with --force to overwrite."
        )


def write_csv(rows: list[AggregateRecord], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(row.to_csv_row() for row in rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse agurim text output into CSV."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="Input agurim text file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output CSV path. Default: <input_dir>/<dataset>.aguri_candidates.csv",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing output CSV.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if any non-empty, non-metadata line cannot be parsed.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = resolve_from_repo_root(args.input.expanduser())
    output_path = (
        resolve_from_repo_root(args.output.expanduser())
        if args.output is not None
        else default_output_path(input_path)
    )

    try:
        ensure_input_exists(input_path)
        ensure_output_writable(output_path, args.force)
        result = parse_agurim_txt(input_path, strict=args.strict)
    except (FileExistsError, FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    write_csv(result.rows, output_path)

    for warning in result.warnings:
        print(f"[WARN] {warning}", file=sys.stderr)

    if not result.rows:
        print("[WARN] No aggregates were parsed.", file=sys.stderr)

    print(f"[DONE] parsed {len(result.rows)} aggregates")
    print(f"CSV: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
