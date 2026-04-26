#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
plt = None


def require_matplotlib_pyplot() -> Any:
    global plt
    if plt is None:
        import matplotlib.pyplot as pyplot

        plt = pyplot
    return plt

DEFAULT_FEATURES = [
    "flow_inter_arrival_time",
    "duration",
    "packet_count",
    "byte_count",
    "pps",
    "bps",
    "avg_packet_size",
    "packets_from_src_ratio",
    "bytes_from_src_ratio",
]

TOP_KEYS = ["packet_count", "byte_count", "duration", "pps", "bps"]


def resolve_from_repo_root(path: Path) -> Path:
    return path if path.is_absolute() else REPO_ROOT / path


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def safe_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def sanitize_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name)


def short_feature_label(name: str) -> str:
    return name.replace("_", " ")


def dataset_name(data: dict[str, Any], input_path: Path) -> str:
    return data.get("scope", {}).get("dataset_name", input_path.stem)


def valid_flow_count(data: dict[str, Any]) -> int:
    return int(data.get("totals", {}).get("valid_flow_count", 0))


def add_common_title(ax: plt.Axes, data: dict[str, Any], title: str) -> None:
    name = data.get("scope", {}).get("dataset_name", "unknown")
    n_flows = valid_flow_count(data)
    ax.set_title(f"{title}\n{name} (n={n_flows})")


def annotate_small_sample(ax: plt.Axes, count: int) -> None:
    # 小標本ではヒストグラムの形に意味を読み込みすぎやすいため、図にも明示する。
    if count < 30:
        ax.text(
            0.99,
            0.98,
            f"small sample: n={count}",
            ha="right",
            va="top",
            transform=ax.transAxes,
            fontsize=9,
            color="dimgray",
        )


def compact_flow_label(record: dict[str, Any], max_host_len: int = 24) -> str:
    def shorten_host(host: str) -> str:
        if len(host) <= max_host_len:
            return host
        return f"{host[:max_host_len - 1]}…"

    proto = record.get("protocol", "")
    src_ip = shorten_host(str(record.get("src_ip", "")))
    dst_ip = shorten_host(str(record.get("dst_ip", "")))
    src = f"{src_ip}:{record.get('src_port', '')}"
    dst = f"{dst_ip}:{record.get('dst_port', '')}"
    return f"{proto} {src} -> {dst}"


def save_figure(fig: plt.Figure, outpath: Path) -> Path:
    plt_module = require_matplotlib_pyplot()
    fig.tight_layout()
    fig.savefig(outpath, dpi=150)
    plt_module.close(fig)
    return outpath


def plot_histogram(
    data: dict[str, Any],
    feature_name: str,
    feature: dict[str, Any],
    outdir: Path,
    use_log_histogram: bool = False,
) -> Path | None:
    plt_module = require_matplotlib_pyplot()
    hist_key = "log_histogram" if use_log_histogram else "histogram"
    histogram = feature.get(hist_key)

    if histogram is None:
        return None

    if use_log_histogram:
        edges = histogram.get("linear_edges", [])
        suffix = "log_hist"
    else:
        edges = histogram.get("edges", [])
        suffix = "hist"

    counts = histogram.get("counts", [])
    stats = feature.get("stats", {})
    count = int(stats.get("count", 0))

    if not edges or not counts or len(edges) != len(counts) + 1:
        return None

    unit = feature.get("unit", "")
    label = short_feature_label(feature_name)
    xlabel = f"{label} ({unit})" if unit else label

    fig, ax = plt_module.subplots(figsize=(9, 5.5))

    # JSON に保存された edge/count をそのまま使い、比較時も再現性のある図にする。
    widths = [edges[i + 1] - edges[i] for i in range(len(counts))]
    ax.bar(edges[:-1], counts, width=widths, align="edge", edgecolor="black", linewidth=0.4)

    if use_log_histogram:
        # log histogram は「log 空間で binning した結果」なので、x 軸を log にして解釈を揃える。
        ax.set_xscale("log")
        non_positive_count = histogram.get("non_positive_count", 0)
        ax.set_xlabel(f"{xlabel} [log x-scale]")
        if non_positive_count:
            ax.text(
                0.99,
                0.90,
                f"excluded non-positive values: {non_positive_count}",
                ha="right",
                va="top",
                transform=ax.transAxes,
                fontsize=9,
                color="dimgray",
            )
        add_common_title(ax, data, f"{label} distribution (log bins)")
    else:
        ax.set_xlabel(xlabel)
        add_common_title(ax, data, f"{label} distribution")

    ax.set_ylabel("Flow count")
    annotate_small_sample(ax, count)

    outpath = outdir / f"{sanitize_filename(feature_name)}_{suffix}.png"
    return save_figure(fig, outpath)


def plot_tcp_flag_totals(data: dict[str, Any], outdir: Path) -> Path | None:
    plt_module = require_matplotlib_pyplot()
    flags = data.get("tcp_flag_totals")
    if not flags:
        return None

    labels = list(flags.keys())
    values = [flags[key] for key in labels]

    fig, ax = plt_module.subplots(figsize=(8, 5))
    ax.bar(labels, values, edgecolor="black", linewidth=0.4)
    ax.set_xlabel("TCP flag")
    ax.set_ylabel("Count")
    ax.tick_params(axis="x", rotation=30)
    add_common_title(ax, data, "TCP flag totals")

    outpath = outdir / "tcp_flag_totals.png"
    return save_figure(fig, outpath)


def plot_tcp_flag_rates(data: dict[str, Any], outdir: Path) -> Path | None:
    plt_module = require_matplotlib_pyplot()
    rates = data.get("tcp_flag_rates_per_flow")
    if not rates:
        return None

    labels = list(rates.keys())
    values = [rates[key] for key in labels]

    fig, ax = plt_module.subplots(figsize=(8.5, 5))
    ax.bar(labels, values, edgecolor="black", linewidth=0.4)
    ax.set_xlabel("TCP flag metric")
    ax.set_ylabel("Average count per flow")
    ax.tick_params(axis="x", rotation=30)
    add_common_title(ax, data, "TCP flag rates per flow")

    outpath = outdir / "tcp_flag_rates_per_flow.png"
    return save_figure(fig, outpath)


def plot_behavioral_indicators(data: dict[str, Any], outdir: Path) -> Path | None:
    plt_module = require_matplotlib_pyplot()
    indicators = data.get("behavioral_indicators")
    if not indicators:
        return None

    labels = list(indicators.keys())
    values = [indicators[key] for key in labels]

    fig, ax = plt_module.subplots(figsize=(10.5, 5.5))
    ax.bar(labels, values, edgecolor="black", linewidth=0.4)
    ax.set_xlabel("Indicator")
    ax.set_ylabel("Ratio")
    ax.set_ylim(0, 1)
    ax.tick_params(axis="x", rotation=30)
    add_common_title(ax, data, "Behavioral indicators")

    outpath = outdir / "behavioral_indicators.png"
    return save_figure(fig, outpath)


def plot_top_flows(
    data: dict[str, Any],
    outdir: Path,
    top_key: str,
    top_n: int,
) -> Path | None:
    plt_module = require_matplotlib_pyplot()
    top = data.get("top", {})
    records = top.get(f"by_{top_key}", [])

    if not records:
        return None

    records = records[:top_n]
    labels = [compact_flow_label(record) for record in records]
    values = [record[top_key] for record in records]

    fig_height = max(4.5, 0.5 * len(records) + 1.5)
    fig, ax = plt_module.subplots(figsize=(12, fig_height))
    ax.barh(labels[::-1], values[::-1], edgecolor="black", linewidth=0.4)
    ax.set_xlabel(top_key)
    ax.set_ylabel("Flow")
    add_common_title(ax, data, f"Top {len(records)} flows by {top_key}")

    outpath = outdir / f"top_flows_by_{sanitize_filename(top_key)}.png"
    return save_figure(fig, outpath)


def plot_protocol_summary(data: dict[str, Any], outdir: Path) -> list[Path]:
    plt_module = require_matplotlib_pyplot()
    protocol_summary = data.get("protocol_summary")
    if not protocol_summary:
        return []

    labels = []
    flow_counts = []
    flow_ratios = []

    for proto, summary in sorted(protocol_summary.items()):
        labels.append(f"proto {proto}")
        flow_counts.append(summary.get("flow_count", 0))
        flow_ratios.append(summary.get("flow_ratio", 0.0))

    created: list[Path] = []

    fig1, ax1 = plt_module.subplots(figsize=(8, 5))
    ax1.bar(labels, flow_counts, edgecolor="black", linewidth=0.4)
    ax1.set_xlabel("Protocol")
    ax1.set_ylabel("Flow count")
    add_common_title(ax1, data, "Protocol flow counts")
    created.append(save_figure(fig1, outdir / "protocol_flow_counts.png"))

    fig2, ax2 = plt_module.subplots(figsize=(8, 5))
    ax2.bar(labels, flow_ratios, edgecolor="black", linewidth=0.4)
    ax2.set_xlabel("Protocol")
    ax2.set_ylabel("Flow ratio")
    ax2.set_ylim(0, 1)
    add_common_title(ax2, data, "Protocol flow ratios")
    created.append(save_figure(fig2, outdir / "protocol_flow_ratios.png"))

    return created


def validate_input_json(data: dict[str, Any]) -> None:
    if "features" not in data:
        raise ValueError("input JSON does not contain 'features'")
    if "scope" not in data:
        raise ValueError("input JSON does not contain 'scope'")


def generate_plots(
    data: dict[str, Any],
    outdir: Path,
    graph: str,
    features: list[str],
    top_n: int,
) -> list[Path]:
    created: list[Path] = []
    safe_mkdir(outdir)

    if graph in ("features", "all"):
        feature_map = data.get("features", {})
        for feature_name in features:
            feature = feature_map.get(feature_name)
            if feature is None:
                print(f"[warn] feature not found: {feature_name}")
                continue

            path = plot_histogram(data, feature_name, feature, outdir, use_log_histogram=False)
            if path:
                created.append(path)

            # ratio 系を log にすると 0 近傍の解釈を誤りやすいので、JSON の推奨値を尊重する。
            if feature.get("log_scale_recommended") and feature.get("unit") != "ratio":
                path = plot_histogram(data, feature_name, feature, outdir, use_log_histogram=True)
                if path:
                    created.append(path)

    if graph in ("tcp_flags", "all"):
        path = plot_tcp_flag_totals(data, outdir)
        if path:
            created.append(path)

        path = plot_tcp_flag_rates(data, outdir)
        if path:
            created.append(path)

    if graph in ("behavior", "all"):
        path = plot_behavioral_indicators(data, outdir)
        if path:
            created.append(path)

    if graph in ("top", "all"):
        for key in TOP_KEYS:
            path = plot_top_flows(data, outdir, key, top_n)
            if path:
                created.append(path)

    if graph in ("protocol", "all"):
        created.extend(plot_protocol_summary(data, outdir))

    return created


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate plots from flow feature summary JSON."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="input feature summary JSON",
    )
    parser.add_argument(
        "--outdir",
        type=Path,
        default=Path("results/flow_plots/all"),
        help="base output directory for plot images",
    )
    parser.add_argument(
        "--graph",
        choices=["features", "tcp_flags", "behavior", "top", "protocol", "all"],
        default="all",
        help="which graph group to generate",
    )
    parser.add_argument(
        "--features",
        nargs="*",
        default=DEFAULT_FEATURES,
        help="feature names to plot",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="number of top flows to plot",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    input_path = resolve_from_repo_root(args.input)
    outdir = resolve_from_repo_root(args.outdir)

    if not input_path.exists():
        print(f"[error] input not found: {input_path}")
        return 1

    try:
        data = load_json(input_path)
        validate_input_json(data)
    except ValueError as exc:
        print(f"[error] {exc}")
        return 1

    output_dir = outdir / sanitize_filename(dataset_name(data, input_path))

    created = generate_plots(
        data=data,
        outdir=output_dir,
        graph=args.graph,
        features=args.features,
        top_n=args.top_n,
    )

    print("[done] created plots:")
    for path in created:
        print(f"  - {path}")

    if not created:
        print("[warn] no plots were created")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
