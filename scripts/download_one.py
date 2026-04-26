#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from cli_output import colorize_tag, format_tagged

DEFAULT_URL = "https://mawi.wide.ad.jp/mawi/ditl/ditl2026/202604080000.pcap.gz"
DEFAULT_OUTDIR = REPO_ROOT / "data/raw"


def format_size(num_bytes: int) -> str:
    """バイト数を人が読みやすいサイズ表記に変換する。

    1024倍ごとに ``B``、``KB``、``MB`` のような単位へ繰り上げ、
    小数第2位までの文字列として返す。
    """
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def resolve_from_repo_root(path: Path) -> Path:
    """相対パスをリポジトリルート基準の絶対パスに変換する。"""
    return path if path.is_absolute() else REPO_ROOT / path


def download_file(url: str, outdir: Path, force: bool = False) -> Path:
    """指定されたURLのファイルを出力ディレクトリへダウンロードする。

    保存ファイル名は ``url`` の最後のパス要素から決める。保存先に同名
    ファイルがある場合、``force`` が偽なら再利用してダウンロードを
    スキップする。ダウンロード中は標準出力に進捗を表示し、失敗した場合は
    作成途中のファイルを削除して ``RuntimeError`` を送出する。
    """
    outdir.mkdir(parents=True, exist_ok=True)
    filename = url.rstrip("/").split("/")[-1]
    outpath = outdir / filename

    if outpath.exists() and not force:
        print(format_tagged("[skip]", f"already exists: {outpath}", "yellow"))
        return outpath

    print(format_tagged("[info]", f"downloading: {url}", "blue"))
    print(format_tagged("[info]", f"save to    : {outpath}", "blue"))

    def reporthook(block_num: int, block_size: int, total_size: int) -> None:
        """``urlretrieve`` から渡されるブロック情報を使って進捗を表示する。"""
        progress_tag = colorize_tag("[downloading]", "cyan")
        if total_size <= 0:
            downloaded = block_num * block_size
            print(f"\r{progress_tag} {format_size(downloaded)}", end="", flush=True)
            return

        downloaded = min(block_num * block_size, total_size)
        percent = downloaded / total_size * 100
        print(
            f"\r{progress_tag} {percent:6.2f}% "
            f"({format_size(downloaded)} / {format_size(total_size)})",
            end="",
            flush=True,
        )

    try:
        urllib.request.urlretrieve(url, outpath, reporthook=reporthook)
        print()
    except Exception as e:
        print()
        if outpath.exists():
            outpath.unlink(missing_ok=True)
        raise RuntimeError(f"download failed: {e}") from e

    print(format_tagged("[done]", f"downloaded: {outpath}", "green"))
    return outpath


def build_parser() -> argparse.ArgumentParser:
    """ダウンロードスクリプトのコマンドライン引数を解析する。"""
    parser = argparse.ArgumentParser(
        description="Download one MAWI pcap.gz trace file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    optional_args = parser.add_argument_group("options")
    optional_args.add_argument(
        "--url",
        default=DEFAULT_URL,
        help="target URL",
    )
    optional_args.add_argument(
        "--outdir",
        type=Path,
        default=DEFAULT_OUTDIR,
        help="output directory",
    )
    optional_args.add_argument(
        "--force",
        action="store_true",
        help="overwrite if the file already exists",
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
    outdir = resolve_from_repo_root(args.outdir)
    try:
        download_file(args.url, outdir, force=args.force)
        return 0
    except Exception as e:
        print(format_tagged("[error]", str(e), "red", stream=sys.stderr), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
