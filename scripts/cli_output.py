from __future__ import annotations

import os
import sys
from typing import TextIO

RESET = "\033[0m"
COLORS = {
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
}


def _supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def colorize_tag(tag: str, color: str, *, stream: TextIO = sys.stdout) -> str:
    if not _supports_color(stream):
        return tag
    return f"{COLORS[color]}{tag}{RESET}"


def format_tagged(tag: str, message: str, color: str, *, stream: TextIO = sys.stdout) -> str:
    colored_tag = colorize_tag(tag, color, stream=stream)
    if not message:
        return colored_tag
    return f"{colored_tag} {message}"
