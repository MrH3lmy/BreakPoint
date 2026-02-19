"""Application logging setup."""

from __future__ import annotations

import importlib
import logging
from pathlib import Path


def setup_logging(log_path: str | Path = "breakpoint.log") -> logging.Logger:
    logger = logging.getLogger("breakpoint")
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
    logger.addHandler(file_handler)

    rich_spec = importlib.util.find_spec("rich.logging")
    if rich_spec:
        rich_logging = importlib.import_module("rich.logging")
        console_handler = rich_logging.RichHandler(markup=True, show_path=False, rich_tracebacks=True)
        console_handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    return logger
