"""Startup self-check."""
from __future__ import annotations

import os
import shutil

import aiohttp
import discord


def run(cfg, db) -> list[tuple[bool, str]]:
    checks = []
    checks.append((bool(cfg.bot_token), "bot token present"))
    checks.append((discord.__version__ >= "2.4", f"discord.py {discord.__version__}"))
    checks.append((aiohttp.__version__ >= "3.9", f"aiohttp {aiohttp.__version__}"))
    try:
        db.conn.execute("SELECT 1")
        checks.append((True, "database writable"))
    except Exception:
        checks.append((False, "database unwritable"))
    free = shutil.disk_usage("data").free / 1e9
    checks.append((free > 0.5, f"disk free {free:.1f} GB"))
    checks.append((os.path.isdir(cfg.export_dir), "export dir"))
    return checks
