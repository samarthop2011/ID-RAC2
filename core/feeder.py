"""Discord feeds with their own token bucket and auto-disable on 429 storms."""
from __future__ import annotations

import asyncio
import logging

import discord

from .ui import GEN_ICON

LOG = logging.getLogger("feeder")
LEVELS = {"off": 0, "vuln": 1, "idrac": 2, "all": 3}
CONF = {"suspect": 0, "likely": 1, "confirmed": 2}


class Feeder:
    def __init__(self, bot, db):
        self.bot, self.db = bot, db
        self.q: asyncio.Queue = asyncio.Queue(maxsize=20000)
        self.alerts: asyncio.Queue = asyncio.Queue(maxsize=3000)
        self.tasks: list[asyncio.Task] = []
        self._bucket = 5.0
        self._disabled_until = 0.0

    def start(self):
        if not self.tasks:
            self.tasks = [asyncio.create_task(self._worker()),
                          asyncio.create_task(self._alert_worker())]

    async def stop(self):
        for t in self.tasks:
            t.cancel()
        self.tasks = []

    def _ch(self, key):
        cid = self.db.get_setting(key, "")
        return self.bot.get_channel(int(cid)) if cid.isdigit() else None

    def level(self) -> int:
        return LEVELS.get(self.db.get_setting("feed_level", "all"), 3)

    def min_conf(self) -> int:
        return CONF.get(self.db.get_setting("notify_min", "likely"), 1)

    def push(self, ip, port, kind):
        if LEVELS.get(kind, 3) <= self.level():
            return
        try:
            self.q.put_nowait((ip, port, kind))
        except asyncio.QueueFull:
            pass

    def push_alert(self, embed, confidence="likely"):
        if CONF.get(confidence, 1) < self.min_conf():
            return
        try:
            self.alerts.put_nowait(embed)
        except asyncio.QueueFull:
            pass

    async def _send(self, ch, **kw) -> bool:
        import time
        while time.monotonic() < self._disabled_until:
            await asyncio.sleep(2)
        try:
            await ch.send(**kw)
            self._bucket = min(5.0, self._bucket * 1.1)
            return True
        except discord.HTTPException as exc:
            if exc.status == 429:
                self._bucket = max(1.0, self._bucket * 0.5)
                self._disabled_until = time.monotonic() + 15
            else:
                LOG.warning("send: %s", exc)
            return False

    async def _worker(self):
        while True:
            batch = []
            try:
                batch.append(await self.q.get())
                await asyncio.sleep(3)
                while len(batch) < 45 and not self.q.empty():
                    batch.append(self.q.get_nowait())
            except asyncio.CancelledError:
                return
            ch = self._ch("feed_channel")
            if ch is None or not batch:
                continue
            lines = []
            for ip, port, kind in batch:
                row = self.db.get_host(ip, port)
                if kind == "dead":
                    lines.append(f"⚫ `{ip}:{port}` closed")
                    continue
                g = row["generation"] if row else 0
                tag = f" · iDRAC{g}" if g else ""
                if row and row["firmware"]:
                    tag += f" · fw {row['firmware']}"
                if row and row["default_creds"]:
                    tag += " · 🔑"
                icon = "🔴" if kind == "vuln" else GEN_ICON.get(g, "⚪")
                lines.append(f"{icon} `{ip}:{port}`{tag}")
            e = discord.Embed(title=f"📡 Scraped — {len(batch)}",
                              description="\n".join(lines)[:4000], color=0x007DB8)
            e.set_footer(text="idrac-hunter live feed")
            await self._send(ch, embed=e)
            await asyncio.sleep(1.0 / max(self._bucket, 1.0))

    async def _alert_worker(self):
        while True:
            try:
                embed = await self.alerts.get()
            except asyncio.CancelledError:
                return
            ch = self._ch("alert_channel")
            if ch:
                await self._send(ch, embed=embed)
            await asyncio.sleep(0.8)
