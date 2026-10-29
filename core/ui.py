from __future__ import annotations

import discord

from . import __version__
from .config import MODES
from .metrics import spark

FILLED, EMPTY = "▰", "▱"
GEN_ICON = {6: "🟣", 7: "🔵", 8: "🟢", 9: "⚪", 0: "⚫"}
GEN_COLOR = {6: 0x9B59B6, 7: 0x007DB8, 8: 0x57F287, 9: 0x99AAB5, 0: 0x2B2D31}


def bar(p: float, w: int = 16) -> str:
    n = int(round(p * w))
    return FILLED * n + EMPTY * (w - n)


def uptime(sec: float) -> str:
    sec = int(sec)
    d, sec = divmod(sec, 86400)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    return f"{d}d {h}h {m}m" if d else (f"{h}h {m}m {s}s" if h else f"{m}m {s}s")


def brand(title, desc="", color=0x007DB8) -> discord.Embed:
    e = discord.Embed(title=title, description=desc, color=color)
    e.set_footer(text=f"idrac-hunter v{__version__}")
    e.timestamp = discord.utils.utcnow()
    return e


def status_embed(state, stats, gen_counts) -> discord.Embed:
    m = MODES.get(state.mode, MODES["normal"])
    if state.running:
        e = brand(f"{m['emoji']} Hunting — {m['label']}", color=m["color"])
        e.add_field(name="Phase", value=f"`{state.phase}`", inline=True)
        e.add_field(name="Cycle", value=f"#{state.cycle}", inline=True)
        e.add_field(name="Uptime", value=uptime(state.uptime), inline=True)
        e.add_field(name="Progress",
                    value=f"`{bar(state.progress)}` {state.progress * 100:.1f}%\n"
                          f"{state.scanned:,} / {state.total_cycle:,}", inline=False)
    else:
        e = brand("⏸ Idle", "Use `/idrac start`.", 0x2B2D31)
    e.add_field(name="This cycle",
                value=f"scraped `{state.scanned:,}` · iDRAC `{state.alive:,}` · "
                      f"vuln `{state.vulns:,}`", inline=False)
    if state.history:
        e.add_field(name="Alive trend", value=f"`{spark(state.history)}`", inline=False)
    e.add_field(name="Database",
                value=f"hosts `{stats['hosts']:,}` · alive `{stats['alive']:,}` · "
                      f"pending `{stats['pending']:,}`\nvulns `{stats['vulns']:,}` "
                      f"(`{stats['confirmed']:,}` confirmed) · creds `{stats['creds']:,}` "
                      f"· bypass `{stats['bypass']:,}`", inline=False)
    dist = " ".join(f"{GEN_ICON[g]} {g or '?'}:`{c}`" for g, c in sorted(gen_counts.items()))
    if dist:
        e.add_field(name="Generations", value=dist, inline=False)
    if state.last_error:
        e.add_field(name="Last error", value=f"```{state.last_error[:300]}```", inline=False)
    return e


def host_embed(r) -> discord.Embed:
    g = r["generation"]
    e = brand(f"{GEN_ICON.get(g, '⚫')} {r['ip']}:{r['port']}", color=GEN_COLOR.get(g, 0x007DB8))
    e.add_field(name="Generation", value=f"iDRAC{g}" if g else "unknown", inline=True)
    e.add_field(name="Firmware", value=f"`{r['firmware'] or '-'}`", inline=True)
    e.add_field(name="Status", value=f"`{r['status']}`", inline=True)
    if r["default_creds"]:
        e.add_field(name="Credentials", value="`root:calvin` works", inline=False)
    if r["auth_bypass"]:
        e.add_field(name="Leak surface", value="unauthenticated endpoints answer", inline=False)
    if r["model"]:
        e.add_field(name="Model", value=f"`{r['model']}`", inline=True)
    if r["evidence"]:
        e.add_field(name="Evidence", value=f"```{r['evidence'][:800]}```", inline=False)
    geo = " · ".join(filter(None, [r["country"], r["asn"], r["org"]]))
    if geo:
        e.add_field(name="Network", value=f"`{geo}`", inline=False)
    if r["sources"]:
        e.add_field(name="Sources", value=f"`{r['sources'][:250]}`", inline=False)
    return e


def vuln_embed(r, cfg) -> discord.Embed:
    c = r["confidence"]
    color = {"confirmed": cfg.vuln_color, "likely": cfg.warn_color}.get(c, 0x99AAB5)
    icon = {"confirmed": "🔴", "likely": "🟠", "suspect": "🟡"}.get(c, "⚪")
    e = brand(f"{icon} {r['cve']} — {c.upper()}", color=color)
    e.add_field(name="Target", value=f"`{r['ip']}:{r['port']}`", inline=True)
    e.add_field(name="Generation", value=f"iDRAC{r['generation']}" if r["generation"]
                else "unknown", inline=True)
    e.add_field(name="Firmware", value=f"`{r['firmware'] or '-'}`", inline=True)
    e.add_field(name="Method", value=f"`{r['method']}`", inline=False)
    e.add_field(name="Evidence", value=f"```{r['evidence'][:800]}```", inline=False)
    e.url = f"https://{r['ip']}:{r['port']}/login.html"
    return e


def alert_embed(ip, port, scheme, verdict, fp, cfg) -> discord.Embed:
    e = vuln_embed({"cve": "CVE-2018-1207", "confidence": verdict.confidence, "ip": ip,
                    "port": port, "generation": verdict.generation,
                    "firmware": verdict.firmware, "method": verdict.method,
                    "evidence": verdict.evidence}, cfg)
    e.title = f"🚨 VULNERABLE iDRAC — {verdict.confidence.upper()}"
    e.add_field(name="URL", value=f"`{scheme}://{ip}:{port}/login.html`", inline=False)
    if fp.default_creds:
        e.add_field(name="Login", value="`root:calvin` accepted", inline=False)
    if fp.model:
        e.add_field(name="Model", value=f"`{fp.model}`", inline=False)
    return e


class Pager(discord.ui.View):
    def __init__(self, rows, total, per, builder):
        super().__init__(timeout=180)
        self.rows, self.total, self.per, self.builder = rows, total, per, builder
        self.page, self.pages = 0, max(1, (total + per - 1) // per)
        self._sync()

    def _sync(self):
        self.prev.disabled = self.page == 0
        self.next.disabled = self.page >= self.pages - 1
        self.counter.label = f"{self.page + 1}/{self.pages}"

    def current(self):
        s = self.page * self.per
        return self.builder(self.rows[s:s + self.per], s, self.total, self.page, self.pages)

    @discord.ui.button(label="◀", style=discord.ButtonStyle.secondary)
    async def prev(self, itx, _):
        self.page = max(0, self.page - 1)
        self._sync()
        await itx.response.edit_message(embed=self.current(), view=self)

    @discord.ui.button(label="1/1", style=discord.ButtonStyle.primary, disabled=True)
    async def counter(self, itx, _):
        pass

    @discord.ui.button(label="▶", style=discord.ButtonStyle.secondary)
    async def next(self, itx, _):
        self.page = min(self.pages - 1, self.page + 1)
        self._sync()
        await itx.response.edit_message(embed=self.current(), view=self)
