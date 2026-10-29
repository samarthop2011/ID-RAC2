#!/usr/bin/env python3
"""iDRAC 6/7/8 hunter — keyless scraper, CVE-2018-1207 triage, 24/7."""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import random
import socket
import time
from logging.handlers import RotatingFileHandler

import discord
from discord import app_commands
from discord.ext import tasks

from core import doctor, metrics, scheduler, sources
from core.config import Config, MODES
from core.db import DB
from core.feeder import Feeder
from core.net import Fetcher, load_proxies
from core.reporter import Reporter
from core.scanner import run_batch, scan_list
from core.state import HuntState
from core.targets import expand, harvest_asns, load_file, parse_blob
from core.ui import GEN_ICON, Pager, brand, host_embed, status_embed

LOG = logging.getLogger("bot")
CFG = Config.load()
DB_ = DB(CFG.db_path)
STATE = HuntState()
FEEDER = Feeder(None, DB_)
START = time.time()

client = discord.Client(intents=discord.Intents.default())
tree = app_commands.CommandTree(client)


def setup_logging():
    os.makedirs("data", exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s")
    fh = RotatingFileHandler(CFG.log_file, maxBytes=10_000_000, backupCount=3)
    fh.setFormatter(fmt)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logging.basicConfig(level=getattr(logging, CFG.log_level.upper(), logging.INFO),
                        handlers=[fh, sh])


def mode_of(name=None):
    return MODES.get(name or STATE.mode, MODES["normal"])


def ports():
    raw = DB_.get_setting("ports", "")
    return [int(p) for p in raw.split(",") if p.strip().isdigit()] or CFG.default_ports


def gens():
    raw = DB_.get_setting("gens", "")
    return [int(g) for g in raw.split(",") if g.strip().isdigit()] or CFG.default_gens


def make_fetcher(mode) -> Fetcher:
    return Fetcher(mode["concurrency"], mode["delay"], mode["timeout"],
                   proxies=load_proxies(CFG.proxy_file))


async def hunt_forever():
    STATE.running = True
    STATE.started_at = time.time()
    DB_.set_setting("running", "1")
    try:
        while STATE.running:
            mode = mode_of()
            async with make_fetcher(mode) as fetcher:
                STATE.reset_cycle()
                reporter = Reporter(DB_, FEEDER, STATE, CFG)
                rid = DB_.start_run(STATE.mode)
                try:
                    if mode["engines"]:
                        STATE.phase = "harvest"
                        for name, s in sources.SOURCES.items():
                            if not STATE.running:
                                break
                            if not DB_.source_due(name, CFG.source_interval_hours):
                                continue
                            try:
                                ips = await asyncio.wait_for(
                                    s.fn(fetcher, CFG.source_result_limit), timeout=200)
                            except Exception as exc:
                                DB_.source_fail(name, str(exc))
                                continue
                            for ip in ips:
                                if DB_.add_host(ip, 443, "https", f"src:{name}", 35):
                                    STATE.harvested += 1
                            DB_.source_ok(name, len(ips))

                    STATE.phase = "expand"
                    nets = load_file(CFG.subnets_file)
                    if CFG.use_datacenters:
                        nets += load_file(CFG.datacenters_file)
                    if CFG.use_asn_harvest:
                        try:
                            nets += await harvest_asns(fetcher, CFG.asns_file)
                        except Exception:
                            pass
                    for cidr in DB_.subnets():
                        try:
                            nets.append(ipaddress.ip_network(cidr, strict=False))
                        except ValueError:
                            pass
                    seen = set()
                    for net in nets:
                        if str(net) in seen:
                            continue
                        seen.add(str(net))
                        for ip in expand(net, mode["sample"], False):
                            if DB_.add_host(ip, 443, "https", f"net:{net}", 10):
                                STATE.harvested += 1

                    STATE.phase = "scan"
                    while STATE.running:
                        if not await run_batch(fetcher, DB_, CFG, mode, reporter,
                                               mode["concurrency"] * 4, gens()):
                            break
                    STATE.phase = "idle"
                    metrics.record(STATE, STATE.alive, STATE.vulns)
                except Exception as exc:
                    LOG.exception("cycle")
                    STATE.last_error = f"{type(exc).__name__}: {exc}"
                finally:
                    DB_.finish_run(rid, STATE.scanned, STATE.alive,
                                   STATE.harvested, STATE.vulns)
                    DB_.export(CFG.export_dir)
            for _ in range(CFG.cycle_interval + random.randint(0, CFG.cycle_jitter)):
                if not STATE.running:
                    break
                await asyncio.sleep(1)
    finally:
        STATE.running = False
        STATE.phase = "idle"
        DB_.set_setting("running", "0")


def ensure_loop():
    if STATE.task is None or STATE.task.done():
        STATE.task = asyncio.create_task(hunt_forever())


@tasks.loop(seconds=45)
async def presence():
    if not client.is_ready():
        return
    s = DB_.stats()
    text = (f"{s['alive']:,} iDRAC · {s['vulns']:,} vuln" if STATE.running
            else f"{s['hosts']:,} hosts · idle")
    await client.change_presence(activity=discord.Activity(
        type=discord.ActivityType.watching, name=text[:128]))


@client.event
async def on_ready():
    FEEDER.bot = client
    FEEDER.start()
    DB_.recover_stuck()
    scheduler.start(DB_, CFG, STATE)
    STATE.mode = DB_.get_setting("mode", CFG.default_mode)
    STATE.gens = gens()
    if DB_.get_setting("running", "0") == "1":
        ensure_loop()
    presence.start()
    if CFG.guild_id:
        g = discord.Object(id=CFG.guild_id)
        tree.copy_global_to(guild=g)
        await tree.sync(guild=g)
    else:
        await tree.sync()
    LOG.info("ready as %s", client.user)


@client.event
async def on_close():
    STATE.running = False
    presence.cancel()
    await FEEDER.stop()
    DB_.export(CFG.export_dir)
    DB_.close()


# ---------------------------------------------------------------- /idrac
idrac = app_commands.Group(name="idrac", description="Control the hunter")


@idrac.command(description="Start 24/7 hunting")
@app_commands.choices(mode=[app_commands.Choice(name=f"{m['emoji']} {m['label']}", value=k)
                            for k, m in MODES.items()])
async def start(itx: discord.Interaction, mode: app_commands.Choice[str] | None = None):
    if STATE.running:
        return await itx.response.send_message("Already running.", ephemeral=True)
    if mode:
        STATE.mode = mode.value
        DB_.set_setting("mode", mode.value)
    m = mode_of()
    ensure_loop()
    await itx.response.send_message(embed=brand(
        f"{m['emoji']} Engaged — {m['label']}", m["blurb"], m["color"]))


@idrac.command(description="Stop hunting")
async def stop(itx: discord.Interaction):
    if not STATE.running:
        return await itx.response.send_message("Not running.", ephemeral=True)
    STATE.running = False
    await itx.response.send_message(embed=brand("⏸ Stopped", color=0x2B2D31))


@idrac.command(description="Status and counters")
async def status(itx: discord.Interaction):
    await itx.response.send_message(embed=status_embed(STATE, DB_.stats(), DB_.gen_counts()))


@idrac.command(description="Change scan mode")
@app_commands.choices(mode=[app_commands.Choice(name=f"{m['emoji']} {m['label']}", value=k)
                            for k, m in MODES.items()])
async def mode(itx: discord.Interaction, mode: app_commands.Choice[str]):
    STATE.mode = mode.value
    DB_.set_setting("mode", mode.value)
    m = mode_of()
    await itx.response.send_message(embed=brand(f"{m['emoji']} → {m['label']}",
                                                m["blurb"], m["color"]))


@idrac.command(description="Only report these generations")
async def generations(itx: discord.Interaction, gens_csv: str):
    DB_.set_setting("gens", gens_csv)
    STATE.gens = gens()
    await itx.response.send_message(embed=brand("🎯 Filter", f"`{STATE.gens}`"))


@idrac.command(description="Requeue every vulnerable host")
async def priority(itx: discord.Interaction):
    n = DB_.conn.execute("UPDATE hosts SET status='retry', next_scan=NULL "
                         "WHERE status='vuln'").rowcount
    DB_.conn.commit()
    await itx.response.send_message(embed=brand("🔄 Requeued", f"{n} hosts"))


# ---------------------------------------------------------------- /scan
scan = app_commands.Group(name="scan", description="Manual scans")


@scan.command(description="Scan a CIDR, range or IP")
async def cidr(itx: discord.Interaction, target: str, full: bool = False):
    await itx.response.defer()
    nets = parse_blob(target)
    if not nets:
        return await itx.followup.send("Bad target.")
    m = mode_of()
    targets = [(ip, ports()[0]) for n in nets for ip in expand(n, m["sample"], full)][:120_000]
    await itx.followup.send(embed=brand("🎯 Sweep queued", f"`{len(targets):,}` targets",
                                        m["color"]))
    local = HuntState(mode=m.value if hasattr(m, "value") else STATE.mode)
    async with make_fetcher(m) as f:
        r = await scan_list(f, DB_, CFG, m, Reporter(DB_, FEEDER, local, CFG), targets, target)
    await itx.followup.send(embed=brand("✅ Done",
                                        f"probed `{r['total']:,}` · iDRAC `{r['alive']:,}` · "
                                        f"vuln `{r['vulns']:,}`"))


@scan.command(description="Scan one host")
async def ip(itx: discord.Interaction, host: str, port: int = 443):
    await itx.response.defer()
    ips = [host]
    try:
        socket.inet_aton(host)
    except OSError:
        async with Fetcher() as f:
            ips = await f.resolve(host)
    if not ips:
        return await itx.followup.send("Unresolvable.")
    m = mode_of()
    local = HuntState()
    async with make_fetcher(m) as f:
        await scan_list(f, DB_, CFG, m, Reporter(DB_, FEEDER, local, CFG),
                        [(i, port) for i in ips], host)
    row = DB_.get_host(ips[0], port)
    await itx.followup.send(embed=host_embed(row) if row else brand("No result"))


@scan.command(description="Upload a .txt of subnets")
async def file(itx: discord.Interaction, attachment: discord.Attachment):
    await itx.response.defer()
    nets = parse_blob((await attachment.read()).decode("utf-8", errors="replace"))
    if not nets:
        return await itx.followup.send("No targets.")
    m = mode_of()
    targets = [(ip, ports()[0]) for n in nets for ip in expand(n, m["sample"], False)][:120_000]
    await itx.followup.send(embed=brand("📄 File queued", f"`{len(targets):,}` targets"))
    local = HuntState()
    async with make_fetcher(m) as f:
        r = await scan_list(f, DB_, CFG, m, Reporter(DB_, FEEDER, local, CFG),
                            targets, attachment.filename)
    await itx.followup.send(embed=brand("✅ Done",
                                        f"probed `{r['total']:,}` · iDRAC `{r['alive']:,}` · "
                                        f"vuln `{r['vulns']:,}`"))


# ---------------------------------------------------------------- /subnets
subnets = app_commands.Group(name="subnets", description="Subnet pool")


@subnets.command(description="Add subnets")
async def add(itx: discord.Interaction, targets: str):
    nets = parse_blob(targets.replace(" ", "\n"))
    for n in nets:
        DB_.add_subnet(str(n), f"user:{itx.user}")
    await itx.response.send_message(embed=brand("➕ Added", f"`{len(nets)}` range(s)"))


@subnets.command(description="Remove a subnet")
async def remove(itx: discord.Interaction, cidr: str):
    ok = DB_.remove_subnet(cidr)
    await itx.response.send_message(embed=brand("➖ Removed" if ok else "Not found",
                                                f"`{cidr}`"), ephemeral=True)


@subnets.command(description="List the pool")
async def listing(itx: discord.Interaction):
    rows = DB_.subnets()
    await itx.response.send_message(embed=brand(
        f"🗺 Pool — {len(rows)}", "\n".join(f"`{r}`" for r in rows[:80])[:4000] or "empty"))


@subnets.command(description="Clear the pool")
async def clear(itx: discord.Interaction):
    DB_.conn.execute("DELETE FROM subnets")
    DB_.conn.commit()
    await itx.response.send_message(embed=brand("🧹 Cleared"))


# ---------------------------------------------------------------- data
@tree.command(description="Browse vulnerable hosts")
@app_commands.choices(confidence=[app_commands.Choice(name=c, value=c)
                                  for c in ("confirmed", "likely", "suspect")])
async def vulns(itx: discord.Interaction, confidence: str | None = None):
    rows, total = DB_.page_vulns(confidence, 0, 30)
    if not total:
        return await itx.response.send_message(embed=brand("Nothing recorded"))
    v = Pager(rows, total, 5, _vpage)
    await itx.response.send_message(embed=v.current(), view=v)


def _vpage(rows, s, total, page, pages):
    e = brand(f"🛑 Vulnerabilities — {total:,}", color=CFG.vuln_color)
    for r in rows:
        icon = {"confirmed": "🔴", "likely": "🟠", "suspect": "🟡"}.get(r["confidence"], "⚪")
        e.add_field(name=f"{icon} {r['ip']}:{r['port']}",
                    value=f"`{r['confidence']}` · iDRAC{r['generation']} · "
                          f"fw `{r['firmware'] or '-'}`\n{r['evidence'][:170]}", inline=False)
    e.set_footer(text=f"page {page + 1}/{pages}")
    return e


@tree.command(description="Browse hosts")
@app_commands.choices(status=[app_commands.Choice(name=s, value=s)
                              for s in ("alive", "vuln", "dead", "new")])
async def hosts(itx: discord.Interaction, status: str | None = None,
                generation: int | None = None):
    rows, total = DB_.page_hosts(status, generation, 0, 48)
    if not total:
        return await itx.response.send_message(embed=brand("No hosts"))
    v = Pager(rows, total, 8, _hpage)
    await itx.response.send_message(embed=v.current(), view=v)


def _hpage(rows, s, total, page, pages):
    e = brand(f"🗄 Hosts — {total:,}")
    for r in rows:
        g = r["generation"]
        e.add_field(name=f"{GEN_ICON.get(g, '⚫')} {r['ip']}:{r['port']}",
                    value=f"`{r['status']}` · iDRAC{g or '?'} · fw `{r['firmware'] or '-'}`",
                    inline=False)
    e.set_footer(text=f"page {page + 1}/{pages}")
    return e


@tree.command(description="Full record for an IP")
async def lookup(itx: discord.Interaction, ip: str, port: int | None = None):
    row = DB_.get_host(ip, port)
    if not row:
        return await itx.response.send_message("Not in the database.", ephemeral=True)
    await itx.response.send_message(embed=host_embed(row))


@tree.command(description="Statistics")
async def stats(itx: discord.Interaction):
    s = DB_.stats()
    e = brand("📊 Statistics")
    e.add_field(name="Hosts", value=f"`{s['hosts']:,}` · alive `{s['alive']:,}`")
    e.add_field(name="Vulns", value=f"`{s['vulns']:,}` (`{s['confirmed']:,}` confirmed)")
    e.add_field(name="Signals", value=f"creds `{s['creds']:,}` · bypass `{s['bypass']:,}`")
    await itx.response.send_message(embed=e)


@tree.command(description="Export the database")
@app_commands.choices(kind=[app_commands.Choice(name=k, value=k)
                            for k in ("all_ips", "vuln_ips", "idrac_hosts", "vulns",
                                      "bundle")])
async def export(itx: discord.Interaction, kind: str = "vuln_ips"):
    await itx.response.defer()
    files = DB_.export(CFG.export_dir, as_zip=(kind == "bundle"))
    await itx.followup.send(file=discord.File(os.path.join(CFG.export_dir,
                                                           files.get(kind, "all_ips.txt"))))


@tree.command(description="Watch a host for rechecks")
async def watch(itx: discord.Interaction, ip: str, port: int = 443):
    DB_.add_watch(ip, port, str(itx.user))
    await itx.response.send_message(embed=brand("👁 Watching", f"`{ip}:{port}`"))


@tree.command(description="Stop watching a host")
async def unwatch(itx: discord.Interaction, ip: str, port: int = 443):
    ok = DB_.drop_watch(ip, port)
    await itx.response.send_message(embed=brand("Removed" if ok else "Not watched",
                                                f"`{ip}:{port}`"), ephemeral=True)


# ---------------------------------------------------------------- config
config = app_commands.Group(name="config", description="Configuration")


@config.command(description="Set the alert channel")
@app_commands.choices(min_confidence=[app_commands.Choice(name=c, value=c)
                                      for c in ("suspect", "likely", "confirmed")])
async def alerts(itx: discord.Interaction, channel: discord.TextChannel,
                 min_confidence: app_commands.Choice[str] | None = None):
    DB_.set_setting("alert_channel", str(channel.id))
    if min_confidence:
        DB_.set_setting("notify_min", min_confidence.value)
    await itx.response.send_message(embed=brand("🔔 Alerts set", channel.mention))


@config.command(description="Set the live feed channel")
@app_commands.choices(level=[app_commands.Choice(name=l, value=l)
                             for l in ("off", "vuln", "idrac", "all")])
async def feed(itx: discord.Interaction, channel: discord.TextChannel,
               level: app_commands.Choice[str] | None = None):
    DB_.set_setting("feed_channel", str(channel.id))
    if level:
        DB_.set_setting("feed_level", level.value)
    await itx.response.send_message(embed=brand("📡 Feed set", channel.mention))


@config.command(description="Set scanned ports")
async def ports_cmd(itx: discord.Interaction, csv: str):
    ps = [p.strip() for p in csv.split(",") if p.strip().isdigit()]
    DB_.set_setting("ports", ",".join(ps))
    await itx.response.send_message(embed=brand("🔌 Ports", f"`{', '.join(ps)}`"))


@config.command(description="Source health and yield")
async def sources_cmd(itx: discord.Interaction):
    rows = {r["name"]: r for r in DB_.source_table()}
    lines = []
    for name, s in sources.SOURCES.items():
        r = rows.get(name)
        st = "ok" if r and r["last_ok"] else ("failing" if r and r["fail_streak"] else "idle")
        icon = {"ok": "🟢", "failing": "🔴", "idle": "⚪"}[st]
        lines.append(f"{icon} `{name}` — {s.notes} · yield `{r['ips_total'] if r else 0}`")
    await itx.response.send_message(embed=brand("🔎 Sources", "\n".join(lines)[:4000]))


@tree.command(description="Self-check")
async def doctor_cmd(itx: discord.Interaction):
    checks = doctor.run(CFG, DB_)
    e = brand("🩺 Self-check")
    e.description = "\n".join(f"{'✅' if ok else '❌'} {label}" for ok, label in checks)
    await itx.response.send_message(embed=e)


@tree.command(description="Latency")
async def ping(itx: discord.Interaction):
    await itx.response.send_message(embed=brand("🏓", f"`{client.latency * 1000:.0f} ms`"))


@tree.command(description="Command overview")
async def help(itx: discord.Interaction):
    e = brand("🛠 idrac-hunter", "Keyless iDRAC 6/7/8 discovery, CVE-2018-1207 triage.")
    e.add_field(name="/idrac start|stop|status|mode|generations|priority", value="Control", inline=False)
    e.add_field(name="/scan cidr|ip|file", value="Manual", inline=False)
    e.add_field(name="/subnets add|remove|list|clear", value="Pool", inline=False)
    e.add_field(name="/vulns /hosts /lookup /stats /export /watch /unwatch", value="Data", inline=False)
    e.add_field(name="/config alerts|feed|ports|sources · /doctor /ping", value="Setup", inline=False)
    await itx.response.send_message(embed=e)


@tree.command(description="Sync commands")
@app_commands.default_permissions(administrator=True)
async def sync(itx: discord.Interaction):
    if CFG.guild_id:
        tree.copy_global_to(guild=discord.Object(id=CFG.guild_id))
        await tree.sync(guild=discord.Object(id=CFG.guild_id))
    else:
        await tree.sync()
    await itx.response.send_message("Synced.", ephemeral=True)


for g in (idrac, scan, subnets, config):
    tree.add_command(g)


if __name__ == "__main__":
    setup_logging()
    if not CFG.bot_token:
        raise SystemExit("Set bot_token or DISCORD_TOKEN")
    client.run(CFG.bot_token, log_handler=None)
