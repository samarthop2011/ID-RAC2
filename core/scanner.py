from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from . import cve_2018_1207 as cve
from .fingerprint import probe
from .prefilter import any_open


def _iso(h):
    return (datetime.now(timezone.utc) + timedelta(hours=h)).isoformat(timespec="seconds")


def _schemes(port):
    return ["http", "https"] if port in (80, 8080) else ["https", "http"]


async def scan_one(fetcher, db, cfg, mode, reporter, row, sem, gens):
    ip, port = row["ip"], row["port"]
    async with sem:
        reporter.state.scanned += 1
        reporter.state.total_cycle = max(reporter.state.total_cycle,
                                         reporter.state.scanned + reporter.state.queue_len)

        if mode["prefilter"] and await any_open(
                ip, [port], timeout=min(3.0, mode["timeout"] / 2)) is None:
            db.mark_dead(ip, port, cfg, "port closed")
            await reporter.scraped(ip, port, False)
            return

        fp, scheme = None, row["scheme"] or "https"
        for s in _schemes(port):
            fp = await probe(fetcher, ip, port, s, creds=mode["creds"])
            if fp.alive:
                scheme = s
                break
        if not fp or not fp.alive:
            db.mark_dead(ip, port, cfg, "no response")
            await reporter.scraped(ip, port, False)
            return

        fields = {"title": (fp.title or "")[:200] or None,
                  "server": (fp.server or "")[:120] or None,
                  "generation": fp.generation, "model": fp.model or None,
                  "firmware": fp.firmware or None,
                  "default_creds": int(fp.default_creds),
                  "score": fp.score, "scheme": scheme,
                  "evidence": "; ".join(fp.evidence)[:1400]}

        if not fp.is_idrac:
            db.mark_alive(ip, port, cfg, **fields)
            await reporter.scraped(ip, port, False)
            return

        await reporter.scraped(ip, port, True, fp.generation)

        if fp.generation and gens and fp.generation not in gens:
            db.mark_alive(ip, port, cfg, **fields)
            return

        leaks, notes, leaked_fw = (0, [], "")
        if mode["probes"] and fp.generation in (6, 7, 8):
            leaks, notes, leaked_fw = await cve.probe_leaks(fetcher, ip, port, scheme)
            fields["auth_bypass"] = int(leaks > 0)
            if leaked_fw and not fp.firmware:
                fp.firmware = leaked_fw
                fields["firmware"] = leaked_fw

        verdict = cve.assess(fp.generation, fp.firmware, fp.default_creds, leaks, notes)

        if not verdict.vulnerable:
            fields.update(status="alive", confidence=verdict.confidence,
                          attempts=0, next_scan=_iso(cfg.rescan_alive_hours))
            db.update_host(ip, port, **fields)
            return

        fields.update(status="vuln", confidence=verdict.confidence, attempts=0,
                      next_scan=_iso(cfg.rescan_vuln_hours))
        db.update_host(ip, port, **fields)
        is_new = db.record_vuln(ip, port, cve.CVE, verdict.confidence, verdict.method,
                                verdict.evidence, fp.generation, fp.firmware)

        if mode["enrich"] and (is_new or verdict.confidence == "confirmed"):
            from .sources import enrich
            d = await enrich(fetcher, ip)
            upd = {k: d[k] for k in ("country", "asn", "org") if d.get(k)}
            if upd:
                db.update_host(ip, port, **upd)

        if is_new or verdict.confidence == "confirmed":
            await reporter.found(ip, port, scheme, verdict, fp)


async def run_batch(fetcher, db, cfg, mode, reporter, limit, gens) -> int:
    rows = db.next_batch(limit)
    if not rows:
        return 0
    reporter.state.queue_len = max(0, reporter.state.queue_len - len(rows))
    reporter.state.total_cycle = reporter.state.scanned + len(rows)
    sem = asyncio.Semaphore(mode["concurrency"])
    await asyncio.gather(*(scan_one(fetcher, db, cfg, mode, reporter, r, sem, gens)
                           for r in rows), return_exceptions=True)
    return len(rows)


async def scan_list(fetcher, db, cfg, mode, reporter, targets, label) -> dict:
    """Manual sweep. Uses the caller's reporter/state so a running hunt is untouched."""
    for ip, port in targets:
        db.add_host(ip, port, "https", f"manual:{label}", score=80)
    sem = asyncio.Semaphore(mode["concurrency"])
    reporter.state.total_cycle = len(targets)
    reporter.state.scanned = reporter.state.alive = reporter.state.vulns = 0
    reporter.state.phase = "manual"

    async def one(ip, port):
        row = db.get_host(ip, port)
        if row:
            db.update_host(ip, port, status="new", attempts=0, next_scan=None)
            await scan_one(fetcher, db, cfg, mode, reporter, row, sem, [])

    await asyncio.gather(*(one(ip, p) for ip, p in targets), return_exceptions=True)
    return {"total": len(targets), "alive": reporter.state.alive, "vulns": reporter.state.vulns}
