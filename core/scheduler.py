"""Watch rechecks and rescan promotion."""
from __future__ import annotations

import asyncio
import logging

LOG = logging.getLogger("scheduler")


async def watch_loop(db, cfg, state):
    while True:
        try:
            due = db.due_watches(cfg.watch_interval_minutes)
            for w in due:
                db.add_host(w["ip"], w["port"], "https", "watch", score=90)
                db.update_host(w["ip"], w["port"], status="new", attempts=0,
                               next_scan=None)
            if due:
                LOG.info("requeued %d watched hosts", len(due))
        except Exception as exc:
            LOG.warning("watch loop: %s", exc)
        await asyncio.sleep(120)


def start(db, cfg, state) -> asyncio.Task:
    return asyncio.create_task(watch_loop(db, cfg, state))
