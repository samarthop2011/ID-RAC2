"""SQLite store with lightweight in-place schema migration."""
from __future__ import annotations

import csv
import json
import os
import sqlite3
import threading
import zipfile
from datetime import datetime, timedelta, timezone

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 443,
    scheme TEXT NOT NULL DEFAULT 'https',
    first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    sources TEXT DEFAULT '', status TEXT NOT NULL DEFAULT 'new',
    attempts INTEGER NOT NULL DEFAULT 0, next_scan TEXT,
    generation INTEGER DEFAULT 0, model TEXT,
    title TEXT, server TEXT, firmware TEXT,
    default_creds INTEGER DEFAULT 0, auth_bypass INTEGER DEFAULT 0,
    country TEXT, asn TEXT, org TEXT, score INTEGER DEFAULT 0,
    confidence TEXT, evidence TEXT, notes TEXT,
    PRIMARY KEY (ip, port)
);
CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL, port INTEGER NOT NULL, cve TEXT NOT NULL,
    confidence TEXT NOT NULL, method TEXT, evidence TEXT,
    generation INTEGER, firmware TEXT,
    confirmed_at TEXT NOT NULL, last_checked TEXT NOT NULL,
    UNIQUE (ip, port, cve)
);
CREATE TABLE IF NOT EXISTS subnets (
    cidr TEXT PRIMARY KEY, source TEXT, added_at TEXT, enabled INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS watches (
    ip TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 443,
    added_by TEXT, added_at TEXT, last_check TEXT, PRIMARY KEY (ip, port)
);
CREATE TABLE IF NOT EXISTS source_stats (
    name TEXT PRIMARY KEY, last_ok TEXT, last_error TEXT,
    fail_streak INTEGER DEFAULT 0, ips_total INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, started TEXT, finished TEXT,
    mode TEXT, scanned INTEGER DEFAULT 0, alive INTEGER DEFAULT 0,
    new_ips INTEGER DEFAULT 0, vulns INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);

CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status, next_scan);
CREATE INDEX IF NOT EXISTS idx_hosts_gen ON hosts(generation);
CREATE INDEX IF NOT EXISTS idx_vulns_conf ON vulns(confidence);
"""

# column -> DDL, applied if missing
MIGRATIONS = {
    "hosts": {"auth_bypass": "INTEGER DEFAULT 0", "model": "TEXT"},
    "vulns": {"generation": "INTEGER", "firmware": "TEXT"},
    "watches": {"last_check": "TEXT"},
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _iso(h: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=h)).isoformat(timespec="seconds")


class DB:
    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self.conn.row_factory = sqlite3.Row
        with self._lock:
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.commit()

    def _migrate(self) -> None:
        for table, cols in MIGRATIONS.items():
            have = {r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            for col, ddl in cols.items():
                if col not in have:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")

    def close(self) -> None:
        with self._lock:
            self.conn.commit()
            self.conn.close()

    # ---- hosts ----
    def add_host(self, ip, port=443, scheme="https", source="", score=0) -> bool:
        now = utcnow()
        with self._lock:
            row = self.conn.execute("SELECT sources FROM hosts WHERE ip=? AND port=?",
                                    (ip, port)).fetchone()
            if row:
                srcs = set(filter(None, (row["sources"] or "").split(","))) | {source}
                self.conn.execute(
                    "UPDATE hosts SET sources=?, last_seen=?, score=MAX(score,?) "
                    "WHERE ip=? AND port=?", (",".join(sorted(srcs)), now, score, ip, port))
                self.conn.commit()
                return False
            self.conn.execute(
                "INSERT INTO hosts (ip,port,scheme,first_seen,last_seen,sources,status,"
                "score,next_scan) VALUES (?,?,?,?,?,?,'new',?,?)",
                (ip, port, scheme, now, now, source, score, now))
            self.conn.commit()
            return True

    def next_batch(self, limit: int) -> list[sqlite3.Row]:
        now = utcnow()
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM hosts WHERE status IN ('new','retry') AND attempts < 8 "
                "AND (next_scan IS NULL OR next_scan <= ?) "
                "ORDER BY score DESC, last_seen ASC LIMIT ?", (now, limit)).fetchall()
            if rows:
                self.conn.executemany(
                    "UPDATE hosts SET status='scanning' WHERE ip=? AND port=?",
                    [(r["ip"], r["port"]) for r in rows])
                self.conn.commit()
            return rows

    def recover_stuck(self) -> int:
        with self._lock:
            n = self.conn.execute(
                "UPDATE hosts SET status='retry' WHERE status='scanning'").rowcount
            self.conn.commit()
            return n

    def update_host(self, ip, port, **f) -> None:
        if not f:
            return
        with self._lock:
            self.conn.execute(
                f"UPDATE hosts SET {', '.join(f'{k}=?' for k in f)} WHERE ip=? AND port=?",
                (*f.values(), ip, port))
            self.conn.commit()

    def mark_dead(self, ip, port, cfg, note="") -> None:
        row = self.conn.execute("SELECT attempts FROM hosts WHERE ip=? AND port=?",
                                (ip, port)).fetchone()
        attempts = (row["attempts"] if row else 0) + 1
        backoff = min(cfg.rescan_dead_hours, 2 ** attempts)  # exponential, capped
        with self._lock:
            self.conn.execute(
                "UPDATE hosts SET status='retry' if attempts<8 else 'dead', "
                "attempts=?, next_scan=?, notes=? WHERE ip=? AND port=?".replace(
                    "status='retry' if attempts<8 else 'dead'",
                    "status=CASE WHEN ?<8 THEN 'retry' ELSE 'dead' END"),
                (attempts, _iso(backoff), note, attempts, ip, port))
            self.conn.commit()

    def mark_alive(self, ip, port, cfg, **f) -> None:
        f.update(status="alive", attempts=0, next_scan=_iso(cfg.rescan_alive_hours),
                 last_seen=utcnow())
        self.update_host(ip, port, **f)

    def get_host(self, ip, port=None):
        with self._lock:
            if port:
                return self.conn.execute("SELECT * FROM hosts WHERE ip=? AND port=?",
                                         (ip, port)).fetchone()
            return self.conn.execute(
                "SELECT * FROM hosts WHERE ip=? ORDER BY score DESC LIMIT 1", (ip,)).fetchone()

    def page_hosts(self, status, gen, offset, limit):
        c, a = [], []
        if status:
            c.append("status=?")
            a.append(status)
        if gen:
            c.append("generation=?")
            a.append(gen)
        where = f"WHERE {' AND '.join(c)}" if c else ""
        with self._lock:
            total = self.conn.execute(f"SELECT COUNT(*) FROM hosts {where}", a).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT * FROM hosts {where} ORDER BY score DESC, last_seen DESC "
                f"LIMIT ? OFFSET ?", (*a, limit, offset)).fetchall()
        return rows, total

    def gen_counts(self) -> dict:
        with self._lock:
            rows = self.conn.execute(
                "SELECT generation, COUNT(*) c FROM hosts WHERE status IN ('alive','vuln') "
                "GROUP BY generation").fetchall()
        return {r["generation"]: r["c"] for r in rows}

    # ---- vulns ----
    def record_vuln(self, ip, port, cve, confidence, method, evidence,
                    generation=0, firmware="") -> bool:
        now = utcnow()
        with self._lock:
            hit = self.conn.execute("SELECT id FROM vulns WHERE ip=? AND port=? AND cve=?",
                                    (ip, port, cve)).fetchone()
            if hit:
                self.conn.execute(
                    "UPDATE vulns SET confidence=?, method=?, evidence=?, generation=?, "
                    "firmware=?, last_checked=? WHERE id=?",
                    (confidence, method, evidence, generation, firmware, now, hit["id"]))
                self.conn.commit()
                return False
            self.conn.execute(
                "INSERT INTO vulns (ip,port,cve,confidence,method,evidence,generation,"
                "firmware,confirmed_at,last_checked) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (ip, port, cve, confidence, method, evidence, generation, firmware, now, now))
            self.conn.commit()
            return True

    def page_vulns(self, confidence, offset, limit):
        where, a = ("WHERE confidence=?", (confidence,)) if confidence else ("", ())
        with self._lock:
            total = self.conn.execute(f"SELECT COUNT(*) FROM vulns {where}", a).fetchone()[0]
            rows = self.conn.execute(
                f"SELECT * FROM vulns {where} ORDER BY confirmed_at DESC LIMIT ? OFFSET ?",
                (*a, limit, offset)).fetchall()
        return rows, total

    # ---- pool / watches ----
    def add_subnet(self, cidr, source):
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO subnets (cidr,source,added_at) VALUES (?,?,?)",
                (cidr, source, utcnow()))
            self.conn.commit()

    def remove_subnet(self, cidr) -> bool:
        with self._lock:
            n = self.conn.execute("DELETE FROM subnets WHERE cidr=?", (cidr,)).rowcount
            self.conn.commit()
            return n > 0

    def subnets(self) -> list[str]:
        with self._lock:
            return [r["cidr"] for r in self.conn.execute("SELECT cidr FROM subnets")]

    def add_watch(self, ip, port, user):
        with self._lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO watches (ip,port,added_by,added_at) VALUES (?,?,?,?)",
                (ip, port, user, utcnow()))
            self.conn.commit()

    def due_watches(self, minutes: int) -> list[sqlite3.Row]:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(
            timespec="seconds")
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM watches WHERE last_check IS NULL OR last_check <= ?",
                (cutoff,)).fetchall()
            if rows:
                self.conn.executemany(
                    "UPDATE watches SET last_check=? WHERE ip=? AND port=?",
                    [(utcnow(), r["ip"], r["port"]) for r in rows])
                self.conn.commit()
            return rows

    def watches(self) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute("SELECT * FROM watches").fetchall()

    def drop_watch(self, ip, port) -> bool:
        with self._lock:
            n = self.conn.execute("DELETE FROM watches WHERE ip=? AND port=?",
                                  (ip, port)).rowcount
            self.conn.commit()
            return n > 0

    # ---- sources ----
    def source_ok(self, name, count):
        with self._lock:
            self.conn.execute(
                "INSERT INTO source_stats (name,last_ok,fail_streak,ips_total) VALUES (?,?,0,?) "
                "ON CONFLICT(name) DO UPDATE SET last_ok=excluded.last_ok, fail_streak=0, "
                "ips_total=ips_total+excluded.ips_total", (name, utcnow(), count))
            self.conn.commit()

    def source_fail(self, name, err):
        with self._lock:
            self.conn.execute(
                "INSERT INTO source_stats (name,last_error,fail_streak) VALUES (?,?,1) "
                "ON CONFLICT(name) DO UPDATE SET last_error=excluded.last_error, "
                "fail_streak=fail_streak+1", (name, err[:400]))
            self.conn.commit()

    def source_due(self, name, hours) -> bool:
        with self._lock:
            r = self.conn.execute(
                "SELECT last_ok,last_error,fail_streak FROM source_stats WHERE name=?",
                (name,)).fetchone()
        if not r:
            return True
        if r["fail_streak"] >= 5:
            hours *= min(r["fail_streak"], 12)
        stamp = r["last_ok"] or r["last_error"]
        if not stamp:
            return True
        return (datetime.fromisoformat(stamp)
                + timedelta(hours=hours)) < datetime.now(timezone.utc)

    def source_table(self):
        with self._lock:
            return self.conn.execute("SELECT * FROM source_stats").fetchall()

    # ---- runs / settings ----
    def start_run(self, mode) -> int:
        with self._lock:
            cur = self.conn.execute("INSERT INTO runs (started,mode) VALUES (?,?)",
                                    (utcnow(), mode))
            self.conn.commit()
            return int(cur.lastrowid)

    def finish_run(self, rid, scanned, alive, new, vulns):
        with self._lock:
            self.conn.execute(
                "UPDATE runs SET finished=?,scanned=?,alive=?,new_ips=?,vulns=? WHERE id=?",
                (utcnow(), scanned, alive, new, vulns, rid))
            self.conn.commit()

    def get_setting(self, k, default=""):
        with self._lock:
            r = self.conn.execute("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
            return r["v"] if r else default

    def set_setting(self, k, v):
        with self._lock:
            self.conn.execute(
                "INSERT INTO settings (k,v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                (k, v))
            self.conn.commit()

    def stats(self) -> dict:
        q = lambda s: self.conn.execute(s).fetchone()[0]
        return {
            "hosts": q("SELECT COUNT(*) FROM hosts"),
            "alive": q("SELECT COUNT(*) FROM hosts WHERE status IN ('alive','vuln')"),
            "pending": q("SELECT COUNT(*) FROM hosts WHERE status IN ('new','retry')"),
            "vulns": q("SELECT COUNT(*) FROM vulns"),
            "confirmed": q("SELECT COUNT(*) FROM vulns WHERE confidence='confirmed'"),
            "creds": q("SELECT COUNT(*) FROM hosts WHERE default_creds=1"),
            "bypass": q("SELECT COUNT(*) FROM hosts WHERE auth_bypass=1"),
            "subnets": q("SELECT COUNT(*) FROM subnets"),
            "watches": q("SELECT COUNT(*) FROM watches"),
        }

    # ---- export ----
    def export(self, out: str, as_zip: bool = False) -> dict:
        os.makedirs(out, exist_ok=True)
        res = {}
        hosts = self.conn.execute("SELECT * FROM hosts ORDER BY score DESC").fetchall()
        res["all_ips.txt"] = _txt(os.path.join(out, "all_ips.txt"), [r["ip"] for r in hosts])
        res["all_hosts.csv"] = _csv(os.path.join(out, "all_hosts.csv"), hosts)
        res["idrac_hosts.csv"] = _csv(
            os.path.join(out, "idrac_hosts.csv"),
            self.conn.execute("SELECT * FROM hosts WHERE generation>0").fetchall())
        vulns = self.conn.execute("SELECT * FROM vulns").fetchall()
        res["vuln_ips.txt"] = _txt(os.path.join(out, "vuln_ips.txt"),
                                   sorted({r["ip"] for r in vulns}))
        res["vulns.csv"] = _csv(os.path.join(out, "vulns.csv"), vulns)
        res["vulns.jsonl"] = _jsonl(os.path.join(out, "vulns.jsonl"), vulns)
        if as_zip:
            zp = os.path.join(out, "idrac-export.zip")
            with zipfile.ZipFile(zp, "w", zipfile.ZIP_DEFLATED) as z:
                for name in res:
                    z.write(os.path.join(out, name), name)
            res["bundle.zip"] = zp
        return res


def _txt(p, rows):
    rows = list(rows)
    open(p, "w", encoding="utf-8").write("\n".join(rows) + ("\n" if rows else ""))
    return len(rows)


def _csv(p, rows):
    if not rows:
        open(p, "w").close()
        return 0
    with open(p, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(rows[0].keys())
        w.writerows([tuple(r) for r in rows])
    return len(rows)


def _jsonl(p, rows):
    with open(p, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(dict(r), default=str) + "\n")
    return len(rows)
