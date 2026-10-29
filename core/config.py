from __future__ import annotations

import os
from dataclasses import dataclass, fields
from typing import Any

import yaml


@dataclass
class Config:
    bot_token: str = ""
    guild_id: int = 0
    db_path: str = "data/idrac.db"
    export_dir: str = "data/exports"
    log_file: str = "data/idrac.log"
    log_level: str = "INFO"
    log_json: bool = False
    subnets_file: str = "subnets.txt"
    datacenters_file: str = "datacenter_subnets.txt"
    use_datacenters: bool = False
    asns_file: str = "asns.txt"
    use_asn_harvest: bool = False
    default_mode: str = "normal"
    default_ports: list = None
    default_gens: list = None
    default_feed_level: str = "all"
    default_notify_min: str = "likely"
    source_interval_hours: int = 6
    source_result_limit: int = 500
    rescan_alive_hours: int = 168
    rescan_dead_hours: int = 720
    rescan_vuln_hours: int = 24
    watch_interval_minutes: int = 180
    cycle_interval: int = 600
    cycle_jitter: int = 180
    proxy_file: str = ""
    brand_color: int = 0x007DB8
    vuln_color: int = 0xED4245
    ok_color: int = 0x57F287
    warn_color: int = 0xFEE75C

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        raw: dict[str, Any] = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        known = {f.name for f in fields(cls)}
        cfg = cls(**{k: v for k, v in raw.items() if k in known})
        cfg.bot_token = os.environ.get("DISCORD_TOKEN", cfg.bot_token)
        cfg.guild_id = int(os.environ.get("GUILD_ID", cfg.guild_id or 0))
        cfg.default_ports = cfg.default_ports or [443, 80, 8443, 5900, 5901, 623]
        cfg.default_gens = cfg.default_gens or [6, 7, 8, 9]
        for d in ("data", cfg.export_dir):
            os.makedirs(d, exist_ok=True)
        return cfg


MODES: dict[str, dict] = {
    "stealth": {"label": "Stealth", "emoji": "🌙", "color": 0x8B5CF6, "concurrency": 40,
                "delay": 0.6, "timeout": 20, "prefilter": False, "sample": 1024,
                "engines": True, "enrich": True, "creds": True, "probes": True,
                "blurb": "Low and slow. Every check on, no prefilter."},
    "normal": {"label": "Normal", "emoji": "⚙️", "color": 0x007DB8, "concurrency": 250,
               "delay": 0.15, "timeout": 12, "prefilter": True, "sample": 4096,
               "engines": True, "enrich": True, "creds": True, "probes": True,
               "blurb": "Balanced. Prefilter, harvesting, full verification."},
    "turbo": {"label": "Turbo", "emoji": "⚡", "color": 0xFEE75C, "concurrency": 1200,
              "delay": 0.0, "timeout": 6, "prefilter": True, "sample": 16384,
              "engines": False, "enrich": False, "creds": False, "probes": True,
              "blurb": "Raw subnet throughput. No engines, no creds."},
    "deep": {"label": "Deep", "emoji": "🔬", "color": 0x57F287, "concurrency": 300,
             "delay": 0.1, "timeout": 15, "prefilter": True, "sample": 65536,
             "engines": True, "enrich": True, "creds": True, "probes": True,
             "blurb": "Full expansion, every source, every probe."},
}
