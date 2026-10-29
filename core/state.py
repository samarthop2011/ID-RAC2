from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class HuntState:
    running: bool = False
    mode: str = "normal"
    started_at: float = 0.0
    cycle: int = 0
    phase: str = "idle"
    scanned: int = 0
    alive: int = 0
    vulns: int = 0
    harvested: int = 0
    queue_len: int = 0
    total_cycle: int = 0
    task: object = None
    last_error: str = ""
    gens: list = field(default_factory=lambda: [6, 7, 8, 9])
    history: list = field(default_factory=list)

    def reset_cycle(self):
        self.cycle += 1
        self.phase = "harvest"
        self.scanned = self.alive = self.vulns = self.harvested = 0
        self.total_cycle = 0

    @property
    def uptime(self) -> float:
        return time.time() - self.started_at if self.started_at else 0.0

    @property
    def progress(self) -> float:
        return min(1.0, self.scanned / self.total_cycle) if self.total_cycle else 0.0
