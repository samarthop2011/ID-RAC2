"""Cycle history and sparkline rendering."""
from __future__ import annotations

BLOCKS = "▁▂▃▄▅▆▇█"


def spark(values: list[int], width: int = 24) -> str:
    vals = values[-width:]
    if not vals or max(vals) == 0:
        return BLOCKS[0] * max(1, len(vals) or 1)
    top = max(vals)
    return "".join(BLOCKS[min(7, int(v / top * 7))] for v in vals)


def record(state, alive: int, vulns: int) -> None:
    state.history.append(alive)
    state.history = state.history[-200:]
