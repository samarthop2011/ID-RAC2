"""CVE-2018-1207 - iDRAC7/iDRAC8 command injection chain.

Fixed in iDRAC7/iDRAC8 2.40.40.40 and iDRAC9 3.21.21.21. Verification is graded:
unauthenticated leak endpoints + parsed firmware vs the fixed baseline + whether
default credentials still work. A pre-fix build is confirmed; an affected family
with an unreadable build is likely.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CVE = "CVE-2018-1207"
RANK = {"none": -1, "unknown": 0, "patched": 0, "suspect": 1, "likely": 2, "confirmed": 3}

FIXED_7_8 = "2.40.40.40"
FIXED_9 = "3.21.21.21"

# Endpoints that should require auth on a patched build.
LEAK_PROBES = [
    ("GET", "/data?get=prodVersion", ("prodversion",)),
    ("GET", "/data?get=macs", ("macs",)),
    ("GET", "/data?get=all", ("prodversion", "macs")),
    ("GET", "/cgi-bin/webcgi/version", ()),
    ("GET", "/restapi/v1/Systems", ("systems",)),
    ("GET", "/redfish/v1/Managers/iDRAC.Embedded.1", ("firmwareversion",)),
    ("GET", "/session?redirect=1", ()),
]


@dataclass
class Verdict:
    vulnerable: bool = False
    confidence: str = "none"
    method: str = ""
    evidence: str = ""
    firmware: str = ""
    generation: int = 0
    leaks: int = 0


def vtuple(v: str):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def vlt(a: str, b: str) -> bool:
    x, y = vtuple(a), vtuple(b)
    n = max(len(x), len(y))
    return x + (0,) * (n - len(x)) < y + (0,) * (n - len(y))


async def probe_leaks(fetcher, ip, port, scheme) -> tuple[int, list[str], str]:
    """Count endpoints answering anonymously; harvest a version if one leaks."""
    base = f"{scheme}://{ip}:{port}"
    hits, fw = 0, ""
    notes: list[str] = []
    for method, path, markers in LEAK_PROBES:
        r = await fetcher.get(base + path, retries=0)
        if r.status not in (200, 302) or not r.body:
            continue
        low = r.body.lower()
        if markers and not any(m in low for m in markers):
            continue
        hits += 1
        notes.append(f"{path} -> {r.status}")
        if not fw:
            m = re.search(r"<prodVersion>([\d.]+)<", r.body)
            if m:
                fw = m.group(1)
    return hits, notes, fw


def assess(generation: int, firmware: str, default_creds: bool, leaks: int,
           leak_notes: list[str]) -> Verdict:
    ev = []
    if generation:
        ev.append(f"iDRAC{generation}")
    if firmware:
        ev.append(f"firmware {firmware}")
    if default_creds:
        ev.append("root:calvin accepted")
    if leaks:
        ev.append(f"{leaks} unauthenticated endpoint(s): " + ", ".join(leak_notes[:4]))

    if generation in (7, 8):
        if firmware and not vlt(firmware, FIXED_7_8):
            ev.append(f"at or above {FIXED_7_8}")
            return Verdict(False, "patched", "firmware-version", "; ".join(ev),
                           firmware, generation, leaks)
        if firmware:
            ev.append(f"below fixed build {FIXED_7_8}")
            conf = "confirmed"
            return Verdict(True, conf, "firmware-version", "; ".join(ev),
                           firmware, generation, leaks)
        ev.append("affected family, build unreadable")
        conf = "likely" if (leaks or default_creds) else "suspect"
        return Verdict(True, conf, "family-heuristic", "; ".join(ev),
                       firmware, generation, leaks)

    if generation == 9:
        if firmware and vlt(firmware, FIXED_9):
            ev.append(f"below fixed build {FIXED_9}")
            return Verdict(True, "likely", "firmware-version", "; ".join(ev),
                           firmware, generation, leaks)
        ev.append("patched or unknown build")
        return Verdict(False, "patched", "firmware-version", "; ".join(ev),
                       firmware, generation, leaks)

    if generation == 6:
        ev.append("iDRAC6 is EOL and predates the fix")
        return Verdict(True, "suspect", "eol-family", "; ".join(ev),
                       firmware, generation, leaks)

    return Verdict(False, "unknown", "no-generation", "; ".join(ev),
                   firmware, generation, leaks)
