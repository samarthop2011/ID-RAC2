"""iDRAC generation fingerprint. Generations come from branded markers,
titles and endpoint shape; firmware from unauthenticated leak surfaces."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

GEN_MARKERS = {
    6: ["idrac6", "idrac 6", "drac 6", "dell remote access controller 6", "webcgi"],
    7: ["idrac7", "idrac 7", "remote access controller 7"],
    8: ["idrac8", "idrac 8", "remote access controller 8"],
    9: ["idrac9", "idrac 9", "/restapi", "redfish/v1"],
}
GENERIC = ["idrac", "integrated dell remote access controller",
           "dell remote access controller", "avctkvm"]

PATHS = ["/", "/login.html", "/index.html", "/data/login", "/restapi/v1/Systems",
         "/redfish/v1/", "/cgi-bin/webcgi/", "/session"]

TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
MODEL = re.compile(r"(PowerEdge\s+[A-Z]\d{3,4}[a-zA-Z]*)", re.I)

VERSION_PATTERNS = [
    re.compile(r"<prodVersion>([\d.]+)</prodVersion>", re.I),
    re.compile(r"prodVersion[\"'\s:=]+([\d.]+)", re.I),
    re.compile(r"idrac-(\d+\.\d+\.\d+\.\d+)", re.I),
    re.compile(r'"FirmwareVersion"\s*:\s*"([\d.]+)"', re.I),
    re.compile(r"(?:version|fwVersion|firmware)[\"'\s:=]+(\d+\.\d+\.\d+\.\d+)", re.I),
    re.compile(r"\b(\d{1,2}\.\d{2}\.\d{2}\.\d{2})\b"),
]


@dataclass
class Fingerprint:
    alive: bool = False
    generation: int = 0
    model: str = ""
    firmware: str = ""
    title: str = ""
    server: str = ""
    default_creds: bool = False
    auth_bypass: bool = False
    score: int = 0
    evidence: list = field(default_factory=list)

    @property
    def is_idrac(self) -> bool:
        return self.alive and (self.generation > 0 or self.score >= 40)


def _version(bodies) -> str:
    for body in bodies:
        for pat in VERSION_PATTERNS:
            m = pat.search(body)
            if m:
                v = m.group(1)
                if 4 <= len(v) <= 20 and v.count(".") >= 2:
                    return v
    return ""


async def probe(fetcher, ip, port, scheme, creds=True) -> Fingerprint:
    fp = Fingerprint()
    base = f"{scheme}://{ip}:{port}"
    bodies: list[str] = []

    for path in PATHS:
        r = await fetcher.get(base + path, retries=0)
        if r.status == 0:
            continue
        fp.alive = True
        bodies.append(r.body)
        low = r.body.lower()
        if not fp.server and r.headers.get("Server"):
            fp.server = r.headers["Server"]

        for gen, marks in GEN_MARKERS.items():
            if any(m in low for m in marks):
                if not fp.generation:
                    fp.generation = gen
                    fp.score += 70
                    fp.evidence.append(f"gen{gen} marker at {path}")
                break
        else:
            if any(m in low for m in GENERIC):
                fp.score += 30
                fp.evidence.append(f"iDRAC marker at {path}")

        if not fp.title:
            m = TITLE.search(r.body)
            if m:
                fp.title = m.group(1).strip()[:110]
                if "idrac" in fp.title.lower():
                    fp.score += 20
                    fp.evidence.append(f"title {fp.title!r}")
        if not fp.model:
            m = MODEL.search(r.body)
            if m:
                fp.model = m.group(1)
        if fp.generation and fp.score >= 70:
            break

    if fp.is_idrac and not fp.firmware:
        fw = _version(bodies)
        if fw:
            fp.firmware = fw
            fp.score += 15
            fp.evidence.append(f"firmware {fw}")

    if creds and fp.generation:
        fp.default_creds = await _try_creds(fetcher, base)
        if fp.default_creds:
            fp.score += 45
            fp.evidence.append("root:calvin accepted")

    if fp.is_idrac:
        fp.score += 25
    return fp


async def _try_creds(fetcher, base) -> bool:
    r = await fetcher.post(base + "/data/login",
                           data={"user": "root", "password": "calvin"},
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           retries=0)
    return "<authResult>0</authResult>" in r.body
