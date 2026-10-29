"""16 keyless discovery sources. Each is isolated; failures never abort a cycle."""
from __future__ import annotations

import asyncio
import base64
import json
import re
import urllib.parse
from dataclasses import dataclass
from typing import Awaitable, Callable

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
PRIV = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)")

SHODAN_Q = ['http.title:"iDRAC"', 'http.html:"Integrated Dell Remote Access Controller"',
            'http.title:"iDRAC7"', 'http.title:"iDRAC8"', 'http.html:"idrac" port:443',
            'http.favicon.hash:-58631160', 'port:5900 "iDRAC"',
            'http.html:"Dell Remote Access Controller 6"']
FOFA_Q = ['title="iDRAC"', 'body="Integrated Dell Remote Access Controller"',
          'title="iDRAC7"', 'title="iDRAC8"', 'body="idrac" && port="443"']
DORK_Q = ['intitle:"iDRAC"', 'intitle:"iDRAC7" OR intitle:"iDRAC8"',
          '"Integrated Dell Remote Access Controller" login', 'inurl:"/data/login" idrac']
CT_Q = ["iDRAC", "idrac.dell.com"]


@dataclass
class Source:
    name: str
    fn: Callable
    kind: str = "engine"
    notes: str = ""


SOURCES: dict[str, Source] = {}


def src(name, kind="engine", notes=""):
    def deco(fn):
        SOURCES[name] = Source(name, fn, kind, notes)
        return fn
    return deco


def _ips(body: str):
    return {i for i in IP_RE.findall(body or "") if not PRIV.match(i)}


async def _run(fetcher, urls, limit):
    out = set()
    for u in urls:
        if len(out) >= limit:
            break
        r = await fetcher.get(u, polite=False, retries=0)
        if r.ok:
            out |= _ips(r.body)
        await asyncio.sleep(1.1)
    return set(list(out)[:limit])


@src("shodan", notes="shodan.io HTML")
async def shodan(f, limit):
    return await _run(f, [f"https://www.shodan.io/search?query={urllib.parse.quote(q)}"
                          for q in SHODAN_Q], limit)


@src("fofa", notes="fofa.info HTML")
async def fofa(f, limit):
    return await _run(f, [f"https://fofa.info/result?qbase64="
                          f"{urllib.parse.quote(base64.b64encode(q.encode()).decode())}"
                          for q in FOFA_Q], limit)


@src("zoomeye", notes="zoomeye.org HTML")
async def zoomeye(f, limit):
    return await _run(f, [f"https://www.zoomeye.org/searchResult?q={urllib.parse.quote(q)}"
                          for q in ('title:"iDRAC"', 'app:"iDRAC"')], limit)


@src("quake", notes="quake.360.net HTML")
async def quake(f, limit):
    return await _run(f, [f"https://quake.360.net/quake/#/searchResult?searchVal="
                          f"{urllib.parse.quote(q)}"
                          for q in ('title:"iDRAC"', 'body:"Integrated Dell Remote Access Controller"')],
                      limit)


@src("hunter", notes="hunter.how HTML")
async def hunter(f, limit):
    return await _run(f, [f"https://hunter.qianxin.com/list?search={urllib.parse.quote(q)}"
                          for q in ('web.title="iDRAC"', 'web.body="idrac"')], limit)


@src("netlas", notes="netlas.io HTML")
async def netlas(f, limit):
    return await _run(f, [f"https://app.netlas.io/responses/?q={urllib.parse.quote(q)}"
                          for q in ('http.title:"iDRAC"',)], limit)


@src("censys", notes="search.censys.io HTML")
async def censys(f, limit):
    return await _run(f, [f"https://search.censys.io/search?resource=hosts&q="
                          f"{urllib.parse.quote(q)}"
                          for q in ('services.http.response.html_title:"iDRAC"',)], limit)


@src("onyphe", notes="onyphe.io HTML")
async def onyphe(f, limit):
    return await _run(f, [f"https://www.onyphe.io/search/?q={urllib.parse.quote(q)}"
                          for q in ('http.title:"iDRAC"',)], limit)


@src("dork_ddg", kind="dork", notes="DuckDuckGo dorks")
async def dork_ddg(f, limit):
    return await _run(f, [f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(q)}"
                          for q in DORK_Q], limit)


@src("dork_bing", kind="dork", notes="Bing dorks")
async def dork_bing(f, limit):
    return await _run(f, [f"https://www.bing.com/search?q={urllib.parse.quote(q)}&count=50"
                          for q in DORK_Q], limit)


@src("dork_mojeek", kind="dork", notes="Mojeek dorks (plain HTML)")
async def dork_mojeek(f, limit):
    return await _run(f, [f"https://www.mojeek.com/search?q={urllib.parse.quote(q)}"
                          for q in DORK_Q], limit)


@src("dork_yahoo", kind="dork", notes="Yahoo dorks")
async def dork_yahoo(f, limit):
    return await _run(f, [f"https://search.yahoo.com/search?p={urllib.parse.quote(q)}"
                          for q in DORK_Q], limit)


@src("crtsh", kind="ct", notes="crt.sh cert transparency")
async def crtsh(f, limit):
    out = set()
    for q in CT_Q:
        r = await f.get(f"https://crt.sh/?q={urllib.parse.quote(q)}&output=json", polite=False)
        if not r.ok:
            continue
        try:
            rows = json.loads(r.body)
        except Exception:
            continue
        names = set()
        for row in rows[:1500]:
            for n in str(row.get("name_value", "")).splitlines():
                n = n.strip().lower().lstrip("*.")
                if "." in n and not n.endswith((".local", ".lan")):
                    names.add(n)
        for i in range(0, len(names), 40):
            for ips in await asyncio.gather(*(f.resolve(n) for n in list(names)[i:i + 40])):
                out |= set(ips)
            if len(out) >= limit:
                return set(list(out)[:limit])
    return set(list(out)[:limit])


@src("hackertarget", kind="ct", notes="HackerTarget hostsearch")
async def hackertarget(f, limit):
    out = set()
    r = await f.get("https://api.hackertarget.com/hostsearch/?q=dell.com", polite=False)
    if r.ok and "error" not in r.body.lower():
        out |= _ips(r.body)
    return set(list(out)[:limit])


async def enrich(f, ip: str) -> dict:
    data = {}
    r = await f.get(f"https://internetdb.shodan.io/{ip}", polite=False)
    if r.ok:
        try:
            d = json.loads(r.body)
            data["vulns"] = d.get("vulns", [])
        except Exception:
            pass
    g = await f.get(f"http://ip-api.com/json/{ip}?fields=status,country,as,org", polite=False)
    if g.ok:
        try:
            d = json.loads(g.body)
            if d.get("status") == "success":
                data.update(country=d.get("country", ""), asn=d.get("as", ""),
                            org=d.get("org", ""))
        except Exception:
            pass
    return data
