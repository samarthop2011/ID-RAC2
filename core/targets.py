from __future__ import annotations

import gzip
import ipaddress
import os
import random
import time

IP2ASN = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
SKIP = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]


def parse_line(line: str):
    line = line.split("#", 1)[0].strip()
    if not line:
        return []
    t = line.split()[0]
    try:
        if "-" in t and t.count(".") == 6:
            a, b = t.split("-")
            nets = list(ipaddress.summarize_address_range(
                ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)))
        else:
            n = ipaddress.ip_network(t, strict=False)
            nets = [n] if n.version == 4 else []
    except ValueError:
        return []
    return [n for n in nets if not any(n.subnet_of(s) for s in SKIP)]


def parse_blob(text: str):
    out = []
    for line in text.splitlines():
        out.extend(parse_line(line))
    return out


def load_file(path: str):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        out.extend(parse_line(line))
    return out


def expand(net, limit: int, full: bool):
    size = net.num_addresses
    if full or size <= limit:
        for ip in (net.hosts() if size > 2 else net):
            yield str(ip)
        return
    rng = random.Random(int(net.network_address))
    base, seen = int(net.network_address), set()
    while len(seen) < limit:
        off = rng.randrange(1, size - 1)
        if off in seen:
            continue
        seen.add(off)
        yield str(ipaddress.IPv4Address(base + off))


async def harvest_asns(fetcher, path, cache="data/ip2asn.tsv.gz", age_h=168):
    if not os.path.exists(path):
        return []
    asns = {int(l.split("#")[0]) for l in open(path, encoding="utf-8")
            if l.split("#")[0].strip().isdigit()}
    if not asns:
        return []
    if not os.path.exists(cache) or time.time() - os.path.getmtime(cache) > age_h * 3600:
        try:
            async with fetcher._s.get(IP2ASN, ssl=False) as r:
                if r.status == 200:
                    open(cache, "wb").write(await r.read())
        except Exception:
            pass
    if not os.path.exists(cache):
        return []
    nets = []
    with gzip.open(cache, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) < 3 or not p[2].isdigit() or int(p[2]) not in asns:
                continue
            try:
                span = int(ipaddress.IPv4Address(p[1])) - int(ipaddress.IPv4Address(p[0])) + 1
                n = ipaddress.ip_network(f"{p[0]}/{32 - (span.bit_length() - 1)}", strict=False)
            except ValueError:
                continue
            if n.prefixlen >= 16:
                nets.append(n)
    return nets
