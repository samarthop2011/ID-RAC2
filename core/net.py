from __future__ import annotations

import asyncio
import random
import ssl
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from .ratelimit import AdaptiveLimiter

UA = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
]
H = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
     "Accept-Language": "en-US,en;q=0.9"}


def _ssl():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    try:
        c.minimum_version = ssl.TLSVersion.TLSv1
    except Exception:
        pass
    try:
        c.set_ciphers("DEFAULT@SECLEVEL=1")
    except Exception:
        pass
    return c


@dataclass
class Response:
    status: int = 0
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 400


class Fetcher:
    def __init__(self, concurrency=200, delay=0.15, timeout=12, proxies=None):
        self.concurrency, self.delay, self.timeout = concurrency, delay, timeout
        self.proxies = proxies or []
        self._s: Optional[aiohttp.ClientSession] = None
        self._host_lim: dict[str, AdaptiveLimiter] = {}
        self._global = AdaptiveLimiter(max(4.0, 1.0 / max(delay, 0.01)))

    async def __aenter__(self):
        self._s = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=self.concurrency, limit_per_host=6,
                                           ssl=_ssl(), ttl_dns_cache=600),
            timeout=aiohttp.ClientTimeout(total=self.timeout,
                                          connect=min(6, self.timeout)),
            headers={"User-Agent": random.choice(UA)})
        return self

    async def __aexit__(self, *e):
        if self._s:
            await self._s.close()

    def _lim(self, host: str) -> AdaptiveLimiter:
        lim = self._host_lim.get(host)
        if lim is None:
            lim = self._host_lim[host] = AdaptiveLimiter(
                max(1.0, 1.0 / max(self.delay, 0.02)), floor=1.0, ceiling=200.0)
        return lim

    async def request(self, method, url, *, headers=None, data=None, json=None,
                      retries=1, read=True, polite=True, allow_redirects=True) -> Response:
        last = Response(url=url, error="none")
        for attempt in range(retries + 1):
            try:
                if polite:
                    await self._global.acquire()
                    await self._lim(urlparse(url).netloc).acquire()
                h = dict(H)
                h["User-Agent"] = random.choice(UA)
                if headers:
                    h.update(headers)
                proxy = random.choice(self.proxies) if self.proxies else None
                async with self._s.request(method, url, headers=h, data=data, json=json,
                                           ssl=False, proxy=proxy,
                                           allow_redirects=allow_redirects) as r:
                    body = ""
                    if read:
                        body = (await r.read())[:300_000].decode("utf-8", errors="replace")
                    last = Response(r.status, str(r.url), dict(r.headers), body)
                if last.status in (429, 503):
                    self._global.on_throttle()
                    self._lim(urlparse(url).netloc).on_throttle()
                elif last.status < 500:
                    self._global.on_success()
                    return last
            except asyncio.TimeoutError:
                last = Response(url=url, error="timeout")
            except Exception as exc:
                last = Response(url=url, error=type(exc).__name__)
            if attempt < retries:
                await asyncio.sleep(0.4 * (2 ** attempt) + random.random() * 0.4)
        return last

    async def get(self, url, **kw):
        return await self.request("GET", url, **kw)

    async def post(self, url, **kw):
        return await self.request("POST", url, **kw)

    async def resolve(self, host):
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=0)
        except Exception:
            return []
        return sorted({i[4][0] for i in infos if ":" not in i[4][0]})


def load_proxies(path: str) -> list[str]:
    import os
    if not path or not os.path.exists(path):
        return []
    return [l.strip() for l in open(path, encoding="utf-8") if l.strip()]
