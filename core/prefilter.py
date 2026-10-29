import asyncio


async def port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def any_open(ip: str, ports: list[int], timeout: float = 2.0) -> int | None:
    res = await asyncio.gather(*(port_open(ip, p, timeout) for p in ports))
    for p, ok in zip(ports, res):
        if ok:
            return p
    return None
