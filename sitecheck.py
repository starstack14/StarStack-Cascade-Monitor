from __future__ import annotations

import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass
class SiteCheckResult:
    route: str
    url: str
    ok: bool
    latency_ms: float | None = None
    status: int | None = None
    error: str = ""


def _check_one(route: str, url: str) -> SiteCheckResult:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers={"User-Agent": "StarStack-Cascade-Monitor/2.5"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            status = int(getattr(response, "status", response.getcode()))
        return SiteCheckResult(route, url, 200 <= status < 500, (time.perf_counter() - started) * 1000, status)
    except Exception as exc:
        return SiteCheckResult(route, url, False, error=str(exc))


def check_sites(routes: dict[str, str]) -> list[SiteCheckResult]:
    with ThreadPoolExecutor(max_workers=max(1, len(routes))) as pool:
        futures = [pool.submit(_check_one, route, url) for route, url in routes.items()]
        return [future.result() for future in futures]
