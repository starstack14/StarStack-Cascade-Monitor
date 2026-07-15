from __future__ import annotations

import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass
class DownloadResult:
    megabits_per_second: float
    ttfb_ms: float
    bytes_received: int
    duration_seconds: float


def measure_download(url: str, timeout: float = 35.0) -> DownloadResult:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "StarStack-Cascade-Monitor/1.2",
            "Cache-Control": "no-cache",
            "Accept-Encoding": "identity",
        },
    )
    started = time.perf_counter()
    first_byte_at = None
    received = 0
    with urllib.request.urlopen(request, timeout=timeout) as response:
        while True:
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            if first_byte_at is None:
                first_byte_at = time.perf_counter()
            received += len(chunk)
    finished = time.perf_counter()
    if not received:
        raise RuntimeError("Сервер не вернул тестовые данные")
    duration = max(0.001, finished - started)
    return DownloadResult(
        megabits_per_second=received * 8 / duration / 1_000_000,
        ttfb_ms=((first_byte_at or finished) - started) * 1000,
        bytes_received=received,
        duration_seconds=duration,
    )


def measure_parallel(urls: list[str], timeout: float = 35.0) -> DownloadResult:
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        results = list(pool.map(lambda address: measure_download(address, timeout), urls))
    duration = max(0.001, time.perf_counter() - started)
    received = sum(result.bytes_received for result in results)
    return DownloadResult(
        megabits_per_second=received * 8 / duration / 1_000_000,
        ttfb_ms=min(result.ttfb_ms for result in results),
        bytes_received=received,
        duration_seconds=duration,
    )
