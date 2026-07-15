from __future__ import annotations

import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass


@dataclass
class RouteSnapshot:
    direct_ip: str = ""
    moscow_ip: str = ""
    germany_ip: str = ""
    error: str = ""

    @property
    def healthy(self) -> bool:
        values = [self.direct_ip, self.moscow_ip, self.germany_ip]
        return all(values) and len(set(values)) == 3


def _fetch_json(url: str):
    request = urllib.request.Request(url, headers={"User-Agent": "StarStack-Cascade-Monitor/1.3"})
    with urllib.request.urlopen(request, timeout=12) as response:
        return json.load(response)


def check_routes(direct_ip: str) -> RouteSnapshot:
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            germany_future = pool.submit(_fetch_json, "https://api.ipify.org?format=json")
            moscow_future = pool.submit(_fetch_json, "https://yandex.ru/internet/api/v0/ip")
            germany_data = germany_future.result()
            moscow_data = moscow_future.result()
        germany_ip = germany_data.get("ip", "") if isinstance(germany_data, dict) else str(germany_data)
        moscow_ip = str(moscow_data).strip('"')
        return RouteSnapshot(direct_ip=direct_ip, moscow_ip=moscow_ip, germany_ip=germany_ip)
    except Exception as exc:
        return RouteSnapshot(direct_ip=direct_ip, error=str(exc))
