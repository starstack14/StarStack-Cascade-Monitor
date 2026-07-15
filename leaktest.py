from __future__ import annotations

import json
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field


@dataclass
class DnsResolver:
    ip: str
    country: str
    asn: str


@dataclass
class LeakTestResult:
    public_ip: str = ""
    resolvers: list[DnsResolver] = field(default_factory=list)
    ipv6_ip: str = ""
    dns_suspected: bool = False
    error: str = ""

    @property
    def safe(self) -> bool:
        return not self.error and bool(self.resolvers) and not self.dns_suspected and not self.ipv6_ip


def _get_json(url: str, timeout: float = 15.0):
    request = urllib.request.Request(url, headers={"User-Agent": "StarStack-Cascade-Monitor/1.4"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def _resolve_probe(host: str) -> None:
    try:
        socket.getaddrinfo(host, 80)
    except OSError:
        pass


def run_leak_test(direct_ip: str = "") -> LeakTestResult:
    result = LeakTestResult()
    try:
        test_id = urllib.request.urlopen("https://bash.ws/id", timeout=12).read().decode("utf-8").strip()
        hosts = [f"{index}.{test_id}.bash.ws" for index in range(10)]
        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(_resolve_probe, hosts))
        data = _get_json(f"https://bash.ws/dnsleak/test/{test_id}?json")
        for item in data:
            if item.get("type") == "ip":
                result.public_ip = str(item.get("ip") or "")
            elif item.get("type") == "dns":
                result.resolvers.append(DnsResolver(
                    str(item.get("ip") or ""), str(item.get("country_name") or ""), str(item.get("asn") or "")
                ))
        suspicious_names = ("beeline", "vimpel", "rostelecom", "mts", "megafon")
        result.dns_suspected = any(
            resolver.ip == direct_ip or any(name in resolver.asn.lower() for name in suspicious_names)
            for resolver in result.resolvers
        )
        try:
            ipv6_data = _get_json("https://api6.ipify.org?format=json", timeout=7)
            if isinstance(ipv6_data, dict):
                result.ipv6_ip = str(ipv6_data.get("ip") or "")
        except Exception:
            result.ipv6_ip = ""
    except Exception as exc:
        result.error = str(exc)
    return result
