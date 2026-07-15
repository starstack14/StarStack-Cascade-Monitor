from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class ApiError(RuntimeError):
    pass


@dataclass
class NodeSnapshot:
    uuid: str
    name: str
    address: str
    port: int
    connected: bool
    disabled: bool
    cpu_percent: float | None
    load_1m: float | None
    ram_percent: float | None
    users_online: int
    traffic_bytes: int
    latency_ms: float | None = None


@dataclass
class OnlineUser:
    username: str
    user_id: int
    node_uuid: str | None
    node_name: str
    seconds_ago: int
    platform: str | None = None
    os_version: str | None = None
    device_model: str | None = None
    user_agent: str | None = None
    request_ip: str | None = None

    @property
    def device_label(self) -> str:
        parts = [part for part in (self.device_model, self.platform, self.os_version) if part]
        if parts:
            return " · ".join(dict.fromkeys(parts))
        if self.user_agent:
            return self.user_agent[:70]
        return "Устройство не передано клиентом"


def _number(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class RemnawaveClient:
    def __init__(self, base_url: str, token: str, access_query: dict[str, str] | None = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.access_query = access_query or {}

    def _get_json(self, path: str) -> tuple[dict, float]:
        if not self.base_url or not self.token:
            raise ApiError("Укажите адрес панели и API-токен в настройках")
        query = urllib.parse.urlencode(self.access_query)
        url = f"{self.base_url}{path}" + (f"?{query}" if query else "")
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "User-Agent": "StarStack-Cascade-Monitor/1.0",
            },
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise ApiError(f"Доступ к API запрещён ({exc.code}). Проверьте токен и его scope") from exc
            raise ApiError(f"Remnawave API вернул HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ApiError(f"Панель недоступна: {exc}") from exc
        return payload, (time.perf_counter() - started) * 1000

    def get_nodes(self) -> tuple[list[NodeSnapshot], float]:
        payload, api_latency = self._get_json("/api/nodes")

        raw_nodes = payload.get("response", [])
        if isinstance(raw_nodes, dict):
            raw_nodes = raw_nodes.get("nodes", [])
        nodes: list[NodeSnapshot] = []
        for item in raw_nodes or []:
            system = item.get("system") or {}
            info = system.get("info") or {}
            stats = system.get("stats") or {}
            total = _number(info.get("memoryTotal")) or 0
            used = _number(stats.get("memoryUsed")) or 0
            load = stats.get("loadAvg") or []
            cpu = _number(stats.get("cpuUsage", stats.get("cpuPercent")))
            nodes.append(NodeSnapshot(
                uuid=str(item.get("uuid", "")),
                name=str(item.get("name", "Без имени")),
                address=str(item.get("address", "")),
                port=int(item.get("port") or 443),
                connected=bool(item.get("isConnected")),
                disabled=bool(item.get("isDisabled")),
                cpu_percent=cpu,
                load_1m=_number(load[0]) if load else None,
                ram_percent=(used / total * 100) if total else None,
                users_online=int(item.get("usersOnline") or 0),
                traffic_bytes=int(item.get("trafficUsedBytes") or 0),
            ))
        return nodes, api_latency

    def get_online_users(self, nodes: list[NodeSnapshot], threshold_seconds: int = 90) -> list[OnlineUser]:
        payload, _ = self._get_json("/api/users")
        response = payload.get("response") or {}
        raw_users = response.get("users", []) if isinstance(response, dict) else []

        devices_by_user: dict[int, dict] = {}
        try:
            device_payload, _ = self._get_json("/api/hwid/devices")
            device_response = device_payload.get("response") or {}
            devices = device_response.get("devices", []) if isinstance(device_response, dict) else []
            for device in devices:
                user_id = int(device.get("userId") or 0)
                if not user_id:
                    continue
                previous = devices_by_user.get(user_id)
                if previous is None or str(device.get("updatedAt", "")) > str(previous.get("updatedAt", "")):
                    devices_by_user[user_id] = device
        except ApiError:
            # HWID scope is optional. Active users can still be displayed.
            pass

        node_names = {node.uuid: node.name for node in nodes}
        now = datetime.now(timezone.utc)
        result: list[OnlineUser] = []
        for user in raw_users:
            traffic = user.get("userTraffic") or {}
            online_at_raw = traffic.get("onlineAt")
            if not online_at_raw:
                continue
            try:
                online_at = datetime.fromisoformat(str(online_at_raw).replace("Z", "+00:00"))
                seconds = max(0, int((now - online_at).total_seconds()))
            except (TypeError, ValueError):
                continue
            if seconds > threshold_seconds:
                continue
            user_id = int(user.get("id") or 0)
            device = devices_by_user.get(user_id, {})
            node_uuid = traffic.get("lastConnectedNodeUuid")
            result.append(OnlineUser(
                username=str(user.get("username") or "Без имени"),
                user_id=user_id,
                node_uuid=node_uuid,
                node_name=node_names.get(node_uuid, "Неизвестная нода"),
                seconds_ago=seconds,
                platform=device.get("platform"),
                os_version=device.get("osVersion"),
                device_model=device.get("deviceModel"),
                user_agent=device.get("userAgent"),
                request_ip=device.get("requestIp"),
            ))
        return sorted(result, key=lambda item: (item.node_name, item.username.lower()))


def tcp_latency(address: str, port: int, timeout: float = 2.0) -> float | None:
    if not address:
        return None
    started = time.perf_counter()
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return (time.perf_counter() - started) * 1000
    except OSError:
        return None
