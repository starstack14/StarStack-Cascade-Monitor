from __future__ import annotations

import json
import re
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class RouterSnapshot:
    configured: bool = False
    online: bool = False
    hostname: str = "NX31"
    model: str = ""
    uptime: int = 0
    load_1m: float | None = None
    ram_percent: float | None = None
    wan_ip: str = ""
    wan_device: str = ""
    link_up: bool = False
    singbox_running: bool = False
    error: str = ""
    access_method: str = ""


@dataclass
class LanDevice:
    hostname: str = "Неизвестное устройство"
    ip: str = ""
    mac: str = ""
    connection: str = "LAN"
    signal_dbm: int | None = None
    rx_mbps: float | None = None
    tx_mbps: float | None = None
    state: str = "UNKNOWN"
    lease_expires: int | None = None


class OpenWrtError(RuntimeError):
    pass


class OpenWrtClient:
    """Minimal read-only client for OpenWrt's standard ubus JSON-RPC endpoint."""

    def __init__(self, base_url: str, username: str, password: str):
        self.url = base_url.rstrip("/") + "/ubus"
        self.username = username
        self.password = password
        self.session = "00000000000000000000000000000000"
        self._request_id = 0

    def _rpc(self, obj: str, method: str, params: dict[str, Any] | None = None) -> dict:
        self._request_id += 1
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "call",
            "params": [self.session, obj, method, params or {}],
        }).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json", "User-Agent": "StarStack-Cascade-Monitor/1.1"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.load(response)
        except urllib.error.HTTPError as exc:
            raise OpenWrtError(f"LuCI HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise OpenWrtError("NX31 не отвечает") from exc
        result = payload.get("result") or []
        if not result or result[0] != 0:
            raise OpenWrtError("LuCI/ubus отклонил запрос")
        return result[1] if len(result) > 1 and isinstance(result[1], dict) else {}

    def login(self) -> None:
        data = self._rpc("session", "login", {"username": self.username, "password": self.password})
        session = data.get("ubus_rpc_session")
        if not session:
            raise OpenWrtError("Неверный логин или пароль NX31")
        self.session = session

    def snapshot(self) -> RouterSnapshot:
        result = RouterSnapshot(configured=True)
        try:
            self.login()
            board = self._rpc("system", "board")
            info = self._rpc("system", "info")
            service = self._rpc("service", "list", {"name": "sing-box"})
            interfaces = self._rpc("network.interface", "dump").get("interface") or []
            wan = next((item for item in interfaces if item.get("interface") == "wan"), None)
            if wan is None:
                wan = next((item for item in interfaces if any(route.get("target") == "0.0.0.0" for route in item.get("route") or [])), {})

            result.online = True
            result.access_method = "LuCI"
            result.hostname = str(board.get("hostname") or "NX31")
            result.model = str((board.get("model") or board.get("system") or ""))
            result.uptime = int(info.get("uptime") or 0)
            load = info.get("load") or []
            if load:
                result.load_1m = float(load[0]) / 65535
            memory = info.get("memory") or {}
            total = float(memory.get("total") or 0)
            available = float(memory.get("available") or memory.get("free") or 0)
            if total:
                result.ram_percent = max(0.0, min(100.0, (total - available) / total * 100))

            result.link_up = bool(wan.get("up"))
            result.wan_device = str(wan.get("l3_device") or wan.get("device") or "")
            addresses = wan.get("ipv4-address") or []
            if addresses:
                result.wan_ip = str(addresses[0].get("address") or "")

            singbox = service.get("sing-box") or service.get("sing_box") or {}
            instances = singbox.get("instances") or {}
            result.singbox_running = any(bool(instance.get("running")) for instance in instances.values())
        except OpenWrtError as exc:
            result.error = str(exc)
        return result


class OpenWrtSshClient:
    def __init__(self, host: str, username: str, private_key: str, port: int = 22):
        self.host = host
        self.username = username
        self.private_key = private_key
        self.port = port

    def _base_command(self) -> list[str]:
        known_hosts = str(Path(self.private_key).with_name("known_hosts"))
        return [
            "ssh.exe", "-i", self.private_key, "-p", str(self.port),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
            "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known_hosts}",
            f"{self.username}@{self.host}",
        ]

    def _json_command(self, command: str) -> dict:
        output = self._text_command(command)
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            raise OpenWrtError("NX31 вернул некорректный JSON через SSH") from exc

    def _text_command(self, command: str, timeout: int = 10) -> str:
        result = subprocess.run(
            self._base_command() + [command], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            message = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else "SSH отказал в доступе"
            raise OpenWrtError(message)
        return result.stdout

    def _binary_command(self, command: str, timeout: int = 60) -> bytes:
        result = subprocess.run(
            self._base_command() + [command], capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", "replace").strip()
            raise OpenWrtError(message or "SSH отказал в доступе")
        return result.stdout

    def snapshot(self) -> RouterSnapshot:
        result = RouterSnapshot(configured=True, access_method="SSH key")
        try:
            board = self._json_command("ubus call system board")
            info = self._json_command("ubus call system info")
            service = self._json_command("ubus call service list")
            interfaces_data = self._json_command("ubus call network.interface dump")
            interfaces = interfaces_data.get("interface") or []
            wan = next((item for item in interfaces if item.get("interface") == "wan"), {})

            result.online = True
            result.hostname = str(board.get("hostname") or "NX31")
            result.model = str(board.get("model") or board.get("system") or "")
            result.uptime = int(info.get("uptime") or 0)
            load = info.get("load") or []
            if load:
                result.load_1m = float(load[0]) / 65535
            memory = info.get("memory") or {}
            total = float(memory.get("total") or 0)
            available = float(memory.get("available") or memory.get("free") or 0)
            if total:
                result.ram_percent = max(0.0, min(100.0, (total - available) / total * 100))
            result.link_up = bool(wan.get("up"))
            result.wan_device = str(wan.get("l3_device") or wan.get("device") or "")
            addresses = wan.get("ipv4-address") or []
            if addresses:
                result.wan_ip = str(addresses[0].get("address") or "")
            singbox = service.get("sing-box") or service.get("sing_box") or {}
            instances = singbox.get("instances") or {}
            result.singbox_running = any(bool(instance.get("running")) for instance in instances.values())
        except (OpenWrtError, subprocess.SubprocessError, OSError) as exc:
            result.error = str(exc)
        return result

    def reboot(self) -> None:
        result = subprocess.run(
            self._base_command() + ["reboot"], capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        error = result.stderr.lower()
        if "permission denied" in error or "no such identity" in error:
            raise OpenWrtError(result.stderr.strip())

    def restart_singbox(self) -> None:
        self._text_command("/etc/init.d/sing-box restart", timeout=20)

    def read_singbox_log(self, lines: int = 120) -> str:
        lines = max(20, min(500, int(lines)))
        return self._text_command(
            f"tail -n {lines} /tmp/sing-box.log 2>/dev/null || logread -e sing-box | tail -n {lines}", timeout=15
        )

    def read_singbox_config(self) -> str:
        return self._text_command("cat /etc/sing-box/config.json", timeout=15)

    def create_system_backup(self) -> bytes:
        data = self._binary_command("sysupgrade -b -", timeout=90)
        if len(data) < 512:
            raise OpenWrtError("NX31 вернул пустую резервную копию")
        return data

    def restore_system_backup(self, backup_file: Path) -> None:
        if not backup_file.exists() or backup_file.stat().st_size < 512:
            raise OpenWrtError("Файл резервной копии отсутствует или слишком мал")
        known_hosts = str(Path(self.private_key).with_name("known_hosts"))
        remote_path = "/tmp/starstack-restore.tar.gz"
        result = subprocess.run(
            ["scp.exe", "-i", self.private_key, "-P", str(self.port), "-o", "BatchMode=yes",
             "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes", f"-oUserKnownHostsFile={known_hosts}",
             str(backup_file), f"{self.username}@{self.host}:{remote_path}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            raise OpenWrtError(result.stderr.strip() or "Не удалось загрузить backup на NX31")
        self._text_command(
            f"nohup sh -c 'sleep 2; sysupgrade -r {remote_path} >/tmp/starstack-restore.log 2>&1' >/dev/null 2>&1 &",
            timeout=15,
        )

    def collect_singbox_diagnostics(self) -> str:
        return self._text_command(
            "{ "
            "echo '=== DATE ==='; date; "
            "echo '=== UPTIME ==='; uptime; "
            "echo '=== SERVICE ==='; /etc/init.d/sing-box status 2>&1 || true; "
            "ubus call service list '{\"name\":\"sing-box\"}' 2>&1 || true; "
            "echo '=== PROCESSES ==='; pgrep -a sing-box 2>&1 || true; "
            "echo '=== ROUTES ==='; ip -4 route 2>&1 || true; "
            "echo '=== DNS ==='; nslookup google.com 127.0.0.1 2>&1 || true; "
            "echo '=== LAST LOG ==='; tail -n 160 /tmp/sing-box.log 2>&1 || logread -e sing-box | tail -n 160; "
            "}", timeout=25
        )

    def get_device_traffic(self) -> dict[str, tuple[int, int]]:
        try:
            payload = self._json_command("nlbw -c json -g mac")
        except OpenWrtError:
            return {}
        columns = payload.get("columns") or []
        rows = payload.get("data") or []
        try:
            mac_index = columns.index("mac")
            rx_index = columns.index("rx_bytes")
            tx_index = columns.index("tx_bytes")
        except ValueError:
            return {}
        totals: dict[str, tuple[int, int]] = {}
        for row in rows:
            if not isinstance(row, list) or len(row) <= max(mac_index, rx_index, tx_index):
                continue
            mac = str(row[mac_index]).lower()
            if mac == "00:00:00:00:00:00":
                continue
            totals[mac] = (int(row[rx_index] or 0), int(row[tx_index] or 0))
        return totals

    @staticmethod
    def _validated_mac(mac: str) -> tuple[str, str]:
        normalized = mac.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", normalized):
            raise OpenWrtError("Некорректный MAC-адрес")
        return normalized, normalized.replace(":", "")

    def blocked_macs(self) -> set[str]:
        output = self._text_command("uci -q show firewall | grep 'starstack_block_.*src_mac=' || true")
        blocked: set[str] = set()
        for line in output.splitlines():
            match = re.search(r"src_mac='?([0-9a-f:]{17})'?", line, re.I)
            if match:
                blocked.add(match.group(1).lower())
        return blocked

    def block_device(self, mac: str) -> None:
        normalized, key = self._validated_mac(mac)
        command = (
            f"uci -q delete firewall.starstack_block_{key}_input; "
            f"uci -q delete firewall.starstack_block_{key}_forward; "
            f"uci set firewall.starstack_block_{key}_input=rule; "
            f"uci set firewall.starstack_block_{key}_input.name='StarStack block {normalized} input'; "
            f"uci set firewall.starstack_block_{key}_input.src='lan'; "
            f"uci set firewall.starstack_block_{key}_input.src_mac='{normalized}'; "
            f"uci set firewall.starstack_block_{key}_input.target='REJECT'; "
            f"uci set firewall.starstack_block_{key}_forward=rule; "
            f"uci set firewall.starstack_block_{key}_forward.name='StarStack block {normalized} forward'; "
            f"uci set firewall.starstack_block_{key}_forward.src='lan'; "
            f"uci set firewall.starstack_block_{key}_forward.dest='*'; "
            f"uci set firewall.starstack_block_{key}_forward.src_mac='{normalized}'; "
            f"uci set firewall.starstack_block_{key}_forward.target='REJECT'; "
            "uci commit firewall; /etc/init.d/firewall reload"
        )
        self._text_command(command, timeout=30)

    def unblock_device(self, mac: str) -> None:
        _, key = self._validated_mac(mac)
        self._text_command(
            f"uci -q delete firewall.starstack_block_{key}_input; "
            f"uci -q delete firewall.starstack_block_{key}_forward; "
            "uci commit firewall; /etc/init.d/firewall reload", timeout=30
        )

    def get_lan_devices(self) -> list[LanDevice]:
        leases = self._text_command("cat /tmp/dhcp.leases 2>/dev/null || true")
        neighbours = self._text_command("ip neigh show dev br-lan 2>/dev/null || ip neigh show 2>/dev/null || true")
        devices: dict[str, LanDevice] = {}
        for line in leases.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            expiry, mac, ip, hostname = parts[:4]
            mac = mac.lower()
            devices[mac] = LanDevice(
                hostname=hostname if hostname != "*" else "Неизвестное устройство",
                ip=ip, mac=mac, lease_expires=int(expiry) if expiry.isdigit() else None,
            )
        for line in neighbours.splitlines():
            match = re.search(r"^(\S+).*?lladdr\s+([0-9a-f:]{17}).*?\s(\S+)$", line, re.I)
            if not match or ":" in match.group(1):
                continue
            ip, mac, state = match.group(1), match.group(2).lower(), match.group(3).upper()
            device = devices.setdefault(mac, LanDevice(ip=ip, mac=mac))
            device.ip = device.ip or ip
            device.state = state

        for obj in self._text_command("ubus list 'hostapd.*' 2>/dev/null || true").splitlines():
            if not re.fullmatch(r"hostapd\.[A-Za-z0-9_.-]+", obj):
                continue
            try:
                payload = self._json_command(f"ubus call {obj} get_clients")
            except OpenWrtError:
                continue
            freq = int(payload.get("freq") or 0)
            band = "2.4 ГГц" if 0 < freq < 3000 else "5 ГГц" if freq else "Wi-Fi"
            for mac, details in (payload.get("clients") or {}).items():
                mac = mac.lower()
                device = devices.setdefault(mac, LanDevice(mac=mac))
                device.connection = f"Wi-Fi {band}"
                device.signal_dbm = int(details.get("signal")) if details.get("signal") is not None else None
                rates = details.get("rate") or {}
                device.rx_mbps = float(rates.get("rx") or 0) / 1_000_000
                device.tx_mbps = float(rates.get("tx") or 0) / 1_000_000
                device.state = "ONLINE" if details.get("authorized") else "ASSOCIATED"
        return sorted(devices.values(), key=lambda item: (item.state not in {"ONLINE", "REACHABLE"}, item.hostname.lower(), item.ip))
