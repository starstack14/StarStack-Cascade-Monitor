from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

from openwrt import LanDevice, RouterSnapshot
from remnawave import NodeSnapshot


class HistoryStore:
    def __init__(self, path: Path):
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        with self.connection:
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS samples (ts INTEGER, kind TEXT, item_key TEXT, ram REAL, latency REAL, load REAL)"
            )
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_samples_lookup ON samples(kind, item_key, ts)")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS events (ts INTEGER, level TEXT, message TEXT)"
            )
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS incidents ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, component TEXT, started INTEGER, ended INTEGER, message TEXT)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_incidents_started ON incidents(started)"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS device_traffic (ts INTEGER, mac TEXT, rx INTEGER, tx INTEGER)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_device_traffic ON device_traffic(mac, ts)"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS known_devices ("
                "mac TEXT PRIMARY KEY, alias TEXT, hostname TEXT, first_seen INTEGER, last_seen INTEGER, "
                "present INTEGER, trusted INTEGER DEFAULT 0)"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS device_presence (ts INTEGER, mac TEXT, event TEXT, hostname TEXT, ip TEXT)"
            )
            self.connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_device_presence ON device_presence(mac, ts)"
            )

    def record(self, router: RouterSnapshot, nodes: list[NodeSnapshot]) -> None:
        now = int(time.time())
        rows = []
        if router.online:
            rows.append((now, "router", "NX31", router.ram_percent, None, router.load_1m))
        for node in nodes:
            rows.append((now, "node", node.uuid, node.ram_percent, node.latency_ms, node.load_1m))
        if not rows:
            return
        with self.lock, self.connection:
            self.connection.executemany("INSERT INTO samples VALUES (?, ?, ?, ?, ?, ?)", rows)
            self.connection.execute("DELETE FROM samples WHERE ts < ?", (now - 7 * 86400,))

    def values(self, kind: str, item_key: str, field: str = "ram", seconds: int = 3600) -> list[float]:
        if field not in {"ram", "latency", "load"}:
            raise ValueError("Unsupported history field")
        since = int(time.time()) - seconds
        with self.lock:
            rows = self.connection.execute(
                f"SELECT {field} FROM samples WHERE kind=? AND item_key=? AND ts>=? AND {field} IS NOT NULL ORDER BY ts",
                (kind, item_key, since),
            ).fetchall()
        values = [float(row[0]) for row in rows]
        if len(values) > 180:
            step = max(1, len(values) // 180)
            values = values[::step][-180:]
        return values

    def close(self) -> None:
        with self.lock:
            self.connection.close()

    def backup_to(self, path: Path) -> None:
        target = sqlite3.connect(path)
        try:
            with self.lock:
                self.connection.backup(target)
        finally:
            target.close()

    def record_device_traffic(self, totals: dict[str, tuple[int, int]]) -> None:
        if not totals:
            return
        now = int(time.time())
        rows = [(now, mac, rx, tx) for mac, (rx, tx) in totals.items()]
        with self.lock, self.connection:
            self.connection.executemany("INSERT INTO device_traffic VALUES (?, ?, ?, ?)", rows)
            self.connection.execute("DELETE FROM device_traffic WHERE ts < ?", (now - 35 * 86400,))

    def device_usage_since(self, mac: str, since: int) -> tuple[int, int]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT rx, tx FROM device_traffic WHERE mac=? AND ts>=? ORDER BY ts",
                (mac, since),
            ).fetchall()
        if len(rows) < 2:
            return 0, 0
        first_rx, first_tx = int(rows[0][0]), int(rows[0][1])
        last_rx, last_tx = int(rows[-1][0]), int(rows[-1][1])
        return max(0, last_rx - first_rx), max(0, last_tx - first_tx)

    def observe_devices(self, devices: list[LanDevice]) -> dict[str, list[tuple[str, str]]]:
        now = int(time.time())
        active_states = {"ONLINE", "REACHABLE", "STALE", "DELAY", "PROBE"}
        changes: dict[str, list[tuple[str, str]]] = {"new": [], "connected": [], "disconnected": []}
        with self.lock, self.connection:
            existing_rows = self.connection.execute(
                "SELECT mac, alias, hostname, last_seen, present FROM known_devices"
            ).fetchall()
            existing = {str(row[0]): row for row in existing_rows}
            baseline = not existing
            active_macs: set[str] = set()
            for device in devices:
                mac = device.mac.lower()
                present = device.state.upper() in active_states
                if present:
                    active_macs.add(mac)
                name = device.hostname or "Неизвестное устройство"
                old = existing.get(mac)
                if old is None:
                    self.connection.execute(
                        "INSERT INTO known_devices(mac, alias, hostname, first_seen, last_seen, present, trusted) "
                        "VALUES (?, '', ?, ?, ?, ?, 0)", (mac, name, now, now, int(present))
                    )
                    self.connection.execute(
                        "INSERT INTO device_presence VALUES (?, ?, ?, ?, ?)",
                        (now, mac, "first_seen", name, device.ip)
                    )
                    if not baseline:
                        changes["new"].append((mac, name))
                else:
                    was_present = bool(old[4])
                    self.connection.execute(
                        "UPDATE known_devices SET hostname=?, last_seen=?, present=? WHERE mac=?",
                        (name, now if present else old[3], int(present), mac)
                    )
                    if present and not was_present:
                        self.connection.execute(
                            "INSERT INTO device_presence VALUES (?, ?, 'connected', ?, ?)", (now, mac, name, device.ip)
                        )
                        changes["connected"].append((mac, name))
            for mac, row in existing.items():
                if bool(row[4]) and mac not in active_macs:
                    self.connection.execute("UPDATE known_devices SET present=0 WHERE mac=?", (mac,))
                    self.connection.execute(
                        "INSERT INTO device_presence VALUES (?, ?, 'disconnected', ?, '')", (now, mac, row[2] or mac)
                    )
                    changes["disconnected"].append((mac, str(row[1] or row[2] or mac)))
        return changes

    def device_metadata(self) -> dict[str, tuple[str, bool]]:
        with self.lock:
            rows = self.connection.execute("SELECT mac, alias, trusted FROM known_devices").fetchall()
        return {str(mac): (str(alias or ""), bool(trusted)) for mac, alias, trusted in rows}

    def known_devices(self) -> list[tuple[str, str, str, int, int, bool, bool]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT mac, alias, hostname, first_seen, last_seen, present, trusted "
                "FROM known_devices ORDER BY trusted DESC, last_seen DESC"
            ).fetchall()
        return [(str(mac), str(alias or ""), str(hostname or ""), int(first_seen), int(last_seen),
                 bool(present), bool(trusted)) for mac, alias, hostname, first_seen, last_seen, present, trusted in rows]

    def set_device_alias(self, mac: str, alias: str) -> None:
        with self.lock, self.connection:
            self.connection.execute("UPDATE known_devices SET alias=? WHERE mac=?", (alias.strip(), mac.lower()))

    def set_device_trusted(self, mac: str, trusted: bool) -> None:
        with self.lock, self.connection:
            self.connection.execute("UPDATE known_devices SET trusted=? WHERE mac=?", (int(trusted), mac.lower()))

    def device_events(self, mac: str, limit: int = 100) -> list[tuple[int, str, str, str]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT ts, event, hostname, ip FROM device_presence WHERE mac=? ORDER BY ts DESC LIMIT ?",
                (mac.lower(), limit),
            ).fetchall()
        return [(int(ts), str(event), str(hostname), str(ip)) for ts, event, hostname, ip in rows]

    def device_rate_series(self, mac: str, seconds: int) -> list[tuple[int, float, float]]:
        since = int(time.time()) - seconds
        with self.lock:
            rows = self.connection.execute(
                "SELECT ts, rx, tx FROM device_traffic WHERE mac=? AND ts>=? ORDER BY ts", (mac.lower(), since)
            ).fetchall()
        series: list[tuple[int, float, float]] = []
        for previous, current in zip(rows, rows[1:]):
            elapsed = max(1, int(current[0]) - int(previous[0]))
            rx = max(0, int(current[1]) - int(previous[1])) * 8 / elapsed / 1_000_000
            tx = max(0, int(current[2]) - int(previous[2])) * 8 / elapsed / 1_000_000
            series.append((int(current[0]), rx, tx))
        if len(series) > 240:
            step = max(1, len(series) // 240)
            series = series[::step][-240:]
        return series

    def add_event(self, level: str, message: str) -> None:
        now = int(time.time())
        with self.lock, self.connection:
            self.connection.execute("INSERT INTO events VALUES (?, ?, ?)", (now, level, message))
            self.connection.execute("DELETE FROM events WHERE ts < ?", (now - 7 * 86400,))

    def recent_events(self, limit: int = 250) -> list[tuple[int, str, str]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT ts, level, message FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [(int(row[0]), str(row[1]), str(row[2])) for row in rows]

    def events_since(self, timestamp: int, levels: tuple[str, ...] = ("warning", "error", "ok")) -> list[tuple[int, str, str]]:
        placeholders = ",".join("?" for _ in levels)
        with self.lock:
            rows = self.connection.execute(
                f"SELECT ts, level, message FROM events WHERE ts>? AND level IN ({placeholders}) ORDER BY ts DESC",
                (timestamp, *levels),
            ).fetchall()
        return [(int(ts), str(level), str(message)) for ts, level, message in rows]

    def sync_incidents(self, health: dict[str, bool]) -> None:
        now = int(time.time())
        with self.lock, self.connection:
            open_rows = self.connection.execute(
                "SELECT id, component FROM incidents WHERE ended IS NULL"
            ).fetchall()
            open_incidents = {str(component): int(row_id) for row_id, component in open_rows}
            for component, healthy in health.items():
                incident_id = open_incidents.get(component)
                if not healthy and incident_id is None:
                    self.connection.execute(
                        "INSERT INTO incidents(component, started, ended, message) VALUES (?, ?, NULL, ?)",
                        (component, now, f"{component}: недоступен"),
                    )
                elif healthy and incident_id is not None:
                    self.connection.execute("UPDATE incidents SET ended=? WHERE id=?", (now, incident_id))
            self.connection.execute("DELETE FROM incidents WHERE started < ?", (now - 30 * 86400,))

    def recent_incidents(self, limit: int = 100) -> list[tuple[int, str, int, int | None, str]]:
        with self.lock:
            rows = self.connection.execute(
                "SELECT id, component, started, ended, message FROM incidents ORDER BY started DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            (int(row_id), str(component), int(started), int(ended) if ended is not None else None, str(message))
            for row_id, component, started, ended, message in rows
        ]
