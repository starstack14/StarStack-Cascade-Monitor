from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import subprocess
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable


LOGIN_HTML = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>StarStack Monitor</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0c080d;color:#fff5f1;font:15px system-ui;background-image:radial-gradient(circle at 50% 0,#451528 0,transparent 46%)}.box{width:min(390px,calc(100% - 32px));background:#21131bea;backdrop-filter:blur(20px);border:1px solid #4b2833;padding:30px;border-radius:20px;box-shadow:0 22px 80px #000a,0 0 35px #ff554814}h1{margin:0;color:#fff;font-size:22px}p{color:#ae8e96;margin:6px 0 22px}label{display:block;color:#ffad5c;font-size:12px;margin:13px 0 6px}input{width:100%;padding:13px;border:1px solid #4b2833;border-radius:10px;background:#0c080d;color:#fff;font-size:16px;outline:none}input:focus{border-color:#75d8ff;box-shadow:0 0 0 3px #75d8ff16}button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:10px;background:linear-gradient(135deg,#ff5548,#f27b4d);color:white;font-weight:700}.err{color:#ff7068;margin:12px 0 0}</style></head><body><form class="box" method="post" action="/login"><h1>◇ StarStack</h1><p>Защищённый доступ к каскаду</p><label>Логин</label><input name="username" autocomplete="username" required><label>Пароль</label><input type="password" name="password" autocomplete="current-password" required><button>ВОЙТИ</button>__ERROR__</form></body></html>"""


DASHBOARD_HTML = r"""<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>StarStack Cascade</title>
<style>:root{--bg:#0c080d;--card:#21131b;--alt:#2b1722;--text:#fff5f1;--muted:#ae8e96;--green:#62e6a7;--red:#ff5548;--orange:#ffad5c;--cyan:#75d8ff;--border:#4b2833}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px system-ui;background-image:radial-gradient(circle at 50% -20%,#4d182c 0,transparent 43%)}main{max-width:760px;margin:auto;padding:15px}.head{display:flex;align-items:center;justify-content:space-between;padding:15px 4px 20px}.brand b{font-size:20px}.brand small{display:block;color:var(--muted);font-size:9px;letter-spacing:1.5px;margin-top:3px}.status{font-weight:700;background:#1a1016;padding:7px 10px;border-radius:9px}.ok{color:var(--green)}.bad{color:var(--red)}.muted{color:var(--muted)}.route{display:grid;grid-template-columns:1fr auto 1fr auto 1fr;gap:7px;align-items:center;margin-bottom:11px}.pill,.card{background:#21131be8;backdrop-filter:blur(14px);border:1px solid var(--border);border-radius:13px;box-shadow:0 12px 34px #0003}.pill{text-align:center;padding:12px 5px;font-size:12px}.arrow{color:var(--orange)}.card{padding:15px;margin:9px 0}.row{display:flex;justify-content:space-between;gap:10px;align-items:center}.title{font-size:16px;font-weight:700}.details{color:var(--muted);font-size:12px;margin-top:8px;line-height:1.7}.ip{color:var(--cyan);font-family:ui-monospace,monospace}.section{margin:20px 2px 8px;color:var(--muted);font-size:10px;font-weight:800;letter-spacing:1px}.device,.user{background:var(--alt);padding:12px;border-radius:10px;margin-top:7px;border:1px solid #4b283377}.badge{padding:3px 7px;border-radius:8px;background:var(--alt);color:var(--orange);font-size:11px}.empty{color:var(--muted);padding:18px;text-align:center}.footer{text-align:center;color:var(--muted);font-size:11px;padding:18px}a{color:var(--muted)}@media(max-width:520px){main{padding:11px}.route{gap:4px}.pill{padding:10px 2px;font-size:10px}.arrow{font-size:10px}.card{padding:13px}.title{font-size:14px}}</style></head><body><main><div class="head"><div class="brand"><b>◇ StarStack</b><small>CASCADE CONTROL · v2.1</small></div><div><span id="overall" class="status muted">● ЗАГРУЗКА</span></div></div><div class="route"><div id="p-router" class="pill">● NX31</div><div class="arrow">▶</div><div id="p-moscow" class="pill">● MOSCOW</div><div class="arrow">▶</div><div id="p-germany" class="pill">● GERMANY</div></div><div id="routes" class="card"></div><div id="router" class="card"></div><div class="section">НОДЫ</div><div id="nodes"></div><div class="section">ПОДКЛЮЧЕНЫ К VPN <span id="uc" class="badge">0</span></div><div id="users"></div><div class="section">ДОМАШНЯЯ СЕТЬ <span id="dc" class="badge">0</span></div><div id="devices"></div><div class="footer"><span id="updated">—</span> · <a href="/logout">выйти</a></div></main><script>
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const cls=b=>b?'ok':'bad';const rate=n=>n==null?'—':(n*8/1e6).toFixed(2)+' Мбит/с';const bytes=n=>{if(!n)return '0 Б';let u=['Б','КБ','МБ','ГБ','ТБ'],i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(1)+' '+u[i]};
async function update(){try{let r=await fetch('/api/status',{cache:'no-store'});if(r.status===401){location='/';return}let d=await r.json();let good=d.healthy;overall.textContent=good?'● КАСКАД OK':'● НУЖНА ПРОВЕРКА';overall.className='status '+cls(good);let node=n=>d.nodes.find(x=>x.name===n)||{};let m=node('Moscow'),g=node('Germany');[['p-router',d.router.online&&d.router.singbox],['p-moscow',m.online],['p-germany',g.online]].forEach(x=>document.getElementById(x[0]).className='pill '+cls(x[1]));routes.innerHTML='<div class="row"><b>МАРШРУТЫ</b><span class="'+cls(d.routes.healthy)+'">'+(d.routes.healthy?'OK':'CHECK')+'</span></div><div class="details ip">DIRECT '+esc(d.routes.direct)+' · MOSCOW '+esc(d.routes.moscow)+' · GERMANY '+esc(d.routes.germany)+'</div>';router.innerHTML='<div class="row"><span class="title">▰ '+esc(d.router.hostname)+'</span><b class="'+cls(d.router.online)+'">'+(d.router.online?'ONLINE':'OFFLINE')+'</b></div><div class="details">sing-box '+(d.router.singbox?'●':'✕')+' · Load '+esc(d.router.load)+' · RAM '+esc(d.router.ram)+'<br>WAN '+esc(d.router.wan)+'</div>';nodes.innerHTML=d.nodes.map(n=>'<div class="card"><div class="row"><span class="title">'+esc(n.flag)+' '+esc(n.name)+'</span><b class="'+cls(n.online)+'">'+(n.online?'ONLINE':'OFFLINE')+'</b></div><div class="details">'+esc(n.latency)+' · Load '+esc(n.load)+' · RAM '+esc(n.ram)+' · 👤 '+esc(n.users)+'<br><span class="ip">Трафик '+bytes(n.traffic)+'</span></div></div>').join('')||'<div class="empty">Нет данных</div>';uc.textContent=d.users.length;users.innerHTML=d.users.map(u=>'<div class="user"><div class="row"><b>'+esc(u.name)+'</b><span class="ok">'+esc(u.node)+'</span></div><div class="details">'+esc(u.device)+' · '+esc(u.ip)+'</div></div>').join('')||'<div class="empty">Нет активных подключений</div>';dc.textContent=d.devices.length;devices.innerHTML=d.devices.map(x=>'<div class="device"><div class="row"><b>'+(x.trusted?'✓ ':'')+esc(x.name)+'</b><span class="'+(x.blocked?'bad':'ok')+'">'+(x.blocked?'BLOCKED':esc(x.state))+'</span></div><div class="details">'+esc(x.ip)+' · '+esc(x.connection)+' · '+esc(x.signal)+'<br><span class="ip">Сейчас ↓ '+rate(x.rx_rate)+' / ↑ '+rate(x.tx_rate)+' · Месяц '+bytes(x.rx_total)+' / '+bytes(x.tx_total)+'</span></div></div>').join('')||'<div class="empty">Устройства не обнаружены</div>';updated.textContent='Обновлено '+new Date(d.updated*1000).toLocaleTimeString();}catch(e){overall.textContent='● НЕТ СВЯЗИ С ПРИЛОЖЕНИЕМ';overall.className='status bad'}}update();setInterval(update,5000);</script></body></html>"""


class DashboardWebServer:
    def __init__(self, port: int, username: str, password: str, state_provider: Callable[[], dict]):
        self.port = port
        self.username = username
        self.password_hash = hashlib.sha256(password.encode("utf-8")).digest()
        self.state_provider = state_provider
        self.sessions: dict[str, float] = {}
        self.attempts: defaultdict[str, deque[float]] = defaultdict(deque)
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "StarStack"

            def log_message(self, *_args) -> None:
                return

            def _headers(self, status: int, content_type: str = "text/html; charset=utf-8") -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Strict-Transport-Security", "max-age=31536000")
                self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")

            def _session(self) -> str | None:
                jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
                morsel = jar.get("starstack_session")
                token = morsel.value if morsel else ""
                expires = owner.sessions.get(token, 0)
                if expires > time.time():
                    return token
                owner.sessions.pop(token, None)
                return None

            def _send(self, body: str | bytes, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
                data = body.encode("utf-8") if isinstance(body, str) else body
                self._headers(status, content_type)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                path = urllib.parse.urlsplit(self.path).path
                if path == "/logout":
                    token = self._session()
                    if token:
                        owner.sessions.pop(token, None)
                    self.send_response(303)
                    self.send_header("Set-Cookie", "starstack_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")
                    self.send_header("Location", "/")
                    self.end_headers()
                elif path == "/api/status":
                    if not self._session():
                        self._send(b"{}", 401, "application/json")
                    else:
                        self._send(json.dumps(owner.state_provider(), ensure_ascii=False).encode("utf-8"), 200, "application/json; charset=utf-8")
                elif path == "/":
                    self._send(DASHBOARD_HTML if self._session() else LOGIN_HTML.replace("__ERROR__", ""))
                else:
                    self._send("Не найдено", 404, "text/plain; charset=utf-8")

            def do_POST(self) -> None:
                if urllib.parse.urlsplit(self.path).path != "/login":
                    self._send("Не найдено", 404, "text/plain; charset=utf-8")
                    return
                forwarded = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                client = forwarded or self.client_address[0]
                now = time.time()
                attempts = owner.attempts[client]
                while attempts and now - attempts[0] > 900:
                    attempts.popleft()
                if len(attempts) >= 8:
                    self._send(LOGIN_HTML.replace("__ERROR__", '<div class="err">Слишком много попыток. Подождите 15 минут.</div>'), 429)
                    return
                length = min(int(self.headers.get("Content-Length", "0") or 0), 4096)
                fields = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
                username = (fields.get("username") or [""])[0]
                supplied = hashlib.sha256(((fields.get("password") or [""])[0]).encode("utf-8")).digest()
                if username != owner.username or not hmac.compare_digest(supplied, owner.password_hash):
                    attempts.append(now)
                    self._send(LOGIN_HTML.replace("__ERROR__", '<div class="err">Неверный логин или пароль</div>'), 401)
                    return
                attempts.clear()
                token = secrets.token_urlsafe(32)
                owner.sessions[token] = now + 86400
                self.send_response(303)
                self.send_header("Set-Cookie", f"starstack_session={token}; Max-Age=86400; Path=/; Secure; HttpOnly; SameSite=Strict")
                self.send_header("Location", "/")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.sessions.clear()


class CaddyManager:
    def __init__(self, executable: Path, caddyfile: Path, log_path: Path):
        self.executable = executable
        self.caddyfile = caddyfile
        self.log_path = log_path
        self.process: subprocess.Popen | None = None
        self.log_handle = None

    def start(self) -> bool:
        if not self.executable.exists() or not self.caddyfile.exists():
            return False
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_handle = self.log_path.open("ab")
        self.process = subprocess.Popen(
            [str(self.executable), "run", "--config", str(self.caddyfile), "--adapter", "caddyfile"],
            cwd=str(self.executable.parent), stdout=self.log_handle, stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return True

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        if self.log_handle:
            self.log_handle.close()
