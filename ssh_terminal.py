from __future__ import annotations

import os
import queue
import subprocess
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk


class SshTerminalWindow(tk.Toplevel):
    """Small local-only SSH terminal. It never uses the web dashboard."""

    def __init__(self, parent, host: str, username: str, private_key: str, port: int = 22,
                 on_action=None):
        super().__init__(parent)
        self.parent = parent
        self.host = host
        self.username = username
        self.private_key = str(private_key)
        self.port = int(port)
        self.on_action = on_action
        self.process: subprocess.Popen | None = None
        self._closed = False
        self._output_queue: queue.Queue[str] = queue.Queue()
        self.title(f"SSH-терминал · {host}")
        self.geometry("900x560")
        self.minsize(640, 360)
        self.configure(bg="#0c080d")
        self.protocol("WM_DELETE_WINDOW", self.close)

        header = tk.Frame(self, bg="#150c12")
        header.pack(fill="x", padx=10, pady=(10, 0))
        tk.Label(header, text=f"SSH  {username}@{host}:{port}", bg="#150c12", fg="#75d8ff",
                 font=("Segoe UI", 10, "bold")).pack(side="left", padx=10, pady=8)
        tk.Button(header, text="Отключить", command=self.close, bg="#4b2833", fg="#fff5f1",
                  relief="flat").pack(side="right", padx=8, pady=6)

        body = tk.Frame(self, bg="#0c080d")
        body.pack(fill="both", expand=True, padx=10, pady=10)
        self.output = tk.Text(body, bg="#09070a", fg="#d6f7df", insertbackground="#fff5f1",
                              relief="flat", wrap="none", font=("Cascadia Mono", 10), state="disabled")
        yscroll = ttk.Scrollbar(body, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=yscroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

        entry_row = tk.Frame(self, bg="#150c12")
        entry_row.pack(fill="x", padx=10, pady=(0, 10))
        tk.Label(entry_row, text=">", bg="#150c12", fg="#62e6a7", font=("Cascadia Mono", 11, "bold")).pack(side="left", padx=8)
        self.command = tk.Entry(entry_row, bg="#21131b", fg="#fff5f1", insertbackground="#fff5f1",
                                relief="flat", font=("Cascadia Mono", 10))
        self.command.pack(side="left", fill="x", expand=True, padx=(0, 8), pady=8)
        self.command.bind("<Return>", self.send_command)
        self.command.focus_set()
        tk.Button(entry_row, text="Отправить", command=self.send_command, bg="#2b1722", fg="#75d8ff",
                  relief="flat").pack(side="right", padx=8, pady=6)

        self.after(80, self._drain_output)
        self._connect()

    def _write(self, text: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", text)
        self.output.see("end")
        self.output.configure(state="disabled")

    def _connect(self) -> None:
        key = Path(self.private_key)
        if not key.exists():
            messagebox.showerror("SSH-ключ не найден", f"Не найден private key:\n{key}", parent=self)
            self.destroy()
            return
        known_hosts = str(key.with_name("known_hosts"))
        command = ["ssh.exe", "-tt", "-i", str(key), "-p", str(self.port),
                   "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=5",
                   "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={known_hosts}",
                   f"{self.username}@{self.host}"]
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT, bufsize=0, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except OSError as exc:
            self._write(f"Не удалось запустить ssh.exe: {exc}\n")
            return
        if self.on_action:
            self.on_action(f"ACTION: открыт SSH-терминал NX31 ({self.host})")
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self) -> None:
        stream = self.process.stdout if self.process else None
        if not stream:
            return
        while not self._closed:
            try:
                chunk = os.read(stream.fileno(), 4096)
            except OSError:
                break
            if not chunk:
                break
            self._output_queue.put(chunk.decode("utf-8", "replace"))

    def _drain_output(self) -> None:
        if self._closed:
            return
        chunks = []
        while True:
            try:
                chunks.append(self._output_queue.get_nowait())
            except queue.Empty:
                break
        if chunks:
            self._write("".join(chunks))
        self.after(80, self._drain_output)

    def send_command(self, _event=None):
        if not self.process or not self.process.stdin or self.process.poll() is not None:
            self._write("\nSSH-сессия завершена.\n")
            return "break"
        text = self.command.get()
        if not text:
            return "break"
        try:
            self.process.stdin.write((text + "\n").encode("utf-8"))
            self.process.stdin.flush()
            self.command.delete(0, "end")
        except OSError as exc:
            self._write(f"\nОшибка отправки: {exc}\n")
        return "break"

    def close(self) -> None:
        self._closed = True
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except OSError:
                pass
        self.destroy()
