#!/usr/bin/env python3
"""
FloatControl - floating network traffic + ping monitor for Windows.

A small always-on-top, draggable overlay that shows:
  * ping (ms) to a chosen host, colour coded, with packet loss and jitter
  * download / upload speed (bytes/s or bits/s)
  * a live traffic graph and session totals

Right-click the widget for all options. Settings are stored in
%APPDATA%\\FloatControl\\config.json.

Run with --console for the classic "chat-thread" text output.

Only dependency besides the standard library: psutil.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, fields
from datetime import datetime
from pathlib import Path
from typing import Deque, Dict, Optional, Tuple

import psutil

# ---------- App identity ----------
APP_NAME = "FloatControl"
APP_VERSION = "1.0.0"
APP_PUBLISHER = "CoolCupMan"
APP_DESCRIPTION = "FloatControl - Network Traffic & Ping Monitor"
# Unique, permanent identity of this application. Do not change between versions.
APP_GUID = "271a2667-664e-4c37-b06b-b7a00486f8df"
APP_USER_MODEL_ID = f"{APP_PUBLISHER}.{APP_NAME}.NetMonitor.{APP_GUID}"

IS_WINDOWS = sys.platform == "win32"
FROZEN = getattr(sys, "frozen", False)


# ---------- Helper functions ----------
def human_rate(n: float, bits: bool = False) -> str:
    """Human readable transfer rate."""
    if n < 0:
        return "N/A"
    if bits:
        n *= 8
        units, base = ("bps", "Kbps", "Mbps", "Gbps", "Tbps"), 1000.0
    else:
        units, base = ("B/s", "KB/s", "MB/s", "GB/s", "TB/s"), 1024.0
    for unit in units:
        if n < base:
            return f"{n:.1f} {unit}" if unit != units[0] else f"{n:.0f} {unit}"
        n /= base
    return f"{n:.1f} P{units[0]}"


def human_size(n: float) -> str:
    """Human readable byte count."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


_PING_TIME_RE = re.compile(r"[=<]\s*([\d.,]+)\s*(?:ms|\u043c\u0441)", re.IGNORECASE)


def parse_ping_ms(ping_output: str) -> float:
    """
    Parse 'ping' output for the round trip time, return ms as float.
    Works for any Windows locale ("time=14ms", "Zeit=14ms", "temps=14 ms",
    "time<1ms") as well as Linux/macOS output. Returns -1.0 if not found.
    """
    m = _PING_TIME_RE.search(ping_output)
    if not m:
        return -1.0
    try:
        val = float(m.group(1).replace(",", "."))
    except ValueError:
        return -1.0
    return min(val, 1.0) if ping_output[m.start()] == "<" else val


def is_loopback(nic: str) -> bool:
    n = nic.lower()
    return n == "lo" or n.startswith("loopback") or n.startswith("lo0")


# ---------- Ping backends ----------
class _IcmpPinger:
    """Native Windows ICMP echo via iphlpapi (no console window, locale independent)."""

    class IP_OPTION_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Ttl", ctypes.c_ubyte),
            ("Tos", ctypes.c_ubyte),
            ("Flags", ctypes.c_ubyte),
            ("OptionsSize", ctypes.c_ubyte),
            ("OptionsData", ctypes.c_void_p),
        ]

    class ICMP_ECHO_REPLY(ctypes.Structure):
        pass

    ICMP_ECHO_REPLY._fields_ = [
        ("Address", ctypes.c_ulong),
        ("Status", ctypes.c_ulong),
        ("RoundTripTime", ctypes.c_ulong),
        ("DataSize", ctypes.c_ushort),
        ("Reserved", ctypes.c_ushort),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]

    def __init__(self):
        from ctypes import wintypes

        self._lib = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)
        self._lib.IcmpCreateFile.restype = wintypes.HANDLE
        self._lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        self._lib.IcmpSendEcho.argtypes = [
            wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ushort,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong,
        ]
        self._lib.IcmpSendEcho.restype = ctypes.c_ulong
        self._handle = self._lib.IcmpCreateFile()
        if not self._handle or self._handle == ctypes.c_void_p(-1).value:
            raise OSError("IcmpCreateFile failed")
        self._payload = ctypes.create_string_buffer(b"FloatControl ping data!!", 32)
        self._reply = ctypes.create_string_buffer(ctypes.sizeof(self.ICMP_ECHO_REPLY) + 32 + 64)

    def ping(self, ip: str, timeout_ms: int) -> float:
        addr = struct.unpack("<I", socket.inet_aton(ip))[0]
        n = self._lib.IcmpSendEcho(
            self._handle, addr, self._payload, 32, None,
            self._reply, ctypes.sizeof(self._reply), timeout_ms,
        )
        if n == 0:
            return -1.0
        reply = self.ICMP_ECHO_REPLY.from_buffer(self._reply)
        if reply.Status != 0:
            return -1.0
        return float(max(reply.RoundTripTime, 0)) if reply.RoundTripTime else 0.5

    def close(self):
        if self._handle:
            self._lib.IcmpCloseHandle(self._handle)
            self._handle = None


def _subprocess_ping(host: str, timeout_ms: int) -> float:
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
        flags = 0x08000000  # CREATE_NO_WINDOW: no console flash in the GUI build
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), host]
        flags = 0
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout_ms / 1000 + 2, creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return -1.0
    return parse_ping_ms(proc.stdout)


# ---------- Ping thread ----------
class PingThread(threading.Thread):
    """Continuously pings host in background and keeps RTT statistics."""

    HISTORY = 30

    def __init__(self, host: str, interval: float = 1.0, timeout_ms: int = 1000):
        super().__init__(daemon=True, name="ping")
        self._lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._wake = threading.Event()
        self.timeout_ms = int(timeout_ms)
        self._host = host
        self._interval = max(0.5, float(interval))
        self._history: Deque[float] = deque(maxlen=self.HISTORY)
        self._rtt = -1.0
        self._last_update = 0.0
        self._error = ""
        self._icmp: Optional[_IcmpPinger] = None
        if IS_WINDOWS:
            try:
                self._icmp = _IcmpPinger()
            except Exception:
                self._icmp = None

    # configuration (thread safe)
    def set_host(self, host: str):
        with self._lock:
            self._host = host
            self._history.clear()
            self._rtt = -1.0
            self._error = ""
        self._wake.set()

    def set_interval(self, interval: float):
        with self._lock:
            self._interval = max(0.5, float(interval))
        self._wake.set()

    @property
    def host(self) -> str:
        with self._lock:
            return self._host

    def _ping_once(self, host: str) -> Tuple[float, str]:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return -1.0, "DNS error"
        if self._icmp is not None:
            try:
                return self._icmp.ping(ip, self.timeout_ms), ""
            except Exception:
                pass
        return _subprocess_ping(ip, self.timeout_ms), ""

    def run(self):
        while not self._stop_evt.is_set():
            with self._lock:
                host, interval = self._host, self._interval
            start = time.monotonic()
            rtt, err = self._ping_once(host)
            with self._lock:
                if host == self._host:  # ignore results for a host that was just replaced
                    self._rtt = rtt
                    self._error = err
                    self._history.append(rtt)
                    self._last_update = time.time()
            remaining = interval - (time.monotonic() - start)
            if remaining > 0:
                self._wake.wait(remaining)
            self._wake.clear()
        if self._icmp is not None:
            self._icmp.close()

    def stop(self):
        self._stop_evt.set()
        self._wake.set()

    def rtt(self) -> Tuple[float, float]:
        """Return (rtt_ms, last_update_ts)."""
        with self._lock:
            return self._rtt, self._last_update

    def stats(self) -> Dict[str, float]:
        """Latest rtt, packet loss %, jitter (ms) over the recent history."""
        with self._lock:
            hist = list(self._history)
            rtt, err = self._rtt, self._error
        ok = [h for h in hist if h >= 0]
        loss = (100.0 * (len(hist) - len(ok)) / len(hist)) if hist else 0.0
        jitter = statistics.mean(abs(a - b) for a, b in zip(ok, ok[1:])) if len(ok) > 1 else 0.0
        return {"rtt": rtt, "loss": loss, "jitter": jitter, "samples": len(hist), "error": err}


# ---------- Traffic sampler ----------
class TrafficSampler:
    """Computes per-interface and total rates from psutil counters."""

    def __init__(self):
        self._prev = psutil.net_io_counters(pernic=True)
        self._prev_time = time.monotonic()

    def sample(self, iface: str = "") -> Tuple[float, float, float, float, Dict[str, Tuple[float, float]]]:
        """
        Return (down_rate, up_rate, recv_delta, sent_delta, per_iface_rates).
        iface="" sums all non-loopback interfaces.
        """
        cur = psutil.net_io_counters(pernic=True)
        now = time.monotonic()
        elapsed = max(now - self._prev_time, 1e-6)
        per: Dict[str, Tuple[float, float]] = {}
        recv_total = sent_total = 0
        for nic, c in cur.items():
            p = self._prev.get(nic)
            if p is None:  # interface just appeared: no baseline yet
                continue
            recv = max(0, c.bytes_recv - p.bytes_recv)  # counter reset/wrap -> 0
            sent = max(0, c.bytes_sent - p.bytes_sent)
            per[nic] = (recv / elapsed, sent / elapsed)
            if (iface and nic == iface) or (not iface and not is_loopback(nic)):
                recv_total += recv
                sent_total += sent
        self._prev, self._prev_time = cur, now
        return recv_total / elapsed, sent_total / elapsed, recv_total, sent_total, per

    @staticmethod
    def interfaces():
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}
        names = sorted(psutil.net_io_counters(pernic=True).keys(), key=str.lower)
        return [n for n in names if not is_loopback(n) and (n not in stats or stats[n].isup)]


# ---------- Config ----------
@dataclass
class Config:
    host: str = "8.8.8.8"
    interval: float = 1.0
    opacity: float = 0.9
    x: Optional[int] = None
    y: Optional[int] = None
    topmost: bool = True
    show_graph: bool = True
    show_details: bool = True
    bits: bool = False
    iface: str = ""
    locked: bool = False

    @staticmethod
    def path() -> Path:
        if IS_WINDOWS:
            base = Path(os.environ.get("APPDATA") or Path.home())
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
        return base / APP_NAME / "config.json"

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        try:
            data = json.loads(cls.path().read_text(encoding="utf-8"))
            for f in fields(cls):
                if f.name in data:
                    setattr(cfg, f.name, data[f.name])
        except (OSError, ValueError, TypeError):
            pass
        cfg.interval = min(max(float(cfg.interval), 0.25), 60.0)
        cfg.opacity = min(max(float(cfg.opacity), 0.2), 1.0)
        return cfg

    def save(self):
        try:
            p = self.path()
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
        except OSError:
            pass


# ---------- Windows integration ----------
def win_set_app_id():
    """Give the process its own AppUserModelID (taskbar grouping, notifications)."""
    if IS_WINDOWS:
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
        except Exception:
            pass


def win_set_dpi_aware():
    if IS_WINDOWS:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


_instance_mutex = None


def win_single_instance() -> bool:
    """Return False if another instance of this app is already running."""
    global _instance_mutex
    if not IS_WINDOWS:
        return True
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        _instance_mutex = kernel32.CreateMutexW(None, False, f"Local\\{APP_NAME}-{APP_GUID}")
        return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS
    except Exception:
        return True


def win_message(text: str, title: str = APP_NAME):
    if IS_WINDOWS:
        try:
            ctypes.windll.user32.MessageBoxW(None, text, title, 0x40 | 0x40000)
            return
        except Exception:
            pass
    print(text)


def win_attach_console() -> bool:
    """Attach to the parent console when the windowed .exe is started with --console."""
    if not IS_WINDOWS or (sys.stdout is not None and not FROZEN):
        return True
    try:
        if ctypes.windll.kernel32.AttachConsole(-1) or ctypes.windll.kernel32.AllocConsole():
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
            sys.stderr = sys.stdout
            return True
    except Exception:
        pass
    return sys.stdout is not None


def virtual_screen(root) -> Tuple[int, int, int, int]:
    """Bounding box of all monitors (x, y, w, h)."""
    if IS_WINDOWS:
        try:
            gsm = ctypes.windll.user32.GetSystemMetrics
            return gsm(76), gsm(77), gsm(78), gsm(79)
        except Exception:
            pass
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()


_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def autostart_supported() -> bool:
    return IS_WINDOWS and FROZEN


def autostart_enabled() -> bool:
    if not autostart_supported():
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as k:
            val, _ = winreg.QueryValueEx(k, APP_NAME)
            return os.path.normcase(sys.executable) in os.path.normcase(val)
    except OSError:
        return False


def set_autostart(enable: bool):
    if not autostart_supported():
        return
    import winreg

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if enable:
            winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, f'"{sys.executable}"')
        else:
            try:
                winreg.DeleteValue(k, APP_NAME)
            except OSError:
                pass


def resource_path(name: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / name


# ---------- Floating widget ----------
class FloatWidget:
    BG = "#15171c"
    BG_GRAPH = "#1d2027"
    FG = "#e8e8e8"
    DIM = "#8a8f98"
    DOWN = "#3fb6ff"
    DOWN_FILL = "#1b4a66"
    UP = "#ff9f43"
    GOOD, WARN, BAD = "#4cd964", "#ffcc00", "#ff4d4d"
    GRAPH_W, GRAPH_H = 176, 40
    SNAP = 14

    def __init__(self, cfg: Config):
        import tkinter as tk

        self.tk = tk
        self.cfg = cfg
        self.root = tk.Tk(className=APP_NAME)
        self.root.title(APP_NAME)
        self.root.overrideredirect(True)
        self.root.configure(bg=self.BG)
        self.root.attributes("-alpha", cfg.opacity)
        self.root.attributes("-topmost", cfg.topmost)
        try:
            self.root.iconbitmap(default=str(resource_path("floatcontrol.ico")))
        except Exception:
            pass

        self.sampler = TrafficSampler()
        self.pinger = PingThread(cfg.host, interval=max(1.0, cfg.interval))
        self.pinger.start()
        self.hist_down: Deque[float] = deque([0.0] * (self.GRAPH_W // 3), maxlen=self.GRAPH_W // 3)
        self.hist_up: Deque[float] = deque([0.0] * (self.GRAPH_W // 3), maxlen=self.GRAPH_W // 3)
        self.total_down = 0
        self.total_up = 0
        self.peak_down = 0.0
        self.peak_up = 0.0
        self._drag: Optional[Tuple[int, int]] = None
        self._after_id = None
        self._tick_count = 0

        self._build_ui()
        self._build_menu()
        self._place_initial()
        self._round_corners()
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self._after_id = self.root.after(int(cfg.interval * 1000), self._tick)

    # ----- UI -----
    def _build_ui(self):
        tk = self.tk
        font = ("Segoe UI", 10) if IS_WINDOWS else ("DejaVu Sans", 9)
        bold = (font[0], font[1], "bold")
        small = (font[0], font[1] - 2)
        self.frame = tk.Frame(self.root, bg=self.BG, padx=8, pady=6)
        self.frame.pack(fill="both", expand=True)

        row = tk.Frame(self.frame, bg=self.BG)
        row.pack(fill="x")
        self.ping_dot = tk.Label(row, text="●", fg=self.DIM, bg=self.BG, font=bold)
        self.ping_dot.pack(side="left")
        self.ping_lbl = tk.Label(row, text="-- ms", fg=self.FG, bg=self.BG, font=bold, anchor="w")
        self.ping_lbl.pack(side="left", padx=(3, 0))
        self.loss_lbl = tk.Label(row, text="", fg=self.DIM, bg=self.BG, font=small, anchor="e")
        self.loss_lbl.pack(side="right")

        rates = tk.Frame(self.frame, bg=self.BG)
        rates.pack(fill="x", pady=(2, 0))
        self.down_lbl = tk.Label(rates, text="↓ --", fg=self.DOWN, bg=self.BG, font=bold, width=12, anchor="w")
        self.down_lbl.pack(side="left")
        self.up_lbl = tk.Label(rates, text="↑ --", fg=self.UP, bg=self.BG, font=bold, width=12, anchor="w")
        self.up_lbl.pack(side="left")

        self.graph = tk.Canvas(
            self.frame, width=self.GRAPH_W, height=self.GRAPH_H, bg=self.BG_GRAPH,
            highlightthickness=0, bd=0,
        )
        self.details = tk.Label(self.frame, text="", fg=self.DIM, bg=self.BG, font=small, justify="left", anchor="w")
        self._apply_layout()

        for w in (self.root, self.frame, row, rates, self.ping_dot, self.ping_lbl,
                  self.loss_lbl, self.down_lbl, self.up_lbl, self.graph, self.details):
            w.bind("<ButtonPress-1>", self._drag_start)
            w.bind("<B1-Motion>", self._drag_move)
            w.bind("<ButtonRelease-1>", self._drag_end)
            w.bind("<Double-Button-1>", lambda e: self._toggle("show_details"))
            w.bind("<Button-3>", self._popup)

    def _apply_layout(self):
        self.graph.pack_forget()
        self.details.pack_forget()
        if self.cfg.show_graph:
            self.graph.pack(fill="x", pady=(5, 0))
        if self.cfg.show_details:
            self.details.pack(fill="x", pady=(4, 0))

    def _build_menu(self):
        tk = self.tk
        cfg = self.cfg
        m = tk.Menu(self.root, tearoff=False)
        m.add_command(label=f"{APP_NAME} {APP_VERSION}", state="disabled")
        m.add_separator()
        m.add_command(label="Ping host…", command=self._ask_host)

        self.v_interval = tk.DoubleVar(value=cfg.interval)
        sub = tk.Menu(m, tearoff=False)
        for s in (0.5, 1.0, 2.0, 5.0):
            sub.add_radiobutton(label=f"{s:g} s", variable=self.v_interval, value=s, command=self._set_interval)
        m.add_cascade(label="Update interval", menu=sub)

        self.v_opacity = tk.DoubleVar(value=round(cfg.opacity, 1))
        sub = tk.Menu(m, tearoff=False)
        for o in (1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4):
            sub.add_radiobutton(label=f"{int(o * 100)} %", variable=self.v_opacity, value=o, command=self._set_opacity)
        m.add_cascade(label="Opacity", menu=sub)

        self.v_bits = tk.BooleanVar(value=cfg.bits)
        sub = tk.Menu(m, tearoff=False)
        sub.add_radiobutton(label="Bytes per second (MB/s)", variable=self.v_bits, value=False, command=self._set_units)
        sub.add_radiobutton(label="Bits per second (Mbps)", variable=self.v_bits, value=True, command=self._set_units)
        m.add_cascade(label="Units", menu=sub)

        self.v_iface = tk.StringVar(value=cfg.iface)
        self.iface_menu = tk.Menu(m, tearoff=False, postcommand=self._fill_iface_menu)
        m.add_cascade(label="Network adapter", menu=self.iface_menu)

        m.add_separator()
        self.v_graph = tk.BooleanVar(value=cfg.show_graph)
        self.v_details = tk.BooleanVar(value=cfg.show_details)
        self.v_topmost = tk.BooleanVar(value=cfg.topmost)
        self.v_locked = tk.BooleanVar(value=cfg.locked)
        m.add_checkbutton(label="Show graph", variable=self.v_graph, command=lambda: self._toggle("show_graph"))
        m.add_checkbutton(label="Show details  (double-click)", variable=self.v_details,
                          command=lambda: self._toggle("show_details"))
        m.add_checkbutton(label="Always on top", variable=self.v_topmost, command=lambda: self._toggle("topmost"))
        m.add_checkbutton(label="Lock position", variable=self.v_locked, command=lambda: self._toggle("locked"))
        if autostart_supported():
            self.v_autostart = tk.BooleanVar(value=autostart_enabled())
            m.add_checkbutton(label="Start with Windows", variable=self.v_autostart, command=self._set_autostart)
        m.add_separator()
        m.add_command(label="Reset session totals", command=self._reset_totals)
        m.add_command(label="About", command=self._about)
        m.add_separator()
        m.add_command(label="Exit", command=self.quit)
        self.menu = m

    def _fill_iface_menu(self):
        self.iface_menu.delete(0, "end")
        self.iface_menu.add_radiobutton(label="All adapters", variable=self.v_iface, value="", command=self._set_iface)
        names = TrafficSampler.interfaces()
        if self.cfg.iface and self.cfg.iface not in names:
            names.append(self.cfg.iface)
        if names:
            self.iface_menu.add_separator()
        for n in names:
            self.iface_menu.add_radiobutton(label=n, variable=self.v_iface, value=n, command=self._set_iface)

    def _place_initial(self):
        self.root.update_idletasks()
        w, h = self.root.winfo_reqwidth(), self.root.winfo_reqheight()
        vx, vy, vw, vh = virtual_screen(self.root)
        x, y = self.cfg.x, self.cfg.y
        if x is None or y is None or not (vx <= x <= vx + vw - 40 and vy <= y <= vy + vh - 20):
            x = self.root.winfo_screenwidth() - w - 24
            y = 24
        self.root.geometry(f"+{int(x)}+{int(y)}")

    def _round_corners(self):
        """Windows 11 rounded corners for the borderless window (ignored elsewhere)."""
        if not IS_WINDOWS:
            return
        try:
            self.root.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id()) or self.root.winfo_id()
            pref = ctypes.c_int(2)  # DWMWCP_ROUND
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(pref), ctypes.sizeof(pref))
        except Exception:
            pass

    # ----- dragging (with edge snapping) -----
    def _drag_start(self, e):
        self._drag = (e.x_root - self.root.winfo_x(), e.y_root - self.root.winfo_y())

    def _drag_move(self, e):
        if self._drag is None or self.cfg.locked:
            return
        x, y = e.x_root - self._drag[0], e.y_root - self._drag[1]
        w, h = self.root.winfo_width(), self.root.winfo_height()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        if abs(x) < self.SNAP:
            x = 0
        elif abs(x + w - sw) < self.SNAP:
            x = sw - w
        if abs(y) < self.SNAP:
            y = 0
        elif abs(y + h - sh) < self.SNAP:
            y = sh - h
        self.root.geometry(f"+{x}+{y}")

    def _drag_end(self, _e):
        if self._drag is not None and not self.cfg.locked:
            self.cfg.x, self.cfg.y = self.root.winfo_x(), self.root.winfo_y()
            self.cfg.save()
        self._drag = None

    # ----- menu actions -----
    def _popup(self, e):
        try:
            self.menu.tk_popup(e.x_root, e.y_root)
        finally:
            self.menu.grab_release()

    def _ask_host(self):
        from tkinter import simpledialog

        self.root.attributes("-topmost", False)
        try:
            host = simpledialog.askstring(
                APP_NAME, "Host or IP address to ping:", initialvalue=self.cfg.host, parent=self.root,
            )
        finally:
            self.root.attributes("-topmost", self.cfg.topmost)
        if host and host.strip():
            self.cfg.host = host.strip()
            self.pinger.set_host(self.cfg.host)
            self.cfg.save()
            self._refresh_ping()

    def _set_interval(self):
        self.cfg.interval = float(self.v_interval.get())
        self.pinger.set_interval(max(1.0, self.cfg.interval))
        self.cfg.save()

    def _set_opacity(self):
        self.cfg.opacity = float(self.v_opacity.get())
        self.root.attributes("-alpha", self.cfg.opacity)
        self.cfg.save()

    def _set_units(self):
        self.cfg.bits = bool(self.v_bits.get())
        self.cfg.save()

    def _set_iface(self):
        self.cfg.iface = self.v_iface.get()
        self.peak_down = self.peak_up = 0.0
        self.cfg.save()

    def _set_autostart(self):
        try:
            set_autostart(bool(self.v_autostart.get()))
        except OSError as ex:
            win_message(f"Could not change autostart setting:\n{ex}")
        self.v_autostart.set(autostart_enabled())

    def _toggle(self, name: str):
        setattr(self.cfg, name, not getattr(self.cfg, name))
        self.v_graph.set(self.cfg.show_graph)
        self.v_details.set(self.cfg.show_details)
        self.v_topmost.set(self.cfg.topmost)
        self.v_locked.set(self.cfg.locked)
        if name == "topmost":
            self.root.attributes("-topmost", self.cfg.topmost)
        if name in ("show_graph", "show_details"):
            self._apply_layout()
            self._render_details()
        self.cfg.save()

    def _reset_totals(self):
        self.total_down = self.total_up = 0
        self.peak_down = self.peak_up = 0.0
        self._render_details()

    def _about(self):
        win_message(
            f"{APP_DESCRIPTION}\nVersion {APP_VERSION}\n\nApp ID: {APP_USER_MODEL_ID}\n"
            f"Settings: {Config.path()}\n\nDrag to move • Double-click to expand/collapse • "
            f"Right-click for options",
            f"About {APP_NAME}",
        )

    # ----- update loop -----
    def _tick(self):
        down, up, rd, sd, _ = self.sampler.sample(self.cfg.iface)
        self.total_down += rd
        self.total_up += sd
        self.peak_down = max(self.peak_down, down)
        self.peak_up = max(self.peak_up, up)
        self.hist_down.append(down)
        self.hist_up.append(up)

        bits = self.cfg.bits
        self.down_lbl.config(text=f"↓ {human_rate(down, bits)}")
        self.up_lbl.config(text=f"↑ {human_rate(up, bits)}")
        self._refresh_ping()
        if self.cfg.show_graph:
            self._draw_graph()
        self._render_details()

        self._tick_count += 1
        if self.cfg.topmost and self._tick_count % 5 == 0:
            self.root.attributes("-topmost", True)  # re-assert after fullscreen apps steal it
        self._after_id = self.root.after(int(self.cfg.interval * 1000), self._tick)

    def _refresh_ping(self):
        st = self.pinger.stats()
        rtt = st["rtt"]
        if st["samples"] == 0:
            self.ping_lbl.config(text="pinging…")
            color = self.DIM
        elif rtt < 0:
            self.ping_lbl.config(text=st["error"] or "timeout")
            color = self.BAD
        else:
            self.ping_lbl.config(text="<1 ms" if rtt < 1 else f"{rtt:.0f} ms")
            color = self.GOOD if rtt < 60 else self.WARN if rtt < 150 else self.BAD
        if st["loss"] >= 10 and rtt >= 0:
            color = self.WARN
        self.ping_dot.config(fg=color)
        self.loss_lbl.config(text=f"{st['loss']:.0f}% loss" if st["samples"] else "")

    def _render_details(self):
        if not self.cfg.show_details:
            return
        st = self.pinger.stats()
        iface = self.cfg.iface or "all adapters"
        if len(iface) > 26:
            iface = iface[:25] + "…"
        bits = self.cfg.bits
        self.details.config(
            text=(
                f"{self.cfg.host}  •  jitter {st['jitter']:.1f} ms\n"
                f"Total ↓ {human_size(self.total_down)}   ↑ {human_size(self.total_up)}\n"
                f"Peak  ↓ {human_rate(self.peak_down, bits)}   ↑ {human_rate(self.peak_up, bits)}\n"
                f"{iface}"
            )
        )

    def _draw_graph(self):
        c = self.graph
        c.delete("all")
        w = c.winfo_width() if c.winfo_width() > 1 else self.GRAPH_W
        h = self.GRAPH_H
        top = max(max(self.hist_down), max(self.hist_up), 1024.0)
        n = len(self.hist_down)
        step = w / max(n - 1, 1)

        def pts(hist):
            return [(i * step, h - 2 - (v / top) * (h - 6)) for i, v in enumerate(hist)]

        for gy in (h / 3, 2 * h / 3):
            c.create_line(0, gy, w, gy, fill="#262a33")
        down_pts = pts(self.hist_down)
        poly = [(0, h)] + down_pts + [(w, h)]
        c.create_polygon(*[v for p in poly for v in p], fill=self.DOWN_FILL, outline="")
        c.create_line(*[v for p in down_pts for v in p], fill=self.DOWN, width=1.5)
        c.create_line(*[v for p in pts(self.hist_up) for v in p], fill=self.UP, width=1.5)
        c.create_text(w - 3, 2, text=human_rate(top, self.cfg.bits), anchor="ne", fill=self.DIM,
                      font=("Segoe UI" if IS_WINDOWS else "DejaVu Sans", 7))

    def quit(self):
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except Exception:
                pass
        self.pinger.stop()
        try:
            self.cfg.x, self.cfg.y = self.root.winfo_x(), self.root.winfo_y()
        except Exception:
            pass
        self.cfg.save()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ---------- Console mode (classic output) ----------
def monitor(interval: float, host: str, per_iface: bool, bits: bool = False, iface: str = ""):
    sampler = TrafficSampler()
    ping_thread = PingThread(host=host, interval=max(1.0, interval))
    ping_thread.start()

    print(f"{APP_NAME} {APP_VERSION}: host={host}  interval={interval:.2f}s  per_iface={per_iface}")
    print("Press Ctrl+C to exit.\n")
    total_down = total_up = 0
    try:
        while True:
            time.sleep(interval)
            down_rate, up_rate, rd, sd, per = sampler.sample(iface)
            total_down += rd
            total_up += sd
            st = ping_thread.stats()
            rtt_ms = st["rtt"]
            if st["samples"] == 0:
                rtt_str = "..."
            elif rtt_ms < 0:
                rtt_str = st["error"] or "timeout"
            else:
                rtt_str = f"{rtt_ms:.1f} ms"
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"-> [{ts}] ping={rtt_str} (loss {st['loss']:.0f}%)  "
                f"↓{human_rate(down_rate, bits):>11}  ↑{human_rate(up_rate, bits):>11}  "
                f"total ↓{human_size(total_down)} ↑{human_size(total_up)}"
            )
            if per_iface:
                for nic, (r, s) in sorted(per.items()):
                    print(f"   {nic}: ↓{human_rate(r, bits)} ↑{human_rate(s, bits)}")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        ping_thread.stop()
        ping_thread.join(timeout=2.0)


# ---------- CLI ----------
def parse_args(argv=None):
    p = argparse.ArgumentParser(prog=APP_NAME, description=APP_DESCRIPTION)
    p.add_argument("--host", "-H", help="Host to ping (default: saved setting or 8.8.8.8)")
    p.add_argument("--interval", "-i", type=float, help="Sample interval in seconds (default: 1.0)")
    p.add_argument("--console", "-c", action="store_true", help="Print text output instead of the floating widget")
    p.add_argument("--per-iface", action="store_true", help="Console mode: also show per-interface rates")
    p.add_argument("--bits", action="store_true", help="Show rates in bits per second")
    p.add_argument("--iface", help="Only measure this network adapter")
    p.add_argument("--reset", action="store_true", help="Reset saved settings and widget position")
    p.add_argument("--version", "-V", action="version", version=f"{APP_NAME} {APP_VERSION} ({APP_USER_MODEL_ID})")
    return p.parse_args(argv)


def main(argv=None):
    if IS_WINDOWS and FROZEN and argv is None and any(a in sys.argv[1:] for a in ("-c", "--console", "-h", "--help", "-V", "--version")):
        win_attach_console()
    args = parse_args(argv)
    win_set_app_id()

    if args.reset:
        try:
            Config.path().unlink()
        except OSError:
            pass
    cfg = Config.load()
    if args.host:
        cfg.host = args.host
    if args.interval:
        cfg.interval = min(max(args.interval, 0.25), 60.0)
    if args.bits:
        cfg.bits = True
    if args.iface is not None:
        cfg.iface = args.iface

    if args.console:
        monitor(interval=cfg.interval, host=cfg.host, per_iface=args.per_iface, bits=cfg.bits, iface=cfg.iface)
        return 0

    if not win_single_instance():
        win_message(f"{APP_NAME} is already running.\nRight-click the floating widget for options.")
        return 0
    win_set_dpi_aware()
    FloatWidget(cfg).run()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # make failures visible in the windowed build
        import traceback

        win_message(f"{APP_NAME} crashed:\n{e}\n\n{traceback.format_exc()[-1500:]}")
        raise
