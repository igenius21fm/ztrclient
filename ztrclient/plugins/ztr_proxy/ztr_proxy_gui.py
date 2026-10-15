#!/usr/bin/env python3
"""ZTR Proxy — a window for the ZTRelay proxy (ztr_proxy.py).

Start the proxy, point your browser at it, and watch what happens: every connection
as it opens (HTTPS, SOCKS5 and plain HTTP), how long its tunnel took, how many
bytes moved, which hosts you use most, and what the route's hops cost you in
time. Hosts you visit often can be kept ready ("Keep ready") so the first
connection to them is instant.

    python3 plugins/ztr_proxy/ztr_proxy_gui.py

The Browser page can open Firefox, Chromium, Chrome, Brave, Edge or Vivaldi
through the proxy in a profile of its own (your normal profile is not touched),
or add the proxy settings to a Firefox profile you pick — and take them out
again.

Needs only Python's standard library (tkinter included) plus what ztr_proxy.py
needs. Runs on Linux and macOS (on a Mac it needs a Python with Tk 8.6).
"""
import base64
import json
import math
import os
import queue
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import zlib
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

import ztr_proxy  # noqa: E402
import ztr_proxy_guard  # noqa: E402

APP_NAME = "ZTR Proxy"
TAGLINE = "Browser traffic through your ZTRelay route"
CONFIG_DIR = Path(os.environ.get("ZTR_PROXY_HOME") or Path.home() / ".config" / "ztr_proxy")
SETTINGS_PATH = CONFIG_DIR / "settings.json"
FIREFOX_PROFILE_DIR = CONFIG_DIR / "firefox-profile"
ROUTES_DIR = Path(SCRIPT_DIR).resolve().parent.parent / "routes"
HOP_PORT = 3478

DEFAULT_SETTINGS = {
    "route": "", "port": ztr_proxy.DEFAULT_PORT, "host": "", "warm": True, "min_uses": ztr_proxy.WARM_MIN_USES,
    "max_age": ztr_proxy.WARM_MAX_AGE, "timing": False, "autostart": False, "pinned": [], "quiet": True, "webrtc": True,
}

BG, CARD, FIELD, BORDER = "#1c1c1e", "#262629", "#1a1a1c", "#3a3a3d"
TEXT, DIM = "#f2f2f7", "#8e8e93"
CYAN, PURPLE, GREEN, RED, AMBER = "#0a84ff", "#bf5af2", "#30d158", "#ff453a", "#ffb340"
SEL, ZEBRA = "#0a64d6", "#1f1f21"
TEAL = "#64d2ff"


# ── settings ─────────────────────────────────────────────────────────────────

def load_settings():
    data = dict(DEFAULT_SETTINGS)
    try:
        saved = json.loads(SETTINGS_PATH.read_text())
        if isinstance(saved, dict):
            data.update({k: v for k, v in saved.items() if k in DEFAULT_SETTINGS})
    except (OSError, ValueError):
        pass
    return data


def save_settings(data):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        tmp = SETTINGS_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps({k: data.get(k) for k in DEFAULT_SETTINGS}, indent=2))
        os.replace(tmp, SETTINGS_PATH)
    except OSError:
        pass


def list_routes():
    try:
        return sorted(p.name for p in ROUTES_DIR.glob("*.ztr"))
    except OSError:
        return []


def route_chain(name):
    """The hops of a route as [(role, address)], from its .ztr file — nothing else in the file is read."""
    try:
        data = json.loads((ROUTES_DIR / name).read_text())
        return [(str(h.get("role", "")), str(h.get("address", ""))) for h in data.get("chain", [])]
    except (OSError, ValueError, AttributeError):
        return []


def tcp_rtt(address, port=HOP_PORT, tries=3, timeout=3.0):
    """Milliseconds to open a TCP connection to a hop's control port (best of a few), or None. Only IP addresses —
    a hop given by name can't be reached without asking the registry, and this window never does."""
    if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", address or ""):
        return None
    best = None
    for _ in range(tries):
        t0 = time.perf_counter()
        try:
            socket.create_connection((address, port), timeout=timeout).close()
        except OSError:
            continue
        ms = (time.perf_counter() - t0) * 1000
        best = ms if best is None else min(best, ms)
    return best


# ── formatting ───────────────────────────────────────────────────────────────

def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def human_rate(n):
    return human_bytes(n) + "/s"


def fmt_seconds(s):
    if s is None:
        return "—"
    return f"{s * 1000:.0f} ms" if s < 1 else f"{s:.1f} s"


def fmt_elapsed(seconds):
    seconds = max(0.0, float(seconds))
    if seconds < 10:
        return f"{seconds:.1f} s"
    s = int(round(seconds))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {s % 3600 // 60:02d} min"


def fmt_clock(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


def fit_text(measure, text, max_px, keep_tail=12):
    """`text`, shortened in the middle (end kept) until measure(text) fits in max_px pixels."""
    if max_px <= 0 or measure(text) <= max_px:
        return text
    lo, hi = 1, len(text)
    best = text[:1] + "…"
    while lo <= hi:
        mid = (lo + hi) // 2
        tail = min(keep_tail, mid // 2)
        cand = text[:mid - tail] + "…" + (text[-tail:] if tail else "")
        if measure(cand) <= max_px:
            best, lo = cand, mid + 1
        else:
            hi = mid - 1
    return best


def percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * q))]


# The modifier a shortcut uses: Command on a Mac, Control elsewhere.
MOD = "Command" if sys.platform == "darwin" else "Control"


def bind_context_menu(widget, handler):
    """Right-click opens the menu — on a Mac that is also a two-finger click (Button-2) or Control-click."""
    widget.bind("<Button-3>", handler)
    if sys.platform == "darwin":
        widget.bind("<Button-2>", handler)
        widget.bind("<Control-Button-1>", handler)


# ── Firefox ──────────────────────────────────────────────────────────────────

FIREFOX_ROOTS = [Path.home() / ".config" / "mozilla" / "firefox", Path.home() / ".mozilla" / "firefox",
                 Path.home() / "Library" / "Application Support" / "Firefox",
                 Path.home() / "snap" / "firefox" / "common" / ".mozilla" / "firefox",
                 Path.home() / ".var" / "app" / "org.mozilla.firefox" / ".mozilla" / "firefox"]
BLOCK_BEGIN = "// >>> ZTR Proxy (managed by the ZTR Proxy window; remove it there) >>>"
BLOCK_END = "// <<< ZTR Proxy <<<"

# Firefox's own background services (updates, telemetry, add-on and settings sync, prefetching) each open tunnels of
# their own; through a route that is real time taken from the pages you asked for.
QUIET_PREFS = [
    ("network.http.speculative-parallel-limit", 0), ("network.predictor.enabled", False),
    ("network.prefetch-next", False), ("network.dns.disablePrefetch", True), ("app.normandy.enabled", False),
    ("toolkit.telemetry.enabled", False), ("toolkit.telemetry.unified", False), ("browser.region.update.enabled", False),
    ("extensions.systemAddon.update.enabled", False), ("extensions.getAddons.cache.enabled", False),
    ("browser.search.suggest.enabled", False), ("browser.send_pings", False), ("extensions.blocklist.enabled", False),
    ("datareporting.policy.dataSubmissionEnabled", False), ("app.update.auto", False),
]
WEBRTC_PREFS = [("media.peerconnection.enabled", False)]  # WebRTC can reveal the address the proxy is there to hide


def firefox_profiles():
    """[(name, path, is_default)] for every Firefox profile found on this computer."""
    found, seen = [], set()
    for root in FIREFOX_ROOTS:
        ini = root / "profiles.ini"
        try:
            text = ini.read_text()
        except OSError:
            continue
        sections, cur = [], None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                cur = {"_section": line[1:-1]}
                sections.append(cur)
            elif "=" in line and cur is not None:
                k, v = line.split("=", 1)
                cur[k.strip()] = v.strip()
        defaults = {s.get("Default") for s in sections if s["_section"].startswith("Install")}
        for sec in sections:
            if not sec["_section"].startswith("Profile") or "Path" not in sec:
                continue
            path = root / sec["Path"] if sec.get("IsRelative", "1") == "1" else Path(sec["Path"])
            if path in seen or not path.is_dir():
                continue
            seen.add(path)
            found.append((sec.get("Name", path.name), path, sec["Path"] in defaults or sec.get("Default") == "1"))
    return found


def _js(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return json.dumps(str(value))


def proxy_prefs(host, port, quiet=True, webrtc=True):
    prefs = [("network.proxy.type", 1), ("network.proxy.http", host), ("network.proxy.http_port", int(port)),
             ("network.proxy.ssl", host), ("network.proxy.ssl_port", int(port)), ("network.proxy.no_proxies_on", ""),
             ("network.proxy.share_proxy_settings", True), ("browser.shell.checkDefaultBrowser", False)]
    if quiet:
        prefs += QUIET_PREFS
    if webrtc:
        prefs += WEBRTC_PREFS
    return prefs


def render_block(prefs):
    return BLOCK_BEGIN + "\n" + "\n".join(f'user_pref("{k}", {_js(v)});' for k, v in prefs) + "\n" + BLOCK_END + "\n"


def strip_block(text):
    pattern = re.compile(re.escape(BLOCK_BEGIN) + r".*?" + re.escape(BLOCK_END) + r"\n?", re.S)
    return pattern.sub("", text)


def apply_user_js(profile_dir, prefs):
    """Writes the proxy settings into the profile's user.js (between markers, replacing an earlier block of ours).
    The first time, the original is kept beside it as user.js.ztr-backup."""
    path = Path(profile_dir) / "user.js"
    try:
        existing = path.read_text()
    except OSError:
        existing = ""
    backup = path.with_name("user.js.ztr-backup")
    if existing and BLOCK_BEGIN not in existing and not backup.exists():
        shutil.copy2(path, backup)
    rest = strip_block(existing).rstrip()
    path.write_text((rest + "\n\n" if rest else "") + render_block(prefs))
    return path


def remove_user_js_block(profile_dir):
    path = Path(profile_dir) / "user.js"
    try:
        existing = path.read_text()
    except OSError:
        return False
    if BLOCK_BEGIN not in existing:
        return False
    rest = strip_block(existing).rstrip()
    if rest:
        path.write_text(rest + "\n")
    else:
        path.unlink()
    return True


def profile_has_block(profile_dir):
    try:
        return BLOCK_BEGIN in (Path(profile_dir) / "user.js").read_text()
    except OSError:
        return False


def profile_in_use(profile_dir):
    p = Path(profile_dir)
    return (p / "lock").is_symlink() or (p / "lock").exists() or (p / ".parentlock").exists() and (p / "lock").exists()


# Browsers the window can open through the proxy. Firefox is set up with a user.js in a profile of its own; the Chrome
# family takes everything on the command line. "snap" and "flatpak" are the sandboxed packages, which can only read
# certain folders, so their profile has to live inside the app's own data area.
BROWSER_CATALOG = [
    # key, name, kind, commands on PATH, snap name, flatpak id
    ("firefox", "Firefox", "firefox", ("firefox", "firefox-esr"), "firefox", "org.mozilla.firefox"),
    ("chromium", "Chromium", "chromium", ("chromium", "chromium-browser"), "chromium", "org.chromium.Chromium"),
    ("chrome", "Google Chrome", "chromium", ("google-chrome-stable", "google-chrome"), None, "com.google.Chrome"),
    ("brave", "Brave", "chromium", ("brave-browser", "brave-browser-stable", "brave"), "brave", "com.brave.Browser"),
    ("edge", "Microsoft Edge", "chromium", ("microsoft-edge-stable", "microsoft-edge"), None, "com.microsoft.Edge"),
    ("vivaldi", "Vivaldi", "chromium", ("vivaldi-stable", "vivaldi"), None, "com.vivaldi.Vivaldi"),
]

# Chrome-family counterparts of QUIET_PREFS and WEBRTC_PREFS.
CHROMIUM_QUIET_FLAGS = ["--disable-background-networking", "--disable-component-update", "--disable-sync",
                        "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--disable-default-apps",
                        "--no-pings", "--metrics-recording-only",
                        "--disable-features=NetworkTimeServiceQuerying,OptimizationHints,Translate,MediaRouter,"
                        "AutofillServerCommunication,CertificateTransparencyComponentUpdater"]
CHROMIUM_WEBRTC_FLAG = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"


# Where a Mac keeps each browser: the app's folder name and the program inside it.
MAC_APPS = {
    "firefox": ("Firefox.app", "firefox"), "chromium": ("Chromium.app", "Chromium"),
    "chrome": ("Google Chrome.app", "Google Chrome"), "brave": ("Brave Browser.app", "Brave Browser"),
    "edge": ("Microsoft Edge.app", "Microsoft Edge"), "vivaldi": ("Vivaldi.app", "Vivaldi"),
}


def _mac_app_program(key):
    """The program inside this browser's app, from /Applications or ~/Applications; None if it isn't installed."""
    app, program = MAC_APPS.get(key, (None, None))
    if not app:
        return None
    for root in (Path("/Applications"), Path.home() / "Applications"):
        path = root / app / "Contents" / "MacOS" / program
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def _is_snap_launcher(path):
    """True for the snap binary and for the small stub scripts distributions leave at /usr/bin that just start the snap."""
    real = os.path.realpath(path)
    if "/snap/" in path or "/snap/" in real or os.path.basename(real) == "snap":
        return True
    try:
        if os.path.getsize(real) < 4096:
            with open(real, "rb") as fh:
                return b"/snap/" in fh.read()
    except OSError:
        pass
    return False


def _flatpak_apps():
    exe = shutil.which("flatpak")
    if not exe:
        return set()
    try:
        out = subprocess.run([exe, "list", "--app", "--columns=application"], capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.SubprocessError):
        return set()
    return {line.strip() for line in out.splitlines() if line.strip()}


def detect_browsers():
    """The browsers on this computer that can be opened through the proxy, each as a dict:
    key, name (with "(Snap)"/"(Flatpak)" when sandboxed), kind, argv (the command to start it), profile (its separate
    profile folder, created on first use) and package (None, "snap" or "flatpak")."""
    found, flatpaks = [], None
    for key, name, kind, commands, snap_name, flatpak_id in BROWSER_CATALOG:
        entry = None
        if sys.platform == "darwin":
            program = _mac_app_program(key)
            if program:
                entry = {"argv": [program], "package": None}
        for cmd in commands if entry is None else ():
            path = shutil.which(cmd)
            if path:
                package = "snap" if _is_snap_launcher(path) else None
                entry = {"argv": [path], "package": package}
                break
        if entry is None and sys.platform != "darwin":
            if flatpaks is None:
                flatpaks = _flatpak_apps()
            if flatpak_id in flatpaks:
                entry = {"argv": [shutil.which("flatpak"), "run", flatpak_id], "package": "flatpak"}
        if entry is None:
            continue
        package = entry["package"]
        if package == "snap":
            profile = Path.home() / "snap" / (snap_name or key) / "common" / "ztr-proxy-profile"
        elif package == "flatpak":
            profile = Path.home() / ".var" / "app" / flatpak_id / "data" / "ztr-proxy-profile"
        elif key == "firefox":
            profile = FIREFOX_PROFILE_DIR
        else:
            profile = CONFIG_DIR / "browser-profiles" / key
        label = name + {"snap": " (Snap)", "flatpak": " (Flatpak)"}.get(package, "")
        found.append({"key": key, "name": name, "label": label, "kind": kind, "argv": entry["argv"], "profile": profile,
                      "package": package})
    return found


def browser_command(browser, host, port, quiet=True, webrtc=True):
    """The full command line that starts `browser` with the proxy already set, in its separate profile."""
    if browser["kind"] == "firefox":
        return browser["argv"] + ["--no-remote", "--profile", str(browser["profile"]), "about:blank"]
    flags = [f"--user-data-dir={browser['profile']}", f"--proxy-server=http://{host}:{int(port)}",
             "--no-first-run", "--no-default-browser-check"]
    if quiet:
        flags += CHROMIUM_QUIET_FLAGS
    if webrtc:
        flags.append(CHROMIUM_WEBRTC_FLAG)
    return browser["argv"] + flags + ["about:blank"]


def launch_browser(browser, host, port, quiet, webrtc):
    """Opens `browser` in a profile of its own (created on first use) with the proxy already set. Returns an error text or None."""
    if not browser:
        return "No supported browser was found on this computer."
    try:
        browser["profile"].mkdir(parents=True, exist_ok=True)
        if browser["kind"] == "firefox":
            apply_user_js(browser["profile"], proxy_prefs(host, port, quiet, webrtc)
                          + [("browser.startup.page", 0), ("browser.startup.homepage", "about:blank")])
        subprocess.Popen(browser_command(browser, host, port, quiet, webrtc), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        return f"Couldn't start {browser['name']}: {e}"
    return None


def check_connection(host, port, target="example.com", timeout=75):
    """One real HTTPS request through the running proxy. Returns {'ok', 'detail', 'tunnel', 'total'}."""
    t0 = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(f"CONNECT {target}:443 HTTP/1.1\r\nHost: {target}:443\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        tunnel = time.perf_counter() - t0
        line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 200 " not in line + " ":
            return {"ok": False, "detail": line or "the proxy closed the connection", "tunnel": tunnel, "total": tunnel}
        tls = ssl.create_default_context().wrap_socket(sock, server_hostname=target)
        tls.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\nUser-Agent: ztr-proxy-check\r\n\r\n".encode())
        first = tls.recv(200).split(b"\r\n", 1)[0].decode("latin-1", "replace")
        tls.close()
        total = time.perf_counter() - t0
        return {"ok": first.startswith("HTTP/") and " 2" in first[8:12], "detail": first, "tunnel": tunnel, "total": total}
    except (OSError, ssl.SSLError) as e:
        return {"ok": False, "detail": str(e) or type(e).__name__, "tunnel": None, "total": time.perf_counter() - t0}


# ── the logo, drawn here so the app stays a single file ──────────────────────

def _png(width, height, rgba):
    raw = b"".join(b"\x00" + bytes(rgba[y * width * 4:(y + 1) * width * 4]) for y in range(height))

    def chunk(kind, data):
        body = kind + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xffffffff)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def logo_png(size, supersample=3):
    """A rounded square (blue to violet) with a ring and an arrow passing through it: traffic going through a gate."""
    n = size * supersample
    top, bottom = (10, 132, 255), (94, 92, 230)
    out = bytearray(size * size * 4)
    radius = 0.23

    def rounded_cov(x, y):  # signed distance to a rounded square covering 0..1
        qx, qy = abs(x - .5) - (.5 - radius), abs(y - .5) - (.5 - radius)
        outside = (max(qx, 0) ** 2 + max(qy, 0) ** 2) ** .5 + min(max(qx, qy), 0) - radius
        return outside <= 0

    def glyph(x, y):
        d = ((x - .5) ** 2 + (y - .5) ** 2) ** .5
        ring = abs(d - .27) <= .042
        shaft = .16 <= x <= .80 and abs(y - .5) <= .036
        head = x >= .74 and abs(y - .5) <= (.93 - x) * 0.95 and x <= .93
        return ring or shaft or head

    for py in range(size):
        for px in range(size):
            cover = white = 0
            for sy in range(supersample):
                for sx in range(supersample):
                    x, y = (px * supersample + sx + .5) / n, (py * supersample + sy + .5) / n
                    if rounded_cov(x, y):
                        cover += 1
                        if glyph(x, y):
                            white += 1
            if not cover:
                continue
            t = py / max(1, size - 1)
            base = [top[i] * (1 - t) + bottom[i] * t for i in range(3)]
            mix = white / cover
            rgb = [base[i] * (1 - mix) + 255 * mix for i in range(3)]
            o = (py * size + px) * 4
            out[o:o + 4] = bytes([int(rgb[0]), int(rgb[1]), int(rgb[2]), int(255 * cover / (supersample * supersample))])
    return _png(size, size, out)


def build_app():
    """Imported lazily so the helpers above work (and are testable) on a machine whose Python has no tkinter."""
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import ttk


    UI = {}  # fonts, filled in by Shell._style
    _corner_cache = {}

    def _rgb(color):
        color = color.lstrip("#")
        return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))

    def _mix(a, b, t):
        return "#%02x%02x%02x" % tuple(int(round(a[i] * (1 - t) + b[i] * t)) for i in range(3))

    def _bg_of(widget):
        """The colour behind a widget, so rounded corners blend into it."""
        try:
            return widget.cget("bg")
        except (tk.TclError, AttributeError):
            pass
        try:
            style = str(widget.cget("style")) or widget.winfo_class()
            return ttk.Style(widget).lookup(style, "background") or BG
        except (tk.TclError, AttributeError):
            return BG

    def _corner(r, fill, border, outside, which, bw):
        key = (r, fill, border, outside, which, bw)
        img = _corner_cache.get(key)
        if img is not None:
            return img
        f, b, o = _rgb(fill), _rgb(border), _rgb(outside)
        samples, rows = 4, []
        for y in range(r):
            row = []
            for x in range(r):
                outer = inner = 0
                for sy in range(samples):
                    for sx in range(samples):
                        px, py = x + (sx + .5) / samples, y + (sy + .5) / samples
                        u = r - px if which in ("tl", "bl") else px
                        v = r - py if which in ("tl", "tr") else py
                        d = (u * u + v * v) ** .5
                        outer += d <= r
                        inner += d <= r - bw
                total = samples * samples
                co, ci = outer / total, inner / total
                colour = tuple(o[i] * (1 - co) + b[i] * (co - ci) + f[i] * ci for i in range(3))
                row.append("#%02x%02x%02x" % tuple(int(round(c)) for c in colour))
            rows.append("{" + " ".join(row) + "}")
        img = tk.PhotoImage(width=r, height=r)
        img.put(" ".join(rows))
        _corner_cache[key] = img
        return img

    def paint_round(cv, x, y, w, h, r, fill, border, outside, tag, bw=1):
        """Draws a filled rounded rectangle (with a 1px border if border differs from fill) on canvas cv."""
        cv.delete(tag)
        if w <= 0 or h <= 0:
            return
        r = int(max(0, min(r, w // 2, h // 2)))
        if not border or border == fill:
            border, bw = fill, 0
        if r < 2:
            cv.create_rectangle(x, y, x + w, y + h, fill=border if bw else fill, outline="", tags=tag)
            if bw:
                cv.create_rectangle(x + bw, y + bw, x + w - bw, y + h - bw, fill=fill, outline="", tags=tag)
            return
        refs = cv.__dict__.setdefault("_corner_refs", {})
        for which, cx, cy in (("tl", x, y), ("tr", x + w - r, y), ("bl", x, y + h - r), ("br", x + w - r, y + h - r)):
            img = _corner(r, fill, border, outside, which, max(1, bw) if bw else 0)
            refs[(which, r, fill, border, outside)] = img
            cv.create_image(cx, cy, anchor="nw", image=img, tags=tag)
        cv.create_rectangle(x + r, y, x + w - r, y + h, fill=fill, outline="", tags=tag)
        cv.create_rectangle(x, y + r, x + w, y + h - r, fill=fill, outline="", tags=tag)
        if bw:
            cv.create_rectangle(x + r, y, x + w - r, y + bw, fill=border, outline="", tags=tag)
            cv.create_rectangle(x + r, y + h - bw, x + w - r, y + h, fill=border, outline="", tags=tag)
            cv.create_rectangle(x, y + r, x + bw, y + h - r, fill=border, outline="", tags=tag)
            cv.create_rectangle(x + w - bw, y + r, x + w, y + h - r, fill=border, outline="", tags=tag)

    class Card(tk.Frame):
        """A rounded panel. Put children in `.body`."""

        def __init__(self, parent, fill=None, border=None, radius=12, pad=(16, 12), bg=None, style="Card.TFrame"):
            super().__init__(parent, bg=bg or _bg_of(parent), bd=0, highlightthickness=0)
            self._fill = fill or CARD
            self._border = BORDER if border is None else border
            self._radius = radius
            self._bg_fixed = bg
            self.cv = tk.Canvas(self, bd=0, highlightthickness=0, bg=self._fill)
            self.cv.place(x=0, y=0, relwidth=1, relheight=1)
            self.body = ttk.Frame(self, style=style)
            self.body.grid(row=0, column=0, sticky="nsew", padx=pad[0], pady=pad[1])
            self.columnconfigure(0, weight=1)
            self.rowconfigure(0, weight=1)
            self.body.columnconfigure(0, weight=1)
            self.cv.bind("<Configure>", lambda e: self.redraw())
            self.cv.bind("<Map>", lambda e: self.after_idle(self.redraw))

        def redraw(self):
            w, h = self.cv.winfo_width(), self.cv.winfo_height()
            outside = self._bg_fixed or _bg_of(self.master)
            self.configure(bg=outside)
            self.cv.configure(bg=outside)
            paint_round(self.cv, 0, 0, w, h, self._radius, self._fill, self._border, outside, "card")

    # button looks: (fill, text, hover fill, pressed fill, disabled fill, disabled text)
    _BTN = {
        "default": ("#3a3a3d", TEXT, "#454548", "#505054", "#2c2c2f", "#6a6a70"),
        "primary": (CYAN, "#ffffff", "#2f95ff", "#0a74e6", "#1f4d80", "#8fb5e2"),
        "go": ("#12335c", "#69b6ff", "#17427a", "#0d2a4d", "#222c38", "#586a7c"),
        "danger": ("#43262a", "#ff6961", "#53302f", "#35201f", "#2e2627", "#70585a"),
        "ghost": (None, DIM, "#3a3a3d", "#454548", None, "#5a5a60"),
    }

    class Btn(tk.Canvas):
        """A rounded button. Same calls as ttk.Button: text, command, state, style, invoke()."""

        def __init__(self, parent, text="", command=None, style="", state="normal", kind=None, selected=False, **kw):
            kw.pop("width", None)
            super().__init__(parent, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._text, self._command, self._state, self._style = text, command, state, style
            self._kind = kind
            self._selected, self._hover, self._down = selected, False, False
            self._fit()
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<Enter>", lambda e: self._set(hover=True))
            self.bind("<Leave>", lambda e: self._set(hover=False, down=False))
            self.bind("<ButtonPress-1>", lambda e: self._set(down=True))
            self.bind("<ButtonRelease-1>", self._release)
            self.bind("<space>", lambda e: self.invoke())
            self.bind("<Return>", lambda e: self.invoke())

        # -- look
        def _kind_name(self):
            if self._kind:
                return self._kind
            for word, kind in (("Primary", "primary"), ("Go", "go"), ("Danger", "danger"), ("Ghost", "ghost")):
                if word in str(self._style):
                    return kind
            return "default"

        def _small(self):
            return "Small" in str(self._style) or self._kind == "tab"

        def _fit(self):
            bold = self._kind_name() == "primary" or (self._kind == "tab" and self._selected)
            font = UI.get("bold" if bold and not self._small() else ("small" if self._small() else "body"))
            if bold and self._small():
                font = UI.get("bold")
            pad = 12 if self._small() else 16
            h = 26 if self._small() else (32 if self._kind_name() == "primary" else 28)
            w = (font.measure(self._text) if font else 8 * len(self._text)) + 2 * pad
            tk.Canvas.configure(self, width=w, height=h)

        def _colors(self):
            kind = self._kind_name()
            if self._kind == "tab":
                kind = "go" if self._selected else "ghost"
            fill, fg, hover, pressed, off_fill, off_fg = _BTN[kind]
            outside = _bg_of(self.master)
            if self._state == "disabled":
                return (off_fill or outside), off_fg, outside
            col = pressed if self._down else (hover if self._hover else fill)
            return (col or outside), fg, outside

        def _draw(self):
            w, h = self.winfo_width(), self.winfo_height()
            fill, fg, outside = self._colors()
            tk.Canvas.configure(self, bg=outside)
            paint_round(self, 0, 0, w, h, 8, fill, fill, outside, "bg", 0)
            self.delete("label")
            font = UI.get("small" if self._small() else "body")
            bold = UI.get("bold") if (self._kind_name() == "primary" or (self._kind == "tab" and self._selected)) else font
            self.create_text(w // 2, h // 2, text=self._text, fill=fg, font=bold or font, tags="label")

        def _set(self, hover=None, down=None):
            if self._state == "disabled":
                return
            if hover is not None:
                self._hover = hover
            if down is not None:
                self._down = down
            self._draw()

        def _release(self, event):
            was_down, self._down = self._down, False
            self._draw()
            if was_down and self._state != "disabled" and 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height():
                self.invoke()

        # -- the ttk.Button calls the app uses
        def invoke(self):
            if self._state != "disabled" and self._command:
                return self._command()

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            changed = False
            for key in ("text", "state", "style", "command", "selected"):
                if key in opts:
                    attr = "_" + key
                    setattr(self, attr, opts.pop(key))
                    changed = True
            if "state" in kw or (cnf and "state" in cnf):
                tk.Canvas.configure(self, cursor="hand2" if self._state != "disabled" else "arrow")
            if opts:
                tk.Canvas.configure(self, **opts)
            if changed:
                self._fit()
                self._draw()

        config = configure

        def cget(self, key):
            return {"text": self._text, "state": self._state, "style": self._style, "command": self._command}.get(key) \
                if key in ("text", "state", "style", "command") else tk.Canvas.cget(self, key)

    class Check(tk.Canvas):
        """A rounded check box with its label (like ttk.Checkbutton)."""

        def __init__(self, parent, text="", variable=None, command=None, state="normal", **kw):
            super().__init__(parent, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._text, self._var, self._command, self._state = text, variable, command, state
            font = UI.get("body")
            tk.Canvas.configure(self, width=24 + (font.measure(text) if font else 8 * len(text)) + 4, height=24)
            if variable is not None:
                variable.trace_add("write", lambda *a: self._draw())
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<ButtonRelease-1>", lambda e: self.invoke())
            self.bind("<space>", lambda e: self.invoke())

        def _on(self):
            return bool(self._var.get()) if self._var is not None else False

        def _draw(self):
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            on, off = self._on(), self._state == "disabled"
            fill = (CYAN if on else FIELD) if not off else "#2f2f31"
            border = CYAN if on else "#6a6a70"
            self.delete("all")
            paint_round(self, 1, 4, 16, 16, 5, fill, border, outside, "box")
            if on:
                self.create_line(5, 12, 8, 15, 13, 8, fill="#ffffff", width=2, capstyle="round", joinstyle="round", tags="box")
            self.create_text(24, 12, text=self._text, anchor="w", fill=TEXT if not off else DIM, font=UI.get("body"), tags="label")

        def invoke(self):
            if self._state == "disabled" or self._var is None:
                return
            self._var.set(not self._var.get())
            if self._command:
                self._command()

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            for key in ("state", "text", "command", "variable"):
                if key in opts:
                    setattr(self, "_" + {"variable": "var"}.get(key, key), opts.pop(key))
            if opts:
                tk.Canvas.configure(self, **opts)
            self._draw()

        config = configure

        def cget(self, key):
            return self._state if key == "state" else tk.Canvas.cget(self, key)

    class Radio(tk.Canvas):
        """A round radio button with its label (like ttk.Radiobutton)."""

        def __init__(self, parent, text="", value=None, variable=None, command=None, state="normal", **kw):
            super().__init__(parent, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._text, self._value, self._var, self._command, self._state = text, value, variable, command, state
            font = UI.get("body")
            tk.Canvas.configure(self, width=24 + (font.measure(text) if font else 8 * len(text)) + 4, height=24)
            variable.trace_add("write", lambda *a: self._draw())
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<ButtonRelease-1>", lambda e: self.invoke())
            self.bind("<space>", lambda e: self.invoke())

        def _draw(self):
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            on, off = self._var.get() == self._value, self._state == "disabled"
            self.delete("all")
            paint_round(self, 1, 4, 16, 16, 8, CYAN if on else FIELD, CYAN if on else "#6a6a70", outside, "box")
            if on:
                paint_round(self, 6, 9, 6, 6, 3, "#ffffff", "#ffffff", CYAN, "dot", 0)
            self.create_text(24, 12, text=self._text, anchor="w", fill=TEXT if not off else DIM, font=UI.get("body"))

        def invoke(self):
            if self._state == "disabled":
                return
            self._var.set(self._value)
            if self._command:
                self._command()

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            for key in ("state", "text", "command"):
                if key in opts:
                    setattr(self, "_" + key, opts.pop(key))
            if opts:
                tk.Canvas.configure(self, **opts)
            self._draw()

        config = configure

        def cget(self, key):
            return self._state if key == "state" else tk.Canvas.cget(self, key)

    class Progress(tk.Canvas):
        """A slim rounded progress bar (like ttk.Progressbar: mode, value, start(), stop())."""

        def __init__(self, parent, mode="determinate", maximum=100, **kw):
            kw.pop("style", None)
            super().__init__(parent, bd=0, highlightthickness=0, height=8)
            self._mode, self._max, self._value, self._phase, self._job = mode, maximum, 0.0, 0.0, None
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))

        def _draw(self):
            w, h = self.winfo_width(), self.winfo_height()
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            paint_round(self, 0, 0, w, h, h // 2, "#1d1d1f", "#1d1d1f", outside, "track", 0)
            if self._mode == "indeterminate":
                seg = max(h, int(w * .28))
                x = int((w + seg) * self._phase) - seg
                x0, x1 = max(0, x), min(w, x + seg)
                if x1 - x0 >= 2:
                    paint_round(self, x0, 0, x1 - x0, h, h // 2, CYAN, CYAN, "#1d1d1f", "fill", 0)
                else:
                    self.delete("fill")
            else:
                fw = int(w * max(0.0, min(1.0, self._value / float(self._max or 1))))
                if fw >= 2:
                    paint_round(self, 0, 0, max(fw, h), h, h // 2, CYAN, CYAN, "#1d1d1f", "fill", 0)
                else:
                    self.delete("fill")

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            for key, attr in (("mode", "_mode"), ("value", "_value"), ("maximum", "_max")):
                if key in opts:
                    setattr(self, attr, opts.pop(key))
            opts.pop("style", None)
            if opts:
                tk.Canvas.configure(self, **opts)
            self._draw()

        config = configure

        def cget(self, key):
            return {"mode": self._mode, "value": float(self._value), "maximum": self._max}.get(key) \
                if key in ("mode", "value", "maximum") else tk.Canvas.cget(self, key)

        def start(self, interval=30):
            self.stop()

            def step():
                self._phase = (self._phase + 0.02) % 1.0
                self._draw()
                self._job = self.after(max(15, int(interval)), step)
            self._job = self.after(0, step)

        def stop(self):
            if self._job is not None:
                self.after_cancel(self._job)
                self._job = None

    class Field(tk.Frame):
        """A rounded text field or drop-down. Behaves like the ttk widget inside it (get, insert, bind, state ...)."""

        is_combo = False

        def __init__(self, parent, combo=False, compact=False, placeholder=None, **kw):
            super().__init__(parent, bg=_bg_of(parent), bd=0, highlightthickness=0)
            self.is_combo = combo
            self._focus = False
            self.cv = tk.Canvas(self, bd=0, highlightthickness=0, bg=FIELD)
            self.cv.place(x=0, y=0, relwidth=1, relheight=1)
            kw.setdefault("style", "Flat.TCombobox" if combo else "Flat.TEntry")
            self.inner = (ttk.Combobox if combo else ttk.Entry)(self, **kw)
            self.inner.grid(row=0, column=0, sticky="ew", padx=(10, 4 if combo else 10), pady=3 if compact else 5)
            self.columnconfigure(0, weight=1)
            self.cv.bind("<Configure>", lambda e: self._draw())
            self.cv.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.inner.bind("<FocusIn>", lambda e: self._focused(True), add="+")
            self.inner.bind("<FocusOut>", lambda e: self._focused(False), add="+")
            self._hint = None
            self._var = kw.get("textvariable")
            if placeholder:  # dim hint text shown while the field is empty and unfocused
                self._hint = tk.Label(self, text=placeholder, bg=FIELD, fg=DIM, font=UI.get("body"), bd=0, padx=0, pady=0)
                self._hint.bind("<Button-1>", lambda e: self.inner.focus_set())
                var = kw.get("textvariable")
                if var is not None:
                    var.trace_add("write", lambda *a: self._show_hint())
                self.inner.bind("<KeyRelease>", lambda e: self._show_hint(), add="+")
                self._show_hint()

        def _show_hint(self):
            if self._hint is None:
                return
            # A variable's write callback runs before the entry itself has the new text, so read the variable when there is one.
            text = self._var.get() if self._var is not None else self.inner.get()
            if text or self._focus:
                self._hint.place_forget()
            else:
                self._hint.place(x=11, rely=0.5, anchor="w")

        def _focused(self, on):
            self._focus = on
            self._show_hint()
            self._draw()

        def _draw(self):
            w, h = self.cv.winfo_width(), self.cv.winfo_height()
            outside = _bg_of(self.master)
            tk.Frame.configure(self, bg=outside)
            self.cv.configure(bg=outside)
            state = str(self.inner.cget("state"))
            border = CYAN if self._focus else ("#2c2c2f" if state == "disabled" else BORDER)
            paint_round(self.cv, 0, 0, w, h, 8, FIELD, border, outside, "field", 1)

        # delegate to the real widget
        def configure(self, cnf=None, **kw):
            res = self.inner.configure(cnf or {}, **kw) if (cnf or kw) else self.inner.configure()
            self._draw()
            return res

        config = configure

        def cget(self, key):
            return self.inner.cget(key)

        def bind(self, sequence=None, func=None, add=None):
            return self.inner.bind(sequence, func, add)

        def focus_set(self):
            self.inner.focus_set()

        def __getattr__(self, name):
            if name in ("inner", "cv"):
                raise AttributeError(name)
            return getattr(self.inner, name)

    def Combo(parent, **kw):
        return Field(parent, combo=True, **kw)

    _gear_cache = {}

    def gear_image(color, bg, size=18):
        """A smooth little cog, drawn pixel by pixel (blended into `bg`) so it isn't jagged like a canvas shape."""
        key = (color, bg, size)
        if key in _gear_cache:
            return _gear_cache[key]
        import math
        c, b = _rgb(color), _rgb(bg)
        samples, rows, mid, k = 4, [], size / 2.0, size / 18.0
        for y in range(size):
            row = []
            for x in range(size):
                hit = 0
                for sy in range(samples):
                    for sx in range(samples):
                        dx, dy = x + (sx + .5) / samples - mid, y + (sy + .5) / samples - mid
                        d = math.hypot(dx, dy)
                        reach = (6.1 + 1.5 * math.tanh(3 * math.cos(8 * math.atan2(dy, dx)))) * k
                        hit += (2.7 * k <= d <= reach)
                t = hit / (samples * samples)
                row.append("#%02x%02x%02x" % tuple(int(round(b[i] * (1 - t) + c[i] * t)) for i in range(3)))
            rows.append("{" + " ".join(row) + "}")
        img = tk.PhotoImage(width=size, height=size)
        img.put(" ".join(rows))
        _gear_cache[key] = img
        return img

    class GearBtn(tk.Canvas):
        """A square icon button with a cog on it."""

        def __init__(self, parent, command=None):
            super().__init__(parent, width=32, height=30, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._command, self._hover, self._down = command, False, False
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<Enter>", lambda e: self._set(hover=True))
            self.bind("<Leave>", lambda e: self._set(hover=False, down=False))
            self.bind("<ButtonPress-1>", lambda e: self._set(down=True))
            self.bind("<ButtonRelease-1>", self._release)
            self.bind("<space>", lambda e: self.invoke())

        def _draw(self):
            w, h = self.winfo_width(), self.winfo_height()
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            fill = "#4a4a4e" if self._down else ("#3a3a3d" if self._hover else outside)
            paint_round(self, 0, 0, w, h, 8, fill, fill, outside, "bg", 0)
            self.delete("icon")
            self._img = gear_image(TEXT if self._hover else DIM, fill)
            self.create_image(w // 2, h // 2, image=self._img, tags="icon")

        def _set(self, hover=None, down=None):
            if hover is not None:
                self._hover = hover
            if down is not None:
                self._down = down
            self._draw()

        def _release(self, event):
            was, self._down = self._down, False
            self._draw()
            if was and 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height():
                self.invoke()

        def invoke(self):
            if self._command:
                return self._command()

    def _dialog(parent, title):
        """A rounded modal window centred on `parent`. Returns (window, body frame)."""
        top = parent.winfo_toplevel()
        win = tk.Toplevel(top)
        win.withdraw()
        win.title(title)
        win.configure(bg=BG)
        win.transient(top)
        win.resizable(False, False)
        card = Card(win, radius=14, pad=(22, 18), bg=BG)
        card.pack(padx=14, pady=14, fill="both", expand=True)
        return win, card.body

    def _place(win, parent):
        """Shows a window near the top of `parent`, without blocking it."""
        top = parent.winfo_toplevel()
        win.update_idletasks()
        w = win.winfo_reqwidth()
        x = top.winfo_rootx() + top.winfo_width() - w - 40
        y = top.winfo_rooty() + 70
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.deiconify()
        win.focus_set()

    def _show_modal(win, parent, focus=None):
        top = parent.winfo_toplevel()
        win.update_idletasks()
        w, h = win.winfo_reqwidth(), win.winfo_reqheight()
        x = top.winfo_rootx() + (top.winfo_width() - w) // 2
        y = top.winfo_rooty() + max(40, (top.winfo_height() - h) // 3)
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.deiconify()
        try:
            win.wait_visibility()
            win.grab_set()
        except tk.TclError:
            pass
        if focus is not None:
            focus.focus_set()
        win.wait_window()

    def ask_string(parent, title, prompt, initial="", ok="OK"):
        """Asks for a line of text. Returns the text, or None if cancelled."""
        win, body = _dialog(parent, title)
        out = {"value": None}
        ttk.Label(body, text=title, style="H.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(body, text=prompt, style="Dim.TLabel", wraplength=400, justify="left").grid(row=1, column=0, sticky="w", pady=(6, 12))
        var = tk.StringVar(value=initial)
        field = Field(body, textvariable=var, width=46)
        field.grid(row=2, column=0, sticky="ew")

        def done(value):
            out["value"] = value
            win.destroy()
        row = ttk.Frame(body, style="Card.TFrame")
        row.grid(row=3, column=0, sticky="e", pady=(18, 0))
        Btn(row, text="Cancel", command=lambda: done(None)).grid(row=0, column=0, padx=(0, 8))
        Btn(row, text=ok, style="Primary.TButton", command=lambda: done(var.get())).grid(row=0, column=1)
        win.bind("<Return>", lambda e: done(var.get()))
        win.bind("<Escape>", lambda e: done(None))
        win.protocol("WM_DELETE_WINDOW", lambda: done(None))
        try:
            field.inner.select_range(0, "end")
        except tk.TclError:
            pass
        _show_modal(win, parent, field)
        return out["value"]

    def ask_yes_no(parent, title, message, ok="OK", danger=False):
        """Asks a yes/no question. Returns True for the confirming button."""
        win, body = _dialog(parent, title)
        out = {"value": False}
        ttk.Label(body, text=title, style="H.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(body, text=message, style="TLabel", wraplength=400, justify="left").grid(row=1, column=0, sticky="w", pady=(8, 0))

        def done(value):
            out["value"] = value
            win.destroy()
        row = ttk.Frame(body, style="Card.TFrame")
        row.grid(row=2, column=0, sticky="e", pady=(20, 0))
        Btn(row, text="Cancel", command=lambda: done(False)).grid(row=0, column=0, padx=(0, 8))
        confirm = Btn(row, text=ok, style="Danger.TButton" if danger else "Primary.TButton", command=lambda: done(True))
        confirm.grid(row=0, column=1)
        win.bind("<Return>", lambda e: done(True))
        win.bind("<Escape>", lambda e: done(False))
        win.protocol("WM_DELETE_WINDOW", lambda: done(False))
        _show_modal(win, parent, confirm)
        return out["value"]

    class ElideLabel(ttk.Label):
        """A label that never grows past the room it's given: long text is cut in the middle (its end is kept, so a
        '._ztr' name stays recognisable) and hovering shows all of it."""

        def __init__(self, parent, var, style, chars=1, keep_tail=12, **kw):
            super().__init__(parent, style=style, width=chars, **kw)
            self.var, self._tip, self._timer, self.keep_tail = var, None, None, keep_tail
            var.trace_add("write", lambda *a: self.refit())
            self.bind("<Configure>", lambda e: self.refit())
            self.bind("<Enter>", self._enter)
            self.bind("<Leave>", self._leave)
            self.refit()

        def _measure(self):
            spec = ttk.Style(self).lookup(str(self.cget("style")), "font") or "TkDefaultFont"
            try:
                return tkfont.Font(root=self, font=spec).measure
            except tk.TclError:
                return tkfont.nametofont("TkDefaultFont").measure

        def refit(self):
            text, width = self.var.get(), self.winfo_width()
            self.configure(text=text if width <= 1 else fit_text(self._measure(), text, width - 6, self.keep_tail))

        def elided(self):
            return str(self.cget("text")) != self.var.get()

        def _enter(self, _e=None):
            if self.elided() and self._timer is None:
                self._timer = self.after(450, self._show_tip)

        def _show_tip(self):
            self._timer = None
            if self._tip is not None or not self.elided():
                return
            tip = self._tip = tk.Toplevel(self)
            tip.wm_overrideredirect(True)
            tip.configure(bg=BORDER)
            tk.Label(tip, text=self.var.get(), bg=CARD, fg=TEXT, justify="left", wraplength=640, padx=10, pady=6).pack(padx=1, pady=1)
            tip.wm_geometry(f"+{self.winfo_pointerx() + 12}+{self.winfo_pointery() + 18}")

        def _leave(self, _e=None):
            if self._timer is not None:
                self.after_cancel(self._timer)
                self._timer = None
            if self._tip is not None:
                self._tip.destroy()
                self._tip = None


    # ── drawing helpers specific to this window ───────────────────────────────────

    def nice_ceiling(value, steps=(1, 2, 2.5, 5, 10)):
        """Round up to a tidy axis maximum (1, 2, 2.5, 5, 10 times a power of ten)."""
        if value <= 0:
            return 1.0
        mag = 10 ** math.floor(math.log10(value))
        for step in steps:
            if value <= step * mag:
                return step * mag
        return 10 * mag

    def nice_top(value):
        """The smallest 3 x {1, 2, 5} x 10^k that is at least `value`, so three equal steps land on tidy numbers."""
        if value <= 0:
            return 3.0
        k = math.floor(math.log10(value / 3.0))
        for s in (1, 2, 5, 10):
            top = 3 * s * 10 ** k
            if top >= value:
                return top
        return 30 * 10 ** k

    def nice_top_bytes(value):
        unit = 1
        while value / unit >= 1024:
            unit *= 1024
        return nice_top(value / unit) * unit

    class Chart(tk.Canvas):
        """A small chart that redraws itself from data it is handed: 'bars' (one per tunnel) or 'area' (two rates)."""

        def __init__(self, parent, kind, height=150, **kw):
            super().__init__(parent, bd=0, highlightthickness=0, height=height, bg=CARD, **kw)
            self.kind, self.data, self.empty_text = kind, [], "Nothing yet"
            self.bind("<Configure>", lambda e: self.draw())
            self.bind("<Map>", lambda e: self.after_idle(self.draw))

        def set(self, data):
            if data != self.data:
                self.data = data
                self.draw()

        def _frame(self, w, h, top_value, fmt, left=46):
            """Axis lines and labels; returns the plotting box."""
            box = (left, 8, w - 10, h - 20)
            x0, y0, x1, y1 = box
            for i in range(4):
                y = y1 - (y1 - y0) * i / 3
                self.create_line(x0, y, x1, y, fill="#323236" if i else "#4a4a4f")
                self.create_text(x0 - 6, y, text=fmt(top_value * i / 3), anchor="e", fill=DIM, font=UI["tiny"])
            return box

        def draw(self):
            self.delete("all")
            w, h = self.winfo_width(), self.winfo_height()
            if w < 60 or h < 60:
                return
            if not self.data:
                self.create_text(w // 2, h // 2, text=self.empty_text, fill=DIM, font=UI["small"])
                return
            (self._bars if self.kind == "bars" else self._area)(w, h)

        def _bars(self, w, h):
            values = [v for _t, v, _warm in self.data]
            top = nice_top(max(0.3, max(values) * 1.1))
            x0, y0, x1, y1 = self._frame(w, h, top, lambda v: fmt_seconds(v) if v else "0")
            count = max(len(self.data), 30)
            slot = (x1 - x0) / count
            width = max(2, min(14, slot * 0.7))
            start = x1 - slot * len(self.data)
            for i, (_t, value, warm) in enumerate(self.data):
                bar = max(1.5, (y1 - y0) * min(value, top) / top)
                color = GREEN if warm else (AMBER if value > 5 else CYAN)
                cx = start + slot * (i + .5)
                paint_round(self, int(cx - width / 2), int(y1 - bar), int(width), int(bar), 2 if width >= 5 else 0, color, color, CARD, f"bar{i}", 0)
            self.create_text(x1, y1 + 11, text="newest", anchor="e", fill=DIM, font=UI["tiny"])

        def _area(self, w, h):
            ups = [u for _t, u, _d in self.data]
            downs = [d for _t, _u, d in self.data]
            top = nice_top_bytes(max(1024.0, max(ups + downs) * 1.15))
            x0, y0, x1, y1 = self._frame(w, h, top, lambda v: human_rate(v) if v else "0", left=70)
            span = max(len(self.data), 60)
            step = (x1 - x0) / (span - 1)

            def xy(i, v):
                return x1 - step * (len(self.data) - 1 - i), y1 - (y1 - y0) * min(v, top) / top
            for series, color in ((ups, PURPLE), (downs, TEAL)):
                pts = [xy(i, v) for i, v in enumerate(series)]
                flat = [c for p in pts for c in p]
                if len(pts) > 1:
                    fill = _mix(_rgb(color), _rgb(CARD), 0.78)
                    self.create_polygon(pts[0][0], y1, *flat, pts[-1][0], y1, fill=fill, outline="")
                    self.create_line(*flat, fill=color, width=2, smooth=True)
            self.create_text(x1, y1 + 11, text="now", anchor="e", fill=DIM, font=UI["tiny"])
            self.create_text(x0, y1 + 11, text=f"{len(self.data)} s ago" if len(self.data) < span else f"{span} s ago", anchor="w", fill=DIM, font=UI["tiny"])

    class Stat(Card):
        """A card with a caption, one big figure and a line of detail."""

        def __init__(self, parent, caption, accent=CYAN):
            super().__init__(parent, radius=14, pad=(16, 12))
            self.accent = accent
            ttk.Label(self.body, text=caption.upper(), style="Dim.TLabel").grid(row=0, column=0, sticky="w")
            self.value = ttk.Label(self.body, text="—", style="Big.TLabel")
            self.value.grid(row=1, column=0, sticky="w", pady=(2, 0))
            self.sub = ttk.Label(self.body, text=" ", style="Dim.TLabel")
            self.sub.grid(row=2, column=0, sticky="w")

        def set(self, value, sub=" ", color=None):
            self.value.configure(text=value, foreground=color or TEXT)
            self.sub.configure(text=sub)

    class ChainView(tk.Canvas):
        """You → entry → middle → exit → the internet, with the time to reach each hop directly underneath."""

        def __init__(self, parent, **kw):
            super().__init__(parent, bd=0, highlightthickness=0, height=70, bg=CARD, **kw)
            self.nodes, self.live, self.phase, self._xs = [], False, 0.0, []
            self.bind("<Configure>", lambda e: self.draw())
            self.bind("<Map>", lambda e: self.after_idle(self.draw))

        def set(self, nodes, live):
            if nodes != self.nodes or live != self.live:
                self.nodes, self.live = nodes, live
                self.draw()

        def animate(self):
            """Moves the dots along the links; the rest of the picture is left alone (redrawing it all is what costs CPU)."""
            self.delete("pulse")
            if self.live and self.nodes and self._xs:
                self.phase = (self.phase + 0.04) % 1.0
                self._dots()

        def _dots(self):
            cy = 24
            for i in range(len(self._xs) - 1):
                t = (self.phase + i * 0.18) % 1.0
                x = self._xs[i] + 14 + (self._xs[i + 1] - self._xs[i] - 28) * t
                paint_round(self, int(x - 3), cy - 3, 6, 6, 3, TEAL, TEAL, CARD, f"pulse{i}", 0)
                self.addtag_withtag("pulse", f"pulse{i}")

        def draw(self):
            self.delete("all")
            w, h = self.winfo_width(), self.winfo_height()
            if not self.nodes or w < 120:
                return
            n = len(self.nodes)
            pad = 70
            xs = self._xs = [pad + (w - 2 * pad) * i / max(1, n - 1) for i in range(n)]
            cy = 24
            for i in range(n - 1):
                self.create_line(xs[i] + 14, cy, xs[i + 1] - 14, cy, fill="#4a4a4f", width=2)
            if self.live:
                self._dots()
            for x, (title, sub, kind) in zip(xs, self.nodes):
                color = {"you": GREEN, "hop": CYAN, "exit": PURPLE, "net": AMBER}.get(kind, CYAN)
                paint_round(self, int(x - 11), cy - 11, 22, 22, 11, _mix(_rgb(color), _rgb(CARD), 0.7), color, CARD, f"ring{x}", 2)
                paint_round(self, int(x - 4), cy - 4, 8, 8, 4, color, color, _mix(_rgb(color), _rgb(CARD), 0.7), f"core{x}", 0)
                self.create_text(x, cy + 24, text=title, fill=TEXT, font=UI["small"])
                self.create_text(x, cy + 38, text=sub, fill=DIM, font=UI["tiny"])

    def sync_tree(tree, rows):
        """Makes the tree show `rows` ([(iid, values, tags)], in order) touching as little as possible, so selection,
        scroll position and hover survive a refresh every half second."""
        have = list(tree.get_children())
        want = [r[0] for r in rows]
        for iid in have:
            if iid not in set(want):
                tree.delete(iid)
        existing = set(tree.get_children())
        for index, (iid, values, tags) in enumerate(rows):
            if iid in existing:
                if tuple(tree.item(iid, "values")) != tuple(str(v) for v in values):
                    tree.item(iid, values=values, tags=tags)
                if tree.index(iid) != index:
                    tree.move(iid, "", index)
            else:
                tree.insert("", index, iid=iid, values=values, tags=tags)

    def make_tree(parent, columns, widths, height=10, anchors=None, stretch="host"):
        """A Treeview with a thin scrollbar, headings and column widths; returns (frame, tree)."""
        frame = ttk.Frame(parent)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show="headings", height=height, selectmode="browse")
        for (key, title), width in zip(columns, widths):
            anchor = (anchors or {}).get(key, "w")
            tree.heading(key, text=title, anchor=anchor)
            tree.column(key, width=width, minwidth=40, anchor=anchor, stretch=(key == stretch))
        bar = ttk.Scrollbar(frame, orient="vertical", command=tree.yview, style="Thin.Vertical.TScrollbar")
        tree.configure(yscrollcommand=bar.set)
        tree.grid(row=0, column=0, sticky="nsew")
        bar.grid(row=0, column=1, sticky="ns")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        tree.tag_configure("odd", background=ZEBRA)
        tree.tag_configure("failed", foreground=RED)
        tree.tag_configure("open", foreground=GREEN)
        tree.tag_configure("warm", foreground=TEAL)
        tree.tag_configure("dim", foreground=DIM)
        tree.tag_configure("blocked", foreground=AMBER)
        return frame, tree

    # ── the window ───────────────────────────────────────────────────────────────

    class App:
        PAGES = [("overview", "Overview"), ("connections", "Connections"), ("hosts", "Hosts"), ("alerts", "Alerts"), ("blocklist", "Blocklist"), ("browser", "Browser"), ("log", "Log")]

        def __init__(self, root, route=None, autostart=False):
            self.root = root
            self.settings = load_settings()
            if route:
                self.settings["route"] = route
            self.tele = ztr_proxy.TELEMETRY
            self.service = None
            self.state = "stopped"          # stopped | starting | running
            self.events = queue.Queue()
            self.snap = self.tele.snapshot()
            self.status = {"spares": [], "refilling": [], "pinned": [], "warm": True, "max_age": 150}
            self.rtts = {}
            self.toast_job = None
            self.settings_win = None
            self.page = None
            self._log_seen = 0
            self._failed_seen = 0
            self._failed_toast = 0.0
            self._alert_pending, self._alert_toast_at, self._alert_label = 0, 0.0, "Alerts"
            ztr_proxy.GUARD.ensure_loaded()
            ztr_proxy.GUARD.detector.listeners.append(self.on_alert)
            self.menu_kw = dict(tearoff=0, bg="#2c2c2f", fg=TEXT, activebackground=SEL, activeforeground="#ffffff",
                                disabledforeground="#6a6a70", bd=0, relief="flat", activeborderwidth=0)
            root.title(APP_NAME)
            root.configure(bg=BG)
            root.minsize(960, 640)
            root.geometry(f"1160x{min(800, max(640, root.winfo_screenheight() - 70))}")
            self._style()
            self.logo_small = tk.PhotoImage(data=base64.b64encode(logo_png(40)))
            try:
                root.iconphoto(True, tk.PhotoImage(data=base64.b64encode(logo_png(96, 2))))
            except tk.TclError:
                pass
            self._build()
            self.show("overview")
            root.protocol("WM_DELETE_WINDOW", self.on_close)
            root.bind(f"<{MOD}-r>", lambda e: self.toggle())
            root.bind(f"<{MOD}-comma>", lambda e: self.open_settings())
            for i, (key, _t) in enumerate(self.PAGES):
                root.bind(f"<{MOD}-Key-{i + 1}>", lambda e, k=key: self.show(k))
            self.refresh_route_card(probe=True)
            self.root.after(400, self._tick)
            self.root.after(90, self._animate)
            if autostart or self.settings.get("autostart"):
                self.root.after(500, self.start)

        # ── look ─────────────────────────────────────────────────────────
        def _style(self):
            fams = set(tkfont.families())
            fam = next((f for f in ("SF Pro Text", "SF Pro Display", "Inter", "Helvetica Neue", "Nimbus Sans", "Liberation Sans",
                                    "Arimo", "Noto Sans", "DejaVu Sans") if f in fams), tkfont.nametofont("TkDefaultFont").actual("family"))
            self.family = fam
            for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
                try:
                    tkfont.nametofont(name).configure(family=fam, size=10)
                except tk.TclError:
                    pass
            mono = next((f for f in ("JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono") if f in fams), "TkFixedFont")
            UI.update(body=tkfont.Font(family=fam, size=10), small=tkfont.Font(family=fam, size=9), tiny=tkfont.Font(family=fam, size=8),
                      bold=tkfont.Font(family=fam, size=10, weight="bold"), h=tkfont.Font(family=fam, size=11, weight="bold"),
                      title=tkfont.Font(family=fam, size=16, weight="bold"), head=tkfont.Font(family=fam, size=9, weight="bold"),
                      big=tkfont.Font(family=fam, size=22, weight="bold"), mono=tkfont.Font(family=mono, size=9))
            s = ttk.Style(self.root)
            s.theme_use("clam")
            s.configure(".", background=BG, foreground=TEXT, fieldbackground=FIELD, bordercolor=BORDER, lightcolor=BORDER,
                        darkcolor=BORDER, troughcolor=FIELD, focuscolor=CYAN, font=UI["body"])
            s.configure("TFrame", background=BG)
            s.configure("Card.TFrame", background=CARD)
            s.configure("Field.TFrame", background=FIELD)
            s.configure("TLabel", background=CARD, foreground=TEXT, font=UI["body"])
            s.configure("Dim.TLabel", background=CARD, foreground=DIM, font=UI["small"])
            s.configure("BgDim.TLabel", background=BG, foreground=DIM, font=UI["small"])
            s.configure("Title.TLabel", background=BG, foreground=TEXT, font=UI["title"])
            s.configure("H.TLabel", background=CARD, foreground=TEXT, font=UI["h"])
            s.configure("Big.TLabel", background=CARD, foreground=TEXT, font=UI["big"])
            s.configure("Mono.TLabel", background=CARD, foreground=TEXT, font=UI["mono"])
            s.configure("Insight.TFrame", background="#1f2c3f")
            s.configure("Insight.TLabel", background="#1f2c3f", foreground=TEXT, font=UI["body"])
            for kind in ("Flat.TEntry", "Flat.TCombobox"):
                s.configure(kind, fieldbackground=FIELD, background=FIELD, foreground=TEXT, insertcolor=TEXT, borderwidth=0,
                            bordercolor=FIELD, lightcolor=FIELD, darkcolor=FIELD, padding=2, arrowcolor=DIM,
                            selectbackground=SEL, selectforeground="#ffffff", font=UI["body"])
                s.map(kind, fieldbackground=[("disabled", FIELD), ("readonly", FIELD)], foreground=[("disabled", DIM), ("readonly", TEXT)],
                      bordercolor=[("focus", FIELD)], lightcolor=[("focus", FIELD)], darkcolor=[("focus", FIELD)],
                      selectbackground=[("readonly", FIELD)], selectforeground=[("readonly", TEXT)], background=[("active", FIELD), ("readonly", FIELD)])
            for opt, val in (("background", FIELD), ("foreground", TEXT), ("selectBackground", SEL), ("selectForeground", "#ffffff"), ("font", UI["body"])):
                self.root.option_add(f"*TCombobox*Listbox.{opt}", val)
            s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
            s.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT, rowheight=26, borderwidth=0, relief="flat", font=UI["body"])
            s.configure("Treeview.Heading", background="#212124", foreground=DIM, padding=(8, 6), font=UI["head"], relief="flat", borderwidth=0)
            s.map("Treeview", background=[("selected", SEL)], foreground=[("selected", "#ffffff")])
            s.map("Treeview.Heading", background=[("active", "#2c2c30")])
            s.layout("Thin.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
                ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
            s.configure("Thin.Vertical.TScrollbar", background="#4a4a4f", troughcolor=FIELD, bordercolor=FIELD, lightcolor="#4a4a4f",
                        darkcolor="#4a4a4f", arrowsize=9, gripcount=0, borderwidth=0)
            s.map("Thin.Vertical.TScrollbar", background=[("active", "#68686e")], lightcolor=[("active", "#68686e")], darkcolor=[("active", "#68686e")])

        # ── layout ───────────────────────────────────────────────────────
        def _build(self):
            root = self.root
            root.columnconfigure(0, weight=1)
            root.rowconfigure(0, weight=1)
            page = ttk.Frame(root, padding=(22, 16, 22, 10))
            page.grid(row=0, column=0, sticky="nsew")
            page.columnconfigure(0, weight=1)
            page.rowconfigure(3, weight=1)

            # header: brand, state, the one button that matters, settings
            head = ttk.Frame(page)
            head.grid(row=0, column=0, sticky="ew", pady=(0, 12))
            head.columnconfigure(0, weight=1)
            brand = ttk.Frame(head)
            brand.grid(row=0, column=0, sticky="ew", padx=(0, 16))
            tk.Label(brand, image=self.logo_small, bg=BG, bd=0).grid(row=0, column=0, rowspan=2, padx=(0, 12))
            ttk.Label(brand, text=APP_NAME, style="Title.TLabel").grid(row=0, column=1, sticky="sw")
            ttk.Label(brand, text=TAGLINE, style="BgDim.TLabel").grid(row=1, column=1, sticky="nw")
            pill = Card(head, radius=15, pad=(12, 6), bg=BG)
            pill.grid(row=0, column=1, sticky="e", padx=(0, 12))
            self.dot = tk.Canvas(pill.body, width=12, height=12, bg=CARD, highlightthickness=0)
            self.dot.grid(row=0, column=0, padx=(0, 7))
            self.paint_dot(DIM)
            self.state_label = ttk.Label(pill.body, text="Stopped", style="Dim.TLabel")
            self.state_label.grid(row=0, column=1)
            self.toggle_btn = Btn(head, text="Start proxy", command=self.toggle, style="Primary.TButton")
            self.toggle_btn.grid(row=0, column=2, padx=(0, 10))
            GearBtn(head, command=self.open_settings).grid(row=0, column=3)

            # the route: which one, and what is between you and the internet
            self.route_card = Card(page, radius=14, pad=(16, 12))
            self.route_card.grid(row=1, column=0, sticky="ew", pady=(0, 12))
            rb = self.route_card.body
            rb.columnconfigure(0, weight=0)
            rb.columnconfigure(2, weight=1)
            ttk.Label(rb, text="ROUTE", style="Dim.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 12))
            self.route_var = tk.StringVar(value=self.settings.get("route", ""))
            self.route_combo = Combo(rb, compact=True, textvariable=self.route_var, state="readonly", width=22, values=list_routes())
            self.route_combo.grid(row=0, column=1, sticky="w")
            self.route_combo.inner.bind("<<ComboboxSelected>>", lambda e: self.on_route_chosen())
            self.route_note = ttk.Label(rb, text="", style="Dim.TLabel")
            self.route_note.grid(row=0, column=2, sticky="e")
            Btn(rb, text="Measure", style="Ghost.TButton", command=lambda: self.refresh_route_card(probe=True)).grid(row=0, column=3, padx=(10, 0))
            self.chain = ChainView(rb)
            self.chain.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(10, 0))

            # page tabs
            self.tabbar = tk.Frame(page, bg=BG)
            self.tabbar.grid(row=2, column=0, sticky="w", pady=(0, 10))
            self.tab_btns = {}
            for i, (key, title) in enumerate(self.PAGES):
                b = Btn(self.tabbar, text=title, kind="tab", selected=False, command=lambda k=key: self.show(k))
                b.grid(row=0, column=i, padx=(0, 6))
                self.tab_btns[key] = b
            self.stack = ttk.Frame(page)
            self.stack.grid(row=3, column=0, sticky="nsew")
            self.stack.columnconfigure(0, weight=1)
            self.stack.rowconfigure(0, weight=1)
            self.pages = {}
            for key, _t in self.PAGES:
                frame = ttk.Frame(self.stack)
                frame.grid(row=0, column=0, sticky="nsew")
                self.pages[key] = frame
            self._build_overview(self.pages["overview"])
            self._build_connections(self.pages["connections"])
            self._build_hosts(self.pages["hosts"])
            self._build_alerts(self.pages["alerts"])
            self._build_blocklist(self.pages["blocklist"])
            self._build_browser(self.pages["browser"])
            self._build_log(self.pages["log"])

            self.foot = ttk.Label(page, text="", style="BgDim.TLabel")
            self.foot.grid(row=4, column=0, sticky="w", pady=(8, 0))
            self.toast_label = tk.Label(root, text="", bg="#2c2c2f", fg=TEXT, font=UI["body"], padx=14, pady=8, bd=0)

        def paint_dot(self, color):
            paint_round(self.dot, 1, 1, 10, 10, 5, color, color, CARD, "dot", 0)

        def show(self, key):
            self.page = key
            self.pages[key].tkraise()
            for k, b in self.tab_btns.items():
                b.configure(selected=(k == key))
            self._refresh_page(force=True)

        def toast(self, text, kind="info", ms=3200):
            colors = {"info": TEXT, "ok": GREEN, "error": RED, "warn": AMBER}
            self.toast_label.configure(text=text, fg=colors.get(kind, TEXT))
            self.toast_label.place(relx=0.5, rely=1.0, anchor="s", y=-18)
            self.toast_label.lift()
            if self.toast_job:
                self.root.after_cancel(self.toast_job)
            self.toast_job = self.root.after(ms, self.toast_label.place_forget)

        def copy(self, text, what="Copied"):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.toast(what, "ok", 1800)

        # ── pages ────────────────────────────────────────────────────────
        def _build_overview(self, f):
            f.columnconfigure((0, 1, 2, 3), weight=1, uniform="stat")
            f.rowconfigure(3, weight=1)
            self.insight_card = Card(f, radius=14, pad=(16, 10), fill="#1f2c3f", border="#2d4a73", style="Insight.TFrame")
            self.insight_card.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 12))
            ib = self.insight_card.body
            ib.columnconfigure(0, weight=1)
            self.insight_text = ttk.Label(ib, text="", style="Insight.TLabel", wraplength=760, justify="left")
            self.insight_text.grid(row=0, column=0, sticky="w")
            self.insight_btn = Btn(ib, text="", style="Small.TButton", command=lambda: None)
            self.insight_btn.grid(row=0, column=1, padx=(12, 0))
            Btn(ib, text="Dismiss", style="Ghost.TButton", command=self.dismiss_insight).grid(row=0, column=2, padx=(4, 0))
            self.insight_card.grid_remove()
            self.insight_key = None
            self.dismissed = set()
            self.st_open = Stat(f, "Open now")
            self.st_ready = Stat(f, "Tunnels ready")
            self.st_setup = Stat(f, "Typical wait")
            self.st_traffic = Stat(f, "Traffic")
            for i, w in enumerate((self.st_open, self.st_ready, self.st_setup, self.st_traffic)):
                w.grid(row=1, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0 if i == 3 else 6), pady=(0, 12))
            c1 = Card(f, radius=14, pad=(16, 12))
            c1.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=(0, 6), pady=(0, 12))
            c2 = Card(f, radius=14, pad=(16, 12))
            c2.grid(row=2, column=2, columnspan=2, sticky="nsew", padx=(6, 0), pady=(0, 12))
            for card, title, attr in ((c1, "Time to get a tunnel", "setup_note"), (c2, "Throughput", "rate_note")):
                card.body.columnconfigure(1, weight=1)
                ttk.Label(card.body, text=title, style="H.TLabel").grid(row=0, column=0, sticky="w")
                note = ttk.Label(card.body, text="", style="Dim.TLabel")
                note.grid(row=0, column=1, sticky="e")
                setattr(self, attr, note)
            self.setup_chart = Chart(c1.body, "bars")
            self.setup_chart.empty_text = "Tunnels show up here as your browser opens them"
            self.setup_chart.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
            self.rate_chart = Chart(c2.body, "area")
            self.rate_chart.empty_text = "Start the proxy to see traffic"
            self.rate_chart.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
            for card in (c1, c2):
                card.body.rowconfigure(1, weight=1)
            legend = ttk.Frame(c1.body, style="Card.TFrame")
            legend.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
            for i, (color, text) in enumerate(((CYAN, "new tunnel"), (GREEN, "ready tunnel (instant)"), (AMBER, "slow (over 5 s)"))):
                tk.Canvas(legend, width=10, height=10, bg=CARD, highlightthickness=0).grid(row=0, column=i * 2, padx=(0 if i == 0 else 14, 5))
                legend.grid_slaves(row=0, column=i * 2)[0].create_rectangle(0, 0, 10, 10, fill=color, outline="")
                ttk.Label(legend, text=text, style="Dim.TLabel").grid(row=0, column=i * 2 + 1)
            legend2 = ttk.Frame(c2.body, style="Card.TFrame")
            legend2.grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
            for i, (color, text) in enumerate(((TEAL, "received"), (PURPLE, "sent"))):
                tk.Canvas(legend2, width=10, height=10, bg=CARD, highlightthickness=0).grid(row=0, column=i * 2, padx=(0 if i == 0 else 14, 5))
                legend2.grid_slaves(row=0, column=i * 2)[0].create_rectangle(0, 0, 10, 10, fill=color, outline="")
                ttk.Label(legend2, text=text, style="Dim.TLabel").grid(row=0, column=i * 2 + 1)
            c3 = Card(f, radius=14, pad=(16, 12))
            c3.grid(row=3, column=0, columnspan=4, sticky="nsew")
            c3.body.rowconfigure(1, weight=1)
            ttk.Label(c3.body, text="Latest connections", style="H.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
            cols = [("time", "Time"), ("kind", "Type"), ("host", "Host"), ("setup", "Wait"), ("down", "Received"), ("state", "State")]
            frame, self.mini_tree = make_tree(c3.body, cols, (80, 80, 380, 90, 100, 130), height=5, anchors={"setup": "e", "down": "e"})
            frame.grid(row=1, column=0, sticky="nsew")

        def _build_connections(self, f):
            f.columnconfigure(0, weight=1)
            f.rowconfigure(1, weight=1)
            bar = ttk.Frame(f)
            bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            bar.columnconfigure(1, weight=1)
            self.filter_var = tk.StringVar()
            Field(bar, compact=True, textvariable=self.filter_var, width=26, placeholder="Filter by host").grid(row=0, column=0, sticky="w")
            self.only_problems = tk.BooleanVar(value=False)
            Check(bar, text="Only problems", variable=self.only_problems).grid(row=0, column=2, padx=(14, 0))
            self.close_btn = Btn(bar, text="Close connection", style="Danger.TButton", command=self.close_selected, state="disabled")
            self.close_btn.grid(row=0, column=3, padx=(14, 0))
            Btn(bar, text="Clear history", style="Ghost.TButton", command=self.clear_history).grid(row=0, column=4, padx=(8, 0))
            cols = [("time", "Time"), ("kind", "Type"), ("host", "Host"), ("tunnel", "Tunnel"), ("setup", "Wait"),
                    ("up", "Sent"), ("down", "Received"), ("state", "State")]
            frame, self.conn_tree = make_tree(f, cols, (80, 80, 360, 80, 80, 90, 100, 150), height=14,
                                              anchors={"setup": "e", "up": "e", "down": "e"})
            frame.grid(row=1, column=0, sticky="nsew")
            self.conn_hint = tk.Label(frame, text="", bg=FIELD, fg=DIM, font=UI["body"], justify="center")
            self.conn_tree.bind("<<TreeviewSelect>>", lambda e: self._conn_selected())
            self.conn_menu = tk.Menu(self.root, **self.menu_kw, font=UI["body"])
            self.conn_menu.add_command(label="Copy host", command=lambda: self.copy_row_host(self.conn_tree))
            self.conn_menu.add_command(label="Keep this host ready", command=self.pin_from_connection)
            self.conn_menu.add_command(label="Block this host", command=self.block_from_connection)
            self.conn_menu.add_command(label="Alert on this host", command=self.watch_from_connection)
            self.conn_menu.add_separator()
            self.conn_menu.add_command(label="Close connection", command=self.close_selected)
            bind_context_menu(self.conn_tree, lambda e: self.popup(self.conn_tree, self.conn_menu, e))
            self.detail = Card(f, radius=12, pad=(14, 10))
            self.detail.grid(row=2, column=0, sticky="ew", pady=(10, 0))
            self.detail_label = ttk.Label(self.detail.body, text="Select a connection to see its details.", style="Dim.TLabel", wraplength=900, justify="left")
            self.detail_label.grid(row=0, column=0, sticky="w")

        def _build_hosts(self, f):
            f.columnconfigure(0, weight=1)
            f.rowconfigure(1, weight=1)
            bar = ttk.Frame(f)
            bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            bar.columnconfigure(5, weight=1)
            self.pin_var = tk.StringVar()
            fld = Field(bar, compact=True, textvariable=self.pin_var, width=28, placeholder="host or host:port")
            fld.grid(row=0, column=0, sticky="w")
            fld.inner.bind("<Return>", lambda e: self.pin_typed())
            Btn(bar, text="Keep ready", style="Primary.TButton", command=self.pin_typed).grid(row=0, column=1, padx=(10, 0))
            self.unpin_btn = Btn(bar, text="Stop keeping ready", command=self.unpin_selected, state="disabled")
            self.unpin_btn.grid(row=0, column=2, padx=(8, 0))
            self.block_btn = Btn(bar, text="Block host", style="Danger.TButton", command=self.block_selected_host, state="disabled")
            self.block_btn.grid(row=0, column=3, padx=(18, 0))
            self.watch_btn = Btn(bar, text="Alert on host", command=self.watch_selected_host, state="disabled")
            self.watch_btn.grid(row=0, column=4, padx=(8, 0))
            self.pin_note = ttk.Label(bar, text="", style="BgDim.TLabel")
            self.pin_note.grid(row=0, column=5, sticky="e")
            cols = [("host", "Host"), ("count", "Visits"), ("warm", "Instant"), ("avg", "Typical wait"), ("up", "Sent"),
                    ("down", "Received"), ("failed", "Failed"), ("last", "Last"), ("kept", "Kept ready"), ("status", "List")]
            frame, self.host_tree = make_tree(f, cols, (280, 60, 70, 95, 80, 90, 60, 80, 90, 90), height=14,
                                              anchors={"count": "e", "warm": "e", "avg": "e", "up": "e", "down": "e", "failed": "e"})
            frame.grid(row=1, column=0, sticky="nsew")
            self.host_tree.bind("<<TreeviewSelect>>", lambda e: self._host_selected())
            self.host_tree.bind("<Double-1>", lambda e: self.toggle_pin_selected())
            self.host_menu = tk.Menu(self.root, **self.menu_kw, font=UI["body"])
            self.host_menu.add_command(label="Copy host", command=lambda: self.copy_row_host(self.host_tree))
            self.host_menu.add_command(label="Keep ready / stop keeping ready", command=self.toggle_pin_selected)
            self.host_menu.add_separator()
            self.host_menu.add_command(label="Block / unblock host", command=self.block_selected_host)
            self.host_menu.add_command(label="Alert on this host", command=self.watch_selected_host)
            bind_context_menu(self.host_tree, lambda e: self.popup(self.host_tree, self.host_menu, e))
            ttk.Label(f, text="A host that is kept ready always has a tunnel waiting, so the first connection to it doesn't wait for the route. "
                              "It costs the hops one extra tunnel setup every couple of minutes per host — keep it for the few sites you use all the time.",
                      style="BgDim.TLabel", wraplength=1000, justify="left").grid(row=2, column=0, sticky="w", pady=(10, 0))

        def _build_browser(self, f):
            f.columnconfigure((0, 1), weight=1, uniform="b")
            a = Card(f, radius=14, pad=(18, 10))
            a.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 12))
            ttk.Label(a.body, text="Proxy address", style="H.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            ttk.Label(a.body, text="Point any program at it. One port speaks both.", style="Dim.TLabel").grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 10))
            self.addr_http = ttk.Label(a.body, text="—", style="Mono.TLabel")
            self.addr_socks = ttk.Label(a.body, text="—", style="Mono.TLabel")
            for row, (title, lab, make) in enumerate((("HTTP proxy", self.addr_http, lambda: self.addr_http.cget("text")),
                                                       ("SOCKS5", self.addr_socks, lambda: self.addr_socks.cget("text")))):
                ttk.Label(a.body, text=title, style="Dim.TLabel").grid(row=2 + row, column=0, sticky="w", padx=(0, 14), pady=3)
                lab.grid(row=2 + row, column=1, sticky="w", pady=3)
                Btn(a.body, text="Copy", style="Small.TButton", command=lambda m=make: self.copy(m(), "Address copied")).grid(row=2 + row, column=2, padx=(12, 0))
            a.body.columnconfigure(1, weight=1)
            ttk.Label(a.body, text="Use socks5h:// (curl: --socks5-hostname) so the proxy looks names up for you, not your computer.",
                      style="Dim.TLabel", wraplength=420, justify="left").grid(row=4, column=0, columnspan=3, sticky="w", pady=(10, 0))
            self.curl_btn = Btn(a.body, text="Copy a curl example", style="Small.TButton", command=self.copy_curl)
            self.curl_btn.grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 0))

            b = Card(f, radius=14, pad=(18, 10))
            b.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 12))
            ttk.Label(b.body, text="Check it works", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(b.body, text="Loads one HTTPS page through the proxy and the whole route.", style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 10))
            self.test_btn = Btn(b.body, text="Test connection", command=self.run_check)
            self.test_btn.grid(row=2, column=0, sticky="w")
            self.test_result = ttk.Label(b.body, text="", style="Dim.TLabel", wraplength=420, justify="left")
            self.test_result.grid(row=3, column=0, sticky="w", pady=(10, 0))
            b.body.columnconfigure(0, weight=1)

            c = Card(f, radius=14, pad=(18, 10))
            c.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(0, 12))
            c.body.columnconfigure((0, 1), weight=1, uniform="ff")
            left = ttk.Frame(c.body, style="Card.TFrame")
            left.grid(row=0, column=0, sticky="nsew", padx=(0, 18))
            right = ttk.Frame(c.body, style="Card.TFrame")
            right.grid(row=0, column=1, sticky="nsew", padx=(18, 0))
            ttk.Label(left, text="Open a browser", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            self.browsers = detect_browsers()
            self.browser_var = tk.StringVar()
            self.browser_combo = Combo(left, compact=True, textvariable=self.browser_var, state="readonly", width=24,
                                       values=[b["label"] for b in self.browsers])
            self.browser_combo.grid(row=1, column=0, sticky="w", pady=(10, 0))
            self.browser_combo.inner.bind("<<ComboboxSelected>>", lambda e: self.browser_chosen())
            self.quiet_var = tk.BooleanVar(value=bool(self.settings.get("quiet", True)))
            self.webrtc_var = tk.BooleanVar(value=bool(self.settings.get("webrtc", True)))
            Check(left, text="Quiet the browser's own background connections", variable=self.quiet_var, command=self.save_prefs).grid(row=2, column=0, sticky="w", pady=(10, 0))
            ttk.Label(left, text="Updates, telemetry and sync each open tunnels and slow pages down.",
                      style="Dim.TLabel", justify="left").grid(row=3, column=0, sticky="w", padx=(26, 0))
            Check(left, text="Block WebRTC", variable=self.webrtc_var, command=self.save_prefs).grid(row=4, column=0, sticky="w", pady=(10, 0))
            ttk.Label(left, text="WebRTC can show a website your real address, around the proxy.",
                      style="Dim.TLabel", justify="left").grid(row=5, column=0, sticky="w", padx=(26, 0))
            self.open_btn = Btn(left, text="Open browser through ZTR", style="Primary.TButton", command=self.open_browser)
            self.open_btn.grid(row=6, column=0, sticky="w", pady=(12, 0))
            self.browser_note = ttk.Label(left, text="", style="Dim.TLabel", wraplength=420, justify="left")
            self.browser_note.grid(row=7, column=0, sticky="w", pady=(6, 0))
            self.browser_var.set(next((b["label"] for b in self.browsers if b["key"] == self.settings.get("browser")),
                                      self.browsers[0]["label"] if self.browsers else ""))
            self.browser_chosen()
            right.columnconfigure(0, weight=1)
            ttk.Label(right, text="Or use a Firefox profile you already have", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            self.profile_var = tk.StringVar()
            self.profile_combo = Combo(right, compact=True, textvariable=self.profile_var, state="readonly", width=30)
            self.profile_combo.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
            self.profile_combo.inner.bind("<<ComboboxSelected>>", lambda e: self.profile_chosen())
            self.apply_btn = Btn(right, text="Add proxy settings", command=self.apply_profile)
            self.apply_btn.grid(row=2, column=0, sticky="w", pady=(10, 0))
            self.remove_btn = Btn(right, text="Remove them", style="Ghost.TButton", command=self.remove_profile)
            self.remove_btn.grid(row=2, column=1, sticky="w", padx=(6, 0), pady=(10, 0))
            self.profile_note = ttk.Label(right, text="", style="Dim.TLabel", wraplength=420, justify="left")
            self.profile_note.grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
            self.profiles = []
            self.reload_profiles()

        def _build_log(self, f):
            f.columnconfigure(0, weight=1)
            f.rowconfigure(1, weight=1)
            bar = ttk.Frame(f)
            bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            bar.columnconfigure(3, weight=1)
            self.level_var = tk.StringVar(value="Everything")
            lv = Combo(bar, compact=True, textvariable=self.level_var, state="readonly", width=14, values=["Everything", "Warnings and errors", "Errors only"])
            lv.grid(row=0, column=0, sticky="w")
            lv.inner.bind("<<ComboboxSelected>>", lambda e: self.rebuild_log())
            self.pause_var = tk.BooleanVar(value=False)
            Check(bar, text="Pause", variable=self.pause_var).grid(row=0, column=1, padx=(14, 0))
            Btn(bar, text="Copy all", style="Ghost.TButton", command=self.copy_log).grid(row=0, column=4, padx=(8, 0))
            Btn(bar, text="Clear", style="Ghost.TButton", command=self.clear_log).grid(row=0, column=5, padx=(8, 0))
            holder = tk.Frame(f, bg=FIELD, bd=0, highlightthickness=0)
            holder.grid(row=1, column=0, sticky="nsew")
            holder.columnconfigure(0, weight=1)
            holder.rowconfigure(0, weight=1)
            self.log_text = tk.Text(holder, bg=FIELD, fg=TEXT, bd=0, highlightthickness=0, wrap="none", font=UI["mono"], padx=12, pady=8,
                                    insertbackground=TEXT, state="disabled", cursor="arrow", selectbackground=SEL)
            sb = ttk.Scrollbar(holder, orient="vertical", command=self.log_text.yview, style="Thin.Vertical.TScrollbar")
            self.log_text.configure(yscrollcommand=sb.set)
            self.log_text.grid(row=0, column=0, sticky="nsew")
            sb.grid(row=0, column=1, sticky="ns")
            self.log_text.tag_configure("time", foreground="#6a6a70")
            self.log_text.tag_configure("info", foreground=TEXT)
            self.log_text.tag_configure("warn", foreground=AMBER)
            self.log_text.tag_configure("error", foreground=RED)

        # ── alerts (what looks suspicious) ───────────────────────────────
        SEV_COLORS = {"high": RED, "medium": AMBER, "low": TEAL, "info": DIM}

        def _build_alerts(self, f):
            f.columnconfigure(0, weight=1)
            f.rowconfigure(2, weight=1)
            chips = ttk.Frame(f)
            chips.grid(row=0, column=0, sticky="ew", pady=(0, 10))
            chips.columnconfigure((0, 1, 2, 3), weight=1, uniform="chip")
            self.sev_filter = tk.StringVar(value="")
            self.chips = {}
            for i, (sev, title) in enumerate((("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info"))):
                card = Card(chips, radius=12, pad=(14, 8))
                card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 5, 0 if i == 3 else 5))
                num = ttk.Label(card.body, text="0", style="Big.TLabel")
                num.grid(row=0, column=0, sticky="w")
                ttk.Label(card.body, text=title.upper(), style="Dim.TLabel").grid(row=0, column=1, sticky="sw", padx=(8, 0), pady=(0, 5))
                sub = ttk.Label(card.body, text=" ", style="Dim.TLabel")
                sub.grid(row=1, column=0, columnspan=2, sticky="w")
                self.chips[sev] = (card, num, sub)
                for w in [card, card.body] + list(card.body.winfo_children()):
                    w.bind("<Button-1>", lambda e, s=sev: self.toggle_sev_filter(s))
                    try:
                        w.configure(cursor="hand2")
                    except tk.TclError:
                        pass
            bar = ttk.Frame(f)
            bar.grid(row=1, column=0, sticky="ew", pady=(0, 10))
            bar.columnconfigure(3, weight=1)
            self.alert_search = tk.StringVar()
            Field(bar, compact=True, textvariable=self.alert_search, width=22, placeholder="Search host or text").grid(row=0, column=0, sticky="w")
            self.rule_var = tk.StringVar(value="All rules")
            rc = Combo(bar, compact=True, textvariable=self.rule_var, state="readonly", width=18,
                       values=["All rules"] + [spec[0] for spec in ztr_proxy_guard.RULES.values()])
            rc.grid(row=0, column=1, padx=(8, 0))
            self.state_var = tk.StringVar(value="Open")
            sc = Combo(bar, compact=True, textvariable=self.state_var, state="readonly", width=12, values=["Open", "New only", "Everything"])
            sc.grid(row=0, column=2, padx=(8, 0))
            Btn(bar, text="Detection rules…", style="Ghost.TButton", command=self.open_rules).grid(row=0, column=4, padx=(8, 0))
            Btn(bar, text="Export…", style="Ghost.TButton", command=self.export_alerts).grid(row=0, column=5, padx=(4, 0))
            Btn(bar, text="Mark all read", style="Ghost.TButton", command=self.ack_all).grid(row=0, column=6, padx=(4, 0))
            cols = [("last", "Last seen"), ("sev", "Severity"), ("rule", "Rule"), ("host", "Host"), ("title", "What happened"),
                    ("count", "Seen"), ("state", "State")]
            frame, self.alert_tree = make_tree(f, cols, (90, 80, 130, 230, 380, 50, 100), height=9, anchors={"count": "e"}, stretch="title")
            frame.grid(row=2, column=0, sticky="nsew")
            for sev, color in self.SEV_COLORS.items():
                self.alert_tree.tag_configure("sev_" + sev, foreground=color)
            self.alert_tree.tag_configure("unread", font=UI["bold"])
            self.alert_tree.tag_configure("done", foreground=DIM)
            self.alert_hint = tk.Label(frame, text="", bg=FIELD, fg=DIM, font=UI["body"], justify="center")
            self.alert_tree.bind("<<TreeviewSelect>>", lambda e: self._alert_selected())
            self.alert_tree.bind("<Double-1>", lambda e: self.ack_selected())
            for v in (self.alert_search, self.rule_var, self.state_var):
                v.trace_add("write", lambda *a: self.refresh_alerts())
            self.rule_var_names = {spec[0]: key for key, spec in ztr_proxy_guard.RULES.items()}
            d = Card(f, radius=12, pad=(16, 10))
            d.grid(row=3, column=0, sticky="ew", pady=(10, 0))
            d.body.columnconfigure(0, weight=1)
            self.alert_title = ttk.Label(d.body, text="Select an alert to see what it is based on.", style="H.TLabel")
            self.alert_title.grid(row=0, column=0, columnspan=6, sticky="w")
            self.alert_evidence = ttk.Label(d.body, text=" ", style="TLabel", wraplength=1040, justify="left")
            self.alert_evidence.grid(row=1, column=0, columnspan=6, sticky="w", pady=(4, 0))
            self.alert_advice = ttk.Label(d.body, text=" ", style="Dim.TLabel", wraplength=1040, justify="left")
            self.alert_advice.grid(row=2, column=0, columnspan=6, sticky="w", pady=(4, 8))
            self.act = {}
            for i, (key, text, style, cmd) in enumerate((
                    ("block", "Block host", "Danger.TButton", self.block_selected_alert),
                    ("trust", "Trust host", "TButton", self.trust_selected_alert),
                    ("watch", "Add to alert list", "TButton", self.watch_selected_alert),
                    ("ack", "Mark read", "TButton", self.ack_selected),
                    ("dismiss", "Dismiss", "Ghost.TButton", self.dismiss_selected),
                    ("copy", "Copy details", "Ghost.TButton", self.copy_alert))):
                b = Btn(d.body, text=text, style=style, command=cmd, state="disabled")
                b.grid(row=3, column=i, sticky="w", padx=(0 if i == 0 else 6, 0))
                self.act[key] = b

        def toggle_sev_filter(self, sev):
            self.sev_filter.set("" if self.sev_filter.get() == sev else sev)
            self.refresh_alerts()

        def alert_rows(self):
            wanted_rule = self.rule_names().get(self.rule_var.get())
            text = self.alert_search.get().strip().lower()
            state = self.state_var.get()
            sev = self.sev_filter.get()
            rows = []
            for a in ztr_proxy.GUARD.store.list():
                if state == "Open" and a["state"] == "dismissed":
                    continue
                if state == "New only" and a["state"] != "new":
                    continue
                if wanted_rule and a["rule"] != wanted_rule:
                    continue
                if sev and a["severity"] != sev:
                    continue
                if text and text not in f"{a['host']} {a['title']} {a['evidence']}".lower():
                    continue
                rows.append(a)
            return rows

        def rule_names(self):
            return {spec[0]: key for key, spec in ztr_proxy_guard.RULES.items()}

        def refresh_alerts(self):
            guard = ztr_proxy.GUARD
            counts = guard.store.counts()
            for sev, (card, num, sub) in self.chips.items():
                n, new = counts.get(sev, 0), counts.get("new_" + sev, 0)
                num.configure(text=str(n), foreground=self.SEV_COLORS[sev] if n else TEXT)
                sub.configure(text=f"{new} new" if new else "all read")
                want = self.SEV_COLORS[sev] if self.sev_filter.get() == sev else BORDER
                if card._border != want:
                    card._border = want
                    card.redraw()
            rows = []
            for a in self.alert_rows():
                tags = ["sev_" + a["severity"]]
                if a["state"] == "new":
                    tags.append("unread")
                elif a["state"] == "dismissed":
                    tags.append("done")
                state = {"new": "new", "acknowledged": "read", "dismissed": "dismissed"}[a["state"]]
                if a["action"]:
                    state += " · blocked"
                rows.append((f"a{a['id']}", (fmt_clock(a["last"]), a["severity"].title(), ztr_proxy_guard.RULES[a["rule"]][0], a["host"], a["title"], a["count"], state), tuple(tags)))
            sel = self.alert_tree.selection()
            sync_tree(self.alert_tree, rows)
            if sel and sel[0] in self.alert_tree.get_children():
                self.alert_tree.selection_set(sel)
            if rows:
                self.alert_hint.place_forget()
            else:
                self.alert_hint.configure(text=("Nothing matches these filters." if guard.store.list() else
                                                "No alerts. The detection rules are watching and will say something here when a connection looks suspicious."))
                self.alert_hint.place(relx=0.5, rely=0.45, anchor="center")
            self._alert_selected()

        def selected_alert(self):
            sel = self.alert_tree.selection()
            return ztr_proxy.GUARD.store.get(int(sel[0][1:])) if sel else None

        def _alert_selected(self):
            a = self.selected_alert()
            guard = ztr_proxy.GUARD
            if not a:
                self.alert_title.configure(text="Select an alert to see what it is based on.")
                self.alert_evidence.configure(text=" ")
                self.alert_advice.configure(text=" ")
                for b in self.act.values():
                    b.configure(state="disabled")
                return
            self.alert_title.configure(text=f"{a['severity'].title()} · {a['title']}")
            self.alert_evidence.configure(text=a["evidence"])
            tail = f"First seen {fmt_clock(a['first'])}, last {fmt_clock(a['last'])}, {a['count']} time{'s' if a['count'] != 1 else ''}."
            if a["action"]:
                tail += f" The host was {a['action']}."
            self.alert_advice.configure(text=ztr_proxy_guard.ADVICE.get(a["rule"], "") + "  " + tail)
            real = not a["host"].startswith("(")
            blocked = real and guard.is_blocked(a["host"], a["port"])
            self.act["block"].configure(state="normal" if real else "disabled", text="Unblock host" if blocked else "Block host",
                                        style="TButton" if blocked else "Danger.TButton")
            self.act["trust"].configure(state="normal" if real and a["rule"] not in ("blocked", "watch") else "disabled",
                                        text="Stop trusting" if real and guard.is_trusted(a["host"]) else "Trust host")
            self.act["watch"].configure(state="normal" if real and a["rule"] != "watch" else "disabled")
            self.act["ack"].configure(state="normal" if a["state"] == "new" else "disabled")
            self.act["dismiss"].configure(state="normal" if a["state"] != "dismissed" else "disabled")
            self.act["copy"].configure(state="normal")

        def block_selected_alert(self):
            a = self.selected_alert()
            if not a or a["host"].startswith("("):
                return
            if ztr_proxy.GUARD.is_blocked(a["host"], a["port"]):
                self.unblock_host(a["host"])
            else:
                self.block_host(a["host"], note=f"from alert: {a['title']}"[:80])
            self.refresh_alerts()

        def trust_selected_alert(self):
            a = self.selected_alert()
            if not a:
                return
            guard = ztr_proxy.GUARD
            if guard.is_trusted(a["host"]):
                guard.untrust(a["host"])
                self.toast(f"{a['host']} is no longer trusted", "info", 1800)
            else:
                guard.trust(a["host"], note="trusted from an alert")
                ztr_proxy.GUARD.store.set_state(a["id"], "dismissed")
                self.toast(f"Trusting {a['host']} — the detection rules will ignore it", "ok")
            self.save_guard()
            self.refresh_alerts()

        def watch_selected_alert(self):
            a = self.selected_alert()
            if a:
                ztr_proxy.GUARD.watch(a["host"], severity="medium", note="from an alert")
                self.save_guard()
                self.toast(f"{a['host']} is on the alert list", "ok", 1800)

        def ack_selected(self):
            a = self.selected_alert()
            if a and a["state"] == "new":
                ztr_proxy.GUARD.store.set_state(a["id"], "acknowledged")
                self.save_guard()
                self.refresh_alerts()

        def dismiss_selected(self):
            a = self.selected_alert()
            if a:
                ztr_proxy.GUARD.store.set_state(a["id"], "dismissed")
                self.save_guard()
                self.refresh_alerts()

        def ack_all(self):
            ztr_proxy.GUARD.store.mark_all("acknowledged", where=lambda a: a["state"] == "new")
            self.save_guard()
            self.refresh_alerts()

        def copy_alert(self):
            a = self.selected_alert()
            if a:
                self.copy(f"[{a['severity'].upper()}] {a['title']}\n{a['evidence']}\nhost: {a['host']}:{a['port']}  rule: {a['rule']}  "
                          f"seen {a['count']}x  first {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a['first']))}  "
                          f"last {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(a['last']))}", "Alert copied")

        def export_alerts(self):
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(parent=self.root, title="Export alerts", defaultextension=".csv", initialfile="ztr-proxy-alerts.csv",
                                                filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
            if path:
                try:
                    n = ztr_proxy.GUARD.store.export(path, "json" if path.endswith(".json") else "csv")
                    self.toast(f"Exported {n} alerts", "ok")
                except OSError as e:
                    self.toast(f"Couldn't export: {e}", "error")

        def open_rules(self):
            win, body = _dialog(self.root, "Detection rules")
            guard = ztr_proxy.GUARD
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Detection rules", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="Each rule looks at connection patterns only; the proxy can't see inside HTTPS. "
                                 "An alert says something looks suspicious, not that a program is malicious.",
                      style="Dim.TLabel", wraplength=460, justify="left").grid(row=1, column=0, sticky="w", pady=(2, 8))
            vars_ = {}
            for i, (key, (title, desc, _on)) in enumerate(ztr_proxy_guard.RULES.items()):
                v = tk.BooleanVar(value=bool(guard.detector.enabled.get(key, True)))
                vars_[key] = v
                Check(body, text=title, variable=v).grid(row=2 + 2 * i, column=0, sticky="w", pady=(6, 0))
                ttk.Label(body, text=desc, style="Dim.TLabel", wraplength=440, justify="left").grid(row=3 + 2 * i, column=0, sticky="w", padx=(26, 0))
            n = 2 + 2 * len(vars_)
            auto = tk.BooleanVar(value=guard.detector.auto_block)
            ttk.Separator(body).grid(row=n, column=0, sticky="ew", pady=12)
            Check(body, text="Block a host automatically when a rule rates it High", variable=auto).grid(row=n + 1, column=0, sticky="w")
            ttk.Label(body, text="Off by default: a rule can be wrong, and a blocked host stays blocked until you unblock it.",
                      style="Dim.TLabel", wraplength=440, justify="left").grid(row=n + 2, column=0, sticky="w", padx=(26, 0))
            popups = tk.BooleanVar(value=bool(self.settings.get("alert_toasts", True)))
            Check(body, text="Show a message when a new alert appears", variable=popups).grid(row=n + 3, column=0, sticky="w", pady=(10, 0))

            def done():
                guard.configure(enabled={k: v.get() for k, v in vars_.items()}, auto_block=auto.get())
                self.settings["alert_toasts"] = popups.get()
                save_settings(self.settings)
                self.save_guard()
                win.destroy()
            Btn(body, text="Done", style="Primary.TButton", command=done).grid(row=n + 4, column=0, sticky="e", pady=(16, 0))
            win.bind("<Escape>", lambda e: win.destroy())
            _place(win, self.root)

        # ── the lists: blocked hosts, alert list, trusted hosts ──────────
        LIST_KINDS = [("block", "Blocked"), ("watch", "Alert list"), ("trust", "Trusted")]

        def _build_blocklist(self, f):
            f.columnconfigure(0, weight=1)
            f.rowconfigure(3, weight=1)
            self.list_kind = tk.StringVar(value="block")
            kinds = ttk.Frame(f)
            kinds.grid(row=0, column=0, sticky="w", pady=(0, 10))
            self.kind_btns = {}
            for i, (key, title) in enumerate(self.LIST_KINDS):
                b = Btn(kinds, text=title, kind="tab", selected=(key == "block"), command=lambda k=key: self.set_list_kind(k))
                b.grid(row=0, column=i, padx=(0, 6))
                self.kind_btns[key] = b
            self.list_blurb = ttk.Label(f, text="", style="BgDim.TLabel", wraplength=1040, justify="left")
            self.list_blurb.grid(row=1, column=0, sticky="w", pady=(0, 10))
            bar = ttk.Frame(f)
            bar.grid(row=2, column=0, sticky="ew", pady=(0, 10))
            bar.columnconfigure(5, weight=1)
            self.list_entry = tk.StringVar()
            self.list_note = tk.StringVar()
            fe = Field(bar, compact=True, textvariable=self.list_entry, width=30, placeholder="host, host:port, address or range")
            fe.grid(row=0, column=0, sticky="w")
            fe.inner.bind("<Return>", lambda e: self.add_list_entry())
            Field(bar, compact=True, textvariable=self.list_note, width=22, placeholder="note (optional)").grid(row=0, column=1, padx=(8, 0))
            self.list_sev = tk.StringVar(value="medium")
            self.list_sev_box = Combo(bar, compact=True, textvariable=self.list_sev, state="readonly", width=8, values=["high", "medium", "low", "info"])
            self.list_sev_box.grid(row=0, column=2, padx=(8, 0))
            self.list_add_btn = Btn(bar, text="Block", style="Primary.TButton", command=self.add_list_entry)
            self.list_add_btn.grid(row=0, column=3, padx=(8, 0))
            self.list_remove_btn = Btn(bar, text="Remove", command=self.remove_list_entry, state="disabled")
            self.list_remove_btn.grid(row=0, column=4, padx=(8, 0))
            self.list_import_btn = Btn(bar, text="Import list…", style="Ghost.TButton", command=self.import_list)
            self.list_import_btn.grid(row=0, column=6, padx=(8, 0))
            Btn(bar, text="Export…", style="Ghost.TButton", command=self.export_list).grid(row=0, column=7, padx=(4, 0))
            cols = [("pattern", "Entry"), ("sev", "Severity"), ("note", "Note"), ("added", "Added"), ("source", "Source"), ("hits", "Matches"), ("last", "Last match")]
            frame, self.list_tree = make_tree(f, cols, (260, 80, 260, 130, 80, 80, 100), height=12, anchors={"hits": "e"}, stretch="note")
            frame.grid(row=3, column=0, sticky="nsew")
            self.list_tree.bind("<<TreeviewSelect>>", lambda e: self.list_remove_btn.configure(state="normal" if self.list_tree.selection() else "disabled"))
            self.list_tree.bind("<Delete>", lambda e: self.remove_list_entry())
            self.list_hint = tk.Label(frame, text="", bg=FIELD, fg=DIM, font=UI["body"], justify="center")
            self.set_list_kind("block")

        BLURBS = {
            "block": "A blocked host is refused before any tunnel is opened — nothing leaves this computer and the route isn't used. "
                     "Blocking example.com also blocks everything under it (www.example.com). Add :port to block one port only.",
            "watch": "Hosts you want to hear about. Connections to them still go through; each contact raises an alert at the severity you choose.",
            "trust": "Hosts the detection rules should leave alone — an update server that checks in on a schedule, say. A blocklist or alert-list entry still applies to them.",
        }

        def set_list_kind(self, kind):
            self.list_kind.set(kind)
            for k, b in self.kind_btns.items():
                b.configure(selected=(k == kind))
            self.list_blurb.configure(text=self.BLURBS[kind])
            self.list_add_btn.configure(text={"block": "Block", "watch": "Add to alert list", "trust": "Trust"}[kind])
            if kind == "watch":
                self.list_sev_box.grid()
            else:
                self.list_sev_box.grid_remove()
            self.list_import_btn.configure(state="normal" if kind == "block" else "disabled")
            self.refresh_blocklist()

        def current_set(self):
            g = ztr_proxy.GUARD
            return {"block": g.blocklist, "watch": g.watchlist, "trust": g.trusted}[self.list_kind.get()]

        def refresh_blocklist(self):
            g = ztr_proxy.GUARD
            kind = self.list_kind.get()
            entries = sorted(self.current_set().entries.values(), key=lambda e: -e.get("added", 0))
            rows = []
            for i, e in enumerate(entries[:1500]):
                hits = g.hits.get(e["pattern"], 0) if kind != "trust" else 0
                last = g.last_hit.get(e["pattern"])
                rows.append((e["pattern"], (e["pattern"], e.get("severity", "") if kind == "watch" else "", e.get("note", ""),
                                            time.strftime("%Y-%m-%d %H:%M", time.localtime(e.get("added", 0))) if e.get("added") else "",
                                            e.get("source", "you") if kind == "block" else "you", hits or "", fmt_clock(last) if last else ""),
                             ("odd",) if i % 2 else ()))
            sel = self.list_tree.selection()
            sync_tree(self.list_tree, rows)
            if sel and sel[0] in self.list_tree.get_children():
                self.list_tree.selection_set(sel)
            if rows:
                self.list_hint.place_forget()
            else:
                self.list_hint.configure(text={"block": "Nothing is blocked.\nAdd a host above, import a list, or block one from an alert.",
                                               "watch": "The alert list is empty.", "trust": "No trusted hosts."}[kind])
                self.list_hint.place(relx=0.5, rely=0.4, anchor="center")
            more = len(entries) - 1500
            if more > 0:
                self.list_blurb.configure(text=self.BLURBS[kind] + f"   (Showing the newest 1500 of {len(entries)}.)")

        def add_list_entry(self):
            text = self.list_entry.get().strip()
            if not text:
                return
            g, kind = ztr_proxy.GUARD, self.list_kind.get()
            try:
                if kind == "block":
                    self.block_host(text, note=self.list_note.get().strip())
                elif kind == "watch":
                    g.watch(text, severity=self.list_sev.get(), note=self.list_note.get().strip())
                    self.toast("Added to the alert list", "ok", 1800)
                else:
                    g.trust(text, note=self.list_note.get().strip())
                    self.toast("Trusted", "ok", 1800)
            except ValueError as e:
                self.toast(f"That can't be added: {e}", "warn")
                return
            self.save_guard()
            self.list_entry.set("")
            self.list_note.set("")
            self.refresh_blocklist()

        def remove_list_entry(self):
            sel = self.list_tree.selection()
            if not sel:
                return
            kind, g = self.list_kind.get(), ztr_proxy.GUARD
            for pattern in sel:
                {"block": g.unblock, "watch": g.unwatch, "trust": g.untrust}[kind](pattern)
            self.save_guard()
            self.toast(("Unblocked " if kind == "block" else "Removed ") + (sel[0] if len(sel) == 1 else f"{len(sel)} entries"), "info", 1800)
            self.refresh_blocklist()

        def import_list(self):
            from tkinter import filedialog
            path = filedialog.askopenfilename(parent=self.root, title="Import a block list")
            if not path:
                return
            try:
                if os.path.getsize(path) > 30 * 1024 * 1024:
                    self.toast("That file is too large (over 30 MB).", "error")
                    return
                text = Path(path).read_text(errors="replace")
            except OSError as e:
                self.toast(f"Couldn't read it: {e}", "error")
                return
            added, dup, skipped = ztr_proxy.GUARD.import_blocklist(text, source=Path(path).name[:20])
            self.save_guard()
            self.toast(f"Blocked {added} new" + (f", {dup} were already there" if dup else "") + (f", {skipped} lines skipped" if skipped else ""), "ok" if added else "info", 4500)
            self.refresh_blocklist()

        def export_list(self):
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(parent=self.root, title="Export this list", defaultextension=".txt", initialfile=f"ztr-proxy-{self.list_kind.get()}.txt")
            if path:
                try:
                    Path(path).write_text("\n".join(sorted(self.current_set().entries)) + "\n")
                    self.toast(f"Exported {len(self.current_set().entries)} entries", "ok")
                except OSError as e:
                    self.toast(f"Couldn't export: {e}", "error")

        # ── blocking, from anywhere in the window ────────────────────────
        def save_guard(self):
            ztr_proxy.GUARD.save()

        def block_host(self, text, note=""):
            """Blocks `text` and cuts any connections to it that are open right now."""
            g = ztr_proxy.GUARD
            entry = g.block(text, note=note)
            cut = 0
            for c in self.tele.snapshot_active():
                if g.blocklist.match(c["host"], c["port"]) is entry or g.blocklist.match(c["host"], c["port"]):
                    cut += 1 if self.tele.close_connection(c["id"]) else 0
            self.save_guard()
            self.toast(f"Blocked {entry['pattern']}" + (f" — closed {cut} open connection{'s' if cut != 1 else ''}" if cut else ""), "ok")
            return entry

        def unblock_host(self, host):
            g = ztr_proxy.GUARD
            entry = g.blocklist.match(host, 0)
            if entry:
                g.unblock(entry["pattern"])
                self.save_guard()
                self.toast(f"Unblocked {entry['pattern']}", "info", 2000)

        # ── the proxy: start, stop, state ────────────────────────────────
        def route_ok(self):
            return self.route_var.get() in list_routes()

        def toggle(self):
            if self.state == "running":
                self.stop()
            elif self.state == "stopped":
                self.start()

        def start(self):
            if self.state != "stopped":
                return
            if not self.route_ok():
                self.toast("Pick a route first.", "warn")
                return
            self.settings["route"] = self.route_var.get()
            save_settings(self.settings)
            self.set_state("starting")
            s = self.settings
            service = ztr_proxy.ProxyService(
                s["route"], host=(s.get("host") or None), port=int(s["port"]), warm_pool=bool(s["warm"]),
                warm_max_age=float(s["max_age"]), warm_min_uses=int(s["min_uses"]), timing_defense=bool(s["timing"]),
                pinned=[tuple(p) for p in s.get("pinned", [])])

            def work():
                try:
                    service.start()
                except OSError as e:
                    self.events.put(("start_failed", f"Port {s['port']} can't be used ({e.strerror or e}). Change it in Settings."))
                except Exception as e:  # a route file that won't load, a missing library, ...
                    self.events.put(("start_failed", f"The proxy couldn't start: {e}"))
                else:
                    self.events.put(("started", service))
            threading.Thread(target=work, daemon=True).start()

        def stop(self):
            service, self.service = self.service, None
            self.set_state("stopped")
            if service:
                threading.Thread(target=service.stop, daemon=True).start()
            self.toast("Proxy stopped", "info", 1800)

        def set_state(self, state):
            self.state = state
            label, color, button = {
                "stopped": ("Stopped", DIM, "Start proxy"),
                "starting": ("Starting…", AMBER, "Starting…"),
                "running": ("Running", GREEN, "Stop proxy"),
            }[state]
            if state == "running" and self.service:
                label = f"Running · {self.service.host}:{self.service.port}"
            self.paint_dot(color)
            self.state_label.configure(text=label)
            self.toggle_btn.configure(text=button, state="disabled" if state == "starting" else "normal",
                                      style="Danger.TButton" if state == "running" else "Primary.TButton")
            self.route_combo.inner.configure(state="disabled" if state != "stopped" else "readonly")
            self.update_addresses()

        def address(self):
            if self.service and self.service.running:
                return self.service.host, self.service.port
            host = ztr_proxy.resolve_host(self.settings.get("host") or None)
            return host, int(self.settings.get("port", ztr_proxy.DEFAULT_PORT))

        def update_addresses(self):
            host, port = self.address()
            self.addr_http.configure(text=f"{host}:{port}")
            self.addr_socks.configure(text=f"socks5h://{host}:{port}")

        # ── route card ───────────────────────────────────────────────────
        def on_route_chosen(self):
            self.settings["route"] = self.route_var.get()
            save_settings(self.settings)
            self.rtts = {}
            self.refresh_route_card(probe=True)

        def refresh_route_card(self, probe=False):
            routes = list_routes()
            self.route_combo.inner.configure(values=routes)
            if self.route_var.get() not in routes:
                self.route_var.set(routes[0] if routes else "")
            name = self.route_var.get()
            chain = route_chain(name) if name else []
            if not routes:
                self.route_note.configure(text="No routes found — add a .ztr file to the routes folder.")
            else:
                self.route_note.configure(text=f"{len(chain)} hops" if chain else "")
                far = max(((r, a) for a, r in self.rtts.items() if r is not None), default=None)
                if far and chain:
                    role = next((ro for ro, ad in chain if ad == far[1]), "")
                    self.route_note.configure(text=f"{len(chain)} hops · the {role} is {far[0]:.0f} ms away, and every round trip pays for the distance")
            if probe and chain:
                def work():
                    result = {}
                    for _role, address in chain:
                        result[address] = tcp_rtt(address)
                    self.events.put(("rtts", name, result))
                threading.Thread(target=work, daemon=True).start()
            self.draw_chain()

        def draw_chain(self):
            chain = route_chain(self.route_var.get())
            nodes = [("This computer", "you", "you")]
            for role, address in chain:
                ms = self.rtts.get(address)
                shown = "hidden hop" if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", address) else address
                sub = shown if ms is None else f"{shown} · {ms:.0f} ms"
                nodes.append((role.title() or "Hop", sub, "exit" if role == "exit" else "hop"))
            if chain:
                nodes.append(("Internet", "the site you visit", "net"))
            else:
                nodes = []
            self.chain.set(nodes, self.state == "running" and bool(self.snap["active"]))

        # ── the refresh loop ─────────────────────────────────────────────
        def _animate(self):
            try:
                self.chain.animate()
                self.root.after(90, self._animate)
            except tk.TclError:  # the window is gone
                pass

        def _tick(self):
            try:
                self._drain_events()
                self.snap = self.tele.snapshot()
                if self.service and self.service.running and self.service.session:
                    self.status = self.service.session.status()
                self._refresh_page()
                self._refresh_footer()
                self._watch_failures()
                self.update_alert_badge()
                ztr_proxy.GUARD.save()
                live = self.state == "running" and bool(self.snap["active"])
                self.chain.set(self.chain.nodes, live)
                self.root.after(500, self._tick)
            except tk.TclError:  # the window is gone
                pass

        def on_alert(self, alert, created, escalated):
            self.events.put(("alert", alert, created, escalated))   # called from the proxy's threads; the window handles it

        def announce_alert(self, alert, created, escalated):
            if not (created or escalated) or not self.settings.get("alert_toasts", True) or ztr_proxy_guard.SEV_RANK[alert["severity"]] < 2:
                return
            now = time.time()
            self._alert_pending += 1
            if now - self._alert_toast_at < 4:
                return
            n, self._alert_pending, self._alert_toast_at = self._alert_pending, 0, now
            text = f"{alert['severity'].title()} alert: {alert['title']}" if n == 1 else f"{n} new alerts, the latest: {alert['title']}"
            self.toast(text[:140], "error" if alert["severity"] == "high" else "warn", 6000)

        def update_alert_badge(self):
            counts = ztr_proxy.GUARD.store.counts()
            n = counts.get("new_high", 0) + counts.get("new_medium", 0)
            label = f"Alerts ({n})" if n else "Alerts"
            if self._alert_label != label:
                self._alert_label = label
                self.tab_btns["alerts"].configure(text=label)

        def _watch_failures(self):
            """A short message when a connection fails, so a problem isn't only visible if you happen to be on the right tab."""
            failed = self.snap["counters"].get("failed", 0)
            if failed < self._failed_seen:
                self._failed_seen = 0
            if failed > self._failed_seen and time.time() - self._failed_toast > 8:
                last = next((c for c in self.snap["recent"] if c["state"] == "failed"), None)
                if last:
                    self.toast(f"Couldn't reach {last['host']} — {str(last['error'])[:90]}", "error", 5000)
                    self._failed_toast = time.time()
            self._failed_seen = failed

        # ── plain-language hints on the overview ─────────────────────────
        MOZILLA = ("mozilla.com", "mozilla.org", "mozilla.net", "firefox.com")

        def pick_insight(self):
            """(key, message, button text, action) for the most useful thing to say right now, or None."""
            snap, c = self.snap, self.snap["counters"]
            counts = ztr_proxy.GUARD.store.counts()
            hi, med = counts.get("new_high", 0), counts.get("new_medium", 0)
            if hi or med:
                what = (f"{hi} high" if hi else "") + (" and " if hi and med else "") + (f"{med} medium" if med else "")
                return (f"alerts:{hi}:{med}", f"{hi + med} new alert{'s' if hi + med != 1 else ''} ({what}) about suspicious connection behaviour.", "Open alerts", lambda: self.show("alerts"))
            if self.state != "running":
                return None
            rows = snap["active"] + snap["recent"]
            tunnels = [r for r in rows if r["kind"] != "HTTP" and r["state"] != "opening"]
            failed = [r for r in rows if r["state"] == "failed"]
            if len(failed) >= 3 and len(failed) / max(1, len(rows)) >= 0.15:
                return ("failures", f"{len(failed)} of your last {len(rows)} connections failed. The Log tab says why.", "Open the log", lambda: self.show("log"))
            pinned = {h for h, _p in self.status.get("pinned", [])}
            by_host = {}
            for r in tunnels:
                if r["setup"] is not None and not r["warm"] and r["host"] not in pinned:
                    by_host.setdefault(r["host"], []).append(r["setup"])
            for host, waits in sorted(by_host.items(), key=lambda kv: -len(kv[1])):
                if len(waits) >= 3 and sum(waits) / len(waits) > 1.0:
                    return (f"repeat:{host}", f"You've opened {host} {len(waits)} times and waited about {fmt_seconds(sum(waits) / len(waits))} for a new tunnel each time. "
                            "Keeping one ready makes the next one instant.", "Keep it ready", lambda h=host: self.pin(h, 443))
            moz = [r for r in tunnels if r["host"].endswith(self.MOZILLA)]
            if len(moz) >= 3 and len(moz) / max(1, len(tunnels)) >= 0.3:
                return ("mozilla", f"{len(moz)} of your last {len(tunnels)} tunnels went to Mozilla's own services, not to pages you opened. They compete with your pages for the route.",
                        "Quiet Firefox…", lambda: self.show("browser"))
            cold = [r["setup"] for r in tunnels if r["setup"] is not None and not r["warm"]][:12]
            if len(cold) >= 3 and sorted(cold)[len(cold) // 2] > 4:
                return ("slow", f"New tunnels are taking {fmt_seconds(sorted(cold)[len(cold) // 2])} right now. Measure shows how far away each hop is; "
                        "a distant exit slows every connection.", "Measure", lambda: self.refresh_route_card(probe=True))
            return None

        def dismiss_insight(self):
            if self.insight_key:
                self.dismissed.add(self.insight_key)
            self.refresh_insight()

        def refresh_insight(self):
            found = self.pick_insight()
            if found and found[0] in self.dismissed:
                found = None
            key = found[0] if found else None
            if key != self.insight_key:
                self.insight_key = key
                if found:
                    self.insight_text.configure(text=found[1])
                    self.insight_btn.configure(text=found[2], command=found[3])
                    self.insight_card.grid()
                else:
                    self.insight_card.grid_remove()

        def _drain_events(self):
            while True:
                try:
                    ev = self.events.get_nowait()
                except queue.Empty:
                    return
                kind = ev[0]
                if kind == "started":
                    self.service = ev[1]
                    self.set_state("running")
                    self.toast(f"Proxy running on {self.service.host}:{self.service.port}", "ok")
                elif kind == "start_failed":
                    self.set_state("stopped")
                    self.toast(ev[1], "error", 6000)
                elif kind == "rtts":
                    if ev[1] == self.route_var.get():
                        self.rtts = ev[2]
                        self.refresh_route_card()
                elif kind == "check":
                    self.show_check(ev[1])
                elif kind == "restart_now":
                    self.start()
                elif kind == "alert":
                    self.announce_alert(*ev[1:])

        def _refresh_page(self, force=False):
            page = self.page
            if page == "overview":
                self.refresh_overview()
            elif page == "connections":
                self.refresh_connections()
            elif page == "hosts":
                self.refresh_hosts()
            elif page == "alerts":
                self.refresh_alerts()
            elif page == "blocklist":
                self.refresh_blocklist()
            elif page == "browser":
                self.refresh_browser()
            elif page == "log":
                self.refresh_log()

        def _refresh_footer(self):
            c = self.snap["counters"]
            if self.state != "running":
                self.foot.configure(text="The proxy is stopped. Start it, then open a browser through it from the Browser page.")
                return
            up = fmt_elapsed(time.time() - self.snap["started"])
            parts = [f"Up {up}", f"{c.get('connections', 0)} connections", f"{c.get('failed', 0)} failed",
                     f"{c.get('retries', 0)} retried"] + ([f"{c['blocked']} blocked"] if c.get("blocked") else []) + [f"{c.get('spares_made', 0)} tunnels prepared ahead",
                     f"{human_bytes(c.get('bytes_down', 0))} received"]
            self.foot.configure(text="  ·  ".join(parts))

        # ── overview ─────────────────────────────────────────────────────
        def refresh_overview(self):
            snap, c = self.snap, self.snap["counters"]
            running = self.state == "running"
            active = snap["active"]
            opening = sum(1 for a in active if a["state"] == "opening")
            self.st_open.set(str(len(active)) if running else "—", f"{opening} still opening" if opening else ("idle" if running and not active else "stopped" if not running else "all connected"),
                             GREEN if active else None)
            spares = self.status.get("spares", [])
            pinned = self.status.get("pinned", [])
            self.st_ready.set(str(len(spares)) if running else "—", f"{len(pinned)} kept ready on purpose" if pinned else "waiting for a repeat visit",
                              TEAL if spares else None)
            series = snap["setup_series"][-30:]
            cold = [v for _t, v, w in series if not w]
            warm = [v for _t, v, w in series if w]
            if cold:
                med = percentile(cold, 0.5)
                self.st_setup.set(fmt_seconds(med), f"new tunnel · {fmt_seconds(percentile(warm, 0.5))} when ready" if warm else "new tunnel", AMBER if med > 5 else None)
            elif warm:
                self.st_setup.set(fmt_seconds(percentile(warm, 0.5)), "ready tunnel", GREEN)
            else:
                self.st_setup.set("—", "no tunnels yet")
            rates = snap["rate_series"]
            if rates:
                up_now = sum(u for _t, u, _d in rates[-3:]) / len(rates[-3:])
                down_now = sum(d for _t, _u, d in rates[-3:]) / len(rates[-3:])
                self.st_traffic.set(human_rate(down_now), f"↑ {human_rate(up_now)}   total ↓ {human_bytes(c.get('bytes_down', 0))}", TEAL if down_now > 1024 else None)
            else:
                self.st_traffic.set("—", "no traffic yet")
            self.refresh_insight()
            self.setup_chart.set(snap["setup_series"][-60:])
            self.rate_chart.set(rates[-120:])
            self.setup_note.configure(text=(f"{len(snap['setup_series'])} tunnels · {c.get('retries', 0)} retried" if snap["setup_series"] else ""))
            self.rate_note.configure(text="")
            rows = self.connection_rows(limit=8)
            sync_tree(self.mini_tree, [(f"o{r[0]}", (r[1], r[2], r[3], r[5], r[7], r[8]), r[9]) for r in rows])

        # ── connections ──────────────────────────────────────────────────
        def connection_rows(self, limit=None, text="", only_problems=False):
            """[(id, time, type, host, tunnel, setup, up, down, state, tags)] — open ones first, then the most recent."""
            now = time.time()
            out = []
            allc = sorted(self.snap["active"], key=lambda c: -c["started"]) + self.snap["recent"]
            for i, c in enumerate(allc):
                if text and text.lower() not in f"{c['host']} {c['detail']}".lower():
                    continue
                failed = c["state"] == "failed"
                if only_problems and not (failed or c["state"] == "blocked"):
                    continue
                if c["state"] == "opening":
                    state, tags = f"opening {fmt_elapsed(now - c['started'])}", ("dim",)
                elif c["state"] == "open":
                    state, tags = f"open {fmt_elapsed(now - c['started'])}", ("open",)
                elif failed:
                    state, tags = "failed", ("failed",)
                elif c["state"] == "blocked":
                    state, tags = "blocked", ("blocked",)
                else:
                    state = (f"HTTP {c['status']}" if c.get("status") else "closed") + f" · {fmt_elapsed((c['ended'] or now) - c['started'])}"
                    tags = ()
                tunnel = "—" if c["kind"] == "HTTP" else ("ready" if c["warm"] else "new") if c["setup"] is not None else "…"
                host = f"{c['host']}:{c['port']}" if c["kind"] != "HTTP" else c["host"] + (f"  {c['detail'].split(' ', 1)[1][:40]}" if c["detail"] else "")
                row_tags = tuple(tags) + (("warm",) if c["warm"] and c["state"] != "failed" and c["kind"] != "HTTP" and not tags else ())
                out.append((c["id"], fmt_clock(c["started"]), c["kind"], host, tunnel, fmt_seconds(c["setup"]), human_bytes(c["up"]),
                            human_bytes(c["down"]), state, row_tags + (("odd",) if i % 2 else ())))
                if limit and len(out) >= limit:
                    break
            return out

        def refresh_connections(self):
            rows = self.connection_rows(text=self.filter_var.get().strip(), only_problems=self.only_problems.get())
            sel = self.conn_tree.selection()
            sync_tree(self.conn_tree, [(f"c{r[0]}", r[1:9], r[9]) for r in rows[:400]])
            if rows:
                self.conn_hint.place_forget()
            else:
                host, port = self.address()
                self.conn_hint.configure(text=("Nothing has connected yet.\nSet your browser's proxy to " + f"{host}:{port}" + " — the Browser tab does it for you.")
                                         if self.state == "running" else "The proxy is stopped.\nStart it to see connections here.")
                self.conn_hint.place(relx=0.5, rely=0.42, anchor="center")
            if sel and sel[0] in self.conn_tree.get_children():
                self.conn_tree.selection_set(sel)
            self._conn_selected()

        def _conn_selected(self):
            sel = self.conn_tree.selection()
            cid = int(sel[0][1:]) if sel else None
            active = {c["id"]: c for c in self.snap["active"]}
            self.close_btn.configure(state="normal" if cid in active else "disabled")
            if cid is None:
                self.detail_label.configure(text="Select a connection to see its details.")
                return
            c = active.get(cid) or next((x for x in self.snap["recent"] if x["id"] == cid), None)
            if not c:
                return
            bits = [f"{c['kind']}  {c['host']}:{c['port']}"]
            if c["detail"]:
                bits.append(c["detail"])
            if c["setup"] is not None:
                bits.append(("Tunnel was ready already" if c["warm"] else "A new tunnel was set up") + f" — {fmt_seconds(c['setup'])}" if c["kind"] != "HTTP"
                            else f"Response after {fmt_seconds(c['setup'])}")
            bits.append(f"Sent {human_bytes(c['up'])}, received {human_bytes(c['down'])}")
            if c["state"] == "blocked":
                bits.append(f"Refused before any tunnel was opened — it matches your blocklist entry {c['error'].split(': ', 1)[-1]}.")
            elif c["error"]:
                bits.append(f"Failed: {c['error']}")
            self.detail_label.configure(text="\n".join(bits), foreground=AMBER if c["state"] == "blocked" else (RED if c["error"] else TEXT))

        def popup(self, tree, menu, event):
            row = tree.identify_row(event.y)
            if row:
                tree.selection_set(row)
                menu.tk_popup(event.x_root, event.y_root)

        def copy_row_host(self, tree):
            sel = tree.selection()
            if sel:
                values = tree.item(sel[0], "values")
                host = values[0] if tree is self.host_tree else values[2]
                self.copy(host.split("  ")[0], "Host copied")

        def pin_from_connection(self):
            sel = self.conn_tree.selection()
            if not sel:
                return
            cid = int(sel[0][1:])
            c = next((x for x in self.snap["active"] + self.snap["recent"] if x["id"] == cid), None)
            if c:
                self.pin(c["host"], c["port"] if c["kind"] != "HTTP" else 443)

        def _host_selected(self):
            sel = self.host_tree.selection()
            self.unpin_btn.configure(state="normal" if sel else "disabled")
            self.watch_btn.configure(state="normal" if sel else "disabled")
            if sel:
                blocked = ztr_proxy.GUARD.is_blocked(sel[0], 0)
                self.block_btn.configure(state="normal", text="Unblock host" if blocked else "Block host", style="TButton" if blocked else "Danger.TButton")
            else:
                self.block_btn.configure(state="disabled", text="Block host", style="Danger.TButton")

        def block_selected_host(self):
            sel = self.host_tree.selection()
            if not sel:
                return
            if ztr_proxy.GUARD.is_blocked(sel[0], 0):
                self.unblock_host(sel[0])
            else:
                self.block_host(sel[0])
            self.refresh_hosts()
            self._host_selected()

        def watch_selected_host(self):
            sel = self.host_tree.selection()
            if sel:
                ztr_proxy.GUARD.watch(sel[0], severity="medium", note="from Hosts")
                self.save_guard()
                self.toast(f"{sel[0]} is on the alert list", "ok", 1800)

        def _connection_host(self):
            sel = self.conn_tree.selection()
            if not sel:
                return None
            cid = int(sel[0][1:])
            return next((x for x in self.snap["active"] + self.snap["recent"] if x["id"] == cid), None)

        def block_from_connection(self):
            c = self._connection_host()
            if c:
                self.block_host(c["host"])

        def watch_from_connection(self):
            c = self._connection_host()
            if c:
                ztr_proxy.GUARD.watch(c["host"], severity="medium", note="from Connections")
                self.save_guard()
                self.toast(f"{c['host']} is on the alert list", "ok", 1800)

        def toggle_pin_selected(self):
            sel = self.host_tree.selection()
            if not sel:
                return
            host = sel[0]
            if any(p[0] == host for p in self.settings.get("pinned", [])):
                self.unpin_selected()
            else:
                self.pin(host, 443)

        def close_selected(self):
            sel = self.conn_tree.selection()
            if sel and self.tele.close_connection(int(sel[0][1:])):
                self.toast("Connection closed", "info", 1500)

        def clear_history(self):
            with self.tele._lock:
                self.tele.recent.clear()
            self.snap = self.tele.snapshot()
            self._refresh_page()

        # ── hosts ────────────────────────────────────────────────────────
        def refresh_hosts(self):
            kept = {h for h, _p in self.status.get("pinned", [])} if self.state == "running" else {h for h, _p in self.settings.get("pinned", [])}
            ready = {s["host"] for s in self.status.get("spares", [])}
            data = {h["host"]: h for h in self.snap["hosts"]}
            for host in kept:
                data.setdefault(host, {"host": host, "count": 0, "warm": 0, "setup_total": 0, "setup_n": 0, "up": 0, "down": 0, "last": 0, "failed": 0})
            rows = []
            for i, h in enumerate(sorted(data.values(), key=lambda h: (h["host"] not in kept, -h["count"], h["host"]))):
                avg = h["setup_total"] / h["setup_n"] if h["setup_n"] else None
                kept_text = ("ready" if h["host"] in ready else "preparing…") if h["host"] in kept and self.state == "running" else ("yes" if h["host"] in kept else "")
                g = ztr_proxy.GUARD
                status = "blocked" if g.is_blocked(h["host"], 0) else ("alert list" if g.watchlist.match(h["host"], 0) else ("trusted" if g.is_trusted(h["host"]) else ""))
                tags = ("warm",) if h["host"] in kept else ()
                if h["failed"] and not tags:
                    tags = ("failed",)
                if status == "blocked":
                    tags = ("blocked",)
                rows.append((h["host"], (h["host"], h["count"], f"{h['warm']}/{h['setup_n']}" if h["setup_n"] else "—", fmt_seconds(avg),
                                         human_bytes(h["up"]), human_bytes(h["down"]), h["failed"] or "", fmt_clock(h["last"]) if h["last"] else "", kept_text, status),
                             tags + (("odd",) if i % 2 else ())))
            sel = self.host_tree.selection()
            sync_tree(self.host_tree, rows)
            if sel and sel[0] in self.host_tree.get_children():
                self.host_tree.selection_set(sel)
            n = len(kept)
            renew = int(self.settings.get("max_age", 150) * ztr_proxy.PIN_RENEW_AT)
            per_minute = n * 60.0 / max(30, renew)
            self.pin_note.configure(text=f"{n} kept ready — about {per_minute:.1f} extra tunnel setups a minute" if n else "")

        def pin_typed(self):
            text = self.pin_var.get().strip()
            if not text:
                return
            host, _, port = text.partition(":")
            host = host.strip().lower()
            if not re.fullmatch(r"[a-z0-9._-]+", host or ""):
                self.toast("That doesn't look like a host name.", "warn")
                return
            try:
                port = int(port or 443)
            except ValueError:
                self.toast("The port should be a number.", "warn")
                return
            self.pin(host, port)
            self.pin_var.set("")

        def pin(self, host, port):
            pins = [list(p) for p in self.settings.get("pinned", []) if tuple(p) != (host, port)] + [[host, port]]
            self.settings["pinned"] = pins
            save_settings(self.settings)
            if self.service and self.service.running:
                self.service.session.pin(host, port)
            self.toast(f"Keeping {host} ready" + ("" if self.state == "running" else " — it starts with the proxy"), "ok")
            self.refresh_hosts()

        def unpin_selected(self):
            sel = self.host_tree.selection()
            if not sel:
                return
            host = sel[0]
            for p in [tuple(x) for x in self.settings.get("pinned", []) if x[0] == host]:
                if self.service and self.service.running:
                    self.service.session.unpin(*p)
            self.settings["pinned"] = [p for p in self.settings.get("pinned", []) if p[0] != host]
            save_settings(self.settings)
            self.toast(f"{host} is no longer kept ready", "info", 1800)
            self.refresh_hosts()

        # ── browser ──────────────────────────────────────────────────────
        def refresh_browser(self):
            self.update_addresses()

        def save_prefs(self):
            self.settings["quiet"], self.settings["webrtc"] = self.quiet_var.get(), self.webrtc_var.get()
            save_settings(self.settings)

        def prefs(self):
            host, port = self.address()
            return proxy_prefs(host, port, self.quiet_var.get(), self.webrtc_var.get())

        def need_running(self):
            if self.state != "running":
                self.toast("Start the proxy first.", "warn")
                return False
            return True

        def copy_curl(self):
            host, port = self.address()
            self.copy(f"curl -x http://{host}:{port} https://example.com/\n"
                      f"curl --socks5-hostname {host}:{port} https://example.com/", "curl examples copied")

        def run_check(self):
            if not self.need_running():
                return
            host, port = self.address()
            self.test_btn.configure(state="disabled", text="Testing…")
            self.test_result.configure(text="Opening a tunnel and loading https://example.com …", foreground=DIM)
            threading.Thread(target=lambda: self.events.put(("check", check_connection(host, port))), daemon=True).start()

        def show_check(self, r):
            self.test_btn.configure(state="normal", text="Test connection")
            if r["ok"]:
                self.test_result.configure(text=f"Works — the page loaded in {fmt_seconds(r['total'])} "
                                                f"(tunnel after {fmt_seconds(r['tunnel'])}). {r['detail']}", foreground=GREEN)
            else:
                self.test_result.configure(text=f"That didn't work: {r['detail']}", foreground=RED)

        def current_browser(self):
            for b in self.browsers:
                if b["label"] == self.browser_var.get():
                    return b
            return None

        def browser_chosen(self):
            b = self.current_browser()
            if not b:
                self.open_btn.configure(text="Open browser through ZTR", state="disabled")
                self.browser_note.configure(text="No supported browser was found. Set your browser's proxy to the address on the left instead.")
                return
            self.settings["browser"] = b["key"]
            save_settings(self.settings)
            self.open_btn.configure(text=f"Open {b['name']} through ZTR", state="normal")
            self.browser_note.configure(text=f"Uses a separate profile, so your normal {b['name']} stays exactly as it is.")

        def open_browser(self):
            if not self.need_running():
                return
            b = self.current_browser()
            host, port = self.address()
            error = launch_browser(b, host, port, self.quiet_var.get(), self.webrtc_var.get())
            self.toast(error or f"{b['name']} is opening with the proxy set", "error" if error else "ok")

        def reload_profiles(self):
            self.profiles = firefox_profiles()
            names = [f"{n}{'  (default)' if d else ''}" for n, _p, d in self.profiles]
            self.profile_combo.inner.configure(values=names)
            if names and not self.profile_var.get():
                self.profile_var.set(names[0])
            self.profile_chosen()

        def current_profile(self):
            names = [f"{n}{'  (default)' if d else ''}" for n, _p, d in self.profiles]
            try:
                return self.profiles[names.index(self.profile_var.get())]
            except ValueError:
                return None

        def profile_chosen(self):
            prof = self.current_profile()
            if not prof:
                self.profile_note.configure(text="No Firefox profiles were found on this computer." if not self.profiles else "")
                self.apply_btn.configure(state="disabled")
                self.remove_btn.configure(state="disabled")
                return
            has = profile_has_block(prof[1])
            self.apply_btn.configure(state="normal", text="Update proxy settings" if has else "Add proxy settings")
            self.remove_btn.configure(state="normal" if has else "disabled")
            self.profile_note.configure(
                text=("The proxy settings are in this profile. They apply the next time Firefox starts." if has else
                      "Nothing is changed in this profile until you press the button; your own settings in it are kept."),
                foreground=GREEN if has else DIM)

        def apply_profile(self):
            prof = self.current_profile()
            if prof:
                try:
                    apply_user_js(prof[1], self.prefs())
                except OSError as e:
                    self.toast(f"Couldn't write to the profile: {e}", "error")
                    return
                self.toast("Added. Restart Firefox to use the proxy.", "ok")
                self.profile_chosen()

        def remove_profile(self):
            prof = self.current_profile()
            if prof and remove_user_js_block(prof[1]):
                self.toast("Removed. Firefox goes back to its own settings next start.", "ok")
            self.profile_chosen()

        # ── log ──────────────────────────────────────────────────────────
        LEVELS = {"Everything": {"info", "warn", "error"}, "Warnings and errors": {"warn", "error"}, "Errors only": {"error"}}

        def _append_log(self, rows):
            wanted = self.LEVELS[self.level_var.get()]
            self.log_text.configure(state="normal")
            at_end = self.log_text.yview()[1] >= 0.98
            for ts, level, text in rows:
                if level not in wanted:
                    continue
                self.log_text.insert("end", fmt_clock(ts) + "  ", "time")
                self.log_text.insert("end", text.replace("\n", " ") + "\n", level)
            if int(self.log_text.index("end-1c").split(".")[0]) > 1500:
                self.log_text.delete("1.0", "300.0")
            if at_end:
                self.log_text.see("end")
            self.log_text.configure(state="disabled")

        def refresh_log(self):
            if self.pause_var.get():
                return
            total = self.snap["counters"].get("log_lines", 0)
            fresh = total - self._log_seen
            if fresh < 0:  # the counters were reset (proxy restarted)
                self.rebuild_log()
                return
            if fresh:
                self._append_log(self.snap["logs"][-min(fresh, len(self.snap["logs"])):])
                self._log_seen = total

        def rebuild_log(self):
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")
            self._append_log(self.snap["logs"])
            self._log_seen = self.snap["counters"].get("log_lines", 0)

        def clear_log(self):
            with self.tele._lock:
                self.tele.logs.clear()
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")

        def copy_log(self):
            self.copy(self.log_text.get("1.0", "end").strip(), "Log copied")

        # ── settings ─────────────────────────────────────────────────────
        def open_settings(self):
            if self.settings_win is not None and self.settings_win.winfo_exists():
                self.settings_win.lift()
                return
            win, body = _dialog(self.root, "Settings")
            self.settings_win = win
            body.columnconfigure(1, weight=1)
            s = self.settings
            port = tk.StringVar(value=str(s["port"]))
            host = tk.StringVar(value=s.get("host") or "")
            warm = tk.BooleanVar(value=bool(s["warm"]))
            uses = tk.StringVar(value=str(s["min_uses"]))
            age = tk.StringVar(value=str(int(s["max_age"])))
            timing = tk.BooleanVar(value=bool(s["timing"]))
            auto = tk.BooleanVar(value=bool(s["autostart"]))
            ttk.Label(body, text="Settings", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")

            def section(row, text):
                ttk.Label(body, text=text.upper(), style="Dim.TLabel").grid(row=row, column=0, columnspan=2, sticky="w", pady=(16, 6))

            def hint(row, text, indent=False):
                ttk.Label(body, text=text, style="Dim.TLabel", wraplength=400, justify="left").grid(
                    row=row, column=0 if indent else 1, columnspan=2 if indent else 1, sticky="w", padx=(26, 0) if indent else 0, pady=(2, 0))
            section(1, "Address")
            ttk.Label(body, text="Port").grid(row=2, column=0, sticky="w", padx=(0, 16))
            Field(body, compact=True, textvariable=port, width=8).grid(row=2, column=1, sticky="w")
            ttk.Label(body, text="Listen on").grid(row=3, column=0, sticky="w", padx=(0, 16), pady=(10, 0))
            Field(body, compact=True, textvariable=host, width=18, placeholder="automatic").grid(row=3, column=1, sticky="w", pady=(10, 0))
            hint(4, f"Automatic is {ztr_proxy.DEFAULT_HOST_CANDIDATE} when this computer has it, otherwise {ztr_proxy.FALLBACK_HOST}. "
                    "Anything else lets other computers use your route.")
            section(5, "Speed")
            Check(body, text="Prepare tunnels ahead for sites I come back to", variable=warm).grid(row=6, column=0, columnspan=2, sticky="w")
            hint(7, "A tunnel waits for a repeat visit, so the next connection to that site doesn't wait for the route.", indent=True)
            ttk.Label(body, text="Prepare after this many visits").grid(row=8, column=0, sticky="w", padx=(0, 16), pady=(12, 0))
            Field(body, compact=True, textvariable=uses, width=5).grid(row=8, column=1, sticky="w", pady=(12, 0))
            ttk.Label(body, text="Keep a ready tunnel for (seconds)").grid(row=9, column=0, sticky="w", padx=(0, 16), pady=(10, 0))
            Field(body, compact=True, textvariable=age, width=5).grid(row=9, column=1, sticky="w", pady=(10, 0))
            section(10, "Privacy")
            Check(body, text="Timing defense", variable=timing).grid(row=11, column=0, columnspan=2, sticky="w")
            hint(12, "The hops add random delays and decoy traffic to every tunnel, which makes traffic harder to match up — and slower.", indent=True)
            section(13, "Window")
            Check(body, text="Start the proxy when this window opens", variable=auto).grid(row=14, column=0, columnspan=2, sticky="w")
            note = ttk.Label(body, text="", style="Dim.TLabel")
            note.grid(row=15, column=0, columnspan=2, sticky="w", pady=(12, 0))

            def done():
                try:
                    new = dict(s, port=int(port.get()), host=host.get().strip(), warm=warm.get(), min_uses=max(1, int(uses.get())),
                               max_age=max(20, float(age.get())), timing=timing.get(), autostart=auto.get())
                    if not 1 <= new["port"] <= 65535:
                        raise ValueError
                except ValueError:
                    note.configure(text="The port, visits and seconds need to be numbers.", foreground=RED)
                    return
                changed = any(new[k] != s[k] for k in ("port", "host", "warm", "min_uses", "max_age", "timing"))
                s.update(new)
                save_settings(s)
                self.settings_win = None
                win.destroy()
                self.update_addresses()
                if changed and self.state == "running":
                    self.toast("Restarting the proxy to apply the changes…", "info")
                    self.restart()
            Btn(body, text="Done", style="Primary.TButton", command=done).grid(row=16, column=0, columnspan=2, sticky="e", pady=(18, 0))
            win.bind("<Escape>", lambda e: (setattr(self, "settings_win", None), win.destroy()))
            win.bind("<Return>", lambda e: done())
            win.protocol("WM_DELETE_WINDOW", lambda: (setattr(self, "settings_win", None), win.destroy()))
            _place(win, self.root)

        def restart(self):
            service, self.service = self.service, None
            self.set_state("stopped")

            def work():
                if service:
                    service.stop()
                self.events.put(("restart_now",))
            threading.Thread(target=work, daemon=True).start()

        def on_close(self):
            self.settings["route"] = self.route_var.get()
            save_settings(self.settings)
            try:
                ztr_proxy.GUARD.detector.listeners.remove(self.on_alert)
            except ValueError:
                pass
            ztr_proxy.GUARD.save(force=True)
            if self.service:
                try:
                    self.service.stop()
                except Exception:
                    pass
            self.root.destroy()

    return App, tk


def main():
    import argparse
    parser = argparse.ArgumentParser(description="A window for the ZTRelay proxy.")
    parser.add_argument("--route", help="a route file in routes/ (default: the one used last)")
    parser.add_argument("--start", action="store_true", help="start the proxy as soon as the window opens")
    parser.add_argument("--write-icon", metavar="PATH", help="write the window's icon to PATH as a PNG and exit (the installer uses it for the applications-menu entry)")
    args = parser.parse_args()
    if args.write_icon:
        Path(args.write_icon).parent.mkdir(parents=True, exist_ok=True)
        Path(args.write_icon).write_bytes(logo_png(128))
        return
    App, tk = build_app()
    root = tk.Tk()
    App(root, route=args.route, autostart=args.start)
    root.mainloop()


if __name__ == "__main__":
    main()
