#!/usr/bin/env python3
"""ZTRelay Setup — a window for installing ztrclient.

Looks at this computer, lets you pick what to set up (the command-line tools,
the background tunnel service, the dashboard, the request composer, Ferry and
ZTR Proxy), then runs the installer for your system with those choices and
shows what it is doing. Nothing here replaces the installers: it calls
installer-linux.sh or installer-macos.sh with their normal options.

    python3 installer_gui.py

Needs only Python's standard library, tkinter included (on a Mac, a Python
with Tk 8.6 or newer). Runs on Linux and macOS.
"""
import base64
import json
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
APP_NAME = "ZTRelay Setup"
TAGLINE = "Install the ZTRelay client"
IS_MAC = sys.platform == "darwin"
INSTALLER = os.path.join(SCRIPT_DIR, "installer-macos.sh" if IS_MAC else "installer-linux.sh")
ROUTES_DIR = Path(SCRIPT_DIR) / "routes"
DEFAULT_PREFIX = str(Path.home() / ".local" / "bin")
DEFAULT_VENV = str(Path.home() / ".local" / "share" / "ztr" / "ztr_venv")
DEFAULT_LOCAL_IP = "10.10.15.10"

BG, RAIL, CARD, FIELD, BORDER = "#1c1c1e", "#171719", "#262629", "#1a1a1c", "#3a3a3d"
TEXT, DIM = "#f2f2f7", "#8e8e93"
CYAN, PURPLE, GREEN, RED, AMBER = "#0a84ff", "#bf5af2", "#30d158", "#ff453a", "#ffb340"
SEL, TEAL = "#0a64d6", "#64d2ff"


# ── what the installer needs, and what this computer has ────────────────────

def _run(argv, timeout=8):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def python_info(path):
    """(version tuple, has Tk 8.6+) for a Python, or None if it can't run."""
    code = ("import sys\n"
            "try:\n import tkinter; tk = tkinter.TkVersion\nexcept Exception:\n tk = 0\n"
            "print('%d.%d.%d %s' % (sys.version_info[0], sys.version_info[1], sys.version_info[2], tk))")
    rc, out = _run([path, "-c", code])
    if rc != 0 or not out:
        return None
    try:
        ver, tk = out.split()[-2:]
        return tuple(int(x) for x in ver.split(".")), float(tk) >= 8.6
    except ValueError:
        return None


def candidate_pythons():
    names = [os.environ.get("ZTR_PYTHON", ""), sys.executable, "python3", "python3.14", "python3.13", "python3.12"]
    if IS_MAC:
        names += ["/opt/homebrew/bin/python3.14", "/opt/homebrew/bin/python3.13", "/opt/homebrew/bin/python3.12",
                  "/usr/local/bin/python3.14", "/usr/local/bin/python3.13", "/usr/local/bin/python3.12",
                  "/Library/Frameworks/Python.framework/Versions/Current/bin/python3"]
    seen = []
    for n in names:
        p = shutil.which(n) if n else None
        if p and p not in seen:
            seen.append(p)
    return seen


def find_python(want_tk=True):
    """The best Python for ztrclient: 3.12 or newer, with Tk 8.6+ if there is one. (path, version, has_tk) or None."""
    best = None
    for path in candidate_pythons():
        if path == "/usr/bin/python3" and IS_MAC and _run(["xcode-select", "-p"])[0] != 0:
            continue  # the stub that opens an install dialog
        info = python_info(path)
        if not info or info[0] < (3, 12):
            continue
        if info[1] or not want_tk:
            return path, info[0], info[1]
        best = best or (path, info[0], info[1])
    return best


def system_name():
    if IS_MAC:
        rc, out = _run(["sw_vers", "-productVersion"])
        return "macOS", ("macOS " + out) if rc == 0 and out else "macOS"
    pretty = ""
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "Linux", pretty or "Linux"


def gather_checks():
    """What this computer has, as rows: key, title, status ('ok' | 'warn' | 'bad'), detail, hint (a command or None)."""
    rows = []
    kind, pretty = system_name()
    rows.append(dict(key="system", title="Operating system", status="ok", detail=pretty, hint=None))
    found = find_python(True)
    pkg = "brew install python@3.13" if IS_MAC else "sudo apt install python3"
    if not found:
        rows.append(dict(key="python", title="Python 3.12 or newer", status="bad", detail="Not found — ztrClient.py needs it", hint=pkg))
    else:
        path, ver, tk = found
        rows.append(dict(key="python", title="Python 3.12 or newer", status="ok", detail="%d.%d.%d  ·  %s" % (ver + (path,)), hint=None))
        if tk:
            rows.append(dict(key="tk", title="Tk for windows (Ferry, ZTR Proxy)", status="ok", detail="Ready", hint=None))
        else:
            hint = "brew install python-tk@%d.%d" % ver[:2] if IS_MAC else "sudo apt install python3-tk"
            rows.append(dict(key="tk", title="Tk for windows (Ferry, ZTR Proxy)", status="warn", detail="Missing — the two windows need it", hint=hint))
        rc, _ = _run([path, "-c", "import venv, ensurepip"])
        if rc != 0:
            rows.append(dict(key="venv", title="Python virtual environments", status="bad", detail="The venv module is missing",
                             hint="sudo apt install python3-venv"))
    if IS_MAC:
        ok = shutil.which("launchctl") is not None
        rows.append(dict(key="services", title="Background services (launchd)", status="ok" if ok else "bad", detail="Ready" if ok else "launchctl not found", hint=None))
    else:
        ok = shutil.which("systemctl") is not None
        rows.append(dict(key="services", title="Background services (systemd)", status="ok" if ok else "warn",
                         detail="Ready" if ok else "systemctl not found — the background services can't be set up", hint=None))
    rows.append(dict(key="ssh", title="ssh", status="ok" if shutil.which("ssh") else "warn",
                     detail="Ready" if shutil.which("ssh") else "Not found — Ferry and ztr_ssh need it",
                     hint=None if shutil.which("ssh") else ("sudo apt install openssh-client" if not IS_MAC else None)))
    rsync = shutil.which("rsync")
    rows.append(dict(key="rsync", title="rsync", status="ok" if rsync else "warn", detail="Ready" if rsync else "Not found — Ferry needs it for folders",
                     hint=None if rsync else ("brew install rsync" if IS_MAC else "sudo apt install rsync")))
    return rows


def list_routes():
    try:
        return sorted(p.name for p in ROUTES_DIR.glob("*.ztr"))
    except OSError:
        return []


def build_command(sel):
    """The installer command line and what to feed its stdin, for these choices.
    sel: service, dashboard, requests, ferry, proxy (bools); local_ip (bool), ip, route, prefix, venv."""
    argv = ["bash", INSTALLER]
    for key, flag in (("service", "--with-service"), ("dashboard", "--with-dashboard"), ("requests", "--with-requests"),
                      ("ferry", "--with-ferry"), ("proxy", "--with-proxy")):
        if sel.get(key):
            argv.append(flag)
    needs_ip = sel.get("service") or sel.get("local_ip")
    if needs_ip:
        argv += ["--with-local-ip", "--local-ip", sel.get("ip") or DEFAULT_LOCAL_IP]
    if sel.get("prefix") and sel["prefix"] != DEFAULT_PREFIX:
        argv += ["--prefix", sel["prefix"]]
    if sel.get("venv") and sel["venv"] != DEFAULT_VENV:
        argv += ["--venv-dir", sel["venv"]]
    stdin = ""
    if sel.get("service") or sel.get("dashboard"):
        stdin = (sel.get("route") or "") + "\n"  # the installer asks which route file the service should use
    return argv, stdin


# What the installer prints as it moves from one stage to the next.
STAGES = [
    ("check", "Checking this computer", re.compile(r"checking prerequisites|python3 found|using Python"), lambda s: True),
    ("env", "Preparing the Python environment", re.compile(r"venv|pycryptodome"), lambda s: True),
    ("cmds", "Installing the commands", re.compile(r"installing wrappers"), lambda s: True),
    ("ferry", "Setting up Ferry", re.compile(r"setting up Ferry"), lambda s: s.get("ferry")),
    ("proxy", "Setting up ZTR Proxy", re.compile(r"setting up ZTR Proxy"), lambda s: s.get("proxy")),
    ("ip", "Adding the dedicated address", re.compile(r"ztr_i0|loopback alias|lo0"), lambda s: s.get("service") or s.get("local_ip")),
    ("service", "Starting the tunnel service", re.compile(r"setting up ztr_tunnel_lp"), lambda s: s.get("service")),
    ("dashboard", "Starting the dashboard", re.compile(r"setting up ztr_dashboard"), lambda s: s.get("dashboard")),
    ("requests", "Starting the request composer", re.compile(r"setting up ztr_requests"), lambda s: s.get("requests")),
]
WARN_WORDS = re.compile(r"couldn't|isn't|wasn't|not found|skipping|no Tk|failed|can't|missing|older than", re.I)
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def stages_for(sel):
    return [(k, title, rx) for k, title, rx, want in STAGES if want(sel)]


def detect_rc_file():
    shell = os.path.basename(os.environ.get("SHELL", ""))
    if shell == "zsh":
        return Path.home() / ".zshrc"
    if shell == "bash":
        return Path.home() / (".bash_profile" if IS_MAC else ".bashrc")
    return Path.home() / ".profile"


def add_lines_to_rc(lines):
    """Appends the PATH/alias lines the installer suggested (each already ends in its own marker comment) to the shell's
    rc file, skipping any that are already there. Returns (path, number added)."""
    rc = detect_rc_file()
    try:
        existing = rc.read_text()
    except OSError:
        existing = ""
    have = set(existing.splitlines())
    new = [l for l in lines if l not in have]
    if new:
        with open(rc, "a") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write("\n" + "\n".join(new) + "\n")
    return rc, len(new)


# ── your account: key, route, secret key ─────────────────────────────────────
# These are the things ztrClient.py reads from its own folder, plus what the launcher does by hand.

DASHBOARD_URL = "https://ztrelay.net/dashboard"
SECRET_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def is_secret_key(value):
    return isinstance(value, str) and SECRET_KEY_RE.match(value.strip()) is not None


def account_paths(base):
    base = Path(base)
    return dict(private=base / "privateKey.pem", public=base / "publicKey.pem", env=base / ".env", routes=base / "routes")


def key_status(base):
    """Does this folder have a key pair? Returns dict(ok, fingerprint, public) — never anything from the private key."""
    paths = account_paths(base)
    if not (paths["private"].is_file() and paths["public"].is_file()):
        return dict(ok=False, fingerprint="", public="")
    try:
        pem = paths["public"].read_text()
        body = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
        digest = __import__("hashlib").sha256(base64.b64decode(body)).hexdigest()
    except (OSError, ValueError):
        return dict(ok=False, fingerprint="", public="")
    return dict(ok=True, fingerprint=" ".join(digest[i:i + 4] for i in range(0, 16, 4)), public=pem)


def read_env_secret(base):
    """The secret_key line of the .env next to ztrClient.py (same rules ztrClient.py uses); None if there is none."""
    try:
        lines = account_paths(base)["env"].read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    found = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        name, sep, value = line.partition("=")
        if not sep or name.strip().lower() != "secret_key":
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].strip()
        found = value.strip()
    return found


def write_env_secret(base, value):
    """Saves the secret key in the .env next to ztrClient.py, keeping every other line, readable by you alone."""
    value = value.strip()
    if not is_secret_key(value):
        raise ValueError("a secret key is 64 hex characters")
    path = account_paths(base)["env"]
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    kept = []
    for line in lines:
        probe = line.strip()
        if probe.startswith("export "):
            probe = probe[len("export "):].lstrip()
        if probe.partition("=")[0].strip().lower() == "secret_key" and "=" in probe:
            continue
        kept.append(line)
    kept.append("secret_key=" + value)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(kept) + "\n")
    os.replace(str(tmp), str(path))
    os.chmod(str(path), 0o600)
    return path


def check_route_file(path):
    """(ok, problem, info) for a .ztr file: it must be JSON with the fields the client needs."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return False, "isn't a readable .ztr file (%s)" % (e.__class__.__name__,), {}
    if not isinstance(data, dict):
        return False, "isn't a .ztr file", {}
    missing = [k for k in ("route_id", "identifier", "chain", "hop_settings") if k not in data]
    if missing:
        return False, "is missing " + ", ".join(missing), {}
    chain = data.get("chain")
    if not isinstance(chain, list) or len(chain) < 2:
        return False, "has no hops", {}
    return True, "", dict(hops=len(chain), secret=is_secret_key(data.get("secret_key")))


def route_files(base):
    """Every .ztr in routes/, as dicts: name, ok, problem, hops, secret (does the file itself hold a real key)."""
    out = []
    try:
        names = sorted(p.name for p in account_paths(base)["routes"].glob("*.ztr"))
    except OSError:
        names = []
    for name in names:
        ok, problem, info = check_route_file(account_paths(base)["routes"] / name)
        out.append(dict(name=name, ok=ok, problem=problem, hops=info.get("hops", 0), secret=info.get("secret", False)))
    return out


def downloaded_routes(days=45):
    """Route files that look like they were just downloaded: *.ztr in Downloads, newest first."""
    found = []
    now = time.time()
    folder = Path.home() / "Downloads"
    try:
        for p in folder.glob("*.ztr"):
            age = now - p.stat().st_mtime
            if age <= days * 86400 and check_route_file(p)[0]:
                found.append((p.stat().st_mtime, p))
    except OSError:
        pass
    return [p for _t, p in sorted(found, reverse=True)]


def import_route(base, source, overwrite=False):
    """Copies a downloaded .ztr into routes/. Returns the new path; raises ValueError with a plain reason."""
    source = Path(source)
    ok, problem, _info = check_route_file(source)
    if not ok:
        raise ValueError("%s %s" % (source.name, problem))
    if not re.match(r"^[A-Za-z0-9._-]+\.ztr$", source.name):
        raise ValueError("the file name %r has characters a route name can't have" % source.name)
    folder = account_paths(base)["routes"]
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / source.name
    if target.exists() and not overwrite:
        raise FileExistsError(source.name)
    shutil.copyfile(str(source), str(target))
    os.chmod(str(target), 0o600)
    return target


def account_summary(base):
    """What is done and what is left: dict of key, route, secret (each True/False) plus the pieces behind them."""
    key = key_status(base)
    routes = route_files(base)
    good = [r for r in routes if r["ok"]]
    env_secret = read_env_secret(base)
    env_ok = is_secret_key(env_secret)
    secret_ok = env_ok or (bool(good) and all(r["secret"] for r in good))
    return dict(key=key, routes=routes, route=bool(good), env=env_ok, env_bad=bool(env_secret) and not env_ok,
                secret=secret_ok, ready=key["ok"] and bool(good) and secret_ok)


# Runs in the installer's Python environment (it has pycryptodome); input and output are JSON, so nothing secret is on a command line.
_KEY_SCRIPT = r'''
import json, os, sys
base, action = sys.argv[1], sys.argv[2]
sys.path.insert(0, base)
from utils.crypt_bot import CryptBot
crypt = CryptBot(pathPrivateKey=os.path.join(base, "privateKey.pem"), pathPublicKey=os.path.join(base, "publicKey.pem"), pathRecipientPublicKey="")
req = json.loads(sys.stdin.read() or "{}")
crypt.create_keys(rsa_size=3072, reuse=True)
os.chmod(crypt.pathPrivateKey, 0o600)  # the key is written readable by everyone; it should be readable by you alone
if action == "create":
    print(json.dumps({"public": open(crypt.pathPublicKey).read()}))
elif action == "sign":
    print(json.dumps({"signature": crypt.sign_(req["nonce"]).hex(), "public": open(crypt.pathPublicKey).read()}))
'''

_TEST_SCRIPT = r'''
import json, os, sys, time
base, route = sys.argv[1], sys.argv[2]
sys.path[:0] = [os.path.join(base, "plugins"), base]
try:
    import ztr_https
    t0 = time.time()
    resp = ztr_https.Session(config_file=route).request("GET", "http://example.com/", timeout=75)
    print(json.dumps({"ok": 200 <= resp.status_code < 400, "status": resp.status_code, "bytes": len(resp.content), "seconds": round(time.time() - t0, 1)}))
except Exception as e:
    print(json.dumps({"ok": False, "error": "%s: %s" % (e.__class__.__name__, str(e)[:240])}))
'''


def venv_python(venv):
    return os.path.join(venv or DEFAULT_VENV, "bin", "python3")


def run_in_venv(venv, script, args, stdin_json=None, timeout=120):
    """Runs one of the scripts above with the installer's Python. Returns (ok, parsed JSON or an error text)."""
    py = venv_python(venv)
    if not os.path.isfile(py):
        return False, "The Python environment isn't set up yet (%s). Run the install step first." % py
    try:
        p = subprocess.run([py, "-c", script] + args, input=json.dumps(stdin_json or {}), capture_output=True, text=True,
                           timeout=timeout, cwd=SCRIPT_DIR)
    except subprocess.TimeoutExpired:
        return False, "That took longer than %d seconds." % timeout
    except OSError as e:
        return False, "Couldn't run Python: %s" % e
    lines = [l for l in p.stdout.splitlines() if l.strip().startswith("{")]
    if p.returncode != 0 or not lines:
        tail = (p.stderr or p.stdout).strip().splitlines()[-1:] or ["no output"]
        if "No module named 'Crypto'" in (p.stderr or ""):
            return False, "pycryptodome isn't installed in that environment — run the install step again."
        return False, tail[0][:240]
    try:
        return True, json.loads(lines[-1])
    except ValueError:
        return False, "Unexpected output from Python."


# ── the window's picture ─────────────────────────────────────────────────────

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

    # ── small pieces of this window ──────────────────────────────────────────

    class Switch(tk.Canvas):
        """An on/off switch tied to a BooleanVar."""

        def __init__(self, parent, variable, command=None, disabled=False):
            super().__init__(parent, width=42, height=24, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._var, self._command, self._disabled = variable, command, disabled
            variable.trace_add("write", lambda *a: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<ButtonRelease-1>", lambda e: self.toggle())
            self.bind("<space>", lambda e: self.toggle())

        def toggle(self):
            if self._disabled:
                return
            self._var.set(not self._var.get())
            if self._command:
                self._command()

        def _draw(self):
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            on = bool(self._var.get())
            if self._disabled:
                fill = "#1f4d80" if on else "#2c2c2f"
            else:
                fill = CYAN if on else "#4a4a4f"
            paint_round(self, 0, 0, 42, 24, 12, fill, fill, outside, "track", 0)
            x = 20 if on else 2
            paint_round(self, x, 2, 20, 20, 10, "#ffffff" if not self._disabled else "#9db4d0", "#ffffff" if not self._disabled else "#9db4d0", fill, "knob", 0)

    class Glyph(tk.Canvas):
        """A 22px status mark: waiting, working (spinning), done, careful or failed."""

        def __init__(self, parent, state="wait", size=22):
            super().__init__(parent, width=size, height=size, bd=0, highlightthickness=0)
            self.size, self.state, self.angle, self._job = size, state, 0, None
            self.bind("<Map>", lambda e: self.after_idle(self.draw))
            self.bind("<Destroy>", lambda e: self._cancel())

        def _cancel(self):
            if self._job:
                try:
                    self.after_cancel(self._job)
                except tk.TclError:
                    pass
                self._job = None

        def set(self, state):
            self.state = state
            self.draw()

        def draw(self):
            self._cancel()
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            self.delete("all")
            s = self.size
            m = 2
            d = s - 2 * m
            if self.state == "wait":
                paint_round(self, m, m, d, d, d // 2, "#55555a", "#55555a", outside, "disc", 0)
                paint_round(self, m + 2, m + 2, d - 4, d - 4, (d - 4) // 2, outside, outside, "#55555a", "hole", 0)
            elif self.state == "work":
                paint_round(self, m, m, d, d, d // 2, "#2f3b4d", "#2f3b4d", outside, "disc", 0)
                paint_round(self, m + 2, m + 2, d - 4, d - 4, (d - 4) // 2, outside, outside, "#2f3b4d", "hole", 0)
                self.create_arc(m + 1, m + 1, s - m - 1, s - m - 1, start=self.angle, extent=110, style="arc", outline=CYAN, width=2)
                self.angle = (self.angle - 18) % 360
                self._job = self.after(40, self.draw)
            elif self.state in ("done", "warn", "fail"):
                fill = {"done": GREEN, "warn": AMBER, "fail": RED}[self.state]
                paint_round(self, m, m, d, d, d // 2, fill, fill, outside, "disc", 0)
                ink = "#0d1a10" if self.state == "done" else "#241a05" if self.state == "warn" else "#2a0d0b"
                c = s / 2
                if self.state == "done":
                    self.create_line(c - 4.5, c + 0.5, c - 1.2, c + 3.8, c + 5, c - 3.4, fill=ink, width=2, capstyle="round", joinstyle="round")
                elif self.state == "warn":
                    self.create_line(c, c - 4.5, c, c + 1.5, fill=ink, width=2, capstyle="round")
                    self.create_oval(c - 1.1, c + 3.4, c + 1.1, c + 5.6, fill=ink, outline="")
                else:
                    self.create_line(c - 3.5, c - 3.5, c + 3.5, c + 3.5, fill=ink, width=2, capstyle="round")
                    self.create_line(c - 3.5, c + 3.5, c + 3.5, c - 3.5, fill=ink, width=2, capstyle="round")

    class Badge(tk.Canvas):
        """The big round mark on the last page."""

        def __init__(self, parent, state="done", size=72):
            super().__init__(parent, width=size, height=size, bd=0, highlightthickness=0, bg=BG)
            self.size = size
            self.set(state)

        def set(self, state):
            self.delete("all")
            s = self.size
            color = {"done": GREEN, "warn": AMBER, "fail": RED}[state]
            soft = {"done": "#16301d", "warn": "#3a2c0e", "fail": "#3a1a19"}[state]
            paint_round(self, 2, 2, s - 4, s - 4, (s - 4) // 2, soft, soft, BG, "soft", 0)
            paint_round(self, 10, 10, s - 20, s - 20, (s - 20) // 2, color, color, soft, "disc", 0)
            c, u = s / 2, s / 72
            ink = {"done": "#0d1a10", "warn": "#241a05", "fail": "#2a0d0b"}[state]
            if state == "done":
                self.create_line(c - 12 * u, c + 1 * u, c - 3 * u, c + 10 * u, c + 13 * u, c - 9 * u, fill=ink, width=5 * u, capstyle="round", joinstyle="round")
            elif state == "warn":
                self.create_line(c, c - 13 * u, c, c + 3 * u, fill=ink, width=5 * u, capstyle="round")
                self.create_oval(c - 3 * u, c + 9 * u, c + 3 * u, c + 15 * u, fill=ink, outline="")
            else:
                self.create_line(c - 10 * u, c - 10 * u, c + 10 * u, c + 10 * u, fill=ink, width=5 * u, capstyle="round")
                self.create_line(c - 10 * u, c + 10 * u, c + 10 * u, c - 10 * u, fill=ink, width=5 * u, capstyle="round")

    class Rail(tk.Canvas):
        """The steps down the left side."""

        STEPS = ["Your system", "Choose", "Install", "Your account", "Finish"]

        def __init__(self, parent, width=230):
            super().__init__(parent, width=width, bd=0, highlightthickness=0, bg=RAIL)
            self.step, self.done_to, self.failed = 0, -1, False
            self.bind("<Configure>", lambda e: self.draw())

        def set(self, step, failed=False):
            self.step, self.failed = step, failed
            self.draw()

        def draw(self):
            self.delete("all")
            x, y0, gap = 40, 168, 54
            n = len(self.STEPS)
            for i, label in enumerate(self.STEPS):
                y = y0 + i * gap
                if i < n - 1:
                    self.create_line(x, y + 14, x, y + gap - 14, fill=GREEN if i < self.step else "#333337", width=2)
            for i, label in enumerate(self.STEPS):
                y = y0 + i * gap
                if i < self.step:
                    self.create_oval(x - 13, y - 13, x + 13, y + 13, fill=GREEN, outline="")
                    self.create_line(x - 5, y, x - 1.5, y + 3.5, x + 5.5, y - 4, fill="#0d1a10", width=2, capstyle="round", joinstyle="round")
                    color, font = TEXT, UI["body"]
                elif i == self.step:
                    ring = RED if self.failed else CYAN
                    self.create_oval(x - 13, y - 13, x + 13, y + 13, fill=ring, outline="")
                    self.create_text(x, y, text=str(i + 1), fill="#ffffff", font=UI["bold"])
                    color, font = "#ffffff", UI["bold"]
                else:
                    self.create_oval(x - 13, y - 13, x + 13, y + 13, fill=RAIL, outline="#3f3f44", width=2)
                    self.create_text(x, y, text=str(i + 1), fill="#6d6d73", font=UI["body"])
                    color, font = "#7d7d83", UI["body"]
                self.create_text(x + 28, y, text=label, anchor="w", fill=color, font=font)

    def autowrap(label, margin=4):
        """Lets a label's text wrap to whatever width its parent has."""
        def fit(event):
            label.configure(wraplength=max(120, event.width - margin))
        label.master.bind("<Configure>", fit, add="+")
        return label

    COMPONENTS = [
        ("cli", "Command-line tools", "ztr_ssh, ztr_forward and ztr_pg: reach a server, forward a port or open a database through a route.", "always"),
        ("service", "Tunnel service", "Keeps tunnels ready in the background, so every tool connects at once. Starts with your computer.", "background"),
        ("dashboard", "Dashboard", "A local page that shows your tunnels, any errors, and live traffic.", "background"),
        ("requests", "Request composer", "A local web page for building a request and sending it through a route.", "background"),
        ("ferry", "Ferry", "A two-pane file manager: your computer on one side, a server on the other.", "app"),
        ("proxy", "ZTR Proxy", "Send your browser's traffic through a route, and watch every connection.", "app"),
    ]

    class App:
        def __init__(self, root, demo=False):
            self.root = root
            self.demo = demo
            self.step = 0
            self.events = queue.Queue()
            self.proc = None
            self.cancelled = False
            self.checks = []
            self.warnings = []
            self.rc_lines = []
            self.log_lines = []
            self.stage_rows = {}
            self.stage_list = []
            self.cur = -1
            self.sel_vars = {}
            self.tmp = None
            self.rc_note = ""
            self.account_dir = tempfile.mkdtemp(prefix="ztr-demo-account-") if demo else SCRIPT_DIR
            self.sel = None
            root.title(APP_NAME)
            root.configure(bg=BG)
            root.minsize(900, 640)
            root.geometry(f"960x{min(700, max(640, root.winfo_screenheight() - 80))}")
            self._style()
            self._style_extra()
            self.vars = {
                "service": tk.BooleanVar(value=False), "dashboard": tk.BooleanVar(value=False), "requests": tk.BooleanVar(value=False),
                "ferry": tk.BooleanVar(value=True), "proxy": tk.BooleanVar(value=True), "local_ip": tk.BooleanVar(value=False),
                "path": tk.BooleanVar(value=True), "cli": tk.BooleanVar(value=True),
            }
            self.route_var = tk.StringVar(value="")
            self.ip_var = tk.StringVar(value=DEFAULT_LOCAL_IP)
            self.prefix_var = tk.StringVar(value=DEFAULT_PREFIX)
            self.venv_var = tk.StringVar(value=DEFAULT_VENV)
            self._build()
            self.goto(0)
            self.run_checks()
            self.root.after(60, self._poll)

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

        def _style_extra(self):
            fam = self.family
            UI.update(hero=tkfont.Font(family=fam, size=24, weight="bold"), lead=tkfont.Font(family=fam, size=12),
                      brand=tkfont.Font(family=fam, size=22, weight="bold"), brandsub=tkfont.Font(family=fam, size=13, weight="bold"),
                      tag=tkfont.Font(family=fam, size=8, weight="bold"))
            s = ttk.Style(self.root)
            s.configure("Hero.TLabel", background=BG, foreground=TEXT, font=UI["hero"])
            s.configure("Lead.TLabel", background=BG, foreground=DIM, font=UI["lead"])
            s.configure("Rail.TLabel", background=RAIL, foreground=DIM, font=UI["small"])
            s.configure("Brand.TLabel", background=RAIL, foreground=TEXT, font=UI["brand"])
            s.configure("BrandSub.TLabel", background=RAIL, foreground=CYAN, font=UI["brandsub"])
            s.configure("RailTitle.TLabel", background=RAIL, foreground=TEXT, font=UI["h"])
            s.configure("Warn.TLabel", background=CARD, foreground=AMBER, font=UI["small"])
            s.configure("Good.TLabel", background=BG, foreground=GREEN, font=UI["body"])
            s.configure("BadText.TLabel", background=BG, foreground=RED, font=UI["body"])
            s.configure("AmberBg.TLabel", background=BG, foreground=AMBER, font=UI["body"])
            s.configure("Bold.TLabel", background=CARD, foreground=TEXT, font=UI["bold"])
            s.configure("Rail.TFrame", background=RAIL)
            s.configure("Amber.TFrame", background="#2e2a1e")

        # ── layout ───────────────────────────────────────────────────────
        def _build(self):
            root = self.root
            root.columnconfigure(1, weight=1)
            root.rowconfigure(0, weight=1)
            left = tk.Frame(root, bg=RAIL, width=240)
            left.grid(row=0, column=0, sticky="ns")
            left.grid_propagate(False)
            left.columnconfigure(0, weight=1)
            left.rowconfigure(2, weight=1)
            brand = tk.Frame(left, bg=RAIL)
            brand.grid(row=0, column=0, sticky="ew", padx=28, pady=(40, 0))
            ttk.Label(brand, text="ZTRelay", style="Brand.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(brand, text="Setup", style="BrandSub.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 0))
            self.rail = Rail(left)
            self.rail.grid(row=0, column=0, rowspan=3, sticky="nsew")
            brand.lift()
            self.foot_note = ttk.Label(left, text="", style="Rail.TLabel", wraplength=190, justify="left")
            self.foot_note.grid(row=3, column=0, sticky="sw", padx=28, pady=(0, 24))

            right = tk.Frame(root, bg=BG)
            right.grid(row=0, column=1, sticky="nsew")
            right.columnconfigure(0, weight=1)
            right.rowconfigure(0, weight=1)
            self.stack = tk.Frame(right, bg=BG)
            self.stack.grid(row=0, column=0, sticky="nsew", padx=(36, 36), pady=(30, 0))
            self.stack.columnconfigure(0, weight=1)
            self.stack.rowconfigure(0, weight=1)
            self.pages = []
            for build in (self._page_system, self._page_choose, self._page_install, self._page_account, self._page_done):
                frame = tk.Frame(self.stack, bg=BG)
                frame.grid(row=0, column=0, sticky="nsew")
                frame.columnconfigure(0, weight=1)
                build(frame)
                self.pages.append(frame)
            bar = tk.Frame(right, bg=BG)
            bar.grid(row=1, column=0, sticky="ew", padx=36, pady=(10, 22))
            bar.columnconfigure(1, weight=1)
            self.bar_note = ttk.Label(bar, text="", style="Lead.TLabel", font=UI["small"])
            self.bar_note.grid(row=0, column=0, sticky="w")
            self.back_btn = Btn(bar, text="Back", style="Ghost.TButton", command=None)
            self.back_btn.grid(row=0, column=2, padx=(0, 10))
            self.next_btn = Btn(bar, text="Continue", style="Primary.TButton", command=None)
            self.next_btn.grid(row=0, column=3)
            self.toast_label = None

        def _heading(self, page, title, lead):
            ttk.Label(page, text=title, style="Hero.TLabel").grid(row=0, column=0, sticky="w")
            lead_label = ttk.Label(page, text=lead, style="Lead.TLabel")
            lead_label.grid(row=1, column=0, sticky="w", pady=(4, 18))
            return lead_label

        # page 1 — what this computer has
        def _page_system(self, page):
            self._heading(page, "Welcome to ZTRelay", "First, a look at what this computer already has.")
            self.check_card = Card(page, radius=14, pad=(20, 8))
            self.check_card.grid(row=2, column=0, sticky="ew")
            self.check_body = self.check_card.body
            self.check_body.columnconfigure(0, weight=0)
            self.check_body.columnconfigure(1, weight=1)
            self.check_summary = ttk.Label(page, text="", style="Good.TLabel")
            self.check_summary.grid(row=3, column=0, sticky="w", pady=(14, 0))
            Btn(page, text="Check again", style="Ghost.TButton", command=self.run_checks).grid(row=3, column=0, sticky="e", pady=(10, 0))
            self.skip_btn = Btn(page, text="Already installed? Set up my account", style="Small.TButton", command=self.account_only)
            if os.path.isfile(venv_python(DEFAULT_VENV)) or self.demo:
                self.skip_btn.grid(row=4, column=0, sticky="w", pady=(18, 0))

        def account_only(self):
            self.sel = self.selection()
            self.goto(3)

        def run_checks(self):
            self.checks = gather_checks()
            for w in self.check_body.winfo_children():
                w.destroy()
            worst = "ok"
            for i, c in enumerate(self.checks):
                state = {"ok": "done", "warn": "warn", "bad": "fail"}[c["status"]]
                Glyph(self.check_body, state).grid(row=i, column=0, padx=(0, 14), pady=9, sticky="w")
                col = ttk.Frame(self.check_body, style="Card.TFrame")
                col.grid(row=i, column=1, sticky="ew", pady=9)
                col.columnconfigure(0, weight=1)
                ttk.Label(col, text=c["title"], style="Bold.TLabel").grid(row=0, column=0, sticky="w")
                ttk.Label(col, text=c["detail"], style="Warn.TLabel" if c["status"] != "ok" else "Dim.TLabel").grid(row=1, column=0, sticky="w")
                if c["hint"]:
                    Btn(self.check_body, text="Copy: " + c["hint"], style="Small.TButton", command=lambda h=c["hint"]: self.copy(h)).grid(row=i, column=2, sticky="e")
                if c["status"] == "bad":
                    worst = "bad"
                elif c["status"] == "warn" and worst == "ok":
                    worst = "warn"
                if i < len(self.checks) - 1:
                    tk.Frame(self.check_body, bg="#303033", height=1).grid(row=i, column=0, columnspan=3, sticky="sew")
            self.worst = worst
            text, style = {"ok": ("Everything is in place.", "Good.TLabel"),
                           "warn": ("Some optional pieces are missing — you can still continue.", "AmberBg.TLabel"),
                           "bad": ("Something required is missing. Install it, then check again.", "BadText.TLabel")}[worst]
            self.check_summary.configure(text=text, style=style)
            tk_ok = next((c["status"] == "ok" for c in self.checks if c["key"] == "tk"), False)
            self.tk_ok = tk_ok
            if self.step == 0:
                self._buttons()

        # page 2 — what to set up
        def _page_choose(self, page):
            self._heading(page, "What would you like to set up?", "The command-line tools are always installed. Add anything else you want.")
            grid = tk.Frame(page, bg=BG)
            grid.grid(row=2, column=0, sticky="ew")
            grid.columnconfigure((0, 1), weight=1, uniform="c")
            self.chips = {}
            for i, (key, title, desc, kind) in enumerate(COMPONENTS):
                card = Card(grid, radius=14, pad=(16, 12))
                card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0, 10) if i % 2 == 0 else (10, 0), pady=(0, 12))
                b = card.body
                b.columnconfigure(0, weight=1)
                ttk.Label(b, text=title, style="H.TLabel").grid(row=0, column=0, sticky="w")
                if kind == "always":
                    Switch(b, self.vars["cli"], disabled=True).grid(row=0, column=1, sticky="e")
                else:
                    Switch(b, self.vars[key], command=self.on_choice).grid(row=0, column=1, sticky="e")
                dl = ttk.Label(b, text=desc, style="Dim.TLabel", wraplength=250, justify="left")
                dl.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 0))
                autowrap(dl)
                chip = ttk.Label(b, text={"always": "Always installed", "background": "Runs in the background", "app": "Opens as an app"}[kind], style="Dim.TLabel", foreground=TEAL)
                chip.grid(row=2, column=0, sticky="w", pady=(8, 0))
                self.chips[key] = chip
            self.opts = Card(page, radius=14, pad=(18, 10))
            self.opts.grid(row=3, column=0, sticky="ew")
            self.opts_body = self.opts.body
            self.opts_body.columnconfigure(1, weight=1)
            r = 0
            self.route_row = ttk.Frame(self.opts_body, style="Card.TFrame")
            self.route_row.grid(row=r, column=0, columnspan=3, sticky="ew", pady=(2, 6))
            self.route_row.columnconfigure(2, weight=1)
            ttk.Label(self.route_row, text="Route for the background services", style="TLabel").grid(row=0, column=0, sticky="w", padx=(0, 12))
            self.route_combo = Combo(self.route_row, compact=True, textvariable=self.route_var, state="readonly", width=24, values=[])
            self.route_combo.grid(row=0, column=1, sticky="w")
            self.route_note = ttk.Label(self.route_row, text="", style="Warn.TLabel")
            self.route_note.grid(row=0, column=2, sticky="w", padx=(12, 0))
            self.route_btn = Btn(self.route_row, text="Open routes folder", style="Small.TButton", command=self.open_routes)
            self.route_btn.grid(row=0, column=3, sticky="e")
            self.ip_row = ttk.Frame(self.opts_body, style="Card.TFrame")
            self.ip_row.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 6))
            self.ip_row.columnconfigure(1, weight=1)
            self.ip_check = Check(self.ip_row, text="Give tunneled sessions their own address", variable=self.vars["local_ip"], command=self.on_choice)
            self.ip_check.grid(row=0, column=0, sticky="w")
            self.ip_field = Field(self.ip_row, compact=True, textvariable=self.ip_var, width=13)
            self.ip_field.grid(row=0, column=1, sticky="w", padx=(12, 0))
            self.ip_note = ttk.Label(self.ip_row, text="Asks for your password once.", style="Dim.TLabel")
            self.ip_note.grid(row=0, column=2, sticky="e")
            row3 = ttk.Frame(self.opts_body, style="Card.TFrame")
            row3.grid(row=2, column=0, columnspan=3, sticky="ew")
            row3.columnconfigure(1, weight=1)
            self.path_check = Check(row3, text="Add the commands to my PATH", variable=self.vars["path"])
            self.path_check.grid(row=0, column=0, sticky="w")
            self.path_note = ttk.Label(row3, text="", style="Dim.TLabel")
            self.path_note.grid(row=0, column=1, sticky="w", padx=(12, 0))
            Btn(row3, text="Advanced…", style="Ghost.TButton", command=self.open_advanced).grid(row=0, column=2, sticky="e")

        def on_choice(self):
            service = self.vars["service"].get()
            dash = self.vars["dashboard"].get() or service
            if service:
                self.vars["local_ip"].set(True)
            needs_route = service or self.vars["dashboard"].get()
            if needs_route:
                self.route_row.grid()
                routes = list_routes()
                self.route_combo.inner.configure(values=routes)
                if routes and self.route_var.get() not in routes:
                    self.route_var.set(routes[0])
                self.route_note.configure(text="" if routes else "None yet")
                self.route_btn.grid() if not routes else self.route_btn.grid_remove()
            else:
                self.route_row.grid_remove()
            ip_relevant = service or self.vars["local_ip"].get() or self.vars["dashboard"].get() or self.vars["requests"].get()
            self.ip_row.grid() if (service or self.vars["local_ip"].get() or ip_relevant) else self.ip_row.grid_remove()
            for key in ("ferry", "proxy"):
                if self.vars[key].get() and not self.tk_ok:
                    self.chips[key].configure(text="Needs Tk — see the first step", foreground=AMBER)
                else:
                    self.chips[key].configure(text="Opens as an app", foreground=TEAL)
            self.path_note.configure(text="Edits %s" % detect_rc_file().name)
            n = sum(1 for k in ("service", "dashboard", "requests", "ferry", "proxy") if self.vars[k].get())
            self.bar_note.configure(text=("%d extra%s selected" % (n, "" if n == 1 else "s")) if n else "Just the command-line tools")
            if self.step == 1:
                self._buttons()

        def open_advanced(self):
            win, body = _dialog(self.root, "Advanced")
            body.columnconfigure(1, weight=1)
            ttk.Label(body, text="Advanced", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))
            ttk.Label(body, text="Install the commands into").grid(row=1, column=0, sticky="w", padx=(0, 12), pady=4)
            a = tk.StringVar(value=self.prefix_var.get())
            Field(body, textvariable=a, width=42).grid(row=1, column=1, sticky="ew", pady=4)
            ttk.Label(body, text="Put the Python environment in").grid(row=2, column=0, sticky="w", padx=(0, 12), pady=4)
            b = tk.StringVar(value=self.venv_var.get())
            Field(body, textvariable=b, width=42).grid(row=2, column=1, sticky="ew", pady=4)
            ttk.Label(body, text="The defaults suit almost everyone.", style="Dim.TLabel").grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 12))
            btns = ttk.Frame(body, style="Card.TFrame")
            btns.grid(row=4, column=0, columnspan=2, sticky="e")

            def save():
                self.prefix_var.set(a.get().strip() or DEFAULT_PREFIX)
                self.venv_var.set(b.get().strip() or DEFAULT_VENV)
                win.destroy()
            Btn(btns, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            Btn(btns, text="Save", style="Primary.TButton", command=save).grid(row=0, column=1)
            _show_modal(win, self.root)

        def open_routes(self):
            ROUTES_DIR.mkdir(parents=True, exist_ok=True)
            opener = ["open"] if IS_MAC else ["xdg-open"]
            try:
                subprocess.Popen(opener + [str(ROUTES_DIR)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            except OSError:
                self.copy(str(ROUTES_DIR), "Folder path copied")

        # page 3 — the install itself
        def _page_install(self, page):
            page.rowconfigure(3, weight=1)
            self.install_lead = self._heading(page, "Setting things up", "This takes a minute or two.")
            self.stage_card = Card(page, radius=14, pad=(20, 14))
            self.stage_card.grid(row=2, column=0, sticky="ew")
            self.stage_body = self.stage_card.body
            self.stage_body.columnconfigure(0, weight=0)
            self.stage_body.columnconfigure(1, weight=1)
            self.progress = Progress(self.stage_body, mode="determinate")
            self.progress.grid(row=99, column=0, columnspan=3, sticky="ew", pady=(12, 0))
            log_card = Card(page, radius=14, pad=(4, 4))
            log_card.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
            log_card.body.rowconfigure(0, weight=1)
            holder = tk.Frame(log_card.body, bg=CARD)
            holder.grid(row=0, column=0, sticky="nsew")
            holder.columnconfigure(0, weight=1)
            holder.rowconfigure(0, weight=1)
            self.log = tk.Text(holder, bg=CARD, fg=DIM, bd=0, highlightthickness=0, wrap="word", font=UI["mono"], padx=14, pady=10,
                               insertbackground=TEXT, state="disabled", cursor="arrow", selectbackground=SEL, height=6)
            sb = ttk.Scrollbar(holder, orient="vertical", command=self.log.yview, style="Thin.Vertical.TScrollbar")
            self.log.configure(yscrollcommand=sb.set)
            self.log.grid(row=0, column=0, sticky="nsew")
            sb.grid(row=0, column=1, sticky="ns")
            self.log.tag_configure("info", foreground="#b9b9c0")
            self.log.tag_configure("dim", foreground="#6d6d73")
            self.log.tag_configure("ok", foreground="#8ee7a6")
            self.log.tag_configure("warn", foreground=AMBER)
            self.log.tag_configure("err", foreground=RED)

        def _fill_stages(self):
            for w in self.stage_body.winfo_children():
                if w is not self.progress:
                    w.destroy()
            self.stage_rows = {}
            for i, (key, title, rx) in enumerate(self.stage_list):
                g = Glyph(self.stage_body, "wait")
                g.grid(row=i, column=0, padx=(0, 12), pady=4, sticky="w")
                lab = ttk.Label(self.stage_body, text=title, style="TLabel", foreground=DIM)
                lab.grid(row=i, column=1, sticky="w")
                note = ttk.Label(self.stage_body, text="", style="Dim.TLabel")
                note.grid(row=i, column=2, sticky="e")
                self.stage_rows[i] = (g, lab, note)

        # page 4 — the result
        def _page_done(self, page):
            page.rowconfigure(4, weight=1)
            top = tk.Frame(page, bg=BG)
            top.grid(row=0, column=0, sticky="ew")
            top.columnconfigure(1, weight=1)
            self.badge = Badge(top, "done")
            self.badge.grid(row=0, column=0, rowspan=2, padx=(0, 18))
            self.done_title = ttk.Label(top, text="ZTRelay is ready", style="Hero.TLabel")
            self.done_title.grid(row=0, column=1, sticky="sw")
            self.done_lead = ttk.Label(top, text="", style="Lead.TLabel")
            self.done_lead.grid(row=1, column=1, sticky="nw")
            self.done_body = tk.Frame(page, bg=BG)
            self.done_body.grid(row=1, column=0, sticky="nsew", pady=(22, 0))
            self.done_body.columnconfigure((0, 1), weight=1, uniform="d")

        # ── your account: key, route, secret key ─────────────────────────
        def in_thread(self, work, done):
            """Runs work() off the screen's thread, then done(result) back on it."""
            def run():
                try:
                    result = work()
                except Exception as e:  # shown to the user, never raised into the event loop
                    result = (False, "%s: %s" % (e.__class__.__name__, e))
                self.events.put(("call", lambda: done(result)))
            threading.Thread(target=run, daemon=True).start()

        def _page_account(self, page):
            self._heading(page, "Connect your account", "A route needs a key, a route file and your secret key. Anything missing is set up here.")
            self.acct_card = Card(page, radius=14, pad=(20, 8))
            self.acct_card.grid(row=2, column=0, sticky="ew")
            self.acct_body = self.acct_card.body
            self.acct_body.columnconfigure(0, weight=0)
            self.acct_body.columnconfigure(1, weight=1)
            self.test_holder = tk.Frame(page, bg=BG)
            self.test_holder.grid(row=3, column=0, sticky="ew", pady=(14, 0))
            self.test_holder.columnconfigure(0, weight=1)
            self.test_route_var = tk.StringVar(value="")
            self.test_state = dict(glyph="wait", note="", color=DIM, button="Test my setup")
            self.acct_summary = {}

        def draw_test(self):
            """The 'try it for real' card, built fresh each time (so it is drawn while its page is showing)."""
            for w in self.test_holder.winfo_children():
                w.destroy()
            sm = self.acct_summary
            ready = bool(sm.get("ready"))
            routes = [r["name"] for r in sm.get("routes", []) if r["ok"]]
            card = Card(self.test_holder, radius=14, pad=(20, 14))
            card.grid(row=0, column=0, sticky="ew")
            tb = card.body
            tb.columnconfigure(0, weight=0)
            tb.columnconfigure(1, weight=1)
            st = self.test_state
            Glyph(tb, "wait" if not ready else st["glyph"]).grid(row=0, column=0, rowspan=2, padx=(0, 14), sticky="n", pady=(2, 0))
            ttk.Label(tb, text="Try it for real", style="Bold.TLabel").grid(row=0, column=1, sticky="w")
            note = "Available once the three steps above are done." if not ready else (st["note"] or "Opens a tunnel through your route and loads one web page.")
            ttk.Label(tb, text=note, style="Dim.TLabel", foreground=st["color"] if ready else DIM, wraplength=420, justify="left").grid(row=1, column=1, sticky="w")
            col = 2
            if len(routes) > 1:
                if self.test_route_var.get() not in routes:
                    self.test_route_var.set(routes[0])
                Combo(tb, compact=True, textvariable=self.test_route_var, state="readonly", width=18, values=routes).grid(row=0, column=col, rowspan=2, sticky="e", padx=(10, 10))
            elif routes:
                self.test_route_var.set(routes[0])
            Btn(tb, text=st["button"], style="Primary.TButton", state="normal" if ready and not st.get("busy") else "disabled",
                command=self.run_test).grid(row=0, column=3, rowspan=2, sticky="e")

        def task_row(self, i, state, title, detail, actions, bad=False):
            Glyph(self.acct_body, state).grid(row=i, column=0, padx=(0, 14), pady=11, sticky="n")
            col = ttk.Frame(self.acct_body, style="Card.TFrame")
            col.grid(row=i, column=1, sticky="ew", pady=9)
            col.columnconfigure(0, weight=1)
            ttk.Label(col, text=title, style="Bold.TLabel").grid(row=0, column=0, sticky="w")
            dl = ttk.Label(col, text=detail, style="Warn.TLabel" if bad else "Dim.TLabel", justify="left", wraplength=330)
            dl.grid(row=1, column=0, sticky="w")
            autowrap(dl)
            bar = ttk.Frame(self.acct_body, style="Card.TFrame")
            bar.grid(row=i, column=2, sticky="e", padx=(12, 0))
            for j, (label, command, style) in enumerate(actions):
                Btn(bar, text=label, style=style, command=command).grid(row=0, column=j, padx=(6 if j else 0, 0))

        def refresh_account(self):
            for w in self.acct_body.winfo_children():
                w.destroy()
            sm = account_summary(self.account_dir)
            self.acct_summary = sm
            k = sm["key"]
            if k["ok"]:
                self.task_row(0, "done", "Your key", "Ready  ·  fingerprint " + k["fingerprint"],
                              [("Register it…", self.register_key, "Small.TButton"), ("Show", self.show_public_key, "Small.TButton")])
            else:
                self.task_row(0, "warn", "Your key", "None yet. One is made on this computer; the private half never leaves it.",
                              [("Create my key", self.create_key, "Primary.TButton")], bad=False)
            good = [r for r in sm["routes"] if r["ok"]]
            if good:
                names = ", ".join(r["name"] for r in good[:3]) + ("…" if len(good) > 3 else "")
                self.task_row(1, "done", "Your route", ("%d route%s: %s" % (len(good), "" if len(good) == 1 else "s", names)),
                              [("Add another…", self.import_route_dialog, "Small.TButton")])
            else:
                bad = [r for r in sm["routes"] if not r["ok"]]
                detail = "None yet. Create one in your dashboard, download it, then add it here."
                if bad:
                    detail = "%s %s." % (bad[0]["name"], bad[0]["problem"])
                self.task_row(1, "warn", "Your route", detail,
                              [("Add a route…", self.import_route_dialog, "Primary.TButton"), ("Dashboard", self.open_dashboard, "Small.TButton")], bad=bool(bad))
            if sm["secret"]:
                where = "Saved in .env" if sm["env"] else "In your route file"
                self.task_row(2, "done", "Your secret key", where + "  ·  stays on this computer", [("Change…", self.secret_dialog, "Small.TButton")])
            else:
                detail = "Needed once. It was shown when you registered, or after Account → Regenerate secret key."
                if sm["env_bad"]:
                    detail = "The one in .env isn't a real key (it should be 64 hex characters)."
                self.task_row(2, "warn", "Your secret key", detail, [("Enter it…", self.secret_dialog, "Primary.TButton")], bad=sm["env_bad"])
            for i in range(2):
                tk.Frame(self.acct_body, bg="#303033", height=1).grid(row=i, column=0, columnspan=3, sticky="sew")
            done = sum(1 for flag in (k["ok"], bool(good), sm["secret"]) if flag)
            ready = sm["ready"]
            self.draw_test()
            if self.step == 3:
                self.bar_note.configure(text="All set" if ready else "%d of 3 done — you can skip this and come back" % done)

        def open_dashboard(self):
            try:
                import webbrowser
                webbrowser.open(DASHBOARD_URL)
            except Exception:
                self.copy(DASHBOARD_URL, "Dashboard address copied")

        # -- the key
        def create_key(self):
            self.toast("Creating your key — a few seconds…", "ok")
            venv = self.venv_var.get().strip() or DEFAULT_VENV

            def work():
                if self.demo:
                    time.sleep(1.4)
                    paths = account_paths(self.account_dir)
                    paths["private"].write_text("demo\n")
                    paths["public"].write_text("-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(os.urandom(120)).decode() + "\n-----END PUBLIC KEY-----\n")
                    return True, {}
                return run_in_venv(venv, _KEY_SCRIPT, [self.account_dir, "create"], timeout=300)

            def done(result):
                ok, info = result
                if not ok:
                    self.toast(str(info), "error")
                self.refresh_account()
                if ok:
                    self.toast("Key created. Next: register it with your dashboard.", "ok")
            self.in_thread(work, done)

        def show_public_key(self):
            pem = self.acct_summary.get("key", {}).get("public", "")
            win, body = _dialog(self.root, "Your public key")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Your public key", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="This is the half you give your dashboard. The private half stays on this computer.", style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 10))
            txt = tk.Text(body, bg=FIELD, fg=TEXT, bd=0, highlightthickness=0, font=UI["mono"], width=66, height=9, wrap="char", padx=10, pady=8)
            txt.insert("1.0", pem)
            txt.configure(state="disabled")
            txt.grid(row=2, column=0, sticky="ew")
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=3, column=0, sticky="e", pady=(12, 0))
            Btn(row, text="Copy", style="Small.TButton", command=lambda: self.copy(pem, "Public key copied")).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Close", style="Primary.TButton", command=win.destroy).grid(row=0, column=1)
            _show_modal(win, self.root)

        def register_key(self):
            """The launcher's job: sign the dashboard's nonce so the public key can be registered."""
            pem = self.acct_summary.get("key", {}).get("public", "")
            win, body = _dialog(self.root, "Register your key")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Register your key", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            steps = ("1.  In your dashboard, open Keys and click Nonce.\n"
                     "2.  Paste the nonce below and press Sign.\n"
                     "3.  Paste the signature and your public key into the form, with your secret key, and submit.")
            ttk.Label(body, text=steps, style="Dim.TLabel", justify="left").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 12))
            nonce = tk.StringVar()
            Field(body, textvariable=nonce, placeholder="Paste the nonce here", width=52).grid(row=2, column=0, sticky="ew", padx=(0, 10))
            sign = Btn(body, text="Sign", style="Primary.TButton", command=lambda: None)
            sign.grid(row=2, column=1, sticky="e")
            out = tk.Text(body, bg=FIELD, fg="#b9b9c0", bd=0, highlightthickness=0, font=UI["mono"], width=60, height=6, wrap="char", padx=10, pady=8)
            out.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0))
            out.insert("1.0", "The signature appears here.")
            out.configure(state="disabled")
            state = {"sig": ""}
            btns = ttk.Frame(body, style="Card.TFrame")
            btns.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(12, 0))
            btns.columnconfigure(3, weight=1)
            copy_sig = Btn(btns, text="Copy signature", style="Small.TButton", state="disabled", command=lambda: self.copy(state["sig"], "Signature copied"))
            copy_sig.grid(row=0, column=0, padx=(0, 8))
            Btn(btns, text="Copy public key", style="Small.TButton", command=lambda: self.copy(pem, "Public key copied")).grid(row=0, column=1, padx=(0, 8))
            Btn(btns, text="Open dashboard", style="Small.TButton", command=self.open_dashboard).grid(row=0, column=2)
            Btn(btns, text="Close", style="Primary.TButton", command=win.destroy).grid(row=0, column=4)

            def show(text, tag_ok=True):
                out.configure(state="normal")
                out.delete("1.0", "end")
                out.insert("1.0", text)
                out.configure(state="disabled", fg="#b9b9c0" if tag_ok else AMBER)

            def do_sign():
                value = nonce.get().strip()
                if not value:
                    show("Paste the nonce from your dashboard first.", False)
                    return
                sign.configure(state="disabled", text="Signing…")
                venv = self.venv_var.get().strip() or DEFAULT_VENV

                def work():
                    if self.demo:
                        time.sleep(0.8)
                        return True, {"signature": os.urandom(48).hex() * 2}
                    return run_in_venv(venv, _KEY_SCRIPT, [self.account_dir, "sign"], {"nonce": value})

                def done(result):
                    if not win.winfo_exists():
                        return
                    sign.configure(state="normal", text="Sign")
                    ok, info = result
                    if ok:
                        state["sig"] = info["signature"]
                        show(info["signature"])
                        copy_sig.configure(state="normal")
                    else:
                        show(str(info), False)
                self.in_thread(work, done)
            sign.configure(command=do_sign)
            _show_modal(win, self.root)

        # -- the route
        def import_route_dialog(self):
            cands = downloaded_routes()
            win, body = _dialog(self.root, "Add a route")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Add your route file", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            ttk.Label(body, text="Create a route in your dashboard, press Download .ztr, then add the file here.", style="Dim.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 12))
            chosen = {"path": cands[0] if cands else None}
            names = {c.name: c for c in cands}
            var = tk.StringVar(value=cands[0].name if cands else "")
            note = ttk.Label(body, text="", style="Warn.TLabel", wraplength=440, justify="left")
            if cands:
                ttk.Label(body, text="Found in your Downloads folder", style="Dim.TLabel").grid(row=2, column=0, sticky="w")
                combo = Combo(body, compact=True, textvariable=var, state="readonly", width=40, values=list(names))
                combo.grid(row=3, column=0, sticky="ew", pady=(4, 0))
                combo.inner.bind("<<ComboboxSelected>>", lambda e: chosen.update(path=names[var.get()]))
            else:
                ttk.Label(body, text="No route files in your Downloads folder yet.", style="Dim.TLabel").grid(row=2, column=0, sticky="w")
            note.grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))
            replace = {"on": False}

            def browse():
                from tkinter import filedialog
                path = filedialog.askopenfilename(parent=win, title="Choose your .ztr file", filetypes=[("ZTR route", "*.ztr"), ("All files", "*")],
                                                  initialdir=str(Path.home() / "Downloads"))
                if path:
                    chosen["path"] = Path(path)
                    var.set(Path(path).name)
                    names.setdefault(Path(path).name, Path(path))
                    note.configure(text="", foreground=DIM)
            Btn(body, text="Choose a file…", style="Small.TButton", command=browse).grid(row=3, column=1, sticky="e", padx=(10, 0))
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=6, column=0, columnspan=2, sticky="e", pady=(14, 0))
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            go = Btn(row, text="Add route", style="Primary.TButton", command=lambda: do_import())
            go.grid(row=0, column=1)

            def do_import():
                path = chosen["path"]
                if not path:
                    note.configure(text="Choose the .ztr file you downloaded.", foreground=AMBER)
                    return
                try:
                    target = import_route(self.account_dir, path, overwrite=replace["on"])
                except FileExistsError:
                    replace["on"] = True
                    go.configure(text="Replace it")
                    note.configure(text="A route with this name is already here. Replace it with this one?", foreground=AMBER)
                    return
                except (ValueError, OSError) as e:
                    note.configure(text=str(e), foreground=AMBER)
                    return
                win.destroy()
                self.refresh_account()
                self.toast("Added %s" % target.name, "ok")
            _show_modal(win, self.root)

        # -- the secret key
        def secret_dialog(self):
            win, body = _dialog(self.root, "Your secret key")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Your secret key", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            ttk.Label(body, text="64 characters, shown once when you registered, or after Account → Regenerate secret key.\n"
                                 "It is kept in a file only you can read, next to ztrClient.py, and works for every route.",
                      style="Dim.TLabel", justify="left").grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 12))
            var = tk.StringVar()
            field = Field(body, textvariable=var, show="•", width=56)
            field.grid(row=2, column=0, sticky="ew", padx=(0, 10))
            shown = tk.BooleanVar(value=False)

            def paste():
                try:
                    var.set(self.root.clipboard_get().strip())
                except tk.TclError:
                    pass
            Btn(body, text="Paste", style="Small.TButton", command=paste).grid(row=2, column=1, sticky="e")
            hint = ttk.Label(body, text="0 of 64 characters", style="Dim.TLabel")
            hint.grid(row=3, column=0, sticky="w", pady=(8, 0))
            Check(body, text="Show it", variable=shown, command=lambda: field.inner.configure(show="" if shown.get() else "•")).grid(row=3, column=1, sticky="e", pady=(6, 0))
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=4, column=0, columnspan=2, sticky="e", pady=(16, 0))
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            save = Btn(row, text="Save", style="Primary.TButton", state="disabled", command=lambda: do_save())
            save.grid(row=0, column=1)

            def check(*_a):
                value = var.get().strip()
                n = len(value)
                if is_secret_key(value):
                    hint.configure(text="64 of 64 characters  ✓", foreground=GREEN)
                    save.configure(state="normal")
                else:
                    bad = n > 0 and not re.match(r"^[0-9a-fA-F]*$", value)
                    hint.configure(text=("Only the digits 0–9 and letters a–f are used." if bad else "%d of 64 characters" % n), foreground=AMBER if (bad or n > 64) else DIM)
                    save.configure(state="disabled")
            var.trace_add("write", check)

            def do_save():
                try:
                    path = write_env_secret(self.account_dir, var.get())
                except (ValueError, OSError) as e:
                    hint.configure(text=str(e), foreground=RED)
                    return
                win.destroy()
                self.refresh_account()
                self.toast("Saved to %s" % path.name, "ok")
            _show_modal(win, self.root, focus=field.inner)

        # -- try it for real
        def run_test(self):
            route = self.test_route_var.get() or (self.acct_summary.get("routes") or [{}])[0].get("name", "")
            if not route:
                return
            venv = self.venv_var.get().strip() or DEFAULT_VENV
            self.test_state.update(glyph="work", note="Opening a tunnel through %s…" % route, color=DIM, button="Testing…", busy=True)
            self.draw_test()

            def work():
                if self.demo:
                    time.sleep(2.2)
                    return True, {"ok": True, "status": 200, "bytes": 1256, "seconds": 3.4}
                return run_in_venv(venv, _TEST_SCRIPT, [self.account_dir, route], timeout=120)

            def done(result):
                ok, info = result
                secret = read_env_secret(self.account_dir) or ""
                if ok and isinstance(info, dict) and info.get("ok"):
                    self.test_state.update(glyph="done", note="Works — example.com answered in %s s through %s." % (info.get("seconds"), route), color=GREEN)
                else:
                    msg = info.get("error") if isinstance(info, dict) else str(info)
                    if secret:
                        msg = (msg or "").replace(secret, "…")
                    self.test_state.update(glyph="fail", note=(msg or "It didn't work.")[:200], color=RED)
                self.test_state.update(button="Test again", busy=False)
                self.draw_test()
            self.in_thread(work, done)

        # ── moving between the steps ─────────────────────────────────────
        def goto(self, step, failed=False):
            self.step = step
            self.pages[step].tkraise()
            self.rail.set(2 if failed else step, failed)  # a stopped run is marked on "Install", not "Finish"
            if step == 1:
                self.on_choice()
            if step == 3:
                self.refresh_account()
            self._buttons()

        def _buttons(self):
            s = self.step
            self.back_btn.grid() if s in (1,) or (s == 4 and self.failed_run) else self.back_btn.grid_remove()
            if s == 0:
                self.next_btn.configure(text="Continue", state="disabled" if self.worst == "bad" else "normal", command=lambda: self.goto(1))
                self.bar_note.configure(text="")
            elif s == 1:
                self.next_btn.configure(text="Install", state="normal", command=self.install)
                self.back_btn.configure(command=lambda: self.goto(0))
            elif s == 2:
                self.next_btn.configure(text="Cancel", state="normal", command=self.cancel, style="Danger.TButton")
                self.back_btn.grid_remove()
                self.bar_note.configure(text="")
            elif s == 3:
                self.back_btn.grid_remove()
                self.next_btn.configure(text="Continue", state="normal", command=lambda: self.show_done(True))
            else:
                if self.failed_run:
                    self.next_btn.configure(text="Close", state="normal", command=self.root.destroy, style="Primary.TButton")
                    self.back_btn.configure(text="Try again", command=lambda: self.goto(1))
                else:
                    self.next_btn.configure(text="Done", state="normal", command=self.root.destroy, style="Primary.TButton")
                self.bar_note.configure(text="")
            if s != 2:
                self.next_btn.configure(style="Primary.TButton")

        failed_run = False
        worst = "ok"
        tk_ok = False

        def selection(self):
            sel = {k: bool(self.vars[k].get()) for k in ("service", "dashboard", "requests", "ferry", "proxy", "local_ip")}
            sel.update(ip=self.ip_var.get().strip(), route=self.route_var.get().strip(), prefix=self.prefix_var.get().strip(), venv=self.venv_var.get().strip())
            return sel

        # ── running the installer ────────────────────────────────────────
        def install(self):
            sel = self.selection()
            if (sel["service"] or sel["dashboard"]) and not sel["route"]:
                self.toast("Pick a route for the background services, or turn them off.", "warn")
                return
            self.sel = sel
            argv, stdin = build_command(sel)
            self.stage_list = stages_for(sel)
            self._fill_stages()
            self.cur = -1
            self.cancelled = False
            self.failed_run = False
            self.warnings, self.rc_lines, self.log_lines = [], [], []
            self.stage_warn = {}
            self._capture_rc = False
            self.log.configure(state="normal")
            self.log.delete("1.0", "end")
            self.log.configure(state="disabled")
            self.progress.configure(value=0)
            self.install_lead.configure(text="This takes a minute or two.")
            self.goto(2)
            self._advance(0)
            env = dict(os.environ)
            env.setdefault("DISPLAY", ":0")  # sudo only uses a password helper when it thinks there is a display
            env["PYTHONUNBUFFERED"] = "1"
            self.tmp = tempfile.mkdtemp(prefix="ztr-setup-")
            helper = os.path.join(self.tmp, "askpass.sh")
            with open(helper, "w") as f:
                f.write("#!/bin/sh\nexec %s %s --askpass \"$@\"\n" % (shlex.quote(sys.executable), shlex.quote(os.path.abspath(__file__))))
            os.chmod(helper, 0o700)
            env["SUDO_ASKPASS"] = helper
            if self.demo:
                argv, stdin = [sys.executable, "-c", DEMO_SCRIPT, json.dumps(sel)], ""
            self.log_add("$ " + " ".join(shlex.quote(a) for a in argv[1:] if not a.startswith("-c")) if not self.demo else "$ (demo run — nothing is installed)", "dim")
            try:
                self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                                             env=env, cwd=SCRIPT_DIR, start_new_session=True)
            except OSError as e:
                self.finish(127, "Couldn't start the installer: %s" % e)
                return
            threading.Thread(target=self._read, args=(self.proc, stdin), daemon=True).start()

        def _read(self, proc, stdin):
            try:
                proc.stdin.write(stdin)
                proc.stdin.close()
            except (OSError, ValueError):
                pass
            for line in proc.stdout:
                self.events.put(("line", line.rstrip("\n")))
            proc.wait()
            self.events.put(("exit", proc.returncode))

        def cancel(self):
            if self.proc and self.proc.poll() is None:
                self.cancelled = True
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                except OSError:
                    pass

        def _poll(self):
            try:
                while True:
                    kind, payload = self.events.get_nowait()
                    if kind == "line":
                        self.on_line(payload)
                    elif kind == "exit":
                        self.finish(payload)
                    elif kind == "call":
                        payload()
            except queue.Empty:
                pass
            self.root.after(60, self._poll)

        def log_add(self, text, tag="info"):
            self.log_lines.append(text)
            self.log.configure(state="normal")
            self.log.insert("end", text + "\n", tag)
            self.log.configure(state="disabled")
            self.log.see("end")

        def on_line(self, raw):
            line = ANSI.sub("", raw)
            text = line[len("[installer] "):] if line.startswith("[installer] ") else line
            if not text.strip():
                return
            if self._capture_rc and line.startswith("    "):
                self.rc_lines.append(line.strip())
                self.log_add(line.strip(), "dim")
                return
            self._capture_rc = "add this to your shell rc file" in text
            tag = "info"
            if line.startswith("    ") or text.startswith("$"):
                tag = "dim"
            elif WARN_WORDS.search(text) and line.startswith("[installer]"):
                tag = "warn"
                self.warnings.append(text)
                if 0 <= self.cur < len(self.stage_list):
                    self.stage_warn[self.cur] = True
            elif re.search(r"\b(found|created|installed|added|removed|ready|started|up with|now answers)\b", text):
                tag = "ok"
            self.log_add(text, tag)
            for idx, (key, title, rx) in enumerate(self.stage_list):
                if idx > self.cur and rx.search(text):
                    self._advance(idx)
                    break
            if 0 <= self.cur < len(self.stage_list):
                g, lab, note = self.stage_rows[self.cur]
                note.configure(text=text[:46] + ("…" if len(text) > 46 else ""))

        stage_warn = {}

        def _advance(self, idx):
            for i in range(self.cur if self.cur >= 0 else 0, idx):
                if i in self.stage_rows:
                    g, lab, note = self.stage_rows[i]
                    g.set("warn" if self.stage_warn.get(i) else "done")
                    lab.configure(foreground=TEXT)
                    note.configure(text="")
            self.cur = idx
            g, lab, note = self.stage_rows[idx]
            g.set("work")
            lab.configure(foreground=TEXT)
            self.progress.configure(value=100.0 * (idx + 0.4) / max(1, len(self.stage_list)))
            self.install_lead.configure(text=self.stage_list[idx][1] + "…")

        def finish(self, rc, message=None):
            self.proc = None
            if self.tmp:
                shutil.rmtree(self.tmp, ignore_errors=True)
                self.tmp = None
            if rc == 0:
                for i, (g, lab, note) in self.stage_rows.items():
                    g.set("warn" if self.stage_warn.get(i) else "done")
                    lab.configure(foreground=TEXT)
                    note.configure(text="")
                self.progress.configure(value=100)
                self.rc_note = ""
                if self.demo:
                    self.rc_note = "Demo run — your shell file was not changed."
                elif self.vars["path"].get() and self.rc_lines:
                    lines = [l if "added by ztrclient installer" in l else l + "  # added by ztrclient installer" for l in self.rc_lines]
                    try:
                        rc_file, added = add_lines_to_rc(lines)
                        self.rc_note = ("Added to %s — open a new terminal to use them." % rc_file.name) if added else ("%s already has them." % rc_file.name)
                    except OSError as e:
                        self.rc_note = "Couldn't edit your shell file: %s" % e
                elif self.rc_lines:
                    self.rc_note = "Not added to your PATH — you asked to skip that."
                self.goto(3)
            else:
                if self.cancelled:
                    message = "Setup was cancelled. Nothing was left half-finished that re-running won't fix."
                else:
                    message = message or "The installer stopped with an error (code %s). The last lines are below." % rc
                if 0 <= self.cur < len(self.stage_list) and self.cur in self.stage_rows:
                    self.stage_rows[self.cur][0].set("fail")
                self.show_done(False, message)

        # ── the last page ────────────────────────────────────────────────
        def show_done(self, ok, message=None):
            self.failed_run = not ok
            self.goto(4, failed=not ok)
            for w in self.done_body.winfo_children():
                w.destroy()
            if not ok:
                self.badge.set("fail")
                self.done_title.configure(text="Setup stopped")
                self.done_lead.configure(text=message or "")
                card = Card(self.done_body, radius=14, pad=(4, 4))
                card.grid(row=0, column=0, columnspan=2, sticky="nsew")
                self.done_body.rowconfigure(0, weight=1)
                card.body.rowconfigure(0, weight=1)
                txt = tk.Text(card.body, bg=CARD, fg="#b9b9c0", bd=0, highlightthickness=0, wrap="word", font=UI["mono"], padx=14, pady=10, height=8)
                txt.grid(row=0, column=0, sticky="nsew")
                txt.insert("1.0", "\n".join(self.log_lines[-14:]))
                txt.configure(state="disabled")
                Btn(self.done_body, text="Copy the log", style="Small.TButton", command=lambda: self.copy("\n".join(self.log_lines), "Log copied")).grid(row=1, column=0, sticky="w", pady=(10, 0))
                return
            sel = self.sel or self.selection()
            warn = bool(self.warnings)
            account_left = not account_summary(self.account_dir)["ready"]
            self.badge.set("warn" if (warn or account_left) else "done")
            self.done_title.configure(text="Almost there" if account_left else ("ZTRelay is ready" if not warn else "Ready, with a few notes"))
            self.done_lead.configure(text=("The tools are installed. Your account needs a few more minutes." if account_left
                                           else "Commands are in %s" % (sel["prefix"] or DEFAULT_PREFIX)))
            # left: open now
            left = Card(self.done_body, radius=14, pad=(18, 14))
            left.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
            lb = left.body
            ttk.Label(lb, text="Open now", style="H.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
            r = 1
            for key, label, hint in (("proxy", "Open ZTR Proxy", "Your browser through a route"), ("ferry", "Open Ferry", "Files on your servers")):
                if sel.get(key):
                    Btn(lb, text=label, style="Primary.TButton" if r == 1 else "", command=lambda k=key: self.launch(k)).grid(row=r, column=0, sticky="w", pady=(0, 2))
                    ttk.Label(lb, text=hint, style="Dim.TLabel").grid(row=r + 1, column=0, sticky="w", pady=(0, 10))
                    r += 2
            if r == 1:
                ttk.Label(lb, text="Try this in a new terminal:", style="Dim.TLabel").grid(row=r, column=0, sticky="w")
                ttk.Label(lb, text='ztr_ssh --rh "example._ztr" --rp 22', style="Mono.TLabel").grid(row=r + 1, column=0, sticky="w", pady=(6, 0))
            # right: route + commands
            right = Card(self.done_body, radius=14, pad=(18, 14))
            right.grid(row=1, column=1, sticky="nsew", padx=(10, 0))
            rb = right.body
            ttk.Label(rb, text="Try it", style="H.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6))
            ttk.Label(rb, text="In a new terminal, open a session through a route:", style="Dim.TLabel", wraplength=330, justify="left").grid(row=1, column=0, sticky="w")
            ttk.Label(rb, text='ztr_ssh --rh "example._ztr" --rp 22', style="Mono.TLabel").grid(row=2, column=0, sticky="w", pady=(8, 0))
            if self.test_state["glyph"] == "done":
                ttk.Label(rb, text="Your setup test passed.", style="Dim.TLabel", foreground=GREEN).grid(row=3, column=0, sticky="w", pady=(12, 0))
            sm = account_summary(self.account_dir)
            if not sm["ready"]:
                left_to_do = [name for name, flag in (("a key", sm["key"]["ok"]), ("a route", sm["route"]), ("your secret key", sm["secret"])) if not flag]
                ac = Card(self.done_body, radius=14, pad=(18, 12), fill="#2e2a1e", border="#4a4023", style="Amber.TFrame")
                ac.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 12))
                ac.body.columnconfigure(0, weight=1)
                tk.Label(ac.body, text="Still to do: " + ", ".join(left_to_do), bg="#2e2a1e", fg="#e6d9a8", font=UI["bold"]).grid(row=0, column=0, sticky="w")
                Btn(ac.body, text="Finish setting up", style="Small.TButton", command=lambda: self.goto(3)).grid(row=0, column=1, sticky="e")
            cmds = Card(self.done_body, radius=14, pad=(18, 12))
            cmds.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 0))
            cb = cmds.body
            cb.columnconfigure(0, weight=0)
            cb.columnconfigure(1, weight=1)
            ttk.Label(cb, text="Your commands", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
            rows = [("ztr_ssh", "open an ssh session through a route"), ("ztr_forward", "forward a local port to a service"), ("ztr_pg", "reach a PostgreSQL server")]
            if sel.get("ferry"):
                rows.append(("ztr_ferry", "the file manager"))
            if sel.get("proxy"):
                rows.append(("ztr_proxy", "the browser proxy"))
            for i, (name, what) in enumerate(rows):
                ttk.Label(cb, text=name, style="Mono.TLabel").grid(row=i + 1, column=0, sticky="w", padx=(0, 18), pady=1)
                ttk.Label(cb, text=what, style="Dim.TLabel").grid(row=i + 1, column=1, sticky="w", pady=1)
            if self.rc_note:
                ttk.Label(cb, text=self.rc_note, style="Dim.TLabel", foreground=TEAL).grid(row=len(rows) + 1, column=0, columnspan=2, sticky="w", pady=(8, 0))
            if warn:
                wc = Card(self.done_body, radius=14, pad=(18, 12), fill="#2e2a1e", border="#4a4023", style="Amber.TFrame")
                wc.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0))
                tk.Label(wc.body, text="Worth a look", bg="#2e2a1e", fg=TEXT, font=UI["h"]).grid(row=0, column=0, sticky="w", pady=(0, 4))
                for i, w in enumerate(self.warnings[:3]):
                    tk.Label(wc.body, text="•  " + w[:150], bg="#2e2a1e", fg="#d8c99a", font=UI["small"], wraplength=620, justify="left").grid(row=i + 1, column=0, sticky="w")
            self.root.after(50, lambda: None)

        def launch(self, key):
            plugin = os.path.join(SCRIPT_DIR, "plugins", "ztr_proxy", "ztr_proxy") if key == "proxy" else os.path.join(SCRIPT_DIR, "plugins", "ztr_ferry")
            env = dict(os.environ)
            env["ZTR_VENV_DIR"] = self.sel.get("venv") or DEFAULT_VENV
            try:
                subprocess.Popen([plugin], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            except OSError as e:
                self.toast("Couldn't open it: %s" % e, "warn")

        # ── small helpers ────────────────────────────────────────────────
        def copy(self, text, note="Copied"):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.toast(note, "ok")

        def toast(self, text, kind="ok"):
            if self.toast_label is not None:
                self.toast_label.destroy()
            color = {"ok": GREEN, "warn": AMBER, "error": RED}.get(kind, TEXT)
            self.toast_label = tk.Label(self.root, text=text, bg="#2c2c2f", fg=color, font=UI["body"], padx=16, pady=8, bd=0)
            self.toast_label.place(relx=0.6, rely=0.93, anchor="center")
            self.root.after(2600, lambda: self.toast_label and self.toast_label.destroy())

    return App, tk


# A stand-in for the installer, so the window can be tried without installing anything (--demo).
DEMO_SCRIPT = r'''
import json, os, sys, time
sel = json.loads(sys.argv[1])
def say(msg, wait=0.5):
    print("[installer] " + msg, flush=True); time.sleep(wait)
say("checking prerequisites ...", 0.7)
say("python3 found (/usr/bin/python3).")
say("creating ztr's venv ...", 1.0)
if os.environ.get("ZTR_SETUP_DEMO_FAIL"):
    print("[installer] couldn't create the venv — on Debian/Ubuntu you likely need: sudo apt install python3-venv", file=sys.stderr, flush=True)
    sys.exit(1)
say("venv created.")
say("installing pycryptodome into the venv ...", 1.2)
say("pycryptodome installed.")
say("installing wrappers into ~/.local/bin ...", 0.6)
for n in ("ztr_ssh", "ztr_forward", "ztr_pg", "ztr_ferry", "ztr_proxy"):
    say(n + " -> ~/.local/bin/" + n, 0.2)
say("declined — add this to your shell rc file yourself if you want it:", 0.1)
print('    export PATH="$HOME/.local/bin:$PATH"  # added by ztrclient installer', flush=True)
if sel.get("ferry"):
    say("setting up Ferry (the file manager) ...", 0.6)
    say("tkinter found — Ferry's window will work.", 0.3)
    say("rsync found.", 0.3)
    say("Ferry added to your applications menu.", 0.5)
if sel.get("proxy"):
    say("setting up ZTR Proxy (the browser-proxy window) ...", 0.6)
    say("tkinter found — ZTR Proxy's window will work.", 0.3)
    say("ZTR Proxy added to your applications menu.", 0.5)
if sel.get("service") or sel.get("local_ip"):
    say("setting up ztr_i0 as a dummy interface bound to %s (needs sudo) ..." % sel.get("ip"), 1.0)
    say("ztr_i0 up with %s." % sel.get("ip"), 0.4)
if sel.get("service"):
    say("setting up ztr_tunnel_lp.py as a systemd --user service ...", 1.0)
    say("service installed and started: ztr-tunnel-lp.service", 0.4)
if sel.get("dashboard"):
    say("setting up ztr_dashboard.py as a systemd --user service ...", 1.0)
    say("service installed and started: ztr-dashboard.service", 0.4)
if sel.get("requests"):
    say("setting up ztr_requests as a systemd --user service ...", 1.0)
    say("service installed and started: ztr-requests.service", 0.4)
say("done. Try: ztr_ssh --rh \"example._ztr\" --rp 22", 0.1)
'''


def askpass_main(prompt):
    """The password window sudo uses when the installer runs from the setup window (sudo calls this program and reads
    the password from what it prints). Exits with 1 if cancelled."""
    import tkinter as tk
    root = tk.Tk()
    root.title("Password")
    root.configure(bg=BG)
    root.resizable(False, False)
    frame = tk.Frame(root, bg=CARD, padx=26, pady=22)
    frame.pack(padx=14, pady=14)
    tk.Label(frame, text="ZTRelay Setup needs your password", bg=CARD, fg=TEXT, font=("Helvetica", 13, "bold")).pack(anchor="w")
    tk.Label(frame, text="To set up the dedicated address. It goes straight to the system and is not kept.", bg=CARD, fg=DIM,
             font=("Helvetica", 10), wraplength=340, justify="left").pack(anchor="w", pady=(4, 12))
    entry = tk.Entry(frame, show="•", bg=FIELD, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Helvetica", 12), width=32,
                     highlightthickness=2, highlightbackground=FIELD, highlightcolor=CYAN)
    entry.pack(fill="x", ipady=6)
    entry.focus_set()
    out = {"value": None}

    def done(value):
        out["value"] = value
        root.destroy()
    row = tk.Frame(frame, bg=CARD)
    row.pack(fill="x", pady=(16, 0))
    tk.Button(row, text="Continue", command=lambda: done(entry.get()), bg=CYAN, fg="#ffffff", relief="flat", padx=16, pady=4, bd=0,
              highlightthickness=0).pack(side="right")
    tk.Button(row, text="Cancel", command=lambda: done(None), bg="#3a3a3d", fg=TEXT, relief="flat", padx=16, pady=4, bd=0,
              highlightthickness=0).pack(side="right", padx=(0, 8))
    root.bind("<Return>", lambda e: done(entry.get()))
    root.bind("<Escape>", lambda e: done(None))
    root.eval("tk::PlaceWindow . center")
    root.attributes("-topmost", True)
    root.mainloop()
    if out["value"] is None:
        return 1
    sys.stdout.write(out["value"] + "\n")
    sys.stdout.flush()
    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="A window for installing ztrclient.")
    parser.add_argument("--demo", action="store_true", help="show the whole flow with a pretend installer; nothing is installed")
    parser.add_argument("--check", action="store_true", help="print what this computer has, as JSON, and exit")
    parser.add_argument("--askpass", nargs="?", const="", metavar="PROMPT", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.askpass is not None:
        return askpass_main(args.askpass)
    if args.check:
        print(json.dumps(gather_checks(), indent=2))
        return 0
    try:
        import tkinter  # noqa: F401
    except ImportError:
        if IS_MAC:
            print("This needs Python's tkinter. With Homebrew: brew install python-tk@%d.%d (or use the python.org installer)." % sys.version_info[:2])
        else:
            print("This needs Python's tkinter. On Debian/Raspberry Pi OS: sudo apt install python3-tk")
        return 1
    if not os.path.isfile(INSTALLER):
        print("%s is missing — run this from the ztrclient folder." % os.path.basename(INSTALLER))
        return 1
    App, tk = build_app()
    try:
        root = tk.Tk()
    except tk.TclError as e:
        print("The window couldn't open (%s)." % e)
        print("Run this from a terminal on your desktop, or install in the terminal instead: ./installer.sh")
        return 1
    App(root, demo=args.demo)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
