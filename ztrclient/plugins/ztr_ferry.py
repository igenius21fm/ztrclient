#!/usr/bin/env python3
"""Ferry — a two-pane file manager for servers reached through a ZTRelay route.

Connect once, then browse your computer on the left and the server on the
right. Double-click a file to send or fetch it, drag a selection across to the
other side (or onto a folder there), or use the Upload / Download buttons.
Folders work too.

Also here: saved sites and per-site bookmarks, a transfer queue (cancel,
retry, remove), sortable columns with a name filter, permissions and chmod,
folder comparison, a choice of what to do when a file already exists, a speed
limit, search on the server, and View / Edit — open a server file in your
editor and upload it again when you save.

It talks to the tunnel service (ztr_tunnel_lp.py) over its control port: on
Connect it asks for a session to the server and opens one ssh connection
through it. Folder listings, new folders, renames and deletes, and every
transfer, reuse that one connection — so you sign in once, not per action. The
server only needs ssh (and a shell); nothing is installed on it.

    python3 plugins/ztr_ferry.py

Needs only Python's standard library (tkinter included) plus rsync and ssh on
the PATH.

Notes on what it does for you:
  * Transfers use rsync, so a re-run only moves what's missing ("Skip files
    that already exist"), and an interrupted file is kept in a hidden
    .ztr-partial folder rather than under its final name — a half-copied file
    is never mistaken for a finished one.
  * Nothing about the servers you visit is kept on disk. Like ztr_ssh, each
    connection gets a fresh local port, so its host key goes in a throwaway
    file that exists only while the connection is open and is deleted with it.
  * A password is handed to ssh through a throwaway helper that reads it from
    the environment. It is never written to disk or put on a command line, and
    never saved in the settings.
"""
import json
import os
import posixpath
import queue
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

APP_NAME = "Ferry"
TAGLINE = "Files between this computer and your servers, over ZTRelay"
_OLD_CONFIG_DIRS = [Path.home() / ".config" / "ztr_courier", Path.home() / ".config" / "ztr_files"]  # earlier names, newest first
CONFIG_DIR = Path(os.environ.get("ZTR_FERRY_HOME") or os.environ.get("ZTR_COURIER_HOME") or os.environ.get("ZTR_FILES_HOME")
                  or Path.home() / ".config" / "ztr_ferry")
SETTINGS_PATH = CONFIG_DIR / "settings.json"
ROUTES_DIR = Path(__file__).resolve().parent.parent / "routes"
PARTIAL_DIR = ".ztr-partial"
DEFAULT_CONTROL_PORT = 2223
# Big transfers are split into batches that run side by side over the one shared connection.
BATCH_MIN_FILES = 100                # this many files (or more) ...
BATCH_MIN_BYTES = 256 * 1024 * 1024  # ... or this many bytes (or more) turns batching on
BATCH_FILE_WEIGHT = 64 * 1024        # what each file costs besides its bytes (round trips), when balancing batches
# A few small files go as one tar stream over the open connection: rsync needs several round trips in a row before it
# moves a byte, which on a slow route costs seconds even for 60 bytes.
FAST_MAX_BYTES = 8 * 1024 * 1024
FAST_MAX_FILES = 40
DEFAULT_STREAMS = 1  # off: on one route, parallel batches share that route's bandwidth and measured slower than a single stream
MAX_STREAMS = 8

# ───────────────────────────── engine (no GUI) ─────────────────────────────


class ControlError(Exception):
    pass


class RemoteError(Exception):
    """Something the server (or the connection to it) refused, in words fit to show."""


class ConnectionLost(RemoteError):
    pass


class ControlClient:
    """One-request-per-connection client for ztr_tunnel_lp.py's control port
    (newline-delimited JSON — see that file's docstring)."""

    def __init__(self, host="127.0.0.1", port=DEFAULT_CONTROL_PORT):
        self.host = host
        self.port = int(port)

    def call(self, request, timeout=120):
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
                sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
                line = sock.makefile("r", encoding="utf-8").readline()
        except OSError as e:
            raise ControlError(
                f"Can't reach the tunnel service on {self.host}:{self.port} — is ztr_tunnel_lp.py running? ({e})"
            ) from None
        if not line:
            raise ControlError("The tunnel service closed the connection without answering.")
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            raise ControlError("The tunnel service sent something that isn't JSON.") from None

    def list(self, timeout=4):
        return self.call({"cmd": "list"}, timeout=timeout)

    def start(self, relay_name, target_port, config_file=None):
        req = {"cmd": "start", "relay_name": relay_name, "target_port": int(target_port)}
        if config_file:
            req["config_file"] = config_file
        res = self.call(req)
        if not res.get("status"):
            raise ControlError(res.get("error") or "The tunnel service couldn't start a tunnel.")
        return res

    def end(self, session_id):
        try:
            self.call({"cmd": "end", "session_id": session_id}, timeout=10)
        except ControlError:
            pass  # the idle reaper closes it anyway


def rsync_capabilities(rsync="rsync"):
    """What this rsync can do — read from its own --help, since macOS ships
    an older rsync-compatible tool than Linux does. None if it isn't there."""
    try:
        out = subprocess.run([rsync, "--help"], capture_output=True, text=True, timeout=10)
        text = (out.stdout or "") + (out.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return None
    # rsync 3 added --info and incremental recursion; --no-inc-recursive is a
    # negated form its --help doesn't list, so go by the version number.
    try:
        ver = subprocess.run([rsync, "--version"], capture_output=True, text=True, timeout=10).stdout
        m = re.search(r"version\s+(\d+)\.", ver)
        major = int(m.group(1)) if m else 0
    except (OSError, subprocess.SubprocessError):
        major = 0
    return {
        "progress2": "--info" in text,
        "stats": "--stats" in text,
        "no_inc_recursive": major >= 3 and "--info" in text,
        "protect_args": "--protect-args" in text or "--secluded-args" in text,
        "partial_dir": "--partial-dir" in text,
        "ignore_existing": "--ignore-existing" in text,
        "progress": "--progress" in text,
        "bwlimit": "--bwlimit" in text,
        "compress": "--compress" in text,
        "files_from": "--files-from" in text,
        "from0": "--from0" in text,
    }


def build_ssh_command(ssh, port, known_hosts, key_path=None, use_password=False):
    """The ssh command that opens the connection, as a list. Every tunnel session has its own local port, so ssh
    meets a "new" host each time (as with ztr_ssh); its key goes in `known_hosts`, a throwaway file for this one
    connection. No server name is written anywhere that outlives it."""
    cmd = [
        ssh,
        "-p", str(port),
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=4",
        "-o", "ConnectTimeout=20",
    ]
    if use_password:
        cmd += ["-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "NumberOfPasswordPrompts=1"]
    else:
        cmd += ["-o", "BatchMode=yes"]  # fail fast instead of waiting on a prompt nobody can answer
        if key_path:
            cmd += ["-i", key_path, "-o", "IdentitiesOnly=yes"]
    return cmd


# ssh options that stop host-key records from being shared or kept. Every server reached through ZTR shows up at the same
# tunnel address, and a setting like `HostKeyAlias 10.10.15.10` in ~/.ssh/config would give them all one identity — the
# second server then looks like "the first one with a changed key". These override any such config for one session.
EPHEMERAL_HOSTKEY_OPTS = ["-o", "UserKnownHostsFile=/dev/null", "-o", "GlobalKnownHostsFile=/dev/null",
                          "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR"]


def normalize_remote(path, as_folder=False):
    """A remote path in the form rsync handles on every version: relative to
    the login folder, because a leading "~/" is only expanded by a remote
    shell — which protected arguments (rsync -s) deliberately bypass."""
    path = (path or "").strip()
    if path in ("~", "~/", ""):
        path = "./"
    elif path.startswith("~/"):
        path = path[2:]
    if as_folder and not path.endswith("/"):
        path += "/"
    return path


def build_rsync_command(rsync, caps, direction, ssh_cmd, user, local_ip, sources, dest,
                        policy="skip", dry_run=False, bwlimit=None, compress=False, files_from=None, base=None):
    """direction 'download': `sources` are remote paths, `dest` a local folder.
    direction 'upload': `sources` are local paths, `dest` a remote folder.
    A folder given without a trailing slash is copied as a folder.
    policy: 'skip' leaves files that already exist alone, 'newer' replaces
    only those the source has changed more recently, 'overwrite' replaces all.
    With files_from (a list file) and base (the folder the listed names are
    relative to), exactly those names are copied — one batch of a large job."""
    caps = caps or {}
    cmd = [rsync, "-a", "-v"]
    if caps.get("protect_args"):
        cmd.append("-s")
    if caps.get("partial_dir"):
        cmd.append(f"--partial-dir={PARTIAL_DIR}")
    if caps.get("progress2"):
        cmd.append("--info=progress2")
        if caps.get("no_inc_recursive"):
            cmd.append("--no-inc-recursive")  # so the overall percentage has a stable total
    elif caps.get("progress"):
        cmd.append("--progress")
    if caps.get("stats"):
        cmd.append("--stats")
    if policy == "skip" and caps.get("ignore_existing", True):
        cmd.append("--ignore-existing")
    elif policy == "newer":
        cmd.append("-u")
    if bwlimit and caps.get("bwlimit"):
        cmd.append(f"--bwlimit={int(bwlimit)}")
    if compress and caps.get("compress"):
        cmd.append("-z")  # rsync leaves already-compressed formats (zip, jpg, mp4 ...) alone on its own
    if files_from:
        cmd.append(f"--files-from={files_from}")
        if caps.get("from0"):
            cmd.append("--from0")
    if dry_run:
        cmd.append("-n")
    cmd += ["-e", " ".join(shlex.quote(p) for p in ssh_cmd)]

    def remote(path):
        # With protect-args the path reaches the server untouched; without it
        # the remote shell splits on spaces, so it needs quoting.
        return f"{user}@{local_ip}:" + (path if caps.get("protect_args") else shlex.quote(path))

    if files_from:
        if direction == "download":
            cmd += [remote(normalize_remote(base, as_folder=True)), str(dest).rstrip("/") + "/"]
        else:
            cmd += [str(base).rstrip("/") + "/", remote(normalize_remote(dest, as_folder=True))]
    elif direction == "download":
        cmd += [remote(normalize_remote(s)) for s in sources] + [str(dest)]
    else:
        cmd += [str(s) for s in sources] + [remote(normalize_remote(dest, as_folder=True))]
    return cmd


# ── planning large transfers ──

LIST_RE = re.compile(r"^([-dlcbps])[rwxsStT-]{9}\s+([\d,]+)\s+\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (.+)$")


def parse_list_only(text):
    """[(relative path, size, is_dir)] from `rsync --list-only` output; None if it holds names batching can't carry."""
    out = []
    for line in text.splitlines():
        m = LIST_RE.match(line)
        if not m:
            continue
        kind, size, name = m.groups()
        if kind == "l":
            name = name.split(" -> ")[0]
        if name == ".":
            continue
        if "\\#" in name or "\n" in name or not name:
            return None  # escaped / odd names: let a single rsync handle it
        out.append((name, 0 if kind in "dl" else int(size.replace(",", "")), kind == "d"))
    return out


def plan_local(sources):
    """[(relative path, size, is_dir)] and the base folder for local paths that share one parent; (None, None) otherwise."""
    sources = [str(s).rstrip("/") for s in sources]
    parents = {os.path.dirname(s) for s in sources}
    if len(parents) != 1:
        return None, None
    base = parents.pop() or "/"
    out = []
    for src in sources:
        name = os.path.basename(src)
        if os.path.isdir(src) and not os.path.islink(src):
            out.append((name, 0, True))
            for root, dirs, files in os.walk(src):
                rel = os.path.relpath(root, base)
                for d in dirs:
                    full = os.path.join(root, d)
                    if os.path.islink(full):
                        out.append((os.path.join(rel, d), 0, False))  # a link is copied as a link, never followed
                    else:
                        out.append((os.path.join(rel, d), 0, True))
                for f in files:
                    try:
                        size = os.lstat(os.path.join(root, f)).st_size
                    except OSError:
                        continue
                    out.append((os.path.join(rel, f), size, False))
        else:
            try:
                out.append((name, os.lstat(src).st_size, False))
            except OSError:
                return None, None
    if any("\n" in n for n, _s, _d in out):
        return None, None
    return out, base


def split_batches(files, n):
    """Spreads [(name, size)] over n batches of about equal cost (bytes plus a per-file cost), biggest first."""
    n = max(1, min(n, len(files)))
    batches = [{"files": [], "bytes": 0, "weight": 0} for _ in range(n)]
    for name, size in sorted(files, key=lambda f: -f[1]):
        b = min(batches, key=lambda b: b["weight"])
        b["files"].append(name)
        b["bytes"] += size
        b["weight"] += size + BATCH_FILE_WEIGHT
    return [b for b in batches if b["files"]]


def write_list(path, names, caps):
    nul = bool((caps or {}).get("from0"))
    with open(path, "wb") as f:
        f.write((("\0" if nul else "\n").join(names) + ("\0" if nul else "\n")).encode("utf-8", "surrogateescape"))


def to_rate(text):
    """'1.20MB/s' -> bytes per second."""
    m = re.match(r"([\d.]+)\s*([kKMGT]?)B/s", text or "")
    if not m:
        return 0.0
    return float(m.group(1)) * {"": 1, "k": 1024, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[m.group(2)]


PROGRESS_RE = re.compile(r"^\s*([\d,]+)\s+(\d+)%\s+(\S+/s)\s+(\d+:\d\d:\d\d)(?:\s+\((.*)\))?\s*$")
STAT_FILES_RE = re.compile(r"Number of (?:regular )?files transferred:\s*([\d,]+)")
STAT_BYTES_RE = re.compile(r"Total transferred file size:\s*([\d,]+)")
NOISE_PREFIXES = (
    "sending incremental file list", "receiving incremental file list", "sending file list",
    "receiving file list", "sent ", "total size is", "building file list", "created directory",
    "Number of", "Total ", "File list ", "Literal data", "Matched data", "rsync",
)


def parse_progress(line):
    m = PROGRESS_RE.match(line)
    if not m:
        return None
    return {"bytes": int(m.group(1).replace(",", "")), "percent": int(m.group(2)),
            "speed": m.group(3), "eta": m.group(4), "extra": m.group(5) or ""}


def is_name_line(line):
    s = line.rstrip()
    return bool(s) and not s.startswith((" ", "\t")) and not s.startswith(NOISE_PREFIXES) and not s.endswith("/") \
        and "rsync:" not in s and "rsync error" not in s and not s.startswith("ssh:") and " warning: " not in s


def explain_exit(code, tail):
    """A plain-language reason for a failure, from the exit code and the last
    lines the tool printed."""
    text = "\n".join(tail).lower()
    if "host key verification failed" in text or "remote host identification has changed" in text:
        return "The server's identity changed while connecting, so nothing was transferred. Try connecting again."
    if "permission denied" in text and ("publickey" in text or "password" in text or "(" in text):
        return "The server refused the login. Check the user name and the key or password."
    if "connection refused" in text or "connection timed out" in text or "no route" in text:
        return "Couldn't reach the server through the tunnel. Check the host and port."
    if "connection closed" in text or "connection reset" in text or "broken pipe" in text:
        return "The connection was cut during the transfer. Run it again — files already copied are skipped."
    if "no such file" in text or "link_stat" in text:
        return "That path doesn't exist on the server (or locally)."
    if code in (23, 24):
        return "Some files couldn't be transferred (they may have changed or aren't readable). The rest were copied."
    if code == 255:
        return "ssh couldn't connect or log in."
    if code == 30:
        return "The transfer timed out."
    return f"rsync stopped with an error (exit code {code})."


class AskpassHelper:
    """Hands a password to ssh without writing it anywhere: a tiny script that
    prints $ZTR_FERRY_PW, which exists only in the child's environment."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="ferry-ask-"))
        os.chmod(self.dir, 0o700)
        self.script = self.dir / "askpass.sh"
        self.script.write_text("#!/bin/sh\nprintf '%s\\n' \"$ZTR_FERRY_PW\"\n")
        self.script.chmod(stat.S_IRWXU)

    def env(self, password):
        env = dict(os.environ)
        env.update({"SSH_ASKPASS": str(self.script), "SSH_ASKPASS_REQUIRE": "force", "ZTR_FERRY_PW": password})
        if sys.platform != "darwin":
            env.setdefault("DISPLAY", ":0")  # ssh only runs the helper when it thinks there is a display
        return env

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


# ── directory listings ──

class Entry:
    __slots__ = ("name", "is_dir", "size", "modified", "perms")

    def __init__(self, name, is_dir, size=0, modified="", perms=""):
        self.name, self.is_dir, self.size, self.modified, self.perms = name, is_dir, size, modified, perms

    def __repr__(self):
        return f"Entry({self.name!r}, dir={self.is_dir}, size={self.size}, {self.modified!r})"


# GNU ls --time-style=long-iso, then the BSD/macOS/busybox-ish shape.
LS_ISO = re.compile(r"^(([-dlcbpsD])[rwxsStT-]{9})\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d)\s+(.+)$")
LS_BSD = re.compile(r"^(([-dlcbpsD])[rwxsStT-]{9})\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+([A-Z][a-z]{2}\s+\d+\s+(?:\d\d:\d\d|\d{4}))\s+(.+)$")


def sort_entries(entries):
    return sorted(entries, key=lambda e: (not e.is_dir, e.name.lower(), e.name))


def parse_ls(text):
    """Entries from `ls -lApL` output (folders first, then by name)."""
    out = []
    for line in text.splitlines():
        m = LS_ISO.match(line) or LS_BSD.match(line)
        if not m:
            continue  # "total N", device files, anything unexpected
        perms, kind, size, when, name = m.groups()
        is_dir = kind == "d" or name.endswith("/")
        name = name.rstrip("/") if is_dir else name
        if name in (".", "..", ""):
            continue
        out.append(Entry(name, is_dir, 0 if is_dir else int(size), when, perms))
    return sort_entries(out)


def perms_to_octal(perms):
    """'-rwxr-xr--' -> '754' ('' if it isn't a permission string)."""
    if len(perms) != 10:
        return ""
    bits = perms[1:]
    digits = []
    for i in range(0, 9, 3):
        r, w, x = bits[i:i + 3]
        digits.append(str((4 if r == "r" else 0) + (2 if w == "w" else 0) + (1 if x in "xst" else 0)))
    return "".join(digits)


def list_local(path):
    """(absolute path, entries) for a folder on this computer."""
    path = os.path.abspath(os.path.expanduser(path or "~"))
    out = []
    with os.scandir(path) as it:
        for de in it:
            try:
                st = de.stat()  # follows links; a broken link falls to the except
                is_dir = de.is_dir()
            except OSError:
                try:
                    st, is_dir = de.stat(follow_symlinks=False), False
                except OSError:
                    continue
            out.append(Entry(de.name, is_dir, 0 if is_dir else st.st_size,
                             time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)), stat.filemode(st.st_mode)))
    return path, sort_entries(out)


def _cd_clause(path):
    if not path or path == "~":
        return "cd"
    if path.startswith("~/"):
        return 'cd "$HOME"/' + shlex.quote(path[2:])
    return "cd -- " + shlex.quote(path)


# ── one connection to one server ──

class Job:
    """One transfer. Plain data, so it's easy to test."""

    def __init__(self, direction, sources, dest, policy="skip", dry_run=False, bwlimit=None,
                 compress=False, streams=1, size_hint=None):
        self.direction, self.sources, self.dest = direction, list(sources), dest
        self.size_hint = size_hint  # total bytes if every source is a plain file of known size, else None
        self.policy, self.dry_run, self.bwlimit = policy, dry_run, bwlimit
        self.compress, self.streams = compress, max(1, min(int(streams or 1), MAX_STREAMS))
        self.cancelled = threading.Event()
        self.proc = None
        self.procs = []  # the batches running side by side

    def cancel(self):
        self.cancelled.set()
        for p in [self.proc] + list(self.procs):
            if p and p.poll() is None:
                try:
                    os.killpg(p.pid, signal.SIGTERM)  # rsync and the ssh it started
                except OSError:
                    try:
                        p.terminate()
                    except OSError:
                        pass


TERMINALS = [  # (program, how it takes a title, how it takes the command to run)
    ("lxterminal", ["-t", "{title}"], ["-e"]),
    ("gnome-terminal", ["--title", "{title}"], ["--"]),
    ("xfce4-terminal", ["--title", "{title}"], ["-x"]),
    ("mate-terminal", ["--title", "{title}"], ["-x"]),
    ("konsole", [], ["-e"]),
    ("kitty", ["--title", "{title}"], []),
    ("alacritty", ["--title", "{title}"], ["-e"]),
    ("foot", ["--title", "{title}"], []),
    ("xterm", ["-T", "{title}"], ["-e"]),
    ("x-terminal-emulator", [], ["-e"]),
]


def find_gnu_tar():
    """This computer's GNU tar (the fast path for a few small files needs its skip/keep-newer options): `tar` on Linux,
    `gtar` (Homebrew's gnu-tar) on a Mac, whose own tar is bsdtar. None if there isn't one."""
    for name in ("gtar", "tar"):
        path = shutil.which(name)
        if not path:
            continue
        try:
            if "GNU tar" in subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10).stdout:
                return path
        except (OSError, subprocess.SubprocessError):
            continue
    return None


# The modifier a shortcut uses: Command on a Mac, Control elsewhere.
MOD = "Command" if sys.platform == "darwin" else "Control"


def mac_terminal_argv(inner):
    """On a Mac: asks Terminal to open a window running `inner`. None if osascript isn't there."""
    osascript = shutil.which("osascript")
    if not osascript:
        return None
    command = " ".join(shlex.quote(a) for a in inner)
    quoted = command.replace("\\", "\\\\").replace('"', '\\"')
    script = 'tell application "Terminal"\nactivate\ndo script "' + quoted + '"\nend tell'
    return [osascript, "-e", script]


def find_ztr_ssh():
    """The ztr_ssh wrapper that sits next to this file, else one on the PATH (FERRY_ZTR_SSH overrides both)."""
    forced = os.environ.get("FERRY_ZTR_SSH")
    if forced:
        return forced if os.access(forced, os.X_OK) else None
    beside = Path(__file__).resolve().parent / "ztr_ssh"
    if beside.is_file() and os.access(beside, os.X_OK):
        return str(beside)
    return shutil.which("ztr_ssh")


def wrap_for_terminal(argv):
    """Runs argv, then waits for Enter, so an error stays on screen instead of the window vanishing."""
    script = '"$@"; code=$?; echo; echo "[ferry] finished (exit $code). Press Enter to close this window."; read _'
    return ["sh", "-c", script, "sh"] + list(argv)


def terminal_argv(argv, title="Ferry"):
    """The command line that opens a terminal window running argv; None if no terminal program is installed.
    FERRY_TERMINAL (for example "xterm -e") overrides the search."""
    inner = wrap_for_terminal(argv)
    forced = os.environ.get("FERRY_TERMINAL", "").strip()
    if forced:
        return shlex.split(forced) + inner
    if sys.platform == "darwin":
        return mac_terminal_argv(inner)
    for program, title_args, run_args in TERMINALS:
        path = shutil.which(program)
        if path:
            return [path] + [a.replace("{title}", title) for a in title_args] + run_args + inner
    return None


def _job_key(job):
    return (job.direction, job.dest, job.policy, job.dry_run, job.bwlimit, job.compress, job.streams)


def _base_names(job):
    return {os.path.basename(str(s).rstrip("/")): str(s).rstrip("/") for s in job.sources}


def mergeable(a, b):
    """True if b can ride along with a in one rsync: same direction, destination and options, and no two
    different sources that would land under the same name."""
    if _job_key(a) != _job_key(b):
        return False
    mine, theirs = _base_names(a), _base_names(b)
    return all(mine.get(name, path) == path for name, path in theirs.items())


def merge_jobs(jobs):
    """One Job covering all of `jobs` (see mergeable). Every transfer costs a fixed few seconds of start-up on a
    slow route, so one rsync for five files beats five rsyncs."""
    first = jobs[0]
    sources, seen = [], set()
    for j in jobs:
        for src in j.sources:
            key = str(src).rstrip("/")
            if key not in seen:
                seen.add(key)
                sources.append(src)
    hints = [j.size_hint for j in jobs]
    return Job(first.direction, sources, first.dest, first.policy, first.dry_run, first.bwlimit, first.compress, first.streams,
               None if any(h is None for h in hints) else sum(hints))


class Connection:
    """A tunnel session plus one long-lived ssh connection through it
    (OpenSSH connection sharing). Everything — listings, folder changes,
    transfers — rides that connection, so the login happens once."""

    def __init__(self, host, port, user, route=None, key_path=None, password=None,
                 control=None, control_port=DEFAULT_CONTROL_PORT, ssh="ssh", rsync="rsync"):
        self.host, self.port, self.user = host, int(port), user
        self.route, self.key_path, self.password = route, key_path, password
        self.control = control or ControlClient(port=control_port)
        self.ssh, self.rsync = ssh, rsync
        self.session_id = self.local_ip = self.local_port = None
        self.caps = None
        self.dir = self.sock = None
        self.warm = False
        self.fast_ok = None  # can both ends do the tar fast path? learned on first use
        self.local_tar = None

    # -- opening and closing

    def open(self, emit=None):
        emit = emit or (lambda *a: None)
        self.caps = rsync_capabilities(self.rsync)
        emit("status", "Opening a tunnel…")
        session = self.control.start(self.host, self.port, self.route)
        self.session_id = session["session_id"]
        self.local_ip, self.local_port, self.warm = session["local_ip"], session["local_port"], bool(session.get("warm"))
        askpass = None
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            self.dir = Path(tempfile.mkdtemp(prefix="ferry-"))
            self.sock = str(self.dir / "m")
            err_path = self.dir / "err"
            use_password = bool(self.password)
            cmd = build_ssh_command(self.ssh, self.local_port, str(self.dir / "known_hosts"), self.key_path, use_password)
            # -f: once logged in, ssh moves to the background and keeps the connection for the commands below.
            cmd += ["-f", "-N", "-M", "-S", self.sock, f"{self.user}@{self.local_ip}"]
            env = None
            if use_password:
                askpass = AskpassHelper()
                env = askpass.env(self.password)
            emit("status", "Signing in…")
            with open(err_path, "wb") as err:  # a file, not a pipe: the background ssh would hold a pipe open
                rc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                                    env=env, timeout=90).returncode
            if rc != 0:
                tail = err_path.read_text(errors="replace").splitlines()[-12:]
                raise RemoteError(explain_exit(rc, tail))
        except subprocess.TimeoutExpired:
            self.close()
            raise RemoteError("Signing in took too long. Check the server and your credentials.") from None
        except BaseException:
            self.close()
            raise
        finally:
            if askpass:
                askpass.close()

    def alive(self):
        if not self.sock:
            return False
        try:
            return subprocess.run(self._base() + ["-O", "check", self._target()], capture_output=True,
                                  timeout=8).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def close(self):
        """Ends the shared connection and the tunnel session. Safe to repeat."""
        if self.sock and os.path.exists(self.sock):
            try:
                subprocess.run(self._base() + ["-O", "exit", self._target()], capture_output=True, timeout=6)
            except (OSError, subprocess.SubprocessError):
                pass
        if self.session_id:
            self.control.end(self.session_id)
            self.session_id = None
        if self.dir:
            shutil.rmtree(self.dir, ignore_errors=True)
        self.dir = self.sock = None

    def ztr_ssh_argv(self, script, control_port=None):
        """The ztr_ssh command that opens a shell on this server (its own tunnel session, same user, key and route)."""
        argv = [script, "-l", self.user] + EPHEMERAL_HOSTKEY_OPTS
        if self.key_path:
            argv += ["-i", self.key_path, "-o", "IdentitiesOnly=yes"]
        argv += ["--rh", self.host, "--rp", str(self.port)]
        if self.route:
            argv += ["--config-file", self.route]
        argv += ["--cp", str(control_port or getattr(self.control, "port", DEFAULT_CONTROL_PORT))]
        return argv

    # -- commands on the server

    def _target(self):
        return f"{self.user}@{self.local_ip}"

    def _base(self):
        return [self.ssh, "-S", self.sock or "", "-o", "ControlMaster=no", "-o", "BatchMode=yes", "-p", str(self.local_port)]

    def _exec(self, script, timeout=60):
        if not self.sock:
            raise ConnectionLost("Not connected.")
        try:
            p = subprocess.run(self._base() + [self._target(), "sh -c " + shlex.quote(script)],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise RemoteError("The server took too long to answer.") from None
        except OSError as e:
            raise ConnectionLost(f"Couldn't run ssh: {e}") from None
        out, err = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
        if p.returncode == 255:
            raise ConnectionLost("The connection to the server was lost.")
        return p.returncode, out, err

    def listdir(self, path=""):
        """(absolute path, entries) for a folder on the server; '' is the login folder."""
        script = (f'{_cd_clause(path)} || exit 3; echo "@@PWD@@$(pwd)"; '
                  'out=$(LC_ALL=C ls -lApL --time-style=long-iso 2>/dev/null); '
                  '[ -n "$out" ] || out=$(LC_ALL=C ls -lApL 2>/dev/null); printf "%s\\n" "$out"')
        rc, out, err = self._exec(script)
        if rc == 3:
            raise RemoteError(f"Can't open {path or 'the home folder'} — it doesn't exist or isn't accessible.")
        first, _, rest = out.partition("\n")
        if rc != 0 or not first.startswith("@@PWD@@"):
            raise RemoteError((err.strip().splitlines() or ["The server didn't return a listing."])[-1])
        return first[len("@@PWD@@"):], parse_ls(rest)

    def mkdir(self, path):
        self._must(f"mkdir -- {shlex.quote(path)}")

    def rename(self, src, dst):
        self._must(f"[ ! -e {shlex.quote(dst)} ] || {{ echo 'Something named that already exists.' >&2; exit 1; }}; "
                   f"mv -- {shlex.quote(src)} {shlex.quote(dst)}")

    def remove(self, paths):
        self._must("rm -r -- " + " ".join(shlex.quote(p) for p in paths))

    def chmod(self, paths, mode, recursive=False):
        if not re.fullmatch(r"[0-7]{3,4}", mode or ""):
            raise RemoteError("Use an octal mode such as 644 or 755.")
        if any(not p.startswith("/") for p in paths):
            raise RemoteError("Permissions can only be changed on full paths.")  # so a name can never look like an option
        self._must(f"chmod {'-R ' if recursive else ''}{mode} " + " ".join(shlex.quote(p) for p in paths))

    def search(self, folder, pattern, limit=300):
        """[(path, is_dir)] for names under `folder` containing `pattern`."""
        if not pattern.strip():
            raise RemoteError("Type part of a file name to look for.")
        script = (f"find {shlex.quote(folder)} -maxdepth 10 -iname {shlex.quote('*' + pattern.strip() + '*')} 2>/dev/null "
                  "| head -n " + str(limit) + " | while IFS= read -r f; do if [ -d \"$f\" ]; then echo \"D $f\"; else echo \"F $f\"; fi; done")
        rc, out, _err = self._exec(script, timeout=120)
        return [(line[2:], line[0] == "D") for line in out.splitlines() if line[:2] in ("D ", "F ")]

    def _must(self, script):
        rc, _out, err = self._exec(script)
        if rc != 0:
            raise RemoteError((err.strip().splitlines() or [f"The server reported an error (code {rc})."])[-1])

    # -- transfers

    def transfer(self, job, emit):
        """Runs one transfer over the shared connection and reports through
        emit(kind, payload): 'status', 'log' (text, level), 'progress', and a
        final 'done'. Large transfers are split into batches that run side by
        side; small ones run as a single rsync. Returns the result dict."""
        result = {"ok": False, "cancelled": False, "message": "", "files": None, "bytes": None, "dry_run": job.dry_run, "seconds": 0.0}
        started = time.time()
        try:
            if self.caps is None:
                raise RemoteError("rsync isn't installed (or isn't on the PATH), so there's nothing to transfer with.")
            if not self.sock or not os.path.exists(self.sock):
                raise ConnectionLost("Not connected.")
            if job.bwlimit and not self.caps.get("bwlimit"):
                emit("log", ("This rsync can't limit speed, so the limit is ignored.", "err"))
            fast = self._fast_plan(job)
            if fast and self._run_tar(job, fast, emit, result):
                return result
            plan = None
            if not job.dry_run and job.streams > 1 and self.caps.get("files_from"):
                emit("status", "Scanning…")
                plan = self._plan(job)
                if job.cancelled.is_set():
                    raise KeyboardInterrupt
            if plan:
                self._run_batched(job, plan, emit, result)
            else:
                self._run_single(job, emit, result)
        except KeyboardInterrupt:
            result.update(cancelled=True, message="Cancelled.")
        except RemoteError as e:
            result["message"] = str(e)
        except Exception as e:  # never let the worker thread die silently
            result["message"] = f"Something went wrong: {e}"
        finally:
            job.proc = None
            job.procs.clear()
            result["seconds"] = time.time() - started
            emit("done", result)
        return result

    def _fast_plan(self, job):
        """(base folder, ['./name', ...]) when the job is a handful of small plain files from one folder; else None."""
        if job.dry_run or job.bwlimit or self.fast_ok is False or len(job.sources) > FAST_MAX_FILES:
            return None
        hint = job.size_hint
        if hint is None and job.direction == "upload":
            try:
                modes = [os.lstat(s) for s in job.sources]
            except OSError:
                return None
            hint = None if any(stat.S_ISDIR(m.st_mode) for m in modes) else sum(m.st_size for m in modes)
            job.size_hint = hint
        if hint is None or hint > FAST_MAX_BYTES:
            return None
        join = posixpath if job.direction == "download" else os.path
        parents = {join.dirname(str(s).rstrip("/")) for s in job.sources}
        if len(parents) != 1:
            return None
        if self.fast_ok is None:  # the local side needs GNU tar for its skip/keep-newer options
            self.local_tar = find_gnu_tar()
            self.fast_ok = bool(self.local_tar)
            if not self.fast_ok:
                return None
        base = parents.pop() or "/"
        return base, ["./" + join.basename(str(s).rstrip("/")) for s in job.sources]

    def _run_tar(self, job, fast, emit, result):
        """Moves the files as one tar stream over the open connection. Returns False if this server's tar can't do it
        (the caller then uses rsync), True once the result is filled in."""
        base, names = fast
        flags = {"skip": ["--skip-old-files"], "newer": ["--keep-newer-files"]}.get(job.policy, [])
        env = dict(os.environ, LC_ALL="C")  # so the "skipped" messages below read the same everywhere
        q = shlex.quote
        if job.direction == "download":
            first = self._base() + [self._target(), "LC_ALL=C tar -C " + q(base) + " -cf - " + " ".join(q(n) for n in names)]
            second = [self.local_tar, "-C", str(job.dest), "-xf", "-", "-p", "-v"] + flags
            first_env, second_env = None, env
        else:
            first = [self.local_tar, "-C", base, "-cf", "-"] + names
            second = self._base() + [self._target(), "LC_ALL=C tar -C " + q(job.dest) + " -xf - -p -v " + " ".join(flags)]
            first_env, second_env = env, None
        emit("log", ("$ " + " | ".join(" ".join(shlex.quote(c) for c in cmd) for cmd in (first, second)), "cmd"))
        emit("status", "Downloading…" if job.direction == "download" else "Uploading…")
        if job.cancelled.is_set():
            raise KeyboardInterrupt
        p1 = subprocess.Popen(first, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=first_env,
                              start_new_session=True)
        p2 = subprocess.Popen(second, stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=second_env,
                              start_new_session=True)
        p1.stdout.close()
        job.procs[:] = [p1, p2]
        if job.cancelled.is_set():
            job.cancel()
        try:
            out2, err2 = p2.communicate(timeout=600)
            err1 = p1.stderr.read()
            code1 = p1.wait()
        except subprocess.TimeoutExpired:
            job.cancel()
            raise RemoteError("The transfer timed out.") from None
        finally:
            for pipe in (p1.stderr,):
                try:
                    pipe.close()
                except OSError:
                    pass
        if job.cancelled.is_set():
            result.update(cancelled=True, message="Cancelled.")
            return True
        err = (err1 + err2).decode("utf-8", "replace")
        lines = [ln for ln in err.splitlines() if ln.strip()]
        if p2.returncode == 255 or code1 == 255:
            raise ConnectionLost("The connection to the server was lost.")
        if any(("unrecognized option" in ln or "invalid option" in ln or "Try 'tar" in ln) for ln in lines) and job.direction == "upload":
            self.fast_ok = False  # this server's tar lacks an option: use rsync from now on
            return False
        names_done = [ln for ln in out2.decode("utf-8", "replace").splitlines() if ln.strip() and not ln.endswith("/")]
        skipped = sum(1 for ln in lines if "skipping existing file" in ln or "is newer or same age" in ln)
        for ln in names_done:
            emit("log", (ln[2:] if ln.startswith("./") else ln, "name"))
        for ln in lines:
            emit("log", (ln, "dim"))
        failed = p2.returncode not in (0,) or code1 not in (0,)
        if failed:
            text = "\n".join(lines).lower()
            if "no such file" in text or "cannot stat" in text:
                result["message"] = "That path doesn't exist on the server (or locally)."
            elif "permission denied" in text or "cannot open" in text or "cannot mkdir" in text:
                result["message"] = "Some files couldn't be written or read (permission denied). The rest were copied."
            else:
                result["message"] = explain_exit(code1 or p2.returncode, lines[-6:]).replace("rsync stopped", "The copy stopped")
            return True
        copied = max(0, len(names_done) - skipped)
        result["ok"], result["files"] = True, copied
        result["bytes"] = (job.size_hint or None) if copied else None
        result["message"] = "Done — everything was already there." if copied == 0 else f"Done — {copied} file(s) copied."
        return True

    def _remote_arg(self, path):
        return f"{self.user}@{self.local_ip}:" + (path if self.caps.get("protect_args") else shlex.quote(path))

    def _plan(self, job):
        """Lists what the job covers and, when it's big enough, how to split it. None means: run it as one rsync."""
        if job.direction == "upload":
            entries, base = plan_local(job.sources)
        else:
            parents = {posixpath.dirname(s.rstrip("/")) for s in job.sources}
            if len(parents) != 1:
                return None
            base = parents.pop() or "/"
            entries = []
            for src in job.sources:  # one listing per source: with two remote sources rsync reads the second as a destination
                cmd = [self.rsync, "-r", "--list-only", "-8"] + (["-s"] if self.caps.get("protect_args") else [])
                cmd += ["-e", " ".join(shlex.quote(p) for p in self._base()), self._remote_arg(normalize_remote(src))]
                try:
                    r = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, timeout=180)
                except (OSError, subprocess.SubprocessError):
                    return None
                if r.returncode != 0:
                    return None
                part = parse_list_only(r.stdout.decode("utf-8", "replace"))
                if part is None:
                    return None
                entries += part
        if not entries or base is None:
            return None
        files = [(n, sz) for n, sz, d in entries if not d]
        total = sum(sz for _n, sz in files)
        if len(files) < 2 or (len(files) < BATCH_MIN_FILES and total < BATCH_MIN_BYTES):
            return None
        return {"base": base, "batches": split_batches(files, job.streams), "dirs": [n for n, _sz, d in entries if d],
                "files": len(files), "bytes": total}

    def _run_batched(self, job, plan, emit, result):
        batches, total, nfiles = plan["batches"], max(1, plan["bytes"]), plan["files"]
        n = len(batches)
        per_limit = max(1, int(job.bwlimit) // n) if job.bwlimit else None
        verb = "Downloading…" if job.direction == "download" else "Uploading…"
        emit("log", (f"Batching: {nfiles} files, {human_bytes(plan['bytes'])} in {n} parallel streams", "info"))
        emit("status", verb)
        tmp = Path(tempfile.mkdtemp(prefix="ferry-batch-", dir=self.dir))
        lock = threading.Lock()
        st = {"done": [0] * n, "files": [0] * n, "xfer_files": 0, "xfer_bytes": 0, "names": 0, "current": "",
              "t": time.time(), "last": 0.0, "rate": 0.0, "last_done": 0}
        codes, tails = [None] * n, [[] for _ in range(n)]
        by_bytes = bool(self.caps.get("progress2"))

        def report(force=False):
            now = time.time()
            if not force and now - st["last"] < 0.25:
                return
            done = sum(st["done"]) if by_bytes else int(sum(st["files"]) / max(1, nfiles) * total)
            done = min(done, total)
            dt = now - st["t"] if st["last"] else 0
            if dt > 0:
                inst = max(0, done - st["last_done"]) / dt
                st["rate"] = inst if st["rate"] == 0 else st["rate"] * 0.7 + inst * 0.3
            st["t"], st["last"], st["last_done"] = now, now, done
            left = int((total - done) / st["rate"]) if st["rate"] > 1 else 0
            emit("progress", {"bytes": done, "percent": min(100, int(done * 100 / total)), "speed": f"{human_bytes(st['rate'])}/s",
                              "eta": f"{left // 3600}:{left % 3600 // 60:02d}:{left % 60:02d}", "extra": "", "file": st["current"]})

        def run_one(k, cmd, track):
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    start_new_session=True)
            job.procs.append(proc)
            if job.cancelled.is_set():
                job.cancel()
            buf = b""
            while True:
                chunk = os.read(proc.stdout.fileno(), 4096)
                if not chunk:
                    break
                buf += chunk
                parts = re.split(rb"[\r\n]", buf)
                buf = parts.pop()
                for raw in parts:
                    line = raw.decode("utf-8", "replace")
                    if not line.strip():
                        continue
                    with lock:
                        prog = parse_progress(line)
                        if prog:
                            if track and by_bytes:
                                st["done"][k] = min(batches[k]["bytes"], prog["bytes"])
                            report()
                            continue
                        m = STAT_FILES_RE.search(line)
                        if m:
                            st["xfer_files"] += int(m.group(1).replace(",", ""))
                        m = STAT_BYTES_RE.search(line)
                        if m:
                            st["xfer_bytes"] += int(m.group(1).replace(",", ""))
                        tails[k].append(line)
                        del tails[k][:-12]
                        if is_name_line(line):
                            st["current"] = line.strip()
                            st["names"] += 1
                            if track:
                                st["files"][k] += 1
                            emit("log", (st["current"], "name"))
                            report()
                        else:
                            emit("log", (line, "dim"))
            return proc.wait()

        def make_cmd(listfile, names):
            write_list(listfile, names, self.caps)
            return build_rsync_command(self.rsync, self.caps, job.direction, self._base(), self.user, self.local_ip, [], job.dest,
                                       job.policy, False, per_limit, job.compress, files_from=str(listfile), base=plan["base"])

        try:
            emit("log", ("$ " + " ".join(shlex.quote(c) for c in make_cmd(tmp / "batch-0", batches[0]["files"])) + f"   (+{n - 1} more like it)", "cmd"))

            def worker(k):
                try:
                    cmd = make_cmd(tmp / f"batch-{k}", batches[k]["files"])
                    codes[k] = run_one(k, cmd, True)
                except Exception as e:
                    codes[k] = 255
                    tails[k].append(str(e))

            threads = [threading.Thread(target=worker, args=(k,), daemon=True) for k in range(n)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            ok_codes = all(c in (0, 23, 24) for c in codes)
            with lock:
                if all(c == 0 for c in codes) and not job.cancelled.is_set():
                    st["done"] = [bt["bytes"] for bt in batches]  # rsync sizes links and folders a little differently than the plan did
                    st["files"] = [len(bt["files"]) for bt in batches]
                report(force=True)
            if plan["dirs"] and ok_codes and not job.cancelled.is_set():
                # folders last, so empty ones exist and every folder ends up with its own timestamps and modes
                run_one(0, make_cmd(tmp / "dirs", plan["dirs"]), False)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if job.cancelled.is_set():
            result.update(cancelled=True, message="Cancelled.")
            return
        bad = next((k for k, c in enumerate(codes) if c not in (0, None)), None)
        result["files"] = st["xfer_files"] if st["xfer_files"] else st["names"]
        result["bytes"] = st["xfer_bytes"] or None
        if bad is None:
            result["ok"] = True
            n_done = result["files"]
            result["message"] = "Done — everything was already there." if n_done == 0 else f"Done — {n_done} file(s) copied in {n} parallel streams."
        else:
            result["message"] = explain_exit(codes[bad], tails[bad])

    def _run_single(self, job, emit, result):
        cmd = build_rsync_command(self.rsync, self.caps, job.direction, self._base(), self.user, self.local_ip,
                                  job.sources, job.dest, job.policy, job.dry_run, job.bwlimit, job.compress)
        emit("log", ("$ " + " ".join(shlex.quote(c) for c in cmd), "cmd"))
        emit("status", "Previewing…" if job.dry_run else ("Downloading…" if job.direction == "download" else "Uploading…"))
        if job.cancelled.is_set():
            raise KeyboardInterrupt
        job.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    start_new_session=True)
        if job.cancelled.is_set():  # Cancel landed while rsync was starting
            job.cancel()
        tail, names, current, buf = [], [], "", b""
        stream = job.proc.stdout
        while True:
            chunk = os.read(stream.fileno(), 4096)
            if not chunk:
                break
            buf += chunk
            parts = re.split(rb"[\r\n]", buf)
            buf = parts.pop()
            for raw in parts:
                line = raw.decode("utf-8", "replace")
                if not line.strip():
                    continue
                prog = parse_progress(line)
                if prog:
                    prog["file"] = current
                    emit("progress", prog)
                    continue
                m = STAT_FILES_RE.search(line)
                if m:
                    result["files"] = int(m.group(1).replace(",", ""))
                m = STAT_BYTES_RE.search(line)
                if m:
                    result["bytes"] = int(m.group(1).replace(",", ""))
                tail.append(line)
                del tail[:-12]
                if is_name_line(line):
                    current = line.strip()
                    names.append(current)
                    emit("log", (current, "name"))
                else:
                    emit("log", (line, "dim"))
        code = job.proc.wait()
        if job.cancelled.is_set():
            result.update(cancelled=True, message="Cancelled.")
        elif code == 0 or code in (23, 24):
            result["ok"] = code == 0
            if job.dry_run:
                result["files"] = len(names)
                result["message"] = (f"Preview: {len(names)} item(s) would be copied. Nothing was transferred."
                                     if names else "Preview: nothing to copy — everything is already there.")
            elif code == 0:
                n = result["files"] if result["files"] is not None else len(names)
                result["message"] = "Done — everything was already there." if n == 0 else f"Done — {n} file(s) copied."
            else:
                result["message"] = explain_exit(code, tail)
        else:
            result["message"] = explain_exit(code, tail)

# ───────────────────────────── settings ─────────────────────────────

DEFAULT_SETTINGS = {
    "host": "", "port": "22", "user": "", "route": "", "auth": "key", "key_path": "",
    "local_dir": str(Path.home()), "policy": "skip", "bwlimit": "", "show_hidden": True, "compare": False,
    "compress": True, "streams": str(DEFAULT_STREAMS),
    "control_port": str(DEFAULT_CONTROL_PORT),
}
SITES_PATH = CONFIG_DIR / "sites.json"


def forget_old_host_keys():
    """Deletes the known_hosts file earlier versions kept (it held a record of the servers connected to)."""
    for folder in [CONFIG_DIR] + _OLD_CONFIG_DIRS:
        try:
            (folder / "known_hosts").unlink()
        except OSError:
            pass


# How old a leftover has to be before it can be swept. A connection folder exists while a sign-in is still in
# progress (up to 90 s), so another running Ferry's folder is never touched; the others are long past their use.
SWEEP_CONNECTION_AGE = 180        # a connection folder with no live ssh connection behind it
SWEEP_HELPER_AGE = 600            # a password-helper folder (deleted right after sign-in)
SWEEP_EDIT_AGE = 24 * 3600        # a "View / Edit" copy of a server file (Ferry watches these for an hour)


def _socket_alive(path):
    """True if something is listening on the unix socket at `path` (an ssh connection that is still up)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect(path)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def sweep_stale_temp(now=None, base=None):
    """Removes what a crashed or killed Ferry left in the temp folder: connection folders (they hold a host-key file),
    password-helper folders and old "View / Edit" copies. Only folders this user owns that are older than the limits
    above, and a connection folder is kept while its ssh connection is still alive. Returns how many were removed."""
    now = time.time() if now is None else now
    base = Path(base or tempfile.gettempdir())
    removed = 0
    try:
        entries = list(base.glob("ferry-*"))
    except OSError:
        return 0
    for path in entries:
        try:
            st = os.lstat(path)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
                continue  # a file, a symlink, or somebody else's — not ours to touch
            age = now - st.st_mtime
            name = path.name
            if name.startswith("ferry-ask-"):
                stale = age > SWEEP_HELPER_AGE
            elif name.startswith("ferry-edit-"):
                stale = age > SWEEP_EDIT_AGE
            else:  # ferry-<random>: one connection
                stale = age > SWEEP_CONNECTION_AGE and not _socket_alive(str(path / "m"))
            if stale:
                shutil.rmtree(path, ignore_errors=True)
                removed += not path.exists()
        except OSError:
            continue
    return removed


def migrate_old_config():
    """Carries saved sites, bookmarks and settings over from the folder an earlier version used (never host keys)."""
    try:
        if any(k in os.environ for k in ("ZTR_FERRY_HOME", "ZTR_COURIER_HOME", "ZTR_FILES_HOME")):
            return
        old = next((d for d in _OLD_CONFIG_DIRS if d.is_dir()), None)
        if not CONFIG_DIR.exists() and old:
            shutil.copytree(old, CONFIG_DIR, ignore=shutil.ignore_patterns("known_hosts"))
    except OSError:
        pass


def load_settings():
    data = dict(DEFAULT_SETTINGS)
    try:
        saved = json.loads(SETTINGS_PATH.read_text())
        if "policy" not in saved and saved.get("skip_existing") is False:
            saved["policy"] = "overwrite"  # from an older version's checkbox
        data.update(saved)
    except (OSError, ValueError):
        pass
    return data


SITE_FIELDS = ("host", "port", "user", "route", "auth", "key_path")


def load_sites():
    """{'sites': {name: {...}}, 'bookmarks': {'local': [...], 'user@host': [...]}} — no passwords, ever."""
    data = {"sites": {}, "bookmarks": {}}
    try:
        saved = json.loads(SITES_PATH.read_text())
        data["sites"] = {str(k): {f: str(v.get(f, "")) for f in SITE_FIELDS} for k, v in saved.get("sites", {}).items()}
        data["bookmarks"] = {str(k): [str(p) for p in v] for k, v in saved.get("bookmarks", {}).items()}
    except (OSError, ValueError, AttributeError):
        pass
    return data


def save_sites(data):
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SITES_PATH.write_text(json.dumps(data, indent=2))
    except OSError:
        pass


def save_settings(data):
    """The password is never part of `data` — only what you'd retype anyway."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(json.dumps({k: data[k] for k in DEFAULT_SETTINGS if k in data}, indent=2))
    except OSError:
        pass


def list_routes():
    try:
        return sorted(p.name for p in ROUTES_DIR.glob("*.ztr"))
    except OSError:
        return []


def fmt_elapsed(seconds):
    """'3.2 s', '42 s', '1 min 05 s', '1 h 02 min'."""
    seconds = max(0.0, float(seconds))
    if seconds < 10:
        return f"{seconds:.1f} s"
    s = int(round(seconds))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {s % 3600 // 60:02d} min"


def shorten_middle(text, limit, keep_tail=10):
    """Cuts the middle out of long text and keeps its end, so 'user@4f9a…c1d2e3._ztr' still reads as a ._ztr name."""
    if len(text) <= limit:
        return text
    keep_tail = min(keep_tail, max(1, limit // 3))
    head = max(1, limit - keep_tail - 1)
    return text[:head] + "…" + text[-keep_tail:]


def fit_text(measure, text, max_px, keep_tail=12):
    """`text`, shortened in the middle (end kept) until measure(text) fits in max_px pixels."""
    if max_px <= 0 or measure(text) <= max_px:
        return text
    lo, hi = 1, len(text)  # how many characters of the original to keep
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


def human_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


# The Ferry logo (a ferry on waves), as small PNGs so the app stays a single file.
LOGO_SMALL = (
    "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAMAAABg3Am1AAABgFBMVEVgU5BfY3nmpvxXlc6xmcw0ZpkFbeJ3kLBzyP+8wsze"
    "3ucAAGYAf38Af78Aqv8Ijv8KkP9SL4SAcKOlecjLYP4TKkYRIzkMGSkAAAAJhP0JhPwMERr9/f0Ieu8JDBINOWgAkf8OMlkK"
    "V7BZOocSQnYDffsAAP8KXcEMSowoKlKEvPdJNXZst/sACyMLasvGydIlOU8vSWcLctk4M2dueYlIVGZ5g5K4tskNU5gJlP9a"
    "mNG7Vu/m6O4IjP9kqenIWvwA//87Z5JKeatPhrpvWpWCi5kNYrcJkf80VXhZZnejq7XQ1NsIkf85KmZDcJuUmabQg/XCt9MA"
    "Vf8Ph/8Jjf8Jkf81RllIKXhjpN6GkJ6cpbGOwvaxtLviwPYAVaoJkf8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACby94GAAAA"
    "YHRSTlP///////8R/////wUCBAaWxf/////+/v4A1/3+///9/gb+/v/+CAH//v////////////////////5W////tf//Af//"
    "/////3T/////mP//////AxFrsf//////////BP89dhCcAAADcUlEQVR42o2We2OaOhTAce2e9313yQESYFBweBVExOe0c7bW"
    "att17fp+bN//W9yTBJV2xbvfH4Lm/HJOCCZRNMFv8qKVnyBr8uVF4R+jkfaidzjUCxke9jB+tBDw/kw33cArJHATYyqTKPzi"
    "n5ueSohaCLZ5ydDnhqL5vq9H6prohbSn+yMfhVNtGP1/uDS+nZYVXzszfyoeDfNM85Wyb3g/K9jGVyypty5BRbA0kh4Kf7gF"
    "AgFSqTSRpULcIQp6QPLPjyPvX473m80qp5kZxNM1pazbK4GUdpGG+KFy+2p7rGwh3MgGofuPhM1nyFuC5QB52Tw62pJUjyp8"
    "8lB490hQviC7hDRms/S4pPytZELzkUCy2kn144cPH6sQD5hkMxOqRcKWFBps3uqwtDU4+SsnkKVAVsI/QrhgJWvCnLB+sqWs"
    "SvpBAIBLnuHIilmKQhwenFxi+CUmqIgIRwog453ju3nn/v7ZfWfeYfXjA3Z3M3iz2el0TnYrMoEQtIUAbVZEPUsAD4UJe91q"
    "zdl1a/ZmMGu1WaeFA2+3ZgNWz54KPM4wCcMSuwCoHwDgMMKwzWL8xupQIFyHYcouwhCFMGZtIYTFwoQdtNPXbJ5OBoPr9IbV"
    "07TObtLjwVMCPlGrVDjoOwqcnAB2Nwi6tdt/n+T2eSDIC6rx3TDMIgzO9y5kgoPJaGAm5noSyAkAqvt+LW5kL8cgBFBNQ6Z+"
    "EtOI4GEGoJ6xFlX0mhMAonXxLv1RIDbi8H+q8/COQyAnoEwptRBK4oYy7vevrq62N/o7n/djApYAA2hOiBuNxvPPO/3tWq22"
    "jYGfOOONPn6tbWyMP+03OLmSdl7JQOyRWisokHh/LPvBAEJXJcnlDmv1PCye8BJ5CUAzUUQACj5/NSgEOM1G7k0wo72ux0XZ"
    "lWMHboRTTW1cKrXDrgVeF/uFBTxgLzJX82hiB4GtghXwxbiXUJCvL10iHgtglY5cxnkj/wdEuNzjhuJYQeRygsC2ZfMymWoH"
    "gWhz37tU5RuKr00TSw7asb2sMQfvQ24DYCVTvmWd/jp0rVUlotvFjgJZdbK1q3/zy7jtjnzdtaxlFTTPqjgezzdqsbG/OE/U"
    "3HQ9GPwCNfoz29jFiWBqRIFTvDc6QWRMf1kcHcSpw+8d6ms4733NzjNK7mzzrojfRYg8B/0H3BMbB9NpVCUAAAAASUVORK5C"
    "YII="
)

LOGO_LARGE = (
    "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAMAAAD04JH5AAABgFBMVEV0XZmcoa1kbn1fpuSGbam2d9zPhvMAmf8jjfcUKkYM"
    "GSgJhf0RIzkAAAD09PgLEhwKZs1ZO4gAfv8oKlIKWq0KXMBsuf0A//8JDBIMgv8Kd+cOh//r6/FINXW9WPAMOGkLSIxxwf8m"
    "N00pk/4UMlHWlPYKdNw6MWZKV2oAqv8AAP8MYbcJhP1ZmdMJhP4yV3gwQ1gNQng4LWJjqenGW/rKePMJhf8JhP5NhLZHR2xI"
    "eahqdIMJhf+UmKnS1NsACiMAVf87Zo0uSGhZZna3vMUMU5lvVpV6hJJkPZKEjZujqbTIydTc5fDDutPa3OJCcZxeod1GK3RB"
    "TF1VisKhlbjjmv5PRYS8w84dHUUKT6A2XIFNaqIJaf8Lf/8jHk1Bb5kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABsOjpgAAAA"
    "YHRSTlP/////////Bf////3/AP///v8D//7//wH/KP4R//////////////7//wMB/tD/rv////////9Ojv////9u////A///"
    "/////////////////////////////////wkr//+dpmqbAAAJxElEQVR42sWb+0PayBbHse3uvRkGEkM0vLpJ2SyFCAKyFy2i"
    "Itb1Vrtab+1ju6///7+4c85MQl6EAAn7/UEHCDmfOY+ZAWZyhTjZegqyY03kFr2gttV2/FsTy56ym60GoKr8De1aCvoXp1DV"
    "xADTKftTG00OO518Cup0Do9HFXRqIgBVLxQqk8N8yupMgGG6FMBmlCPHerWqpKBmVdzucMSCqscDMMIKN9/UTMOSUpFlDDSF"
    "uwEQ4gDUwh/H2PVrQ6JSiqKSdd1EL6gFdTGAWqhA2jXNdK07DAN0w6jgK++cL/wT6L0pZSYT0uEY8zwMwOyD+xWLZgdApQMI"
    "g5fABbBVtK9J2YqaSDDVQwDcvkmlrAkG3Ad2AEDF+A8yt88IDJ4HfoBpobKV/rs+GDnjAQfQVZXVn7YV+yIParrqAcACULZk"
    "nxEcYCLOATAAVUvanqpuEHI8Aw+3lQDzNOiouFbKYQCYA5rSNkUVcIEqAKbbdgCvxY4DoGIGpHn7kqN4F1QgC3JiDLqm6ZuP"
    "Y4BSxNEIAdgYkNoUVAppYSF0eAj0Qi29FHSMHr1mikXgMdAZQLswSm0Q5PZez3W0kABiMGHez/FpcNNZiBLimIfOv+SaI0TX"
    "wTECtKEIN0sBcvVl3GtIX0XvX3rkRCI6CTAENsvBDYuQnBb3X+13f581mANeBrSQgC1S1YKdswvTToIcpF6FAJ6932d6tT/8"
    "+PtntLqLiiWALFQLeg6LYOlESGdv5mrQaID9Vwxh/FlYnyNwgqgpsVJQkwHQF59+cvXp+yABOX2PxqH/j177AoFn4gYAtPGT"
    "V59y1BcbAHjeHc9eYwLs7kYQOACe+KUM0CiJ/NvdjSBAFziplALACxIMwX2p1MD6240EiHLBSgDSdz6CN9QZfbgucvfk61+l"
    "o6Ojx8doAgfAU0arJWHjP3N9LyJApdN3XDdv6ztnoKenF7uxMYgBoDFitn74+QdHP/8Xrpao9aUYobvoGIg68N5zJYBSGICc"
    "FeuOip7mUwYANMoD5G0xUr9uF+D+/PycGz4XrW0C1Iu37DXyjEWgeEZY65Q11gSgqwJQBLgCs7TOWi1oNZZ4gKYO8AzNugD9"
    "RQCiDL13JJsAUJ8HrHiAyAiwi/8BALo+QCkuBwIheLlwKlgHQIz2Pg/s8ucQ4IJdEUjCx+CCxFkP0NUBiNTnmn3nmQxy+FTj"
    "jpl927Aa9AbK/1ZirR321F3uF48+P0ZnQDIANs8Xl4gPxP6W7/UnYT/ogCQA5KqYgp5Kr6PsBwBIJMF5sb45QP1NKRpAWwYA"
    "2Z2GWn9F2V8FoO4Nb7BdLy65qNj6GmU/OUD9tAG6wge32O7jUuS+hQ/eoZUbbLcwad/28cGOA0Ci7CcFYNPcBV/3vWPtezEu"
    "9Is4BszHgx1s0wuYDusNMXYIJ7whkVNtYoAbIkoSaly8hL5piRduxWQM7RZQSm4OCwCaGsC5NzhRAFes/V4imQHcLQNo/dMA"
    "UR7439oApTCAuM6qz3sWzgFKUwW4FVVwhgmODy5a8MKpqAKYlL6Ij0g3MHb2+UXOMLIZANNZC8TL/Q7bV/d8gMAHt/jCDrZv"
    "8B3nV3jRXTElgE3V3ygJoaeev/yft10sxl+0gQfSmg0bKwIQz3okjQicBe2T5B4gNxt7oL5DCU3kAbH6ZM9Xm66U/I8b6t9K"
    "03M/UHWAxhYDSPlsVaVOTyMBWMPMFoA7YDEAaylZ2ndMxQFkGgRrAYBPWjUr5TWnq7EA5p62l4W0at6TazEAkrK3p6SvPSVv"
    "eut9MQAxlSx8wCJLSCIPEGoozQxckDd8mRYDQGQjiwo4IIkBqHydSQkmBmCqpm7/Wl4JwMhoEnCjvAwALkhVprwaAKHpBqEZ"
    "0cF4gJQrwVgZANMkNWlkDQCS4qYGshZApGS5HJYsy2Q1rQUAVqjV6PUuL8cnrh4ue7OZZVH+eiYA2D+pMfs27naH8BNtSPv7"
    "+8PuyUOvARhlOT0A5lxCpf638cch/3E4TgjyISHHAgA3ovBm2pj1/j7pfvBYfoXN4XDY/dB1NQzAwe/I3ZPxZa/P41KWvckS"
    "CyBd9lAQ427X6ZSne3jbxvxbbD5kSVZ/1nsYs/Cwi3xvGHa748uH3lzjMY0BoEMnpL7+gOWP428z1h8oAXlBabDnrRlD52ni"
    "jYwva06iAMQ9rVBEWRegz8xyOVlqMS8jx/ijSNdQonRjAMiDuGrIUmn89+XMkmjCpA5xsORlgbl8OOk+xxwRNx4+b8QBEMkC"
    "USrGGzmg1TmAnlJ+W35nOQigegFE1TtlQGFjtiv+i/laKJ5be6rgTwZgF9SOZ6qU+WBnmJoG29JDM3K12lQOrk0DBvfVQPjF"
    "kuHMirLYxGLjNh63oMxrTWkmW+AomsZA6BKPiBdZEAbXBwp0aCCuZQA1BsA3MkniyWZEjz0f7fPhNUqVgVwPLNzNEJExYNjk"
    "ht21sewsOjsF2xZbuSzZtxIVfjbghybfiENhrz44KTI2CnPKXEp0DJu8s7KE+5txL9nIXa/JRvPAxO4sSnvnaeyZplQTL9vA"
    "U3BiwakCeTDfzOapQxmqPlFmuSBGPAg6c2BIfHaa35pXYRs2NOqwoZFuUFdlkWWGaZrzCLAHA8NanKRVKIL5lk6z7HPx6rWO"
    "JOGRC+4SNZjJhndLZ8WJgUw8Qw71D0pruEYWiStJ7lhmiXFAPhBbm3POvmasA9n0fJrfQ0cCzbzEkmUGRoQZHUBEQl81GDKv"
    "gU4bdjbzjc0j4QL5t+hvFjgJLm3lGBEnFSLM+gHKGq8BZ2s37K03yhgCE+XkU+A27JnfTHCK5d+IDp41+DtCb+DpaAoNTEMM"
    "AnlV1x0AdEEVCjSYLNAh3qPw9y1xX8ZwTvFpIOwnWfFvbufDsVZeEFF8j2Rwr+zFmYXe4vhJYiupbLIMsKf2HEBVVZglysuS"
    "i2cXOsUvXjiEJKrgspXHpYD3iAcGIW+VEw6AcWm4/BZwumDiP+LhHLKRyiRzyTAGHgYPucAxo8OtEJSh/4dt96CRe85Ib9tA"
    "YJTlZW7eQBB/sK/qaviol859oJEyIZmZl83giTvPYTed50HTKmeCANOxBL8EHPtO/HmP+9m4NmFrJol/CEnTOKzQJfzGZVLQ"
    "9YUHHtuFGp63VAzi/Ry5ad7jxyXjAA88/uk/bhg88gknTvGobVUbSCTqq5A1JLNhVKvyk6+FwIHL0KFXlQVo1HEW3r5F5rpy"
    "18SdiVrQ1aXHfmGEqhx30v6etHM8UkMnXqMPPtsQpD8qk/QgOoeTSg3cayc9+j3ljqrVKimoVuOejT7Kvujwu62qoTPK659+"
    "b6tTe9XT9/z0v5qC9NiO/B+urg87hLakTAAAAABJRU5ErkJggg=="
)


FILE_KINDS = {
    "image": {"jpg", "jpeg", "png", "gif", "svg", "webp", "bmp", "tif", "tiff", "heic", "ico", "raw"},
    "archive": {"zip", "gz", "tgz", "tar", "bz2", "xz", "7z", "rar", "zst", "deb", "rpm", "iso", "img"},
    "code": {"py", "js", "ts", "tsx", "jsx", "sh", "bash", "c", "h", "cpp", "hpp", "go", "rs", "java", "json", "yml", "yaml",
             "toml", "html", "css", "sql", "php", "rb", "lua", "xml", "ini", "conf", "cfg", "ejs", "md", "service"},
    "doc": {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "txt", "rtf", "csv", "log", "epub"},
    "media": {"mp3", "wav", "flac", "ogg", "m4a", "mp4", "mkv", "mov", "avi", "webm"},
}


def file_kind(name):
    """'image', 'archive', 'code', 'doc', 'media' or 'file' — by the extension, for the icon."""
    ext = name.rsplit(".", 1)[-1].lower() if "." in name.strip(".") else ""
    return next((k for k, exts in FILE_KINDS.items() if ext in exts), "file")


# ───────────────────────────── GUI ─────────────────────────────

# A dark, Mac-like palette: graphite surfaces, system blue for the accent (CYAN keeps its old name).
BG, CARD, FIELD, BORDER = "#1c1c1e", "#262629", "#1a1a1c", "#3a3a3d"
TEXT, DIM = "#f2f2f7", "#8e8e93"
CYAN, PURPLE, GREEN, RED, AMBER = "#0a84ff", "#bf5af2", "#30d158", "#ff453a", "#ffb340"
SEL, ZEBRA = "#0a64d6", "#1f1f21"
MAX_LOG_LINES = 2000
POLICIES = [("skip", "Skip files that already exist"), ("newer", "Overwrite if the source is newer"), ("overwrite", "Overwrite")]
EDIT_MAX_BYTES = 100 * 1024 * 1024
EDIT_WATCH_SECONDS = 3600


class QueueItem:
    _count = 0

    def __init__(self, job, label, refresh):
        QueueItem._count += 1
        self.id = QueueItem._count
        self.job, self.label, self.refresh = job, label, refresh  # refresh: the pane to reload afterwards
        self.state, self.message = "queued", ""
        self.started = self.seconds = None  # when it began running / how long it took
        self.bytes = None  # what it moved, once finished


def build_app():
    """Imported lazily so the engine above works (and is testable) on a
    machine whose Python has no tkinter."""
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, ttk

    # ── a small kit of rounded, Mac-style widgets ────────────────────────────────
    # ttk can't round corners, so these draw their own shapes on a canvas. Corners are small images whose edge pixels are
    # blended between the shape colour and the colour behind it, which keeps them smooth (a canvas oval is jagged).

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

    class Pane:
        """One side of the window: a path bar, a file list and a filter."""

        TITLES = {"name": "Name", "size": "Size", "modified": "Modified", "perms": "Mode"}

        def __init__(self, app, parent, title, remote):
            self.app, self.remote = app, remote
            self.path, self.entries, self.rows = "", [], []
            self.placeholder = ""
            self.seconds = None  # how long the last server listing took
            self.base_summary = ""
            self.sort_key, self.sort_rev = "name", False
            self.var = tk.StringVar()
            self.filter = tk.StringVar()
            self._drag = None
            self.frame = Card(parent, radius=12, pad=(14, 12), bg=BG)
            f = self.frame.body
            f.columnconfigure(0, weight=1)
            f.rowconfigure(2, weight=1)
            head = ttk.Frame(f, style="Card.TFrame")
            head.grid(row=0, column=0, sticky="ew")
            head.columnconfigure(0, weight=1)
            ttk.Label(head, text=title, style="H.TLabel").grid(row=0, column=0, sticky="w")
            self.bm_menu = tk.Menu(head, postcommand=self._fill_bookmarks, **app.menu_kw)
            self.bm_btn = Btn(head, text="Bookmarks  ▾", style="Small.TButton", command=self._bm_popup)
            self.bm_btn.grid(row=0, column=1, sticky="e")

            bar = ttk.Frame(f, style="Card.TFrame")
            bar.grid(row=1, column=0, sticky="ew", pady=(10, 10))
            bar.columnconfigure(1, weight=1)
            self.up_btn = Btn(bar, text="Up", style="Small.TButton", command=self.up)
            self.up_btn.grid(row=0, column=0)
            self.entry = Field(bar, compact=True, textvariable=self.var)
            self.entry.grid(row=0, column=1, sticky="ew", padx=8)
            self.entry.bind("<Return>", lambda e: app.go(self, self.var.get().strip()))
            self.refresh_btn = Btn(bar, text="Refresh", style="Small.TButton", command=lambda: app.go(self, self.path))
            self.refresh_btn.grid(row=0, column=2)

            tcard = Card(f, fill=FIELD, border=BORDER, radius=9, pad=(4, 4), style="Field.TFrame", bg=CARD)
            tcard.grid(row=2, column=0, sticky="nsew")
            wrap = tcard.body
            wrap.columnconfigure(0, weight=1)
            wrap.rowconfigure(0, weight=1)
            self.tree = ttk.Treeview(wrap, columns=("size", "modified", "perms"), selectmode="extended")
            for col, width, anchor, stretch in (("#0", 220, "w", True), ("size", 78, "e", False),
                                                ("modified", 138, "w", False), ("perms", 90, "w", False)):
                self.tree.column(col, width=width, minwidth=60 if col != "#0" else 120, anchor=anchor, stretch=stretch)
            sb = ttk.Scrollbar(wrap, orient="vertical", style="Thin.Vertical.TScrollbar", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            self.tree.grid(row=0, column=0, sticky="nsew")
            sb.grid(row=0, column=1, sticky="ns", padx=(2, 0))
            self.tree.tag_configure("odd", background=ZEBRA)
            self.tree.tag_configure("dim", foreground=DIM)
            self.tree.tag_configure("only", foreground=GREEN)
            self.tree.tag_configure("diff", foreground=AMBER)
            self._headings()
            t = self.tree
            t.bind("<Double-1>", self._activate)
            t.bind("<Return>", self._activate)
            t.bind("<BackSpace>", lambda e: self.up())
            t.bind("<F5>", lambda e: app.go(self, self.path))
            t.bind("<F2>", lambda e: app.rename(self))
            t.bind("<Delete>", lambda e: app.delete(self))
            t.bind(f"<{MOD}-a>", self._select_all)
            t.bind("<Button-3>", self._menu)
            t.bind("<Button-2>", self._menu)
            if sys.platform == "darwin":
                t.bind("<Control-Button-1>", self._menu)
            t.bind("<<TreeviewSelect>>", lambda e: self._show_summary())
            t.bind("<ButtonPress-1>", self._press)
            t.bind("<B1-Motion>", self._motion)
            t.bind("<ButtonRelease-1>", self._release)

            self.actions = ttk.Frame(f, style="Card.TFrame")
            self.actions.grid(row=3, column=0, sticky="ew", pady=(12, 0))
            foot = ttk.Frame(f, style="Card.TFrame")
            foot.grid(row=4, column=0, sticky="ew", pady=(10, 0))
            foot.columnconfigure(0, weight=1)
            self.summary_var = tk.StringVar()
            self.summary = ElideLabel(foot, self.summary_var, "Dim.TLabel")
            self.summary.grid(row=0, column=0, sticky="ew")
            Field(foot, compact=True, textvariable=self.filter, width=14, placeholder="Filter").grid(row=0, column=1, padx=(8, 0))
            self.filter.trace_add("write", lambda *a: self.render())

        def _bm_popup(self):
            b = self.bm_btn
            try:
                self.bm_menu.tk_popup(b.winfo_rootx(), b.winfo_rooty() + b.winfo_height() + 2)
            finally:
                self.bm_menu.grab_release()

        # -- paths and data
        def join(self, name):
            return posixpath.join(self.path, name) if self.remote else os.path.join(self.path, name)

        def parent(self):
            if self.remote:
                return posixpath.dirname(self.path.rstrip("/")) or "/"
            return os.path.dirname(self.path)

        def up(self):
            if self.path and self.parent() != self.path:
                self.app.go(self, self.parent())

        def show(self, path, entries, seconds=None):
            changed = path != self.path
            self.path, self.entries, self.placeholder, self.seconds = path, entries, "", seconds
            self.var.set(path)
            if changed:
                self.filter.set("")
            self.render()
            if self.app.compare.get():
                self.app.other(self).render()

        def clear(self, message):
            self.path, self.entries, self.placeholder = "", [], message
            self.var.set("")
            self.render()

        # -- sorting and drawing
        def _headings(self):
            for col in ("#0", "size", "modified", "perms"):
                key = "name" if col == "#0" else col
                arrow = (" ▲" if not self.sort_rev else " ▼") if key == self.sort_key else ""
                self.tree.heading(col, text=self.TITLES[key] + arrow, anchor="e" if col == "size" else "w",
                                  command=lambda k=key: self.sort_by(k))

        def sort_by(self, key):
            self.sort_rev = (not self.sort_rev) if key == self.sort_key else False
            self.sort_key = key
            self._headings()
            self.render()

        def _ordered(self, entries):
            key = self.sort_key
            by_name = lambda e: (e.name.lower(), e.name)
            keyfn = {"name": by_name, "size": lambda e: (e.size, e.name.lower()), "modified": lambda e: (e.modified, e.name.lower()),
                     "perms": lambda e: (e.perms, e.name.lower())}[key]
            dirs = sorted((e for e in entries if e.is_dir), key=by_name if key == "size" else keyfn, reverse=self.sort_rev)
            files = sorted((e for e in entries if not e.is_dir), key=keyfn, reverse=self.sort_rev)
            return dirs + files

        def render(self):
            tree = self.tree
            tree.delete(*tree.get_children())
            self.rows = []
            if self.placeholder:
                tree.insert("", "end", iid="msg", text=self.placeholder, tags=("dim",))
                self.base_summary = ""
                self._show_summary()
                return
            if self.path and self.parent() != self.path:
                tree.insert("", "end", iid="up", text="..", image=self.app.icons["folder"], values=("", "", ""))
            needle = self.filter.get().strip().lower()
            shown = [e for e in self.entries
                     if (self.app.show_hidden.get() or not e.name.startswith(".")) and (not needle or needle in e.name.lower())]
            shown = self._ordered(shown)
            other = self.app.other(self)
            theirs = {e.name: e for e in other.entries} if (self.app.compare.get() and other.path) else None
            for i, e in enumerate(shown):
                tag = ()
                if theirs is not None:
                    o = theirs.get(e.name)
                    tag = ("only",) if o is None else (("diff",) if (not e.is_dir and not o.is_dir and o.size != e.size) else ())
                if i % 2:
                    tag = tag + ("odd",)
                tree.insert("", "end", iid=str(i), text=e.name, image=self.app.icon_for(e),
                            values=("" if e.is_dir else human_bytes(e.size), e.modified, e.perms), tags=tag)
            self.rows = shown
            if not shown:
                tree.insert("", "end", iid="msg", text="Nothing matches the filter" if needle else "This folder is empty", tags=("dim",))
            folders = sum(1 for e in shown if e.is_dir)
            hidden = len(self.entries) - len(shown)
            self.base_summary = (f"{len(shown) - folders} file(s), {folders} folder(s)" + (f"  ·  {hidden} not shown" if hidden else "")
                                 + (f"  ·  listed in {fmt_elapsed(self.seconds)}" if self.seconds is not None else ""))
            self._show_summary()

        def _show_summary(self):
            picked = self.selected()
            extra = ""
            if picked:
                size = sum(e.size for e in picked if not e.is_dir)
                extra = f"{len(picked)} selected" + (f" · {human_bytes(size)}" if size else "") + "   |   "
            self.summary_var.set(extra + self.base_summary)

        def selected(self):
            return [self.rows[int(i)] for i in self.tree.selection() if i.isdigit() and int(i) < len(self.rows)]

        def selected_paths(self):
            return [self.join(e.name) for e in self.selected()]

        def size_hint(self, paths):
            """Total bytes of `paths` if every one is a plain file listed here, else None (a folder's size isn't known)."""
            by_path = {self.join(e.name): e for e in self.rows}
            entries = [by_path.get(p) for p in paths]
            if not entries or any(e is None or e.is_dir for e in entries):
                return None
            return sum(e.size for e in entries)

        def _select_all(self, _event=None):
            self.tree.selection_set([str(i) for i in range(len(self.rows))])
            return "break"

        # -- bookmarks
        def _fill_bookmarks(self):
            m = self.bm_menu
            m.delete(0, "end")
            usable = bool(self.path)
            m.add_command(label="Bookmark this folder", command=lambda: self.app.add_bookmark(self), state="normal" if usable else "disabled")
            items = self.app.bookmarks_for(self)
            if items:
                m.add_separator()
                for p in items:
                    m.add_command(label=p, command=lambda p=p: self.app.go(self, p))
                m.add_separator()
                sub = tk.Menu(m, **self.app.menu_kw)
                for p in items:
                    sub.add_command(label=p, command=lambda p=p: self.app.remove_bookmark(self, p))
                m.add_cascade(label="Remove a bookmark", menu=sub)

        # -- mouse and keyboard
        def _activate(self, event=None):
            if event is not None and event.type == tk.EventType.ButtonPress:
                iid = self.tree.identify_row(event.y)
                if not iid:
                    return
                self.tree.selection_set(iid)
            sel = self.tree.selection()
            if not sel:
                return
            if sel[0] == "up":
                return self.up()
            if not sel[0].isdigit():
                return
            entry = self.rows[int(sel[0])]
            if entry.is_dir:
                self.app.go(self, self.join(entry.name))
            else:
                self.app.transfer_from(self, [self.join(entry.name)])

        def _menu(self, event):
            iid = self.tree.identify_row(event.y)
            if iid and iid not in self.tree.selection():
                self.tree.selection_set(iid)
            self.app.show_menu(self, event)

        # Dragging the selection onto the other pane (or onto a folder in it) transfers it.
        def _press(self, event):
            self.tree.focus_set()
            iid = self.tree.identify_row(event.y)
            sel = self.tree.selection()
            keep = bool(iid and iid in sel and len(sel) > 1 and not (event.state & 0x0005))
            self._drag = {"start": (event.x, event.y), "moved": False, "reselect": None if keep else iid}
            if keep:
                self._drag["keep"] = True
                return "break"  # keep the multi-selection while the drag starts

        def _motion(self, event):
            d = self._drag
            if d and not d["moved"] and abs(event.x - d["start"][0]) + abs(event.y - d["start"][1]) > 8 and self.tree.selection():
                d["moved"] = True
                self.tree.configure(cursor="hand2")

        def _release(self, event):
            d, self._drag = self._drag, None
            self.tree.configure(cursor="")
            if not d:
                return
            if d["moved"]:
                other = self.app.other(self)
                w = self.tree.winfo_containing(event.x_root, event.y_root)
                if w is not None and str(w).startswith(str(other.frame)):
                    row = other.tree.identify_row(event.y_root - other.tree.winfo_rooty())
                    dest = None
                    if row.isdigit() and int(row) < len(other.rows) and other.rows[int(row)].is_dir:
                        dest = other.join(other.rows[int(row)].name)
                    elif row == "up":
                        dest = other.parent()
                    self.app.transfer_from(self, dest=dest)
            elif d.get("keep") and d["reselect"]:
                self.tree.selection_set(d["reselect"])

    class Workspace:
        """One connection tab: its own form, panes, queue and log."""

        conn_extra = {}  # tests pass a fake control / ssh here

        def __init__(self, shell, parent, blank=False):
            self.shell, self.frame, self.root = shell, parent, shell.root
            self.settings, self.sites, self.icons, self.menu_kw = shell.settings, shell.sites, shell.icons, shell.menu_kw
            self.show_hidden, self.compare = shell.show_hidden, shell.compare  # shared options
            self.policy, self.bwlimit, self.dry = shell.policy, shell.bwlimit, shell.dry
            self.compress, self.streams = shell.compress, shell.streams
            self.events = queue.Queue()
            self.conn = None
            self.connecting = False
            self.closed = False
            self.job = None  # the transfer running now (possibly several queued items merged)
            self.current = None  # the first queued item in it
            self.group = []  # every queued item the running transfer covers
            self._t_job, self._progress_text = 0.0, ""
            self._next_timer = None
            self.queue = []
            self.search_win = None
            self._build(parent)
            self._load_fields(blank)
            self._auth_changed()
            self._update_buttons()
            self.go(self.local, self.settings.get("local_dir") or str(Path.home()))
            self.remote.clear("Not connected")
            self._poll_connection()

        def icon_for(self, entry):
            return self.shell.icon_for(entry)

        def ask_string(self, title, prompt, initial="", ok="OK"):
            return ask_string(self.root, title, prompt, initial, ok)

        def ask_yes_no(self, title, message, ok="OK", danger=False):
            return ask_yes_no(self.root, title, message, ok, danger)

        def title(self):
            if self.connecting:
                return "Connecting…"
            if not self.conn:
                return "New connection"
            c = self.conn
            name = next((n for n, st in self.sites["sites"].items() if (st.get("host"), st.get("user")) == (c.host, c.user)), None)
            active = sum(1 for i in self.queue if i.state in ("queued", "running"))
            return shorten_middle(name or f"{c.user}@{c.host}", 34) + (f"  ·  {active}" if active else "")

        def retitle(self):
            self.shell.retitle(self)

        def other(self, pane):
            return self.remote if pane is self.local else self.local

        # ── layout ───────────────────────────────────────────────────────
        def _card(self, parent, **kw):
            card = Card(parent, **kw)
            return card, card.body

        def _field(self, parent, label, var, width=10, show=""):
            frame = ttk.Frame(parent, style="Card.TFrame")
            frame.columnconfigure(0, weight=1)
            ttk.Label(frame, text=label, style="Dim.TLabel").grid(row=0, column=0, sticky="w")
            entry = Field(frame, textvariable=var, width=width, show=show)
            entry.grid(row=1, column=0, sticky="ew", pady=(4, 0))
            self.form_inputs.append(entry)
            return frame

        def _build(self, page):
            page.columnconfigure(0, weight=1)
            page.rowconfigure(1, weight=1)
            self.form_inputs = []

            # connection: a form until connected, then a one-line bar
            slot = ttk.Frame(page)
            slot.grid(row=0, column=0, sticky="ew", pady=(0, 12))
            slot.columnconfigure(0, weight=1)
            self.host, self.port, self.user = tk.StringVar(), tk.StringVar(), tk.StringVar()
            self.route, self.auth = tk.StringVar(), tk.StringVar(value="key")
            self.key_path, self.password, self.control_port = tk.StringVar(), tk.StringVar(), tk.StringVar()
            self.site_var = tk.StringVar()

            self.form_outer, c = self._card(slot, radius=14, pad=(18, 14))
            self.form_outer.grid(row=0, column=0, sticky="ew")
            for col, weight in ((0, 4), (1, 0), (2, 3), (3, 3)):
                c.columnconfigure(col, weight=weight)
            sites_row = ttk.Frame(c, style="Card.TFrame")
            sites_row.grid(row=0, column=0, columnspan=4, sticky="ew", pady=(0, 12))
            sites_row.columnconfigure(1, weight=1)
            ttk.Label(sites_row, text="Saved sites", style="Dim.TLabel").grid(row=0, column=0, padx=(0, 10))
            self.site_box = Combo(sites_row, compact=True, textvariable=self.site_var, state="readonly", values=sorted(self.sites["sites"]))
            self.site_box.grid(row=0, column=1, sticky="ew")
            self.site_box.bind("<<ComboboxSelected>>", lambda e: self._use_site())
            save_btn = Btn(sites_row, text="Save site", style="Small.TButton", command=self._save_site)
            save_btn.grid(row=0, column=2, padx=(8, 0))
            del_btn = Btn(sites_row, text="Delete site", style="Small.TButton", command=self._delete_site)
            del_btn.grid(row=0, column=3, padx=(8, 0))
            self.form_inputs += [self.site_box, save_btn, del_btn]

            self._field(c, "Server  (the ._ztr name or address)", self.host).grid(row=1, column=0, sticky="ew", padx=(0, 12))
            self._field(c, "Port", self.port, width=6).grid(row=1, column=1, sticky="ew", padx=(0, 12))
            self._field(c, "User", self.user).grid(row=1, column=2, sticky="ew", padx=(0, 12))
            rf = ttk.Frame(c, style="Card.TFrame")
            rf.grid(row=1, column=3, sticky="ew")
            rf.columnconfigure(0, weight=1)
            ttk.Label(rf, text="Route", style="Dim.TLabel").grid(row=0, column=0, sticky="w")
            self.route_box = Combo(rf, textvariable=self.route, state="readonly", values=["Service default"] + list_routes())
            self.route_box.grid(row=1, column=0, sticky="ew", pady=(4, 0))
            self.form_inputs.append(self.route_box)

            auth_row = ttk.Frame(c, style="Card.TFrame")
            auth_row.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(14, 0))
            auth_row.columnconfigure(2, weight=1)
            ttk.Label(auth_row, text="Sign in with", style="Dim.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")
            for i, (text, value) in enumerate((("SSH key", "key"), ("Password", "password"))):
                rb = Radio(auth_row, text=text, value=value, variable=self.auth, command=self._auth_changed)
                rb.grid(row=1, column=i, sticky="w", padx=(0, 14), pady=(4, 0))
                self.form_inputs.append(rb)
            self.key_row = ttk.Frame(auth_row, style="Card.TFrame")
            self.pw_row = ttk.Frame(auth_row, style="Card.TFrame")
            for row in (self.key_row, self.pw_row):
                row.grid(row=1, column=2, sticky="ew", padx=(6, 0), pady=(4, 0))
                row.columnconfigure(0, weight=1)
            key_entry = Field(self.key_row, textvariable=self.key_path)
            key_entry.grid(row=0, column=0, sticky="ew")
            key_btn = Btn(self.key_row, text="Choose…", style="Small.TButton", command=self._pick_key)
            key_btn.grid(row=0, column=1, padx=(8, 0))
            ttk.Label(self.key_row, text="Leave empty to use your default key or ssh-agent", style="Dim.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))
            pw_entry = Field(self.pw_row, textvariable=self.password, show="•")
            pw_entry.grid(row=0, column=0, sticky="ew")
            pw_entry.bind("<Return>", lambda e: self._connect())
            ttk.Label(self.pw_row, text="Used for this session only — never saved", style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 0))
            self.form_inputs += [key_entry, key_btn, pw_entry]
            cp = ttk.Frame(auth_row, style="Card.TFrame")
            cp.grid(row=0, column=3, rowspan=2, sticky="e", padx=(12, 14))
            ttk.Label(cp, text="Control port", style="Dim.TLabel").grid(row=0, column=0, sticky="w")
            cp_entry = Field(cp, textvariable=self.control_port, width=6)
            cp_entry.grid(row=1, column=0, pady=(4, 0))
            self.form_inputs.append(cp_entry)
            self.connect_btn = Btn(auth_row, text="Connect", style="Primary.TButton", command=self._connect)
            self.connect_btn.grid(row=0, column=4, rowspan=2, sticky="e")
            self.connect_status = tk.StringVar()
            self.connect_status_label = ttk.Label(c, textvariable=self.connect_status, style="Dim.TLabel", justify="left")
            self.connect_status_label.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(10, 0))
            self.connect_status_label.bind("<Configure>", lambda e: self.connect_status_label.configure(wraplength=max(240, e.width - 8)))

            self.bar_outer, b = self._card(slot, radius=14, pad=(18, 10))
            self.bar_outer.grid(row=0, column=0, sticky="ew")
            b.columnconfigure(0, weight=1)
            self.bar_text = tk.StringVar()
            who = ttk.Frame(b, style="Card.TFrame")
            who.grid(row=0, column=0, sticky="ew", padx=(0, 12))
            dot = tk.Canvas(who, width=14, height=14, bg=CARD, highlightthickness=0)
            dot.grid(row=0, column=0, padx=(0, 8))
            dot.create_oval(2, 2, 12, 12, fill=GREEN, outline="")
            who.columnconfigure(1, weight=1)
            ElideLabel(who, self.bar_text, "Ok.H.TLabel").grid(row=0, column=1, sticky="ew")
            self.ssh_btn = Btn(b, text="ztr_ssh", style="Go.TButton", command=self.open_terminal)
            self.ssh_btn.grid(row=0, column=1, sticky="e", padx=(0, 8))
            self.search_btn = Btn(b, text="Search server…", command=self.open_search)
            self.search_btn.grid(row=0, column=2, sticky="e", padx=(0, 8))
            Btn(b, text="Disconnect", command=self._disconnect).grid(row=0, column=3, sticky="e")
            self.bar_outer.grid_remove()

            # the two panes
            panes = tk.PanedWindow(page, orient="horizontal", bg=BG, sashwidth=12, sashrelief="flat", bd=0, opaqueresize=True)
            panes.grid(row=1, column=0, sticky="nsew", pady=(0, 12))
            self.local = Pane(self, panes, "This computer", remote=False)
            self.remote = Pane(self, panes, "Server", remote=True)
            panes.add(self.local.frame, stretch="always", minsize=340)
            panes.add(self.remote.frame, stretch="always", minsize=340)

            self.up_btn = Btn(self.local.actions, text="Upload →", style="Go.TButton", command=lambda: self.transfer_from(self.local))
            self.up_btn.grid(row=0, column=0, padx=(0, 8))
            self.down_btn = Btn(self.remote.actions, text="← Download", style="Go.TButton", command=lambda: self.transfer_from(self.remote))
            self.down_btn.grid(row=0, column=0, padx=(0, 8))
            self.pane_buttons = []
            for pane in (self.local, self.remote):
                for i, (text, cmd) in enumerate((("New folder", self.mkdir), ("Rename", self.rename), ("Delete", self.delete)), start=1):
                    btn = Btn(pane.actions, text=text, style="Small.TButton", command=lambda c=cmd, p=pane: c(p))
                    btn.grid(row=0, column=i, padx=(0, 6))
                    if pane.remote:
                        self.pane_buttons.append(btn)

            # transfers
            outer, pg = self._card(page, radius=14, pad=(18, 12))
            outer.grid(row=2, column=0, sticky="ew")
            pg.columnconfigure(0, weight=1)
            top = ttk.Frame(pg, style="Card.TFrame")
            top.grid(row=0, column=0, sticky="ew")
            self.status = tk.StringVar(value="Ready.")
            self.status_label = ElideLabel(top, self.status, "H.TLabel")
            self.status_label.grid(row=0, column=0, sticky="ew")
            self.detail = tk.StringVar(value="")
            ElideLabel(top, self.detail, "Dim.TLabel", keep_tail=0, anchor="e", justify="right").grid(row=0, column=1, sticky="ew", padx=(12, 12))
            top.columnconfigure(0, weight=3)
            top.columnconfigure(1, weight=2)
            self.cancel_btn = Btn(top, text="Cancel", style="Danger.TButton", command=self._cancel, state="disabled")
            self.cancel_btn.grid(row=0, column=2, sticky="e")
            self.bar = Progress(pg, mode="determinate", maximum=100)
            self.bar.grid(row=1, column=0, sticky="ew", pady=(10, 4))

            book = self.qbook = ttk.Frame(pg, style="Card.TFrame")
            book.grid(row=3, column=0, sticky="ew", pady=(6, 0))
            book.columnconfigure(0, weight=1)
            seg = ttk.Frame(book, style="Card.TFrame")
            seg.grid(row=0, column=0, sticky="w", pady=(0, 8))
            self.seg_queue = Btn(seg, text="Queue", kind="tab", selected=True, command=lambda: self._qpage("queue"))
            self.seg_queue.grid(row=0, column=0, padx=(0, 6))
            self.seg_log = Btn(seg, text="Details", kind="tab", selected=False, command=lambda: self._qpage("log"))
            self.seg_log.grid(row=0, column=1)

            self.q_page = ttk.Frame(book, style="Card.TFrame")
            self.q_page.grid(row=1, column=0, sticky="ew")
            self.q_page.columnconfigure(0, weight=1)
            qcard = Card(self.q_page, fill=FIELD, border=BORDER, radius=9, pad=(4, 4), style="Field.TFrame", bg=CARD)
            qcard.grid(row=0, column=0, sticky="ew")
            qwrap = qcard.body
            qwrap.columnconfigure(0, weight=1)
            self.qtree = ttk.Treeview(qwrap, columns=("state",), height=2, selectmode="extended")
            self.qtree.heading("#0", text="Transfer", anchor="w")
            self.qtree.heading("state", text="Status", anchor="w")
            self.qtree.column("#0", width=520, stretch=True)
            self.qtree.column("state", width=360, stretch=False)
            self.qtree.tag_configure("done", foreground=GREEN)
            self.qtree.tag_configure("failed", foreground=RED)
            self.qtree.tag_configure("run", foreground=CYAN)
            self.qtree.tag_configure("dim", foreground=DIM)
            qsb = ttk.Scrollbar(qwrap, orient="vertical", style="Thin.Vertical.TScrollbar", command=self.qtree.yview)
            self.qtree.configure(yscrollcommand=qsb.set)
            self.qtree.grid(row=0, column=0, sticky="ew")
            qsb.grid(row=0, column=1, sticky="ns", padx=(2, 0))
            qbtn = ttk.Frame(self.q_page, style="Card.TFrame")
            qbtn.grid(row=1, column=0, sticky="w", pady=(10, 0))
            for i, (text, cmd) in enumerate((("Remove selected", self._q_remove), ("Retry failed", self._q_retry), ("Clear finished", self._q_clear))):
                Btn(qbtn, text=text, style="Small.TButton", command=cmd).grid(row=0, column=i, padx=(0, 6))

            self.log_page = ttk.Frame(book, style="Card.TFrame")
            self.log_page.grid(row=1, column=0, sticky="ew")
            self.log_page.columnconfigure(0, weight=1)
            lcard = Card(self.log_page, fill=FIELD, border=BORDER, radius=9, pad=(4, 4), style="Field.TFrame", bg=CARD)
            lcard.grid(row=0, column=0, sticky="ew")
            lwrap = lcard.body
            lwrap.columnconfigure(0, weight=1)
            self.log = tk.Text(lwrap, height=5, bg=FIELD, fg=DIM, insertbackground=CYAN, relief="flat", bd=0,
                               highlightthickness=0, wrap="none", font=UI["mono"], padx=8, pady=6, state="disabled")
            lsb = ttk.Scrollbar(lwrap, orient="vertical", style="Thin.Vertical.TScrollbar", command=self.log.yview)
            self.log.configure(yscrollcommand=lsb.set)
            self.log.grid(row=0, column=0, sticky="ew")
            lsb.grid(row=0, column=1, sticky="ns", padx=(2, 0))
            for tag, color in (("info", CYAN), ("cmd", PURPLE), ("name", TEXT), ("dim", DIM), ("err", RED), ("ok", GREEN)):
                self.log.tag_configure(tag, foreground=color)
            self.log_page.grid_remove()

            self.menu = tk.Menu(self.root, **self.menu_kw)

        def _qpage(self, which):
            """Switches the lower panel between the transfer queue and the details log."""
            queue_on = which == "queue"
            self.seg_queue.configure(selected=queue_on)
            self.seg_log.configure(selected=not queue_on)
            (self.q_page if queue_on else self.log_page).grid()
            (self.log_page if queue_on else self.q_page).grid_remove()

        # ── settings and saved sites ─────────────────────────────────────
        def _load_fields(self, blank=False):
            st = self.settings
            self.control_port.set(st["control_port"])
            if blank:  # a new tab starts empty; saved sites fill it in
                self.port.set("22")
                self.route.set("Service default")
                return
            self.host.set(st["host"]); self.port.set(st["port"]); self.user.set(st["user"])
            self.route.set(st["route"] if st["route"] in list_routes() else "Service default")
            self.auth.set(st["auth"]); self.key_path.set(st["key_path"])

        def _policy_key(self):
            return next((k for k, label in POLICIES if label == self.policy.get()), "skip")

        def _streams(self):
            try:
                return max(1, min(int(self.streams.get().strip() or DEFAULT_STREAMS), MAX_STREAMS))
            except ValueError:
                return DEFAULT_STREAMS

        def _bwlimit(self):
            try:
                n = int(self.bwlimit.get().strip() or 0)
            except ValueError:
                return None
            return n if n > 0 else None

        def _save_fields(self):
            save_settings({
                "host": self.host.get().strip(), "port": self.port.get().strip() or "22", "user": self.user.get().strip(),
                "route": "" if self.route.get() == "Service default" else self.route.get(), "auth": self.auth.get(),
                "key_path": self.key_path.get().strip(), "control_port": self.control_port.get().strip() or str(DEFAULT_CONTROL_PORT),
                "local_dir": self.local.path or str(Path.home()), "policy": self._policy_key(), "bwlimit": self.bwlimit.get().strip(),
                "show_hidden": bool(self.show_hidden.get()), "compare": bool(self.compare.get()),
                "compress": bool(self.compress.get()), "streams": str(self._streams()),
            })

        def _use_site(self):
            site = self.sites["sites"].get(self.site_var.get())
            if not site:
                return
            self.host.set(site["host"]); self.port.set(site["port"] or "22"); self.user.set(site["user"])
            self.route.set(site["route"] if site["route"] in list_routes() else "Service default")
            self.auth.set(site["auth"] or "key"); self.key_path.set(site["key_path"])
            self.password.set("")
            self._auth_changed()

        def _save_site(self):
            host, user = self.host.get().strip(), self.user.get().strip()
            if not host or not user:
                return self._connect_error("Fill in the server and user first, then save the site.")
            name = self.ask_string("Save site", "Name for this site:", self.site_var.get() or f"{user}@{host}", ok="Save")
            name = (name or "").strip()
            if not name:
                return
            self.sites["sites"][name] = {
                "host": host, "port": self.port.get().strip() or "22", "user": user,
                "route": "" if self.route.get() == "Service default" else self.route.get(),
                "auth": self.auth.get(), "key_path": self.key_path.get().strip(),
            }
            save_sites(self.sites)
            self.site_box.configure(values=sorted(self.sites["sites"]))
            self.site_var.set(name)
            self.connect_status.set(f"Saved “{name}”. Passwords are never saved.")
            self.connect_status_label.configure(style="Dim.TLabel")

        def _delete_site(self):
            name = self.site_var.get()
            if name not in self.sites["sites"]:
                return self._connect_error("Pick a saved site to delete.")
            if not self.ask_yes_no("Delete site", f"Delete the saved site “{name}”?", ok="Delete", danger=True):
                return
            del self.sites["sites"][name]
            save_sites(self.sites)
            self.site_box.configure(values=sorted(self.sites["sites"]))
            self.site_var.set("")

        def _bm_key(self, pane):
            if not pane.remote:
                return "local"
            return f"{self.conn.user}@{self.conn.host}" if self.conn else None

        def bookmarks_for(self, pane):
            key = self._bm_key(pane)
            return list(self.sites["bookmarks"].get(key, [])) if key else []

        def add_bookmark(self, pane):
            key = self._bm_key(pane)
            if key and pane.path and pane.path not in self.sites["bookmarks"].setdefault(key, []):
                self.sites["bookmarks"][key].append(pane.path)
                save_sites(self.sites)
                self._set_status(f"Bookmarked {pane.path}", "ok")

        def remove_bookmark(self, pane, path):
            key = self._bm_key(pane)
            if key and path in self.sites["bookmarks"].get(key, []):
                self.sites["bookmarks"][key].remove(path)
                save_sites(self.sites)

        # ── small behaviours ─────────────────────────────────────────────
        def _auth_changed(self):
            if self.auth.get() == "password":
                self.key_row.grid_remove(); self.pw_row.grid()
            else:
                self.pw_row.grid_remove(); self.key_row.grid()

        def _pick_key(self):
            path = filedialog.askopenfilename(title="Choose your private key", initialdir=str(Path.home() / ".ssh"))
            if path:
                self.key_path.set(path)

        def _set_status(self, text, kind=None):
            self.status.set(text)
            self.status_label.configure(style={"ok": "Ok.H.TLabel", "err": "Err.H.TLabel"}.get(kind, "H.TLabel"))
            self.status_label.refit()

        def _log_line(self, text, level="dim"):
            self.log.configure(state="normal")
            self.log.insert("end", text + "\n", level)
            lines = int(self.log.index("end-1c").split(".")[0])
            if lines > MAX_LOG_LINES:
                self.log.delete("1.0", f"{lines - MAX_LOG_LINES}.0")
            self.log.configure(state="disabled")
            self.log.see("end")

        def _update_buttons(self):
            connected = self.conn is not None and not self.connecting
            self.up_btn.configure(state="normal" if connected else "disabled")
            self.down_btn.configure(state="normal" if connected else "disabled")
            for b in self.pane_buttons + [self.search_btn, self.ssh_btn]:
                b.configure(state="normal" if connected else "disabled")
            self.remote.up_btn.configure(state="normal" if connected else "disabled")
            self.remote.refresh_btn.configure(state="normal" if connected else "disabled")
            self.remote.entry.configure(state="normal" if connected else "disabled")
            self.remote.bm_btn.configure(state="normal" if connected else "disabled")
            self.cancel_btn.configure(state="normal" if self.job else "disabled")
            # the queue and log only take up room once there's something to show
            if connected or self.queue:
                self.qbook.grid()
            else:
                self.qbook.grid_remove()
            busy = self.connecting
            self.connect_btn.configure(state="disabled" if busy else "normal", text="Connecting…" if busy else "Connect")
            for w in self.form_inputs:
                try:
                    w.configure(state="disabled" if busy else ("readonly" if getattr(w, "is_combo", False) else "normal"))
                except tk.TclError:
                    pass

        def _bg(self, work, done=None):
            """Run work() off the window thread; done(result, error) runs back on it."""
            def run():
                try:
                    res, err = work(), None
                except Exception as e:  # reported through done(), not lost
                    res, err = None, e
                if done:
                    self.events.put(("call", lambda: done(res, err)))
            threading.Thread(target=run, daemon=True).start()

        # ── connecting ───────────────────────────────────────────────────
        def _connect(self):
            if self.connecting or self.conn:
                return
            host, user = self.host.get().strip(), self.user.get().strip()
            if not host:
                return self._connect_error("Enter the server (its ._ztr name or address).")
            if not user:
                return self._connect_error("Enter the user name on the server.")
            try:
                port, cport = int(self.port.get() or 22), int(self.control_port.get() or DEFAULT_CONTROL_PORT)
            except ValueError:
                return self._connect_error("Port numbers must be numbers.")
            use_password = self.auth.get() == "password"
            if use_password and not self.password.get():
                return self._connect_error("Enter the password, or switch to SSH key.")
            route = None if self.route.get() in ("", "Service default") else self.route.get()
            conn = Connection(host, port, user, route, self.key_path.get().strip() or None,
                              self.password.get() if use_password else None, control_port=cport, **self.conn_extra)
            self._save_fields()
            self.connecting = True
            self._t_connect = time.time()
            self.retitle()
            self.connect_status.set("Connecting…")
            self.connect_status_label.configure(style="Dim.TLabel")
            self._update_buttons()
            self._bg(lambda: conn.open(lambda k, p: self.events.put((k, p))), lambda _r, err: self._connected(conn, err))

        def _connect_error(self, message):
            self.connect_status.set(message)
            self.connect_status_label.configure(style="Err.H.TLabel")

        def _connected(self, conn, err):
            self.connecting = False
            self.retitle()
            if err:
                conn.close()
                self._update_buttons()
                self._set_status("Ready.")
                return self._connect_error(str(err) if isinstance(err, (ControlError, RemoteError)) else f"Something went wrong: {err}")
            self.conn = conn
            self.retitle()
            self.form_outer.grid_remove()
            self.bar_outer.grid()
            self.bar_text.set(f"Connected  ·  {conn.user}@{conn.host}" + (f"  ·  route {conn.route}" if conn.route else ""))
            self._set_status(f"Connected in {fmt_elapsed(time.time() - self._t_connect)}.", "ok")
            self._update_buttons()
            self.go(self.remote, "")

        def _disconnect(self, message="Disconnected."):
            conn, self.conn = self.conn, None
            self.retitle()
            if self.job:
                self.job.cancel()
            for item in self.queue:
                if item.state == "queued":
                    item.state, item.message = "cancelled", "Disconnected"
            self._q_refresh()
            if conn:
                self._bg(conn.close)
            self.remote.clear("Not connected")
            self.bar_outer.grid_remove()
            self.form_outer.grid()
            self.connect_status.set("")
            self._set_status(message)
            self._update_buttons()

        def _lost(self, message="The connection to the server was lost."):
            if self.conn:
                self._disconnect(message)
                self._connect_error(message + " Connect again to continue.")

        # ── browsing ─────────────────────────────────────────────────────
        def go(self, pane, path):
            if not pane.remote:
                try:
                    shown, entries = list_local(path)
                except OSError as e:
                    return self._set_status(f"Can't open that folder: {e.strerror or e}", "err")
                pane.show(shown, entries)
                return
            conn = self.conn
            if not conn:
                return
            pane.tree.configure(cursor="watch")
            t0 = time.time()

            def done(res, err):
                pane.tree.configure(cursor="")
                if err is None:
                    pane.show(*res, seconds=time.time() - t0)
                elif isinstance(err, ConnectionLost):
                    self._lost(str(err))
                else:
                    self._set_status(str(err), "err")
            self._bg(lambda: conn.listdir(path), done)

        # ── file operations ──────────────────────────────────────────────
        def _ask_name(self, title, prompt, initial=""):
            name = self.ask_string(title, prompt, initial)
            name = (name or "").strip()
            if not name:
                return None
            if "/" in name or name in (".", ".."):
                self._set_status("A name can't contain “/”.", "err")
                return None
            return name

        def mkdir(self, pane):
            name = self._ask_name("New folder", "Name of the new folder:")
            if not name or not pane.path:
                return
            if pane.remote:
                self._remote_op(lambda c: c.mkdir(pane.join(name)), pane, f"Created {name}.")
            else:
                try:
                    os.mkdir(pane.join(name))
                except OSError as e:
                    return self._set_status(f"Couldn't create it: {e.strerror or e}", "err")
                self.go(pane, pane.path)

        def rename(self, pane):
            sel = pane.selected()
            if len(sel) != 1:
                return self._set_status("Select one file or folder to rename.", "err")
            old = sel[0].name
            name = self._ask_name("Rename", f"New name for “{old}”:", old)
            if not name or name == old:
                return
            if pane.remote:
                self._remote_op(lambda c: c.rename(pane.join(old), pane.join(name)), pane, f"Renamed to {name}.")
            else:
                if os.path.exists(pane.join(name)):
                    return self._set_status("Something named that already exists.", "err")
                try:
                    os.rename(pane.join(old), pane.join(name))
                except OSError as e:
                    return self._set_status(f"Couldn't rename it: {e.strerror or e}", "err")
                self.go(pane, pane.path)

        def delete(self, pane):
            if pane.remote and not self.conn:
                return
            sel = pane.selected()
            if not sel:
                return self._set_status("Select what you want to delete.", "err")
            what = f"“{sel[0].name}”" if len(sel) == 1 else f"{len(sel)} items"
            where = "on the server" if pane.remote else "on this computer"
            if not self.ask_yes_no("Delete", f"Delete {what} {where}? This can't be undone.", ok="Delete", danger=True):
                return
            paths = pane.selected_paths()
            if pane.remote:
                self._remote_op(lambda c: c.remove(paths), pane, f"Deleted {what}.")
                return
            try:
                for p in paths:
                    shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
            except OSError as e:
                self._set_status(f"Couldn't delete it: {e.strerror or e}", "err")
            self.go(pane, pane.path)

        def permissions(self, pane):
            sel = pane.selected()
            if not sel or (pane.remote and not self.conn):
                return self._set_status("Select what you want to change permissions on.", "err")
            mode = self.ask_string("Permissions", "Permissions as an octal number (for example 644, or 755 for a program or folder):",
                                   perms_to_octal(sel[0].perms) or "644", ok="Apply")
            mode = (mode or "").strip()
            if not mode:
                return
            if not re.fullmatch(r"[0-7]{3,4}", mode):
                return self._set_status("Use an octal number such as 644 or 755.", "err")
            recursive = any(e.is_dir for e in sel) and self.ask_yes_no(
                "Permissions", "Apply this to everything inside the selected folder(s) too?", ok="Apply to everything")
            paths = pane.selected_paths()
            if pane.remote:
                self._remote_op(lambda c: c.chmod(paths, mode, recursive), pane, f"Permissions set to {mode}.")
                return
            r = subprocess.run(["chmod"] + (["-R"] if recursive else []) + [mode] + paths, capture_output=True, text=True)
            self._set_status(f"Permissions set to {mode}." if r.returncode == 0 else (r.stderr.strip() or "chmod failed."),
                             "ok" if r.returncode == 0 else "err")
            self.go(pane, pane.path)

        def copy_path(self, pane):
            paths = pane.selected_paths() or ([pane.path] if pane.path else [])
            if paths:
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(paths))
                self._set_status("Copied the path." if len(paths) == 1 else f"Copied {len(paths)} paths.", "ok")

        def _remote_op(self, op, pane, ok_message):
            conn = self.conn
            if not conn:
                return

            t0 = time.time()

            def done(_res, err):
                if isinstance(err, ConnectionLost):
                    return self._lost(str(err))
                self._set_status(str(err) if err else f"{ok_message}  ({fmt_elapsed(time.time() - t0)})", "err" if err else "ok")
                self.go(pane, pane.path)
            self._bg(lambda: op(conn), done)

        # ── open / edit ──────────────────────────────────────────────────
        def _open_local(self, path):
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            try:
                subprocess.Popen([opener, path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
                return True
            except OSError:
                self._set_status(f"Couldn't open it — no program is set to open this kind of file ({opener} not found).", "err")
                return False

        def open_file(self, pane):
            sel = [e for e in pane.selected() if not e.is_dir]
            if len(sel) != 1:
                return self._set_status("Select one file to open.", "err")
            entry = sel[0]
            if not pane.remote:
                self._open_local(pane.join(entry.name))
                return
            conn = self.conn
            if not conn:
                return
            if entry.size > EDIT_MAX_BYTES:
                return self._set_status("That file is too large to open this way. Download it instead.", "err")
            tmp = Path(tempfile.mkdtemp(prefix="ferry-edit-"))
            job = Job("download", [pane.join(entry.name)], str(tmp), "overwrite", size_hint=entry.size)
            self._set_status(f"Fetching {entry.name}…")
            t0 = time.time()

            def done(res, err):
                if err or not res["ok"]:
                    shutil.rmtree(tmp, ignore_errors=True)
                    return self._set_status(str(err) if err else res["message"], "err")
                local = tmp / entry.name
                if self._open_local(str(local)):
                    self._set_status(f"Opened {entry.name} after {fmt_elapsed(time.time() - t0)}. Save it in your editor to upload the changes.", "ok")
                    self._watch_edit(local, pane.path, conn)
            self._bg(lambda: conn.transfer(job, lambda *a: None), done)

        def _watch_edit(self, local, remote_dir, conn):
            state = {"mtime": os.path.getmtime(local), "until": time.time() + EDIT_WATCH_SECONDS}

            def tick():
                if time.time() > state["until"] or self.conn is not conn:
                    shutil.rmtree(local.parent, ignore_errors=True)
                    return
                try:
                    m = os.path.getmtime(local)
                except OSError:
                    return
                if m != state["mtime"]:
                    state["mtime"] = m
                    if self.ask_yes_no("Upload changes", f"“{local.name}” was changed. Upload it back to the server?", ok="Upload"):
                        job = Job("upload", [str(local)], remote_dir, "overwrite", self._bwlimit(), self.compress.get())
                        self._enqueue(job, f"Upload {local.name} → {remote_dir}", self.remote if self.remote.path == remote_dir else None)
                self.root.after(1500, tick)
            self.root.after(1500, tick)

        # ── a terminal on the server ─────────────────────────────────────
        def open_terminal(self):
            """Opens a terminal window running ztr_ssh into the server this tab is connected to."""
            conn = self.conn
            if not conn:
                return
            script = find_ztr_ssh()
            if not script:
                return self._set_status("ztr_ssh wasn't found next to Ferry or on your PATH.", "err")
            try:
                cport = int(self.control_port.get() or DEFAULT_CONTROL_PORT)
            except ValueError:
                cport = DEFAULT_CONTROL_PORT
            argv = terminal_argv(conn.ztr_ssh_argv(script, cport), f"ztr_ssh {conn.user}@{conn.host}")
            if not argv:
                return self._set_status("Terminal couldn't be opened (osascript wasn't found). Set FERRY_TERMINAL to a terminal program that takes a command after -e." if sys.platform == "darwin"
                                        else "No terminal program was found. Install lxterminal or xterm, or set FERRY_TERMINAL.", "err")
            try:
                subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
            except OSError as e:
                return self._set_status(f"Couldn't open a terminal: {e.strerror or e}", "err")
            self._set_status(f"Opened a terminal: ztr_ssh {conn.user}@{shorten_middle(conn.host, 40)}", "ok")

        # ── searching the server ─────────────────────────────────────────
        def open_search(self):
            if not self.conn or not self.remote.path:
                return
            if self.search_win is not None and self.search_win.winfo_exists():
                self.search_win.lift()
                return
            win = self.search_win = tk.Toplevel(self.root)
            win.title("Search the server")
            win.configure(bg=CARD)
            win.geometry("640x420")
            win.columnconfigure(0, weight=1)
            win.rowconfigure(2, weight=1)
            where = tk.StringVar(value=self.remote.path)
            term = tk.StringVar()
            msg = tk.StringVar(value="Searches inside the folder below, including its subfolders.")
            top = ttk.Frame(win, style="Card.TFrame", padding=(14, 12, 14, 6))
            top.grid(row=0, column=0, sticky="ew")
            top.columnconfigure(1, weight=1)
            ttk.Label(top, text="Folder", style="Dim.TLabel").grid(row=0, column=0, padx=(0, 8))
            Field(top, compact=True, textvariable=where).grid(row=0, column=1, sticky="ew")
            ttk.Label(top, text="Name contains", style="Dim.TLabel").grid(row=1, column=0, padx=(0, 8), pady=(8, 0))
            entry = Field(top, compact=True, textvariable=term)
            entry.grid(row=1, column=1, sticky="ew", pady=(8, 0))
            go_btn = Btn(top, text="Search", style="Go.TButton")
            go_btn.grid(row=1, column=2, padx=(8, 0), pady=(8, 0))
            ttk.Label(win, textvariable=msg, style="Dim.TLabel", padding=(14, 0)).grid(row=1, column=0, sticky="w")
            box = tk.Listbox(win, bg=FIELD, fg=TEXT, selectbackground=SEL, selectforeground="#ffffff", relief="flat", bd=0,
                             highlightthickness=1, highlightbackground=BORDER, activestyle="none", font=UI["body"])
            box.grid(row=2, column=0, sticky="nsew", padx=14, pady=(6, 14))
            found = []
            win._vars = (where, term, msg)  # keep them alive for as long as the window is

            def run(_e=None):
                conn = self.conn
                if not conn:
                    return
                msg.set("Searching…")
                t0 = time.time()
                box.delete(0, "end")
                found.clear()

                def done(res, err):
                    if not win.winfo_exists():
                        return
                    if err:
                        return msg.set(str(err))
                    found.extend(res)
                    for path, is_dir in res:
                        box.insert("end", ("[folder]  " if is_dir else "") + path)
                    took = fmt_elapsed(time.time() - t0)
                    msg.set(f"{len(res)} match(es) in {took}. Double-click one to open its folder." if res else f"Nothing matched ({took}).")
                folder, text = where.get(), term.get()  # read here: Tk variables belong to the window thread
                self._bg(lambda: conn.search(folder, text), done)

            def open_hit(_e=None):
                sel = box.curselection()
                if sel:
                    path, is_dir = found[sel[0]]
                    self.go(self.remote, path if is_dir else posixpath.dirname(path))
            go_btn.configure(command=run)
            entry.bind("<Return>", run)
            box.bind("<Double-1>", open_hit)
            entry.focus_set()

        # ── transfers and the queue ──────────────────────────────────────
        def transfer_from(self, pane, paths=None, dest=None):
            """Queue sending (local pane) or fetching (server pane) the selection."""
            if not self.conn:
                return
            paths = paths or pane.selected_paths()
            if not paths:
                return self._set_status("Select something to " + ("download." if pane.remote else "upload."), "err")
            dest_pane = self.local if pane.remote else self.remote
            dest = dest or dest_pane.path
            if not dest:
                return self._set_status("Open the destination folder first.", "err")
            direction = "download" if pane.remote else "upload"
            job = Job(direction, paths, dest, self._policy_key(), self.dry.get(), self._bwlimit(), self.compress.get(), self._streams(),
                      pane.size_hint(paths))
            what = shorten_middle(posixpath.basename(paths[0].rstrip("/")), 38) if len(paths) == 1 else f"{len(paths)} items"
            self._save_fields()
            self._enqueue(job, f"{'Download' if pane.remote else 'Upload'}  {what}  →  {shorten_middle(dest, 44, 16)}", dest_pane if dest == dest_pane.path else None)

        def _enqueue(self, job, label, refresh):
            item = QueueItem(job, label, refresh)
            self.queue.append(item)
            self._q_refresh()
            self._schedule_next()

        def _schedule_next(self, delay=300):
            """Starts the queue after a moment, so a burst of clicks becomes one transfer instead of several."""
            if self._next_timer is None and not self.closed:
                self._next_timer = self.root.after(delay, self._fire_next)

        def _fire_next(self):
            self._next_timer = None
            if not self.closed:
                self._next()

        def _next(self):
            if self.job or not self.conn or self.connecting:
                return
            first = next((i for i in self.queue if i.state == "queued"), None)
            if not first:
                return
            group = [first]
            for item in self.queue:
                if item is not first and item.state == "queued" and mergeable(first.job, item.job):
                    group.append(item)
            job = first.job if len(group) == 1 else merge_jobs([i.job for i in group])
            now = time.time()
            self._t_job, self._progress_text = now, ""
            for item in group:
                item.state, item.started, item.seconds = "running", now, None
                item.message = f"Merged with {len(group) - 1} other(s)" if len(group) > 1 else ""
            self.group, self.current, self.job = group, first, job
            self._t_job = now
            self._set_status(first.label if len(group) == 1 else f"{len(group)} transfers together  →  {job.dest}")  # the label elides to fit
            self.detail.set("")
            self.bar.configure(mode="indeterminate", value=0)
            self.bar.start(12)
            self._update_buttons()
            self._q_refresh()
            conn = self.conn
            self._bg(lambda: conn.transfer(job, lambda k, p: self.events.put((k, p))), None)
            self._tick()

        def _tick(self):
            """Keeps the elapsed time moving while a transfer works, even between progress updates."""
            if self.closed or not self.job:
                return
            self._show_detail()
            for item in self.group:
                if self.qtree.exists(str(item.id)):
                    self.qtree.set(str(item.id), "state", self._q_text(item))
            self.root.after(500, self._tick)

        def _show_detail(self):
            elapsed = fmt_elapsed(time.time() - self._t_job)
            self.detail.set(f"{elapsed}  ·  {self._progress_text}" if self._progress_text else elapsed)

        def _q_text(self, item):
            text = {"queued": "Waiting", "running": item.message or "Working…", "done": item.message or "Done",
                    "failed": item.message or "Failed", "cancelled": item.message or "Cancelled"}[item.state]
            took = time.time() - item.started if (item.state == "running" and item.started) else item.seconds
            if took is None:
                return text
            avg = f"  ·  {human_bytes(item.bytes / took)}/s" if (item.state == "done" and item.bytes and took >= 1) else ""
            return f"{text}  ·  {fmt_elapsed(took)}{avg}"

        def _q_refresh(self):
            sel = set(self.qtree.selection())
            self.qtree.delete(*self.qtree.get_children())
            for item in self.queue:
                tag = {"done": "done", "failed": "failed", "running": "run"}.get(item.state, "dim")
                self.qtree.insert("", "end", iid=str(item.id), text=item.label, values=(self._q_text(item),), tags=(tag,))
            self.retitle()
            keep = [i for i in sel if self.qtree.exists(i)]
            if keep:
                self.qtree.selection_set(keep)

        def _q_remove(self):
            ids = {int(i) for i in self.qtree.selection()}
            self.queue = [i for i in self.queue if not (i.id in ids and i.state != "running")]
            self._q_refresh()

        def _q_retry(self):
            for item in self.queue:
                if item.state in ("failed", "cancelled"):
                    old = item.job
                    item.job = Job(old.direction, old.sources, old.dest, old.policy, old.dry_run, old.bwlimit, old.compress, old.streams, old.size_hint)
                    item.state, item.message = "queued", ""
            self._q_refresh()
            self._next()

        def _q_clear(self):
            self.queue = [i for i in self.queue if i.state in ("queued", "running")]
            self._q_refresh()

        def _cancel(self):
            if self.job:
                self._set_status("Cancelling…")
                self.job.cancel()

        def shutdown(self):
            """Ends this tab's work; returns the thread closing its connection (or None)."""
            self.closed = True
            if self._next_timer is not None:
                self.root.after_cancel(self._next_timer)
                self._next_timer = None
            if self.job:
                self.job.cancel()
            if self.search_win is not None and self.search_win.winfo_exists():
                self.search_win.destroy()
            conn, self.conn = self.conn, None
            if not conn:
                return None
            t = threading.Thread(target=conn.close, daemon=True)
            t.start()
            return t

        def _on_progress(self, p):
            if str(self.bar.cget("mode")) != "determinate":
                self.bar.stop()
                self.bar.configure(mode="determinate")
            self.bar.configure(value=p["percent"])
            name = p.get("file") or ""
            if len(name) > 58:
                name = "…" + name[-57:]
            self._progress_text = "  ·  ".join(x for x in (f"{p['percent']}%", f"{human_bytes(p['bytes'])} so far", p["speed"],
                                                           f"{p['eta']} left" if p["eta"] != "0:00:00" else "", name) if x)
            self._show_detail()
            for item in self.group:
                item.message = f"{p['percent']}%  ·  {p['speed']}"
                if self.qtree.exists(str(item.id)):
                    self.qtree.set(str(item.id), "state", self._q_text(item))

        def _on_done(self, r):
            group = self.group
            self.bar.stop()
            self.bar.configure(mode="determinate", value=100 if (r["ok"] and not r["dry_run"]) else 0)
            self.job = self.current = None
            self.group = []
            took = time.time() - self._t_job  # the same clock the live counter used
            for item in group:
                item.state = "done" if r["ok"] else ("cancelled" if r["cancelled"] else "failed")
                item.message, item.seconds, item.bytes = r["message"], took, r["bytes"]
            self._q_refresh()
            kind = "ok" if r["ok"] else ("err" if not r["cancelled"] else None)
            self._set_status(f"{r['message']}  ({fmt_elapsed(took)})", kind)
            if r["ok"] and r["bytes"]:
                avg = f"  ·  {human_bytes(r['bytes'] / took)}/s avg" if took >= 1 else ""
                self.detail.set(f"{human_bytes(r['bytes'])} transferred in {fmt_elapsed(took)}{avg}")
            else:
                self.detail.set(f"Took {fmt_elapsed(took)}")
            self._log_line(f"{r['message']}  ({fmt_elapsed(took)})", "ok" if r["ok"] else "err")
            if not r["dry_run"]:
                for pane in {id(i.refresh): i.refresh for i in group if i.refresh is not None}.values():
                    self.go(pane, pane.path)
            if r["message"].startswith("Not connected") and self.conn:
                self._lost()
            self._update_buttons()
            self._next()

        # ── context menu ─────────────────────────────────────────────────
        def show_menu(self, pane, event):
            m = self.menu
            m.delete(0, "end")
            connected = self.conn is not None
            usable = "normal" if (connected or not pane.remote) else "disabled"
            m.add_command(label="← Download" if pane.remote else "Upload →", command=lambda: self.transfer_from(pane), state="normal" if connected else "disabled")
            m.add_command(label="View / Edit" if pane.remote else "Open", command=lambda: self.open_file(pane), state=usable)
            m.add_separator()
            m.add_command(label="New folder", command=lambda: self.mkdir(pane), state=usable)
            m.add_command(label="Rename", command=lambda: self.rename(pane), state=usable)
            m.add_command(label="Delete", command=lambda: self.delete(pane), state=usable)
            m.add_command(label="Permissions…", command=lambda: self.permissions(pane), state=usable)
            m.add_separator()
            m.add_command(label="Copy path", command=lambda: self.copy_path(pane))
            m.add_command(label="Refresh", command=lambda: self.go(pane, pane.path), state=usable)
            if pane.remote:
                m.add_command(label="Search server…", command=self.open_search, state=usable)
            try:
                m.tk_popup(event.x_root, event.y_root)
            finally:
                m.grab_release()

        # ── background feeds ─────────────────────────────────────────────
        def drain(self):
            """Applies what the worker threads reported (called by the shell's timer)."""
            try:
                while not self.closed:
                    kind, payload = self.events.get_nowait()
                    if kind == "call":
                        payload()
                    elif kind == "status":
                        if self.connecting:
                            self.connect_status.set(payload)
                        else:
                            self._set_status(payload)
                    elif kind == "log":
                        self._log_line(*payload)
                    elif kind == "progress":
                        self._on_progress(payload)
                    elif kind == "done":
                        self._on_done(payload)
            except queue.Empty:
                pass

        def _poll_connection(self):
            if self.closed:
                return
            conn = self.conn
            if conn and not self.job and not self.connecting:
                self._bg(conn.alive, lambda ok, err: (self._lost() if (ok is False and self.conn is conn) else None))
            self.root.after(10000, self._poll_connection)

    workspace_class = Workspace

    class Shell:
        """The window: header, tab strip, and the options every tab shares."""

        Workspace = workspace_class

        def ask_yes_no(self, title, message, ok="OK", danger=False):
            return ask_yes_no(self.root, title, message, ok, danger)

        def __init__(self, root):
            self.root = root
            migrate_old_config()
            forget_old_host_keys()
            sweep_stale_temp()
            self.settings = load_settings()
            self.sites = load_sites()
            self.workspaces = []
            self.settings_win = None
            self.events = queue.Queue()
            self.menu_kw = dict(tearoff=0, bg="#2c2c2f", fg=TEXT, activebackground=SEL, activeforeground="#ffffff",
                                disabledforeground="#6a6a70", bd=0, relief="flat", activeborderwidth=0)
            root.title(APP_NAME)
            root.configure(bg=BG)
            root.minsize(960, 640)
            root.geometry(f"1180x{min(960, max(640, root.winfo_screenheight() - 70))}")
            self._style()
            self.menu_kw["font"] = UI["body"]
            self._icons()
            self.logo_small = tk.PhotoImage(data=LOGO_SMALL)
            self.logo_large = tk.PhotoImage(data=LOGO_LARGE)
            try:
                root.iconphoto(True, self.logo_large)
            except tk.TclError:
                pass
            self.show_hidden = tk.BooleanVar(value=bool(self.settings.get("show_hidden", True)))
            self.compare = tk.BooleanVar(value=bool(self.settings.get("compare", False)))
            self.policy = tk.StringVar(value=dict(POLICIES).get(self.settings.get("policy"), POLICIES[0][1]))
            self.bwlimit = tk.StringVar(value=str(self.settings.get("bwlimit", "")))
            self.dry = tk.BooleanVar(value=False)
            self.compress = tk.BooleanVar(value=bool(self.settings.get("compress", True)))
            self.streams = tk.StringVar(value=str(self.settings.get("streams", DEFAULT_STREAMS)))
            self._build()
            self.new_tab(first=True)
            root.protocol("WM_DELETE_WINDOW", self._on_close)
            root.bind(f"<{MOD}-t>", lambda e: self.new_tab())
            root.bind(f"<{MOD}-w>", lambda e: self.close_tab())
            root.bind(f"<{MOD}-comma>", lambda e: self.open_settings())
            self._poll_events()
            self._poll_service()

        # ── look ─────────────────────────────────────────────────────────
        def _style(self):
            fams = set(tkfont.families())
            # Variable fonts (Cantarell, Nunito) can't be set to bold in Tk, so real Regular/Bold families come first.
            fam = next((f for f in ("SF Pro Text", "SF Pro Display", "Inter", "Helvetica Neue", "Nimbus Sans", "Liberation Sans",
                                    "Arimo", "Noto Sans", "DejaVu Sans") if f in fams), tkfont.nametofont("TkDefaultFont").actual("family"))
            self.family = fam
            for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
                try:
                    tkfont.nametofont(name).configure(family=fam, size=10)
                except tk.TclError:
                    pass
            mono = next((f for f in ("JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono") if f in fams), "TkFixedFont")
            UI.update(body=tkfont.Font(family=fam, size=10), small=tkfont.Font(family=fam, size=9),
                      bold=tkfont.Font(family=fam, size=10, weight="bold"), h=tkfont.Font(family=fam, size=11, weight="bold"),
                      title=tkfont.Font(family=fam, size=16, weight="bold"), head=tkfont.Font(family=fam, size=9, weight="bold"),
                      mono=tkfont.Font(family=mono, size=9))
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
            s.configure("Ok.H.TLabel", background=CARD, foreground=GREEN, font=UI["h"])
            s.configure("Err.H.TLabel", background=CARD, foreground=RED, font=UI["h"])
            # text fields live inside rounded Field wrappers, so the ttk widget itself has no border of its own
            for kind in ("Flat.TEntry", "Flat.TCombobox"):
                s.configure(kind, fieldbackground=FIELD, background=FIELD, foreground=TEXT, insertcolor=TEXT, borderwidth=0,
                            bordercolor=FIELD, lightcolor=FIELD, darkcolor=FIELD, padding=2, arrowcolor=DIM,
                            selectbackground=SEL, selectforeground="#ffffff", font=UI["body"])
                s.map(kind, fieldbackground=[("disabled", FIELD), ("readonly", FIELD)], foreground=[("disabled", DIM), ("readonly", TEXT)],
                      bordercolor=[("focus", FIELD)], lightcolor=[("focus", FIELD)], darkcolor=[("focus", FIELD)],
                      selectbackground=[("readonly", FIELD)], selectforeground=[("readonly", TEXT)], background=[("active", FIELD), ("readonly", FIELD)])
            for opt, val in (("background", FIELD), ("foreground", TEXT), ("selectBackground", SEL), ("selectForeground", "#ffffff"), ("font", UI["body"])):
                self.root.option_add(f"*TCombobox*Listbox.{opt}", val)
            # file lists
            s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
            s.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT, rowheight=26, borderwidth=0, relief="flat", font=UI["body"])
            s.configure("Treeview.Heading", background="#212124", foreground=DIM, padding=(8, 6), font=UI["head"], relief="flat", borderwidth=0)
            s.map("Treeview", background=[("selected", SEL)], foreground=[("selected", "#ffffff")])
            s.map("Treeview.Heading", background=[("active", "#2c2c30")])
            # slim scrollbars without arrow buttons
            s.layout("Thin.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
                ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
            s.configure("Thin.Vertical.TScrollbar", background="#4a4a4f", troughcolor=FIELD, bordercolor=FIELD, lightcolor="#4a4a4f",
                        darkcolor="#4a4a4f", arrowsize=9, gripcount=0, borderwidth=0)
            s.map("Thin.Vertical.TScrollbar", background=[("active", "#68686e")], lightcolor=[("active", "#68686e")], darkcolor=[("active", "#68686e")])
            # the notebook is only a page switcher: its own tabs are hidden and the tab bar above draws the real ones
            s.layout("Conn.TNotebook.Tab", [])
            s.configure("Conn.TNotebook", background=BG, borderwidth=0, tabmargins=0, bordercolor=BG, lightcolor=BG, darkcolor=BG)

        def _icons(self):
            """Small drawn icons (no emoji: some Tk builds crash on colour glyphs)."""
            def make(draw):
                img = tk.PhotoImage(width=16, height=16)
                for color, box in draw:
                    img.put(color, to=box)
                return img

            def page(accent):  # a sheet with a coloured label, so the kind reads at a glance
                return make([("#5d6772", (3, 1, 13, 15)), ("#d5dbe1", (4, 2, 12, 14)), ("#5d6772", (5, 4, 11, 5)),
                             ("#5d6772", (5, 6, 11, 7)), (accent, (4, 9, 12, 13))])
            self.icons = {
                "folder": make([("#3b8fe0", (1, 3, 7, 5)), ("#5ab4ff", (1, 5, 15, 14)), ("#8fd0ff", (1, 5, 15, 6))]),
                "file": page("#8d949c"), "image": page("#20c997"), "archive": page("#f08c3a"),
                "code": page(CYAN), "doc": page("#ff6b81"), "media": page(PURPLE),
            }

        def icon_for(self, entry):
            return self.icons["folder"] if entry.is_dir else self.icons[file_kind(entry.name)]

        # ── layout ───────────────────────────────────────────────────────
        def _build(self):
            root = self.root
            root.columnconfigure(0, weight=1)
            root.rowconfigure(0, weight=1)
            page = ttk.Frame(root, padding=(22, 16, 22, 16))
            page.grid(row=0, column=0, sticky="nsew")
            page.columnconfigure(0, weight=1)
            page.rowconfigure(2, weight=1)

            head = ttk.Frame(page)
            head.grid(row=0, column=0, sticky="ew", pady=(0, 14))
            head.columnconfigure(0, weight=1)
            brand = ttk.Frame(head)
            brand.grid(row=0, column=0, sticky="ew", padx=(0, 16))
            tk.Label(brand, image=self.logo_small, bg=BG, bd=0).grid(row=0, column=0, rowspan=2, padx=(0, 12))
            ttk.Label(brand, text=APP_NAME, style="Title.TLabel").grid(row=0, column=1, sticky="sw")
            ElideLabel(brand, tk.StringVar(value=TAGLINE), "BgDim.TLabel").grid(row=1, column=1, sticky="new")
            brand.columnconfigure(1, weight=1)
            Btn(head, text="+  New tab", command=self.new_tab).grid(row=0, column=1, padx=(0, 8))
            Btn(head, text="Close tab", style="Ghost.TButton", command=self.close_tab).grid(row=0, column=2, padx=(0, 6))
            self.settings_btn = GearBtn(head, command=self.open_settings)
            self.settings_btn.grid(row=0, column=3, padx=(0, 14))
            pill = Card(head, radius=15, pad=(12, 6), bg=BG)
            pill.grid(row=0, column=4, sticky="e")
            self.dot = tk.Canvas(pill.body, width=12, height=12, bg=CARD, highlightthickness=0)
            self.dot.grid(row=0, column=0, padx=(0, 7))
            self.dot_id = self.dot.create_oval(2, 2, 10, 10, fill=AMBER, outline="")
            self.service_label = ttk.Label(pill.body, text="Checking tunnel service…", style="Dim.TLabel")
            self.service_label.grid(row=0, column=1)

            self.tabbar = tk.Frame(page, bg=BG)
            self.tabbar.grid(row=1, column=0, sticky="w", pady=(0, 10))
            self._tabs_shown = None
            self.nb = ttk.Notebook(page, style="Conn.TNotebook")
            self.nb.grid(row=2, column=0, sticky="nsew")
            self.nb.bind("<<NotebookTabChanged>>", lambda e: (self.refresh_tabs(), self._poll_service(once=True)))

        # ── settings window ──────────────────────────────────────────────
        def open_settings(self):
            """A small window with the options every tab shares (how files are copied, what the lists show)."""
            if self.settings_win is not None and self.settings_win.winfo_exists():
                self.settings_win.lift()
                self.settings_win.focus_set()
                return
            win, body = _dialog(self.root, "Settings")
            self.settings_win = win
            body.columnconfigure(1, weight=1)
            ttk.Label(body, text="Settings", style="H.TLabel").grid(row=0, column=0, columnspan=2, sticky="w")

            def section(row, text):
                ttk.Label(body, text=text.upper(), style="Dim.TLabel").grid(row=row, column=0, columnspan=2, sticky="w", pady=(16, 6))

            def hint(row, text, under_check=False):
                lab = ttk.Label(body, text=text, style="Dim.TLabel", wraplength=400 if under_check else 380, justify="left")
                if under_check:  # lines up with the check box's own text
                    lab.grid(row=row, column=0, columnspan=2, sticky="w", padx=(26, 0), pady=(2, 0))
                else:
                    lab.grid(row=row, column=1, sticky="w", pady=(2, 0))

            section(1, "Transfers")
            ttk.Label(body, text="If a file already exists").grid(row=2, column=0, sticky="w", padx=(0, 16), pady=(0, 0))
            Combo(body, compact=True, textvariable=self.policy, state="readonly", width=30, values=[l for _k, l in POLICIES]).grid(row=2, column=1, sticky="w")
            ttk.Label(body, text="Speed limit (KB/s)").grid(row=3, column=0, sticky="w", padx=(0, 16), pady=(12, 0))
            Field(body, compact=True, textvariable=self.bwlimit, width=8).grid(row=3, column=1, sticky="w", pady=(12, 0))
            hint(4, "Leave empty for no limit.")
            ttk.Label(body, text="Parallel batches").grid(row=5, column=0, sticky="w", padx=(0, 16), pady=(12, 0))
            Field(body, compact=True, textvariable=self.streams, width=4).grid(row=5, column=1, sticky="w", pady=(12, 0))
            hint(6, f"1 = off. Splits transfers of {BATCH_MIN_FILES}+ files (or {BATCH_MIN_BYTES // (1024 * 1024)} MB+) into batches that run "
                    "together. Only worth trying if one transfer can't fill your connection.")
            Check(body, text="Compress while copying", variable=self.compress).grid(row=7, column=0, columnspan=2, sticky="w", pady=(14, 0))
            hint(8, "Helps with text and code. Files that are already compressed are left alone.", under_check=True)
            Check(body, text="Preview only (copy nothing)", variable=self.dry).grid(row=9, column=0, columnspan=2, sticky="w", pady=(12, 0))

            section(10, "File lists")
            Check(body, text="Compare folders", variable=self.compare, command=self.rerender_all).grid(row=11, column=0, columnspan=2, sticky="w")
            hint(12, "Colours files that exist on only one side or differ in size.", under_check=True)
            Check(body, text="Show hidden files", variable=self.show_hidden, command=self.rerender_all).grid(row=13, column=0, columnspan=2, sticky="w", pady=(12, 0))

            def close():
                self.settings_win = None
                win.destroy()
                ws = self.current()
                if ws:
                    ws._save_fields()
            Btn(body, text="Done", style="Primary.TButton", command=close).grid(row=14, column=0, columnspan=2, sticky="e", pady=(20, 0))
            win.bind("<Escape>", lambda e: close())
            win.protocol("WM_DELETE_WINDOW", close)
            _place(win, self.root)

        # ── tabs ─────────────────────────────────────────────────────────
        def refresh_tabs(self):
            """Redraws the rounded tab strip from the notebook's pages (only when something changed)."""
            tabs = [str(t) for t in self.nb.tabs()]
            state = (tuple((t, self.nb.tab(t, "text")) for t in tabs), str(self.nb.select()))
            if state == self._tabs_shown:
                return
            self._tabs_shown = state
            for w in self.tabbar.winfo_children():
                w.destroy()
            for i, t in enumerate(tabs):
                b = Btn(self.tabbar, text=self.nb.tab(t, "text"), kind="tab", selected=(t == str(self.nb.select())),
                        command=lambda t=t: self.nb.select(t))
                b.grid(row=0, column=i, padx=(0, 6))
                b.bind("<ButtonRelease-2>", lambda e, t=t: self._close_page(t))

        def new_tab(self, first=False):
            frame = ttk.Frame(self.nb)
            ws = self.Workspace(self, frame, blank=not first)
            self.workspaces.append(ws)
            self.nb.add(frame, text=ws.title())
            self.nb.select(frame)
            self.refresh_tabs()
            return ws

        def current(self):
            sel = self.nb.select()
            return next((w for w in self.workspaces if str(w.frame) == sel), self.workspaces[0] if self.workspaces else None)

        def retitle(self, ws):
            if ws in self.workspaces:
                self.nb.tab(ws.frame, text=ws.title())
                self.refresh_tabs()

        def close_tab(self, ws=None):
            ws = ws or self.current()
            if ws is None:
                return
            if ws.job or any(i.state in ("queued", "running") for i in ws.queue):
                if not self.ask_yes_no("Close tab", "This tab still has transfers waiting or running. Close it anyway?", ok="Close tab", danger=True):
                    return
            ws.shutdown()
            self.workspaces.remove(ws)
            self.nb.forget(ws.frame)
            ws.frame.destroy()
            if not self.workspaces:
                self.new_tab()
            self.refresh_tabs()

        def _close_page(self, tab_id):
            self.close_tab(next((w for w in self.workspaces if str(w.frame) == str(tab_id)), None))

        def rerender_all(self):
            for ws in self.workspaces:
                ws.local.render()
                ws.remote.render()

        def _on_close(self):
            ws = self.current()
            if ws:
                ws._save_fields()
            if self.settings_win is not None and self.settings_win.winfo_exists():
                self.settings_win.destroy()
            closers = [t for t in (w.shutdown() for w in list(self.workspaces)) if t]
            deadline = time.time() + 8
            for t in closers:
                t.join(max(0.1, deadline - time.time()))
            self.root.destroy()

        # ── background feeds ─────────────────────────────────────────────
        def _poll_events(self):
            for ws in list(self.workspaces):
                ws.drain()
            try:
                while True:
                    kind, payload = self.events.get_nowait()
                    if kind == "service":
                        ok, n = payload
                        self.dot.itemconfigure(self.dot_id, fill=GREEN if ok else RED)
                        self.service_label.configure(
                            text=(f"Tunnel service online · {n} open session{'s' if n != 1 else ''}" if ok else "Tunnel service not reachable"))
            except queue.Empty:
                pass
            self.root.after(80, self._poll_events)

        def _poll_service(self, once=False):
            def check(port):
                try:
                    self.events.put(("service", (True, len(ControlClient(port=port).list()["sessions"]))))
                except Exception:
                    self.events.put(("service", (False, 0)))
            ws = self.current() if self.workspaces else None
            try:
                port = int(ws.control_port.get() or DEFAULT_CONTROL_PORT) if ws else DEFAULT_CONTROL_PORT
            except ValueError:
                port = DEFAULT_CONTROL_PORT
            threading.Thread(target=check, args=(port,), daemon=True).start()
            if not once:
                self.root.after(3000, self._poll_service)

    return Shell


def write_icon(path):
    """Writes Ferry's 128x128 icon as a PNG (the installer uses it for the desktop launcher)."""
    import base64
    data = base64.b64decode("".join(LOGO_LARGE))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(data)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--write-icon":
        write_icon(sys.argv[2])
        return 0
    try:
        import tkinter as tk
    except ImportError:
        if sys.platform == "darwin":
            print("This needs Python's tkinter. With Homebrew: brew install python-tk@%d.%d (or use the python.org installer, which includes it)."
                  % sys.version_info[:2])
        else:
            print("This needs Python's tkinter. On Debian/Raspberry Pi OS: sudo apt install python3-tk")
        return 1
    Shell = build_app()
    root = tk.Tk()
    Shell(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
