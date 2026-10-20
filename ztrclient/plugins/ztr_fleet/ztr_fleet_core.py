#!/usr/bin/env python3
"""ZTR Fleet — run commands, scripts and file transfers on several servers at once, each through its own ZTRelay route.

This is the engine behind both `ztr_fleet` (the command line) and the ZTR Fleet window. It reads the fleet file,
opens one tunnel per server through that server's own route, and runs ssh or scp through it.

    ztr_fleet 'uptime'                          one command on every server
    ztr_fleet --script deploy.sh --batch 2      a local script, two servers at a time, stopping if one fails
    ztr_fleet --put app.conf --to /tmp/         send a file to every server
    ztr_fleet --get /var/log/syslog --into logs a file back from every server
    ztr_fleet --shell web1                      a terminal on one server

Needs only Python's standard library, and the tunnel service (ztr_tunnel_lp.py) running. Linux and macOS.
"""
import argparse
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGINS_DIR = Path(SCRIPT_DIR).resolve().parent
ROUTES_DIR = PLUGINS_DIR.parent / "routes"
FORWARD = PLUGINS_DIR / "ztr_forward"
SSH_WRAPPER = PLUGINS_DIR / "ztr_ssh"
CONFIG_DIR = Path(os.environ.get("ZTR_FLEET_HOME") or Path.home() / ".config" / "ztr_fleet")
SNIPPETS_PATH = CONFIG_DIR / "snippets.json"
HISTORY_PATH = CONFIG_DIR / "history.json"
HOOKS_PATH = CONFIG_DIR / "hooks.json"
HOOKS_DIR = CONFIG_DIR / "hooks"
JOBS_PATH = CONFIG_DIR / "jobs.json"
KNOWN_HOSTS = Path(os.environ.get("ZTR_FLEET_KNOWN_HOSTS") or CONFIG_DIR / "known_hosts")
FERRY_SITES = Path(os.environ.get("ZTR_FERRY_HOME") or Path.home() / ".config" / "ztr_ferry") / "sites.json"
CONTROL_PORT = 2223
HISTORY_LIMIT = 40
OUTPUT_KEEP = 6000      # characters of each server's output kept in the history

DEFAULT_SNIPPETS = [
    ("Check connection", "true"),
    ("Uptime", "uptime"),
    ("Disk space", "df -h / | tail -n 1"),
    ("Memory", "free -h 2>/dev/null | head -n 2 || vm_stat | head -n 4"),
    ("Kernel", "uname -sr"),
    ("Pending updates", "apt list --upgradable 2>/dev/null | tail -n +2 | wc -l"),
    ("Who is logged in", "who"),
    ("Failed services", "systemctl --failed --no-legend 2>/dev/null | head -n 5"),
]


# ── the fleet file ───────────────────────────────────────────────────────────

NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9._:-]+$")
ROUTE_RE = re.compile(r"^[A-Za-z0-9._-]+\.ztr$")
VAR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RESERVED = {"name", "route", "alias", "user", "port", "key", "group"}


@dataclass
class Server:
    name: str
    route: str = "route.ztr"
    alias: str = ""
    user: str = "root"
    port: str = "22"
    key: str = ""
    group: str = ""
    vars: dict = field(default_factory=dict)

    def problems(self, routes_dir=None):
        found = []
        if not NAME_RE.match(self.name or ""):
            found.append("The name may only use letters, digits, . _ -")
        if not ALIAS_RE.match(self.alias or ""):
            found.append("The alias (…._ztr) or address is missing or has odd characters")
        if not ROUTE_RE.match(self.route or ""):
            found.append("The route should be the file name of a .ztr in routes/")
        elif routes_dir is not None and not (Path(routes_dir) / self.route).is_file():
            found.append("%s isn't in the routes folder" % self.route)
        if not NAME_RE.match(self.user or ""):
            found.append("The user has characters a login can't")
        if not str(self.port).isdigit():
            found.append("The port isn't a number")
        if self.group and not NAME_RE.match(self.group):
            found.append("The group may only use letters, digits, . _ -")
        if self.key and not os.path.isfile(os.path.expanduser(self.key)):
            found.append("The key file doesn't exist")
        for k, v in self.vars.items():
            if not VAR_RE.match(k) or k in RESERVED:
                found.append("'%s' can't be used as a variable name" % k)
            elif not v or re.search(r"\s", v):
                found.append("The value of %s must be one word" % k)
        return found

    def values(self):
        """What {name}, {alias}, … stand for in a command for this server."""
        base = dict(name=self.name, alias=self.alias, user=self.user, port=str(self.port), route=self.route, group=self.group)
        base.update(self.vars)
        return base


def parse_fleet(text):
    """The servers in a fleet file, and the lines that couldn't be read: ([Server], [(line number, message)])."""
    servers, problems, seen = [], [], set()
    for number, raw in enumerate(text.splitlines(), 1):
        fields = raw.split("#", 1)[0].split()
        if not fields:
            continue
        if len(fields) < 4:
            problems.append((number, "needs at least: name route-file alias user"))
            continue
        name, route, alias, user = fields[:4]
        port = fields[4] if len(fields) > 4 else "-"
        port = "22" if port == "-" else port
        key = group = ""
        extra_vars = {}
        bad = None
        for extra in fields[5:]:
            if extra.startswith("key="):
                key = extra[4:]
            elif extra.startswith("group="):
                group = extra[6:]
            elif "=" in extra and VAR_RE.match(extra.split("=", 1)[0]) and extra.split("=", 1)[0] not in RESERVED:
                k, v = extra.split("=", 1)
                extra_vars[k] = v
            else:
                bad = "'%s' isn't an option (use group=NAME, key=PATH, or your own NAME=value)" % extra
        if bad:
            problems.append((number, bad))
            continue
        if name in seen:
            problems.append((number, "the name '%s' is used twice" % name))
            continue
        seen.add(name)
        servers.append(Server(name, route, alias, user, port, key, group, extra_vars))
    return servers, problems


def format_fleet(servers, header=None):
    """The fleet file for these servers, columns lined up."""
    rows = []
    for s in servers:
        extras = ([("group=" + s.group)] if s.group else []) + ([("key=" + s.key)] if s.key else []) + ["%s=%s" % kv for kv in sorted(s.vars.items())]
        rows.append((s.name, s.route, s.alias, s.user, str(s.port), " ".join(extras)))
    head = ("# name", "route file", "alias (--rh)", "user", "port", "options")
    widths = [max(len(r[i]) for r in rows + [head]) for i in range(5)]
    lines = list(header or ["# Servers for ztr_fleet. One per line: name, route file, alias, user, ssh port, then options",
                            "# (group=NAME, key=PATH, or your own NAME=value for use as {NAME} in commands). `ztr_fleet --example` shows the format."])
    lines.append("  ".join(head[i].ljust(widths[i]) for i in range(5)).rstrip() + "  options")
    for r in rows:
        lines.append(("  ".join(r[i].ljust(widths[i]) for i in range(5)) + ("  " + r[5] if r[5] else "")).rstrip())
    return "\n".join(lines) + "\n"


def default_fleet_path():
    if os.environ.get("ZTR_FLEET_FILE"):
        return Path(os.environ["ZTR_FLEET_FILE"])
    if Path("fleet.conf").is_file():
        return Path("fleet.conf").resolve()
    return CONFIG_DIR / "fleet.conf"


def load_fleet(path):
    try:
        return parse_fleet(Path(path).read_text(encoding="utf-8"))
    except OSError:
        return [], []


def save_fleet(path, servers):
    """Writes the fleet file, keeping the comment lines at the top of the old one."""
    path = Path(path)
    header = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.startswith("#") and not line.lstrip("# ").startswith("name"):
                header.append(line)
            elif line.strip():
                break
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(format_fleet(servers, header or None), encoding="utf-8")
    os.replace(str(tmp), str(path))


def ferry_servers():
    """The saved sites in Ferry as servers (route defaults to the one the tunnel service started with)."""
    try:
        sites = json.loads(FERRY_SITES.read_text(encoding="utf-8")).get("sites", {})
    except (OSError, ValueError):
        return []
    found = []
    for name, s in sites.items():
        safe = re.sub(r"[^A-Za-z0-9._-]", "-", name) or "site"
        found.append(Server(safe, s.get("route") or "route.ztr", s.get("host", ""), s.get("user") or "root",
                            str(s.get("port") or "22"), s.get("key_path") or "", ""))
    return found


def list_routes():
    try:
        return sorted(p.name for p in ROUTES_DIR.glob("*.ztr"))
    except OSError:
        return []


_ROUTE_COUNTRY = {}


def route_country(name):
    """The two-letter code a route's .ztr gives as `exit_country` (the country its exit is in), or ''. Cached per file."""
    try:
        path = ROUTES_DIR / name
        stamp = path.stat().st_mtime
        hit = _ROUTE_COUNTRY.get(name)
        if hit and hit[0] == stamp:
            return hit[1]
        value = json.loads(path.read_text()).get("exit_country")
    except (OSError, ValueError, AttributeError):
        return ""
    code = value.upper() if isinstance(value, str) and re.fullmatch(r"[A-Za-z]{2}", value) else ""
    _ROUTE_COUNTRY[name] = (stamp, code)
    return code


def route_label(name):
    """A route's name for a list: 'US  ·  route.ztr', unless the file name already starts with the country (US_3b983776.ztr)."""
    code = route_country(name) if name else ""
    return f"{code}  ·  {name}" if code and not name.upper().startswith(code + "_") else name


def service_up(port=CONTROL_PORT):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5):
            return True
    except OSError:
        return False


# ── what a command may say, and what is risky ────────────────────────────────

_PLACEHOLDER = re.compile(r"\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}|(?<!\$)\{([A-Za-z_][A-Za-z0-9_]*)\}")


def substitute(text, server):
    """Fills {name}, {alias}, {user}, {port}, {route}, {group} and the server's own variables into `text`.
    {{name}} stays as {name}. Returns (text, [names that aren't defined for this server])."""
    values = server.values()
    missing = []

    def fill(m):
        if m.group(1):
            return "{" + m.group(1) + "}"
        key = m.group(2)
        if key in values:
            return values[key]
        if key not in missing:
            missing.append(key)
        return m.group(0)
    return _PLACEHOLDER.sub(fill, text), missing


DANGER = [
    (r"\brm\s+(-[A-Za-z]*[rR][A-Za-z]*|--recursive)\b", "deletes files recursively (rm -r)"),
    (r"\bmkfs(\.\w+)?\b", "formats a disk (mkfs)"),
    (r"\bdd\b[^|;&]*\bof=/dev/", "writes straight to a disk (dd of=/dev/…)"),
    (r"(^|[;&|]\s*|\bsudo\s+)(shutdown|reboot|poweroff|halt)\b|\binit\s+[06]\b|\bsystemctl\s+(reboot|poweroff|halt)\b", "shuts down or restarts the server"),
    (r":\(\)\s*\{", "looks like a fork bomb"),
    (r">\s*/dev/(sd|nvme|vd|hd)", "overwrites a disk"),
    (r"\bch(mod|own)\s+-R\b[^;&|]*\s/(\s|$)", "changes permissions or owner of everything under /"),
    (r"\bdrop\s+(database|table)\b", "drops a database or table"),
]
NOTICE = [
    (r"\bsystemctl\s+(stop|restart|disable|mask)\b|\bservice\s+\S+\s+(stop|restart)\b", "stops or restarts a service"),
    (r"\b(apt|apt-get|dnf|yum|apk|pacman)\s+(-\S+\s+)*(install|remove|purge|upgrade|dist-upgrade|autoremove)\b", "installs, removes or upgrades packages"),
    (r"\b(kill|pkill|killall)\b", "stops processes"),
    (r"\b(iptables|ufw|nft|firewall-cmd)\b", "changes the firewall"),
    (r"\bsudo\b", "runs with sudo"),
]


def risks(text):
    """([serious reasons], [things worth knowing]) about what a command or script would do."""
    return ([why for pattern, why in DANGER if re.search(pattern, text, re.I)], [why for pattern, why in NOTICE if re.search(pattern, text, re.I)])


# ── running a job ─────────────────────────────────────────────────────────────

# `ztr_forward` hands the command a new tunnel's address as $ZTR_LOCAL_IP / $ZTR_LOCAL_PORT. Every tunnel has a new
# port, so ssh would see a "new host" each time: HostKeyAlias keeps each server's key under its name instead, and a
# key that later changes is refused. The positional arguments are always: 1 name, 2 known_hosts, 3 user,
# 4 what to run (or the remote path), 5 key file, 6 local path.
_SSH_OPTS = ('-o BatchMode=yes -o ConnectTimeout=20 -o LogLevel=ERROR -o HostKeyAlias="$1" -o UserKnownHostsFile="$2" '
             '-o StrictHostKeyChecking=accept-new ${5:+-i "$5" -o IdentitiesOnly=yes}')
INNER = {
    "cmd": 'exec ssh -n ' + _SSH_OPTS + ' -p "$ZTR_LOCAL_PORT" "$3@$ZTR_LOCAL_IP" "$4"',
    "cmd_stdin": 'exec ssh ' + _SSH_OPTS + ' -p "$ZTR_LOCAL_PORT" "$3@$ZTR_LOCAL_IP" "$4"',
    "script": 'exec ssh ' + _SSH_OPTS + ' -p "$ZTR_LOCAL_PORT" "$3@$ZTR_LOCAL_IP" "$4"',
    "put": 'exec scp -q -r -P "$ZTR_LOCAL_PORT" ' + _SSH_OPTS + ' -- "$6" "$3@$ZTR_LOCAL_IP:$4"',
    "get": 'exec scp -q -r -P "$ZTR_LOCAL_PORT" ' + _SSH_OPTS + ' -- "$3@$ZTR_LOCAL_IP:$4" "$6"',
}
INNER["INNER"] = INNER["cmd"]  # (the original single-command form, for callers that only run commands)
NOISE = re.compile(r"^\[ztr_forward\] (requesting tunnel|tunnel ready|ending session)")

# With "send my sudo password": the password goes down ssh's standard input, is read once into a variable, and a
# `sudo` function hands it to sudo only when sudo really needs one (never when the account has a password-free sudo or
# a fresh sudo ticket), so it can't end up in another program's input. It is never in a command line or a file.
SUDO_WRAPPER = ('IFS= read -r ZTR_PW; sudo() { if command sudo -n true 2>/dev/null; then command sudo -n "$@"; '
                'else printf "%s\\n" "$ZTR_PW" | command sudo -S -p "" "$@"; fi; }; eval "$1"')


def sudo_secret(job, server):
    """The sudo password to send to this server: its own if it has one, else the shared one, else ''."""
    return (job.get("sudo_passwords") or {}).get(server.name) or job.get("sudo_password") or ""


def interpreter_for(script_text):
    """How to run a script: from its first line (#!/usr/bin/env python3 → python3), else bash."""
    first = script_text.split("\n", 1)[0]
    if first.startswith("#!"):
        if "python" in first:
            return "python3 -"
        if re.search(r"\b(sh|dash|ash)\b\s*$", first.strip()) and "bash" not in first:
            return "sh -s"
    return "bash -s"


def make_job(kind, **kw):
    """A job to run on every server: command (command=), script (script=path), put (local=, remote=), get (remote=, into=)."""
    job = dict(kind=kind)
    job.update(kw)
    if kind == "script" and "text" not in job:
        job["text"] = Path(job["script"]).read_text(encoding="utf-8")
    return job


def describe_job(job):
    kind = job["kind"]
    if kind == "cmd":
        return job["command"]
    if kind == "script":
        return "script %s" % os.path.basename(job.get("script") or "script")
    if kind == "put":
        return "send %s → %s" % (os.path.basename(job["local"].rstrip("/")), job.get("remote") or "the login folder")
    return "fetch %s → %s" % (job["remote"], job.get("into") or ".")


def job_problems(servers, job):
    """What would stop this job before it starts: [(server name, message)]."""
    found = []
    for s in servers:
        texts = [job.get("command")] if job["kind"] == "cmd" else [job.get("remote")] if job["kind"] in ("put", "get") else []
        for t in texts:
            if t:
                _text, missing = substitute(t, s)
                if missing:
                    found.append((s.name, "no value for {%s} (use {{%s}} to write it literally)" % (", ".join(missing), missing[0])))
    return found


def build_argv(server, job, control_port=CONTROL_PORT, known_hosts=None, forward=None):
    """(the ztr_forward command line, the text to send on standard input or None) for one server."""
    key = os.path.expanduser(server.key) if server.key else ""
    kind, stdin, local = job["kind"], None, ""
    if kind == "cmd":
        command, _ = substitute(job["command"], server)
        secret = sudo_secret(job, server)
        if secret:
            remote = "bash -c %s _ %s" % (shlex.quote(SUDO_WRAPPER), shlex.quote(command))
            stdin, inner = secret + "\n", INNER["cmd_stdin"]
        else:
            remote, inner = command, INNER["cmd"]
    elif kind == "script":
        env = " ".join("%s=%s" % ("ZTR_" + k.upper(), shlex.quote(v)) for k, v in server.values().items())
        remote, stdin, inner = "env %s %s" % (env, job.get("interpreter") or interpreter_for(job["text"])), job["text"], INNER["script"]
    elif kind == "put":
        remote, _ = substitute(job.get("remote") or "", server)
        local, inner = job["local"], INNER["put"]
    else:
        remote, _ = substitute(job["remote"], server)
        local, inner = str(Path(job["into"]) / server.name), INNER["get"]
    argv = [str(forward or FORWARD), "--rh", server.alias, "--rp", str(server.port), "--config-file", server.route,
            "--cp", str(control_port), "--", "bash", "-c", inner, "_", server.name, str(known_hosts or KNOWN_HOSTS),
            server.user, remote, key, local]
    return argv, stdin


def _scrub(text, secrets):
    """Hides any sudo password that a server's output or error happens to repeat."""
    for secret in ([secrets] if isinstance(secrets, str) else secrets):
        if secret and text:
            text = text.replace(secret, "••••")
    return text


def run_job(server, job, timeout, control_port=CONTROL_PORT, procs=None, cancelled=None):
    """One server: a tunnel through its route, then the job through that tunnel. Returns a result dict."""
    started = time.time()
    result = dict(name=server.name, route=server.route, status="failed", rc=1, secs=0, out="", err="", ended=0, attempts=1)
    secret = [job.get("sudo_password") or ""] + list((job.get("sudo_passwords") or {}).values())
    try:
        argv, stdin = build_argv(server, job, control_port)
        if job["kind"] == "get":
            Path(argv[-1]).mkdir(parents=True, exist_ok=True)
        KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, start_new_session=True)
    except OSError as e:
        result.update(err="Couldn't start: %s" % e, rc=127)
        return result
    if procs is not None:
        procs[server.name] = proc
    try:
        out, err = proc.communicate(input=stdin, timeout=timeout)
        rc = proc.returncode
        status = "ok" if rc == 0 else "failed"
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)  # ztr_forward catches this and ends its tunnel session
        except OSError:
            pass
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            out, err = proc.communicate()
        rc, status = 124, "timeout"
    if cancelled is not None and cancelled.is_set() and status != "ok":
        status = "cancelled"
    err = "\n".join(l for l in (err or "").splitlines() if not NOISE.match(l))
    out = (out or "").rstrip("\n")
    if status != "ok" and not err.strip() and not (cancelled is not None and cancelled.is_set()):
        err = ("No answer within %ds." % timeout if status == "timeout" else
               "The connection closed before the server answered (ssh exit 255). The route or the server may be down — try again, or open a shell to see more." if rc == 255 else
               "It stopped with exit code %s and said nothing." % rc)
    if status == "ok" and job["kind"] == "put":
        out = "Sent %s" % os.path.basename(job["local"].rstrip("/"))
    elif status == "ok" and job["kind"] == "get":
        out = "Saved to %s" % argv[-1]
    result.update(status=status, rc=rc, out=_scrub(out, secret), err=_scrub(err.strip(), secret), secs=int(round(time.time() - started)),
                  ended=time.time())
    return result


# ── local scripts that receive each answer ───────────────────────────────────

HOOK_KEEP = 4000   # characters of a script's own output kept with the result


def norm_hook(h):
    """A hook as a dict: path, on, name, only (servers or groups, comma-separated), match (the answer must contain it), failed,
    scope ("each" = once per server with its answer; "all" = once at the end with every answer)."""
    if isinstance(h, str):
        h = dict(path=h)
    return dict(path=str(h["path"]), on=bool(h.get("on", True)), name=str(h.get("name") or ""), only=str(h.get("only") or ""),
                match=str(h.get("match") or ""), failed=bool(h.get("failed", False)),
                scope="all" if h.get("scope") == "all" else "each")


def hook_title(h):
    return h.get("name") or os.path.basename(h["path"])


def load_hooks():
    """The saved local scripts: [dict(path, on, name, only, match, failed)]."""
    try:
        data = json.loads(HOOKS_PATH.read_text(encoding="utf-8"))
        return [norm_hook(h) for h in data if isinstance(h, dict) and h.get("path")]
    except (OSError, ValueError, TypeError):
        return []


def save_hooks(hooks):
    HOOKS_PATH.parent.mkdir(parents=True, exist_ok=True)
    HOOKS_PATH.write_text(json.dumps([norm_hook(h) for h in hooks], indent=1), encoding="utf-8")


def hook_wanted(h, server, result, also_failed=False):
    """Whether this hook should get this server's answer: the server is one it is meant for, the answer says what it
    wants to see, and the server succeeded (or the hook asked for failures too)."""
    h = norm_hook(h)
    if h["scope"] == "all":
        return False
    if result["status"] != "ok" and not ((h["failed"] or also_failed) and result["status"] in ("failed", "timeout")):
        return False
    only = [w.strip() for w in h["only"].split(",") if w.strip()]
    if only and server.name not in only and (not server.group or server.group not in only):
        return False
    if h["match"]:
        text = result["out"]
        try:
            return re.search(h["match"], text, re.I) is not None
        except re.error:
            return h["match"].lower() in text.lower()
    return True


def fix_executable(path):
    """Makes a script runnable by its owner (chmod u+x). True if it worked."""
    try:
        full = os.path.expanduser(path)
        os.chmod(full, os.stat(full).st_mode | 0o100)
        return True
    except OSError:
        return False


def scan_hooks_folder():
    """Scripts in the hooks folder: [path]."""
    try:
        return sorted(str(f) for f in HOOKS_DIR.iterdir() if f.is_file() and not f.name.startswith(".") and not f.name.endswith("~"))
    except OSError:
        return []


HOOK_TEMPLATES = {
    "ips": ("Save the IP addresses in the answer", "ips.sh", """#!/bin/bash
# Fleet runs this once per server, after its answer arrives. The answer is on standard input.
# Called as:  --server NAME --status ok --answer-file PATH --error-file PATH
# Saves every IP address in the answer (one per line, no repeats) next to the server's name.
server="$2"
out="${ZTR_FLEET_OUT:-$HOME/fleet-results}"
mkdir -p "$out"
grep -Eo '[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' | sort -u | sed "s/^/$server /" >> "$out/ips.txt"
echo "saved $(grep -c "^$server " "$out/ips.txt") address(es) for $server in $out/ips.txt"
"""),
    "log": ("Add every answer to a log file", "log_answers.sh", """#!/bin/bash
# Fleet runs this once per server, after its answer arrives. The answer is on standard input.
# Called as:  --server NAME --status ok --answer-file PATH --error-file PATH
# Appends the answer to a log, with the time and the server's name.
server="$2"; status="$4"
out="${ZTR_FLEET_OUT:-$HOME/fleet-results}"
mkdir -p "$out"
{ echo "== $(date '+%Y-%m-%d %H:%M:%S')  $server  [$status]"; cat; echo; } >> "$out/answers.log"
echo "added to $out/answers.log"
"""),
    "file": ("Save each server's answer in its own file", "save_answer.sh", """#!/bin/bash
# Fleet runs this once per server, after its answer arrives. The answer is on standard input.
# Called as:  --server NAME --status ok --answer-file PATH --error-file PATH
# Writes the answer to <results folder>/<server>.txt (replacing the last one).
server="$2"
out="${ZTR_FLEET_OUT:-$HOME/fleet-results}"
mkdir -p "$out"
cat > "$out/$server.txt"
echo "saved $out/$server.txt"
"""),
    "csv": ("Add one line per server to a CSV file", "to_csv.py", """#!/usr/bin/env python3
# Fleet runs this once per server, after its answer arrives. The answer is on standard input.
# Called as:  --server NAME --status ok --answer-file PATH --error-file PATH
# Adds a row: time, server, status, the first line of the answer.
import argparse, csv, os, sys, time

parser = argparse.ArgumentParser()
parser.add_argument("--server"); parser.add_argument("--status")
parser.add_argument("--answer-file"); parser.add_argument("--error-file")
args = parser.parse_args()
answer = sys.stdin.read()          # untrusted text from the server
first = answer.strip().splitlines()[0] if answer.strip() else ""
out = os.environ.get("ZTR_FLEET_OUT") or os.path.expanduser("~/fleet-results")
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "answers.csv"), "a", newline="") as f:
    csv.writer(f).writerow([time.strftime("%Y-%m-%d %H:%M:%S"), args.server, args.status, first])
print("added a row for", args.server)
"""),
    "blank": ("A blank script to start from (Python)", "my_hook.py", """#!/usr/bin/env python3
# Fleet runs this once per server, after its answer arrives.
# The answer is on standard input; the server's values are in ZTR_NAME, ZTR_ALIAS, ZTR_USER, ZTR_GROUP ...
# Called as:  --server NAME --status ok --answer-file PATH --error-file PATH
import argparse, sys

parser = argparse.ArgumentParser()
parser.add_argument("--server"); parser.add_argument("--status")
parser.add_argument("--answer-file"); parser.add_argument("--error-file")
args = parser.parse_args()
answer = sys.stdin.read()          # untrusted text from the server -- never run it or paste it into a command

# Do whatever you like with it here. What you print shows up in Fleet next to the server's answer.
print("%s answered %d line(s)" % (args.server, len(answer.splitlines())))
"""),
}


def create_hook(template, name=None):
    """Writes a starter script into the hooks folder (never over an existing file) and returns its path."""
    _title, filename, body = HOOK_TEMPLATES[template]
    HOOKS_DIR.mkdir(parents=True, exist_ok=True)
    base = re.sub(r"[^A-Za-z0-9._-]", "_", name or filename) or filename
    if "." not in base:
        base += Path(filename).suffix
    path, n = HOOKS_DIR / base, 1
    while path.exists():
        n += 1
        path = HOOKS_DIR / ("%s_%d%s" % (Path(base).stem, n, Path(base).suffix))
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def hook_command(path):
    """(the argv that starts this script, None) or (None, why it can't be started)."""
    full = os.path.expanduser(path)
    if not os.path.isfile(full):
        return None, "%s doesn't exist" % path
    ext = Path(full).suffix.lower()
    if os.access(full, os.X_OK):
        try:
            with open(full, "rb") as f:
                head = f.read(2)
        except OSError:
            head = b""
        if head != b"#!" and ext in (".py", ".sh", ".bash"):  # runnable file with no first line saying how: pick by extension
            return ([sys.executable, full] if ext == ".py" else ["bash", full]), None
        return [full], None
    if ext == ".py":
        return [sys.executable, full], None
    if ext in (".sh", ".bash"):
        return ["bash", full], None
    return None, "%s isn't executable — run: chmod +x %s" % (os.path.basename(path), shlex.quote(path))


def hook_argv(prefix, server, status, answer_file, error_file):
    return prefix + ["--server", server.name, "--status", status, "--answer-file", answer_file, "--error-file", error_file]


NEXT_PREFIX = "FLEET-NEXT "


def parse_followups(text, source="", origin=""):
    """Splits a hook's output into (the text to show, [follow-up proposals]). A hook proposes a next step by printing a
    line:  FLEET-NEXT {"title": "...", "command": "...", "servers": ["web1"]}  (or "group": "web", or "all": true).
    These are only proposals — Fleet shows them for review and never runs one by itself."""
    kept, found = [], []
    for line in text.splitlines():
        if line.startswith(NEXT_PREFIX) and len(found) < 10:
            try:
                d = json.loads(line[len(NEXT_PREFIX):])
                command = str(d["command"]).strip()
                servers = [str(x) for x in d.get("servers", [])] if isinstance(d.get("servers", []), list) else []
                if command and len(command) <= 2000 and (servers or d.get("group") or d.get("all")):
                    found.append(dict(title=str(d.get("title") or command)[:120], command=command, servers=servers,
                                      group=str(d.get("group") or ""), all=bool(d.get("all")), source=source, origin=origin))
                    continue
            except (ValueError, KeyError, TypeError):
                pass
        kept.append(line)
    return "\n".join(kept), found


def collect_followups(results):
    """All follow-up proposals made by hooks in these results, without repeats: [dict(title, command, servers, group, all, source)]."""
    seen, found = set(), []
    for r in results:
        for h in list(r.get("hooks", [])):
            for n in h.get("next", []):
                key = (n["command"], tuple(sorted(n["servers"])), n["group"], n["all"])
                if key not in seen:
                    seen.add(key)
                    found.append(n)
    return found


def followup_targets(proposal, servers):
    """(the servers a follow-up is meant for, [names that aren't in the fleet])."""
    if proposal["all"]:
        return list(servers), []
    by_name = {s.name: s for s in servers}
    chosen = [by_name[n] for n in proposal["servers"] if n in by_name]
    if proposal["group"]:
        chosen += [s for s in servers if s.group == proposal["group"] and s not in chosen]
    return chosen, [n for n in proposal["servers"] if n not in by_name]


def followup_cli(proposal, fleet_file=None):
    """The command line that would run a follow-up."""
    parts = ["ztr_fleet"]
    if fleet_file:
        parts += ["--file", str(fleet_file)]
    if proposal["all"]:
        pass
    elif proposal["group"] and not proposal["servers"]:
        parts += ["--group", proposal["group"]]
    else:
        parts += ["--only", ",".join(proposal["servers"])]
    parts += ["--", proposal["command"]]
    return " ".join(shlex.quote(x) for x in parts)


def _exec_hook(path, extra_args, stdin_text, env, files, name, timeout, source="", origin=""):
    """Starts one hook without a shell, in the script's own folder, with its input as standard input and as files."""
    started = time.time()
    done = dict(name=name, path=path, rc=1, out="", err="", secs=0, next=[])
    prefix, why = hook_command(path)
    if not prefix:
        return dict(done, rc=127, err=why)
    try:
        with tempfile.TemporaryDirectory(prefix="ztr-fleet-") as tmp:
            paths = {}
            for flag, (filename, content) in files.items():
                paths[flag] = os.path.join(tmp, filename)
                Path(paths[flag]).write_text(content, encoding="utf-8")
            argv = prefix + [x if not isinstance(x, tuple) else paths[x[0]] for x in extra_args]
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
                                    cwd=os.path.dirname(os.path.abspath(os.path.expanduser(path))), start_new_session=True)
            try:
                out, err = proc.communicate(input=stdin_text, timeout=timeout)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    pass
                out, err = proc.communicate()
                rc, err = 124, (err or "") + "\nStopped after %ds." % timeout
    except OSError as e:
        return dict(done, rc=127, err="Couldn't start it: %s" % e)
    shown, nxt = parse_followups(out or "", source=name, origin=origin)
    return dict(done, rc=rc, out=shown.strip()[:HOOK_KEEP], err=(err or "").strip()[:HOOK_KEEP], secs=int(round(time.time() - started)), next=nxt)


def run_hook(path, server, result, job, timeout=60, name=None):
    """Runs one local script for one server's answer. The answer is its standard input and a file, and the script is
    started without a shell, so nothing in the answer can be taken for a command. Returns dict(name, path, rc, out, err, secs, next)."""
    env = dict(os.environ)
    env.update({"ZTR_" + k.upper(): v for k, v in server.values().items()})
    env.update(ZTR_SERVER=server.name, ZTR_STATUS=result["status"], ZTR_EXIT=str(result["rc"]), ZTR_COMMAND=describe_job(job))
    args = ["--server", server.name, "--status", result["status"], "--answer-file", ("answer",), "--error-file", ("error",)]
    files = dict(answer=("answer.txt", result["out"] + "\n"), error=("error.txt", (result.get("err") or "") + "\n"))
    return _exec_hook(path, args, result["out"] + "\n", env, files, name or os.path.basename(path), timeout, origin=server.name)


def summary_payload(job, servers, results, started=None):
    """Everything one run produced, as a dict a whole-fleet hook can read as JSON."""
    by_name = {s.name: s for s in servers}
    rows = []
    for r in results:
        s = by_name.get(r["name"])
        rows.append(dict(name=r["name"], status=r["status"], exit=r["rc"], seconds=r["secs"], attempts=r.get("attempts", 1), output=r["out"],
                         error=r.get("err") or "", route=r.get("route", ""), group=s.group if s else "", alias=s.alias if s else "",
                         user=s.user if s else "", variables=dict(s.vars) if s else {}))
    ok = sum(1 for r in rows if r["status"] == "ok")
    skipped = sum(1 for r in rows if r["status"] == "skipped")
    return dict(command=describe_job(job), kind=job["kind"], started=started or time.time(), servers=rows,
                summary=dict(servers=len(rows), ok=ok, failed=len(rows) - ok - skipped, skipped=skipped))


def run_summary_hook(path, payload, timeout=120, name=None):
    """Runs a whole-fleet hook once: all the answers as JSON on standard input and in a file."""
    env = dict(os.environ)
    sm = payload["summary"]
    env.update(ZTR_COMMAND=payload["command"], ZTR_SERVERS=str(sm["servers"]), ZTR_OK=str(sm["ok"]), ZTR_FAILED=str(sm["failed"]))
    text = json.dumps(payload, indent=1)
    args = ["--all", "--servers", str(sm["servers"]), "--ok", str(sm["ok"]), "--failed", str(sm["failed"]), "--results-file", ("results",)]
    return _exec_hook(path, args, text, env, dict(results=("results.json", text)), name or os.path.basename(path), timeout, origin="all")


def batches(servers, batch=0, canary=False):
    """The servers split into rolling batches: all at once when batch is 0; with canary, one server goes first."""
    servers = list(servers)
    if batch <= 0:
        return [servers] if servers else []
    out = []
    if canary and servers:
        out.append(servers[:1])
        servers = servers[1:]
    out += [servers[i:i + batch] for i in range(0, len(servers), batch)]
    return out


class Runner:
    """Runs a job on many servers, at most `jobs` at a time, optionally in rolling batches that stop at the first
    failure, retrying servers that fail. Reports through emit(): ("start", name), ("retry", name, attempt, of),
    ("done", result), ("note", text), ("finished", None)."""

    def __init__(self, servers, job, jobs, timeout, emit, control_port=CONTROL_PORT, work=run_job, batch=0, canary=False,
                 pause=0, stop_on_failure=None, retries=0, retry_wait=5, hooks=(), hook_failed=False):
        self.servers, self.job, self.jobs, self.timeout = list(servers), job, max(1, int(jobs)), int(timeout)
        self.emit, self.control_port, self.work = emit, control_port, work
        self.batch, self.canary, self.pause = int(batch), bool(canary), max(0, float(pause))
        self.stop_on_failure = (self.batch > 0) if stop_on_failure is None else bool(stop_on_failure)
        self.retries, self.retry_wait = max(0, int(retries)), max(0, float(retry_wait))
        self.hooks, self.hook_failed = [norm_hook(h) for h in hooks], bool(hook_failed)
        self.summary = []
        self.procs, self.cancelled = {}, threading.Event()
        self.results = {}

    @property
    def command(self):  # (what the window shows as "the command")
        return describe_job(self.job)

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _result(self, server, status, why=""):
        return dict(name=server.name, route=server.route, status=status, rc=1, secs=0, out="", err=why, ended=time.time(), attempts=0)

    def _wait(self, seconds):
        """Sleeps, but wakes up at once if the run is cancelled. True when it slept the whole time."""
        return not self.cancelled.wait(seconds)

    def _one(self, server, slots):
        with slots:
            attempts = self.retries + 1
            result = None
            for n in range(1, attempts + 1):
                if self.cancelled.is_set():
                    result = result or self._result(server, "cancelled")
                    break
                self.emit(("start", server.name))
                result = self.work(server, self.job, self.timeout, self.control_port, self.procs, self.cancelled)
                result["attempts"] = n
                if result["status"] not in ("failed", "timeout") or n == attempts:
                    break
                self.emit(("retry", server.name, n + 1, attempts))
                if not self._wait(self.retry_wait):
                    break
        if self.hooks and not self.cancelled.is_set():
            wanted = [h for h in self.hooks if hook_wanted(h, server, result, self.hook_failed)]
            if wanted:
                result["hooks"] = [run_hook(h["path"], server, result, self.job, name=hook_title(h)) for h in wanted]
        self.results[server.name] = result
        self.emit(("done", result))

    def _run(self):
        plan = batches(self.servers, self.batch, self.canary)
        stopped_by = None
        for index, group in enumerate(plan):
            if self.cancelled.is_set() or stopped_by:
                for s in group:
                    r = self._result(s, "cancelled" if self.cancelled.is_set() else "skipped",
                                     "" if self.cancelled.is_set() else "Not run: stopped after %s did not succeed" % stopped_by)
                    self.results[s.name] = r
                    self.emit(("done", r))
                continue
            if len(plan) > 1:
                self.emit(("note", "Batch %d of %d: %s" % (index + 1, len(plan), ", ".join(s.name for s in group))))
            slots = threading.Semaphore(self.jobs)
            threads = [threading.Thread(target=self._one, args=(s, slots), daemon=True) for s in group]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            failed = [s.name for s in group if self.results.get(s.name, {}).get("status") != "ok"]
            if failed and self.stop_on_failure and index < len(plan) - 1 and not self.cancelled.is_set():
                stopped_by = failed[0]
                self.emit(("note", "Stopping: %s did not succeed" % failed[0]))
            elif index < len(plan) - 1 and self.pause and not self.cancelled.is_set():
                self.emit(("note", "Waiting %ds before the next batch" % self.pause))
                self._wait(self.pause)
        wide = [h for h in self.hooks if h["scope"] == "all"]
        self.summary = []
        if wide and not self.cancelled.is_set():
            ordered = [self.results[x.name] for x in self.servers if x.name in self.results]
            for h in wide:
                only = [w.strip() for w in h["only"].split(",") if w.strip()]
                rows = [r for r in ordered if not only or r["name"] in only or next((x.group for x in self.servers if x.name == r["name"]), "") in only]
                payload = summary_payload(self.job, self.servers, rows)
                self.summary.append(run_summary_hook(h["path"], payload, name=hook_title(h)))
            self.emit(("summary", self.summary))
        self.emit(("finished", None))

    def cancel(self):
        self.cancelled.set()
        for proc in list(self.procs.values()):
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except OSError:
                    pass


def group_outputs(results, ignore_numbers=False):
    """Servers that answered the same way, together, biggest group first: [dict(text, members, ok, status)]."""
    groups = {}
    for r in results:
        if r["status"] != "ok":
            key = ("!" + r["status"], (r.get("err") or "").strip()[-200:])
            text = r.get("err") or ""
        else:
            text = r["out"].strip()
            key = ("ok", re.sub(r"\d+", "#", text) if ignore_numbers else text)
        g = groups.setdefault(key, dict(text=text, members=[], ok=r["status"] == "ok", status=r["status"]))
        g["members"].append(r["name"])
    return sorted(groups.values(), key=lambda g: (-len(g["members"]), g["members"][0]))


# ── a shell on one server ─────────────────────────────────────────────────────

def shell_argv(server, control_port=CONTROL_PORT, ztr_ssh=None):
    """The ztr_ssh command line that opens an interactive session on one server."""
    argv = [str(ztr_ssh or SSH_WRAPPER)]
    if server.user:
        argv += ["-l", server.user]
    if server.key:
        argv += ["-i", os.path.expanduser(server.key), "-o", "IdentitiesOnly=yes"]
    argv += ["-o", "HostKeyAlias=" + server.name, "-o", "UserKnownHostsFile=" + str(KNOWN_HOSTS), "-o", "StrictHostKeyChecking=accept-new",
             "--rh", server.alias, "--rp", str(server.port), "--config-file", server.route, "--cp", str(control_port)]
    return argv


TERMINALS = [  # (program, how it takes a title, how it takes the command to run)
    ("lxterminal", ["-t", "{title}"], ["-e"]), ("gnome-terminal", ["--title", "{title}"], ["--"]),
    ("xfce4-terminal", ["--title", "{title}"], ["-x"]), ("mate-terminal", ["--title", "{title}"], ["-x"]),
    ("konsole", [], ["-e"]), ("kitty", ["--title", "{title}"], []), ("alacritty", ["--title", "{title}"], ["-e"]),
    ("foot", ["--title", "{title}"], []), ("xterm", ["-T", "{title}"], ["-e"]), ("x-terminal-emulator", [], ["-e"]),
]


def terminal_argv(argv, title="ZTR Fleet"):
    """The command line that opens a terminal window running argv (and waits for Enter before closing); None if there
    is no terminal program. FLEET_TERMINAL (for example "xterm -e") overrides the search."""
    inner = ["sh", "-c", '"$@"; code=$?; echo; echo "[ztr_fleet] session ended (exit $code). Press Enter to close this window."; read _', "sh"] + list(argv)
    forced = os.environ.get("FLEET_TERMINAL", "").strip()
    if forced:
        return shlex.split(forced) + inner
    if sys.platform == "darwin":
        osascript = shutil.which("osascript")
        if not osascript:
            return None
        command = " ".join(shlex.quote(a) for a in inner).replace("\\", "\\\\").replace('"', '\\"')
        return [osascript, "-e", 'tell application "Terminal"\nactivate\ndo script "%s"\nend tell' % command]
    for program, title_args, run_args in TERMINALS:
        path = shutil.which(program)
        if path:
            return [path] + [a.replace("{title}", title) for a in title_args] + run_args + inner
    return None


# ── saved commands and history ───────────────────────────────────────────────

def load_snippets():
    try:
        mine = json.loads(SNIPPETS_PATH.read_text(encoding="utf-8"))
        mine = [(str(a), str(b)) for a, b in mine]
    except (OSError, ValueError, TypeError):
        mine = []
    names = {a for a, _b in mine}
    return mine + [s for s in DEFAULT_SNIPPETS if s[0] not in names]


def save_snippet(name, command):
    try:
        mine = [(a, b) for a, b in json.loads(SNIPPETS_PATH.read_text(encoding="utf-8")) if a != name]
    except (OSError, ValueError, TypeError):
        mine = []
    mine.insert(0, (name, command))
    SNIPPETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNIPPETS_PATH.write_text(json.dumps(mine, indent=1), encoding="utf-8")


def load_history():
    try:
        data = json.loads(HISTORY_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def add_history(command, results, jobs, timeout, kind="cmd", source=""):
    entry = dict(ts=time.time(), command=command, kind=kind, jobs=jobs, timeout=timeout, source=source,
                 results=[dict(name=r["name"], status=r["status"], rc=r["rc"], secs=r["secs"], route=r.get("route", ""),
                               out=r["out"][:OUTPUT_KEEP], err=(r.get("err") or "")[:1500], attempts=r.get("attempts", 1),
                               hooks=[dict(name=h["name"], rc=h["rc"]) for h in r.get("hooks", [])]) for r in results])
    data = [entry] + load_history()
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(data[:HISTORY_LIMIT]), encoding="utf-8")
    try:
        os.chmod(str(HISTORY_PATH), 0o600)  # the answers can hold anything a command printed
    except OSError:
        pass
    return entry


def results_text(command, results):
    """A plain-text report, for copying."""
    lines = ["$ " + command, ""]
    for r in results:
        lines.append("== %s  [%s]  %ss" % (r["name"], "ok" if r["status"] == "ok" else r["status"] + " (exit %s)" % r["rc"], r["secs"]))
        lines.append(r["out"] if r["status"] == "ok" else (r.get("err") or r["out"]))
        lines.append("")
    return "\n".join(lines)


# Pretend servers for --demo and for trying the window without contacting anything.
DEMO_SERVERS = [
    Server("web1", "web.ztr", "web1._ztr", "deploy", "22", "", "web", {"env": "prod"}),
    Server("web2", "web.ztr", "web2._ztr", "deploy", "22", "", "web", {"env": "prod"}),
    Server("web3", "eu.ztr", "web3._ztr", "deploy", "22", "", "web", {"env": "staging"}),
    Server("db1", "data.ztr", "db1._ztr", "deploy", "22", "~/.ssh/id_db", "data"),
    Server("db2", "data.ztr", "db2._ztr", "deploy", "22", "", "data"),
    Server("edge-eu", "eu.ztr", "edge-eu._ztr", "root", "2222", "", "edge"),
    Server("edge-us", "us.ztr", "edge-us._ztr", "root", "22", "", "edge"),
    Server("backup", "data.ztr", "backup._ztr", "root", "22", "", ""),
]


def demo_work(server, job, timeout, control_port=CONTROL_PORT, procs=None, cancelled=None):
    import random
    command = describe_job(job)
    rnd = random.Random(hash((server.name, command)) & 0xffff)
    delay = 1.0 + rnd.random() * 3.5
    t0 = time.time()
    while time.time() - t0 < delay:
        if cancelled is not None and cancelled.is_set():
            break
        time.sleep(0.1)
    secs = int(round(time.time() - t0))
    base = dict(name=server.name, route=server.route, secs=secs, ended=time.time(), attempts=1)
    if cancelled is not None and cancelled.is_set():
        return dict(base, status="cancelled", rc=1, out="", err="")
    if server.name == "edge-us":
        return dict(base, status="failed", rc=255, out="", err="ssh: connect to host 10.10.15.10 port 41022: Connection refused")
    if server.name == "backup":
        return dict(base, status="timeout", rc=124, secs=timeout, out="", err="Terminated")
    host, kind = server.name, job["kind"]
    if kind == "put":
        return dict(base, status="ok", rc=0, out="Sent %s" % os.path.basename(job["local"].rstrip("/")), err="")
    if kind == "get":
        return dict(base, status="ok", rc=0, out="Saved to %s" % (Path(job["into"]) / host), err="")
    c = (job.get("command") or "").strip() if kind == "cmd" else ""
    if kind == "script":
        out = "[%s] %s done\nenv=%s" % (host, os.path.basename(job.get("script") or "script"), server.vars.get("env", "-"))
    elif c.startswith("uptime"):
        up = {"web1": "12 days", "web2": "12 days", "web3": "12 days", "db1": "81 days", "db2": "81 days", "edge-eu": "3 days"}.get(host, "1 day")
        out = " %02d:%02d:%02d up %s, %d users,  load average: %.2f, %.2f, %.2f" % (
            rnd.randint(0, 23), rnd.randint(0, 59), rnd.randint(0, 59), up, rnd.randint(0, 3), rnd.random(), rnd.random(), rnd.random())
    elif c.startswith("df"):
        out = "/dev/vda1  80G  %dG  %dG  %d%% /" % (rnd.randint(20, 60), rnd.randint(20, 55), rnd.randint(25, 75))
    elif c.startswith("uname"):
        out = "Linux 6.8.0-%d-generic" % (45 if host != "web3" else 41)
    elif c == "true":
        out = ""
    else:
        out = "%s: %s" % (host, substitute(c, server)[0][:60])
    return dict(base, status="ok", rc=0, out=out, err="")


# ── saved jobs and schedules ─────────────────────────────────────────────────

DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
DEFAULT_OPTS = dict(jobs=4, timeout=60, batch=0, canary=False, stop=False, pause=0, retries=0)


def norm_schedule(sc):
    """A schedule as a dict: every N minutes (kind 'every', minutes), daily (kind 'daily', at 'HH:MM') or weekly (kind 'weekly', day, at)."""
    sc = dict(sc or {})
    kind = sc.get("kind", "daily")
    at = str(sc.get("at") or "03:00")
    m = re.match(r"^(\d{1,2}):(\d{2})$", at)
    if not m or int(m.group(1)) > 23 or int(m.group(2)) > 59:
        at = "03:00"
    else:
        at = "%02d:%s" % (int(m.group(1)), m.group(2))
    if kind == "every":
        return dict(kind="every", minutes=max(1, min(int(sc.get("minutes") or 60), 7 * 24 * 60)))
    if kind == "weekly":
        day = str(sc.get("day") or "mon").lower()[:3]
        return dict(kind="weekly", day=day if day in DAYS else "mon", at=at)
    return dict(kind="daily", at=at)


def describe_schedule(sc):
    sc = norm_schedule(sc)
    if sc["kind"] == "every":
        n = sc["minutes"]
        return "every %d minutes" % n if n < 60 or n % 60 else ("every hour" if n == 60 else "every %d hours" % (n // 60))
    if sc["kind"] == "weekly":
        return "every %s at %s" % (sc["day"].capitalize(), sc["at"])
    return "every day at %s" % sc["at"]


def on_calendar(sc):
    """The systemd OnCalendar= text for a schedule."""
    sc = norm_schedule(sc)
    if sc["kind"] == "every":
        n = sc["minutes"]
        return "*:0/%d" % n if n < 60 else ("hourly" if n == 60 else "*-*-* 0/%d:00:00" % (n // 60) if n % 60 == 0 and n < 24 * 60 else "daily")
    hh, mm = sc["at"].split(":")
    if sc["kind"] == "weekly":
        return "%s *-*-* %s:%s:00" % (sc["day"].capitalize(), hh, mm)
    return "*-*-* %s:%s:00" % (hh, mm)


def norm_saved_job(j):
    """A saved job: what to run (mode cmd/script, command or script path), where (servers list, group or all), how (opts),
    which hooks (the saved ones that are switched on, or none), when (sched) and which fleet file."""
    opts = dict(DEFAULT_OPTS)
    opts.update({k: j.get("opts", {}).get(k, v) for k, v in DEFAULT_OPTS.items()})
    return dict(name=str(j["name"]), mode="script" if j.get("mode") == "script" else "cmd", command=str(j.get("command") or ""),
                script=str(j.get("script") or ""), servers=[str(x) for x in j.get("servers", [])], group=str(j.get("group") or ""),
                all=bool(j.get("all")), opts=opts, hooks="saved" if j.get("hooks") == "saved" else "none",
                sched=norm_schedule(j.get("sched")), on=bool(j.get("on", True)), file=str(j.get("file") or ""))


def saved_job_problems(j):
    found = []
    if not NAME_RE.match(j["name"] or ""):
        found.append("The name may only use letters, digits, . _ -")
    if j["mode"] == "cmd" and not j["command"].strip():
        found.append("There's no command to run")
    if j["mode"] == "script" and not os.path.isfile(os.path.expanduser(j["script"])):
        found.append("The script %s doesn't exist" % (j["script"] or "(none chosen)"))
    if not (j["servers"] or j["group"] or j["all"]):
        found.append("Choose which servers it runs on")
    return found


def load_saved_jobs():
    try:
        data = json.loads(JOBS_PATH.read_text(encoding="utf-8"))
        return [norm_saved_job(j) for j in data if isinstance(j, dict) and j.get("name")]
    except (OSError, ValueError, TypeError, KeyError):
        return []


def save_saved_jobs(jobs):
    JOBS_PATH.parent.mkdir(parents=True, exist_ok=True)
    JOBS_PATH.write_text(json.dumps([norm_saved_job(j) for j in jobs], indent=1), encoding="utf-8")


def saved_job_servers(j, servers):
    """The servers a saved job runs on, and the names it lists that are gone from the fleet file."""
    if j["all"]:
        return list(servers), []
    by_name = {s.name: s for s in servers}
    chosen = [by_name[n] for n in j["servers"] if n in by_name]
    chosen += [s for s in servers if j["group"] and s.group == j["group"] and s not in chosen]
    return chosen, [n for n in j["servers"] if n not in by_name]


LAUNCHER = Path(SCRIPT_DIR) / "ztr_fleet"
UNIT_DIR = Path.home() / ".config" / "systemd" / "user"
LAUNCHD_DIR = Path.home() / "Library" / "LaunchAgents"


def unit_slug(name):
    return "ztr-fleet-" + re.sub(r"[^A-Za-z0-9_-]", "-", name)


def launchd_label(name):
    return "com.ztrelay.fleet." + re.sub(r"[^A-Za-z0-9_-]", "-", name)


def job_log_path(name):
    """Where a scheduled job's output goes on macOS (launchd keeps nothing by itself)."""
    return CONFIG_DIR / "logs" / (re.sub(r"[^A-Za-z0-9_-]", "-", name) + ".log")


LOG_KEEP_BYTES = 128 * 1024
LOG_TRIM_ABOVE = 512 * 1024


def trim_log(path):
    """Keeps a job's log from growing for ever: past 512 KB only the newest 128 KB stay."""
    try:
        if not path or os.path.getsize(path) <= LOG_TRIM_ABOVE:
            return
        with open(path, "r+b") as f:
            f.seek(-LOG_KEEP_BYTES, os.SEEK_END)
            tail = f.read()
            tail = tail[tail.find(b"\n") + 1:]
            f.seek(0)
            f.write(tail)
            f.truncate()
    except OSError:
        pass


# macOS keeps background jobs (anything launchd starts) out of these folders unless the program has been given access
# in System Settings, so a schedule whose files live there is stopped before it starts ("Operation not permitted").
MAC_PROTECTED = ("Downloads", "Desktop", "Documents")


def macos_blocked_folder(path):
    """The protected folder (Downloads, Desktop, Documents, iCloud Drive) `path` is inside, or None. macOS only."""
    if sys.platform != "darwin" or not path:
        return None
    try:
        p = Path(path).expanduser().resolve()
        home = Path.home().resolve()
    except OSError:
        return None
    for name in MAC_PROTECTED:
        try:
            p.relative_to(home / name)
            return name
        except ValueError:
            pass
    try:
        p.relative_to(home / "Library" / "Mobile Documents")
        return "iCloud Drive"
    except ValueError:
        return None


def blocked_client_message(folder):
    return ("macOS doesn't let background jobs read your %s folder, so a schedule can't start from here: ZTR Fleet is in %s. "
            "Move the client folder out of Downloads, Desktop and Documents (for example to ~/ztrclient) and set the schedule again."
            % (folder, folder))


def schedule_problem(j):
    """A sentence saying why this job's schedule can't run on this computer, or None. Only macOS has such a case: a
    background job can't read Downloads, Desktop or Documents."""
    if sys.platform != "darwin":
        return None
    folder = macos_blocked_folder(LAUNCHER)
    if folder:
        return blocked_client_message(folder)
    for what, path in (("the fleet file", j.get("file")), ("the script", j.get("script") if j.get("mode") == "script" else None)):
        folder = macos_blocked_folder(path)
        if folder:
            return ("%s (%s) is in your %s folder, which macOS doesn't let background jobs read. Move it somewhere else, such as your "
                    "home folder, and save the job again." % (what[0].upper() + what[1:], path, folder))
    return None


def timer_files(j, launcher=None):
    """(the .service text, the .timer text) that run a saved job on its schedule — a systemd user timer."""
    launcher = str(launcher or LAUNCHER)
    env = "Environment=ZTR_FLEET_HOME=%s\n" % CONFIG_DIR if os.environ.get("ZTR_FLEET_HOME") else ""
    service = ("[Unit]\nDescription=ZTR Fleet job %s\n\n[Service]\nType=oneshot\n%sExecStart=%s --run-job %s\n" %
               (j["name"], env, shlex.quote(launcher), shlex.quote(j["name"])))
    timer = ("[Unit]\nDescription=ZTR Fleet job %s (%s)\n\n[Timer]\nOnCalendar=%s\nPersistent=false\nUnit=%s.service\n\n[Install]\nWantedBy=timers.target\n" %
             (j["name"], describe_schedule(j["sched"]), on_calendar(j["sched"]), unit_slug(j["name"])))
    return service, timer


def launchd_plist(j, launcher=None):
    """The launchd agent (macOS) that runs a saved job on its schedule."""
    import plistlib
    sc = norm_schedule(j["sched"])
    log = str(job_log_path(j["name"]))
    plist = dict(Label=launchd_label(j["name"]), ProgramArguments=[str(launcher or LAUNCHER), "--run-job", j["name"]],
                 RunAtLoad=False, StandardOutPath=log, StandardErrorPath=log)
    home = str(Path.home())
    # launchd starts jobs with only /usr/bin:/bin:/usr/sbin:/sbin, which has neither Homebrew nor ~/.local/bin
    env = dict(PATH=":".join([home + "/.local/bin", "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]),
               ZTR_FLEET_LOG=log)
    if CONFIG_DIR != Path.home() / ".config" / "ztr_fleet":
        env["ZTR_FLEET_HOME"] = str(CONFIG_DIR)
    plist["EnvironmentVariables"] = env
    if sc["kind"] == "every":
        plist["StartInterval"] = sc["minutes"] * 60
    else:
        hh, mm = (int(x) for x in sc["at"].split(":"))
        when = dict(Hour=hh, Minute=mm)
        if sc["kind"] == "weekly":
            when["Weekday"] = (DAYS.index(sc["day"]) + 1) % 7  # launchd: 0 or 7 is Sunday
        plist["StartCalendarInterval"] = when
    return plistlib.dumps(plist)


def _systemctl(*args):
    r = subprocess.run(["systemctl", "--user"] + list(args), capture_output=True, text=True, timeout=30)
    return r.returncode, (r.stdout + r.stderr).strip()


def schedule_available():
    """None when this computer can run scheduled jobs, else a sentence saying why not."""
    if sys.platform == "darwin":
        if not shutil.which("launchctl"):
            return "launchctl wasn't found."
        folder = macos_blocked_folder(LAUNCHER)
        return blocked_client_message(folder) if folder else None
    if not shutil.which("systemctl"):
        return "Scheduling needs systemd (systemctl wasn't found)."
    try:
        code, text = _systemctl("show-environment")
    except (OSError, subprocess.TimeoutExpired):
        return "systemd's user services aren't reachable here."
    return None if code == 0 else "systemd's user services aren't running for this login (%s)." % (text.splitlines() or ["no answer"])[0]


def install_schedule(j):
    """Turns a saved job's schedule on. Returns (True, message) or (False, why not)."""
    try:
        if sys.platform == "darwin":
            why = schedule_problem(j)
            if why:
                return False, why
            LAUNCHD_DIR.mkdir(parents=True, exist_ok=True)
            job_log_path(j["name"]).parent.mkdir(parents=True, exist_ok=True)
            path = LAUNCHD_DIR / ("com.ztrelay.fleet.%s.plist" % re.sub(r"[^A-Za-z0-9_-]", "-", j["name"]))
            path.write_bytes(launchd_plist(j))
            subprocess.run(["launchctl", "bootout", "gui/%d" % os.getuid(), str(path)], capture_output=True)
            r = subprocess.run(["launchctl", "bootstrap", "gui/%d" % os.getuid(), str(path)], capture_output=True, text=True)
            return (r.returncode == 0, "Scheduled with launchd." if r.returncode == 0 else (r.stderr.strip() or "launchctl failed"))
        UNIT_DIR.mkdir(parents=True, exist_ok=True)
        service, timer = timer_files(j)
        (UNIT_DIR / (unit_slug(j["name"]) + ".service")).write_text(service, encoding="utf-8")
        (UNIT_DIR / (unit_slug(j["name"]) + ".timer")).write_text(timer, encoding="utf-8")
        _systemctl("daemon-reload")
        code, text = _systemctl("enable", "--now", unit_slug(j["name"]) + ".timer")
        return (code == 0, "Scheduled with a systemd timer." if code == 0 else text)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def remove_schedule(name):
    """Turns a job's schedule off and removes its timer files."""
    try:
        if sys.platform == "darwin":
            path = LAUNCHD_DIR / ("com.ztrelay.fleet.%s.plist" % re.sub(r"[^A-Za-z0-9_-]", "-", name))
            subprocess.run(["launchctl", "bootout", "gui/%d" % os.getuid(), str(path)], capture_output=True)
            path.unlink(missing_ok=True)
            return True
        _systemctl("disable", "--now", unit_slug(name) + ".timer")
        for suffix in (".timer", ".service"):
            (UNIT_DIR / (unit_slug(name) + suffix)).unlink(missing_ok=True)
        _systemctl("daemon-reload")
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _launchd_state(name):
    """(runs, last exit code or None) from launchd for a job's agent, or None when it isn't loaded."""
    r = subprocess.run(["launchctl", "print", "gui/%d/%s" % (os.getuid(), launchd_label(name))], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        return None
    runs = re.search(r"\bruns = (\d+)", r.stdout)
    code = re.search(r"last exit code = (-?\d+)", r.stdout)
    return (int(runs.group(1)) if runs else 0), (int(code.group(1)) if code else None)


def start_problem(name, runs, code):
    """A sentence for a macOS job that launchd started but that never got going, or None."""
    if not runs or code not in (126, 127):
        return None
    try:
        log = job_log_path(name).read_text(errors="replace")[-4000:]
    except OSError:
        log = ""
    folder = macos_blocked_folder(LAUNCHER)
    if folder or "Operation not permitted" in log:
        return ("macOS stopped it before it started (exit %d). Background jobs can't read your %s folder, and ZTR Fleet is there. "
                "Move the client folder out of Downloads, Desktop and Documents (for example to ~/ztrclient) and set the schedule again."
                % (code, folder or "Downloads, Desktop or Documents"))
    if code == 127:
        return "It couldn't start: a command it needs wasn't found (exit 127). The log shows which."
    return "It couldn't start (exit 126, usually a permissions problem). The log shows the reason."


def schedule_status(name):
    """dict(active, next, last, problem, runs, log) for a job's timer — next and last are 'YYYY-MM-DD HH:MM' or ''.
    `problem` is a sentence when the schedule is on but can't get going (macOS), else ''."""
    out = dict(active=False, next="", last="", problem="", runs=0, log="")
    try:
        if sys.platform == "darwin":
            path = LAUNCHD_DIR / ("com.ztrelay.fleet.%s.plist" % re.sub(r"[^A-Za-z0-9_-]", "-", name))
            out["active"] = path.is_file()
            out["log"] = str(job_log_path(name)) if job_log_path(name).is_file() else ""
            if out["active"]:
                state = _launchd_state(name)
                if state is None:
                    out["problem"] = "The schedule file is there but launchd hasn't loaded it. Pause the job and resume it."
                else:
                    out["runs"] = state[0]
                    out["problem"] = start_problem(name, state[0], state[1]) or ""
            return out
        code, text = _systemctl("show", unit_slug(name) + ".timer", "-p", "ActiveState", "-p", "NextElapseUSecRealtime", "-p", "LastTriggerUSec")
    except (OSError, subprocess.TimeoutExpired):
        return out
    for line in text.splitlines():
        key, _eq, value = line.partition("=")
        if key == "ActiveState":
            out["active"] = value == "active"
        elif key == "NextElapseUSecRealtime" and value and value != "n/a":
            out["next"] = value.split(" ", 1)[1][:16] if " " in value else value
        elif key == "LastTriggerUSec" and value and value != "n/a":
            out["last"] = value.split(" ", 1)[1][:16] if " " in value else value
    return out


# ── the command line ──────────────────────────────────────────────────────────

EXAMPLE = """\
# name    route file     alias (--rh)       user     ssh port (default 22)   options (group=NAME key=PATH, or your own NAME=value)
web1      web.ztr        web1._ztr          deploy   22                      group=web env=prod
db1       data.ztr       db1._ztr           deploy   -                       group=data key=~/.ssh/id_db
edge-eu   eu.ztr         edge-eu._ztr       root     2222
"""

EPILOG = """\
The fleet file lists one server per line (see --example): name, route file, alias, user, ssh port, then options —
group=NAME (for --group), key=PATH (an ssh key for that server) and your own NAME=value, which a command can use as
{NAME}. A command can also use {name}, {alias}, {user}, {port}, {route} and {group}; write {{name}} to keep the braces.
It is read from ./fleet.conf if that exists, otherwise ~/.config/ztr_fleet/fleet.conf ($ZTR_FLEET_FILE or --file
choose another).

--hook SCRIPT runs a local script after each server's answer arrives (for instance to save the IPs from `ufw status`). The
answer is the script's standard input and also a file; the script is started without a shell, with --server NAME,
--status ok|failed|timeout, --answer-file PATH and --error-file PATH, and the server's values in ZTR_NAME, ZTR_ALIAS …
Treat the answer as untrusted text: a server can print anything.

Each result is printed as soon as that server finishes (--ordered waits and prints them in file order). The exit code is
0 when every server succeeded, 1 when any did not, and 2 when the fleet file, the options or the setup are wrong.

Needs the tunnel service running (see ztr_ssh), each route file in routes/, and ssh key login (an agent or a key in
~/.ssh) — nothing here can type a password, except --ask-sudo and --sudo-each, which send a sudo password (one for all, or one per
server) over ssh and keep it nowhere. Options go before the command.
"""


class Palette:
    def __init__(self, stream):
        on = hasattr(stream, "isatty") and stream.isatty()
        self.ok, self.bad, self.warn, self.dim, self.off = ("\033[0;32m", "\033[0;31m", "\033[0;33m", "\033[2m", "\033[0m") if on else ("", "", "", "", "")


def _err(text):
    c = Palette(sys.stderr)
    print("%s[ztr_fleet] %s%s" % (c.bad, text, c.off), file=sys.stderr)


def build_parser():
    p = argparse.ArgumentParser(prog="ztr_fleet", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
                                description="Run a command, a script or a file transfer on several servers at once, each through its own ZTRelay route.",
                                usage="ztr_fleet [options] COMMAND...\n       ztr_fleet [options] --script FILE | --put FILE [--to PATH] | --get PATH [--into DIR]\n"
                                      "       ztr_fleet --shell NAME | --check | --example | --gui")
    a = p.add_argument
    a("--file", help="the fleet file")
    a("--only", help="only these servers (comma-separated names)")
    a("--group", help="only the servers in this group")
    a("--jobs", type=int, default=4, help="servers contacted at the same time (default 4)")
    a("--timeout", type=int, default=60, help="seconds each server may take, tunnel included (default 60)")
    a("--cp", type=int, default=CONTROL_PORT, help="the tunnel service's control port (default 2223)")
    a("--script", metavar="FILE", help="run this local script on every server instead of a command")
    a("--put", metavar="FILE", help="send this file or folder to every server")
    a("--to", metavar="PATH", default="", help="with --put: where on the server (default: the login folder)")
    a("--get", metavar="PATH", help="fetch this file or folder from every server")
    a("--into", metavar="DIR", default="fleet-files", help="with --get: a folder to save into, one subfolder per server (default fleet-files)")
    a("--batch", type=int, default=0, help="roll out N servers at a time, stopping at the first failure")
    a("--canary", action="store_true", help="with --batch: run on one server first, and go on only if it succeeds")
    a("--pause", type=float, default=0, help="with --batch: seconds to wait between batches")
    a("--keep-going", action="store_true", help="with --batch: carry on even if a server fails")
    a("--retries", type=int, default=0, help="try a failed server again, up to N more times")
    a("--retry-wait", type=float, default=5, help="seconds between tries (default 5)")
    a("--ask-sudo", action="store_true", help="ask for your sudo password once and send it to sudo on each server")
    a("--sudo-each", action="store_true", help="ask for a sudo password for each server (Enter keeps the shared one from --ask-sudo, or none)")
    a("--hook", action="append", default=[], metavar="SCRIPT", help="after each server's answer, run this local script (repeatable); it gets "
                                                                       "the answer on standard input and --server NAME --status S --answer-file F --error-file F")
    a("--hook-all", action="append", default=[], metavar="SCRIPT", help="after the whole run, run this local script once; it gets every answer as JSON "
                                                                          "(on standard input and in --results-file)")
    a("--run-job", metavar="NAME", help="run a saved job (made in the window with Schedule…) exactly as saved; this is what a schedule calls")
    a("--list-jobs", action="store_true", help="list the saved jobs and their schedules")
    a("--saved-hooks", action="store_true", help="also run the scripts switched on in the window's hook list, with their filters")
    a("--hook-failed", action="store_true", help="also run the --hook scripts for servers that did not succeed")
    a("--yes", action="store_true", help="don't ask before a command that looks destructive")
    a("--dry-run", action="store_true", help="show what would run where, and connect to nothing")
    a("--ordered", action="store_true", help="print the results in the fleet file's order, once all are done")
    a("--out", metavar="DIR", help="also save every server's output in this folder, one file each")
    a("--json", action="store_true", help="print one JSON line per server as it finishes, then a summary line")
    a("--shell", metavar="NAME", help="open an interactive session on one server")
    a("--check", action="store_true", help="look over the fleet file and the tunnel service; connect to nothing")
    a("--example", action="store_true", help="print a sample fleet file")
    a("--gui", action="store_true", help="open the window")
    a("command", nargs=argparse.REMAINDER)
    return p


def _select(args):
    """Reads the fleet file and applies --only/--group. Returns (selected servers, all servers, problem count)."""
    path = Path(args.file) if args.file else default_fleet_path()
    if not path.is_file():
        _err("no fleet file at %s" % path)
        print("  Create one (ztr_fleet --example shows the format), or point to it with --file.", file=sys.stderr)
        return None, None, 1
    servers, lines = load_fleet(path)
    problems = 0
    for number, message in lines:
        _err("%s:%d: %s" % (path, number, message))
        problems += 1
    for s in servers:
        for message in s.problems(ROUTES_DIR):
            _err("%s: %s: %s" % (path, s.name, message))
            problems += 1
    only = {n.strip() for n in args.only.split(",") if n.strip()} if args.only else None
    chosen = [s for s in servers if (only is None or s.name in only) and (not args.group or s.group == args.group)]
    if problems:
        return None, servers, problems
    if only is not None or args.group:
        if not chosen:
            _err("no server matches %s%s in %s" % ("--only %s" % args.only if only else "", (" --group %s" % args.group) if args.group else "", path))
            return None, servers, 1
        missing = sorted(only - {s.name for s in servers}) if only else []
        if missing:
            _err("not in %s: %s" % (path, ", ".join(missing)))
            return None, servers, 1
    elif not chosen:
        _err("%s doesn't list any servers" % path)
        return None, servers, 1
    return chosen, servers, 0


def _print_check(chosen, service):
    wn = max([4] + [len(s.name) for s in chosen]); wr = max([5] + [len(s.route) for s in chosen]); wa = max([5] + [len(s.alias) for s in chosen])
    print("%-*s  %-*s  %-*s  %-18s  %s" % (wn, "NAME", wr, "ROUTE", wa, "ALIAS", "USER@PORT", "GROUP / KEY / VARIABLES"))
    for s in chosen:
        extra = " ".join(([s.group] if s.group else []) + (["key"] if s.key else []) + ["%s=%s" % kv for kv in sorted(s.vars.items())]) or "-"
        print("%-*s  %-*s  %-*s  %-18s  %s" % (wn, s.name, wr, s.route, wa, s.alias, "%s@%s" % (s.user, s.port), extra))
    print("%d server(s) look fine; the tunnel service is %sanswering." % (len(chosen), "" if service else "NOT "))


def _format_block(result, timeout, palette):
    status = result["status"]
    if status == "ok":
        mark = palette.ok + "ok" + palette.off
    elif status == "timeout":
        mark = "%stimed out after %ds%s" % (palette.bad, timeout, palette.off)
    elif status == "skipped":
        mark = palette.warn + "skipped" + palette.off
    elif status == "cancelled":
        mark = palette.warn + "cancelled" + palette.off
    else:
        mark = "%sFAILED (exit %s)%s" % (palette.bad, result["rc"], palette.off)
    tries = "  %s(tried %d times)%s" % (palette.dim, result["attempts"], palette.off) if result.get("attempts", 1) > 1 else ""
    lines = ["── %s  [%s]  %s%ss%s%s" % (result["name"], mark, palette.dim, result["secs"], palette.off, tries)]
    lines += ["   " + l for l in result["out"].splitlines()]
    if status != "ok" and result.get("err"):
        lines += ["   ! " + l for l in result["err"].splitlines()[-5:]]
    for h in result.get("hooks", []):
        lines.append("   ↳ %s: %s" % (h["name"], "ok" if h["rc"] == 0 else "exit %s" % h["rc"]))
        lines += ["       " + l for l in (h["out"] if h["rc"] == 0 else (h["err"] or h["out"])).splitlines()[-5:]]
    return "\n".join(lines)


def cli(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    command = " ".join(args.command[1:] if args.command[:1] == ["--"] else args.command)
    if args.example:
        sys.stdout.write(EXAMPLE)
        return 0
    if args.list_jobs:
        saved = load_saved_jobs()
        if not saved:
            print("No saved jobs. Make one in the window: set up a run, then Schedule…")
        for j in saved:
            st = schedule_status(j["name"])
            print("%-20s %-6s %s%s  →  %s" % (j["name"], "on" if st["active"] else "off", describe_schedule(j["sched"]),
                                              ("  (next %s)" % st["next"]) if st["next"] else "",
                                              j["command"] if j["mode"] == "cmd" else "script " + os.path.basename(j["script"])))
            if st.get("problem"):
                print("    ! %s" % st["problem"])
        return 0
    saved_spec = None
    if args.run_job:
        trim_log(os.environ.get("ZTR_FLEET_LOG"))
        if command or args.script or args.put or args.get or args.shell or args.check:
            _err("--run-job runs a saved job on its own; don't give a command or other mode with it")
            return 2
        saved_spec = next((j for j in load_saved_jobs() if j["name"] == args.run_job), None)
        if not saved_spec:
            _err("no saved job named '%s' (ztr_fleet --list-jobs shows them)" % args.run_job)
            return 2
        bad_spec = saved_job_problems(saved_spec)
        if bad_spec:
            _err("job '%s': %s" % (saved_spec["name"], "; ".join(bad_spec)))
            return 2
        o = saved_spec["opts"]
        args.jobs, args.timeout, args.batch, args.pause, args.retries = o["jobs"], o["timeout"], o["batch"], o["pause"], o["retries"]
        rolling = o["batch"] > 0
        args.canary, args.keep_going, args.yes, args.only, args.group = rolling and bool(o["canary"]), rolling and not o["stop"], True, None, None
        args.pause = o["pause"] if rolling else 0
        args.saved_hooks = saved_spec["hooks"] == "saved"
        if not args.file and saved_spec["file"]:
            args.file = saved_spec["file"]
        if saved_spec["mode"] == "cmd":
            command = saved_spec["command"]
        else:
            args.script = saved_spec["script"]
    modes = [bool(command), bool(args.script), bool(args.put), bool(args.get), bool(args.shell), args.check]
    if sum(modes) > 1:
        _err("choose one of: a command, --script, --put, --get, --shell, --check")
        return 2
    if not any(modes):
        _err("nothing to run. Give the command to run on each server, e.g.: ztr_fleet 'uptime'")
        return 2
    if args.jobs < 1 or args.timeout < 1 or args.batch < 0 or args.retries < 0:
        _err("--jobs and --timeout must be 1 or more; --batch and --retries can't be negative")
        return 2
    if args.hook_failed and not (args.hook or args.saved_hooks):
        _err("--hook-failed goes with --hook SCRIPT or --saved-hooks")
        return 2
    hooks = ([norm_hook(h) for h in args.hook] + [norm_hook(dict(path=h, scope="all")) for h in args.hook_all]
             + ([h for h in load_hooks() if h["on"]] if args.saved_hooks else []))
    for h in hooks:
        if hook_command(h["path"])[0] is None:
            _err(hook_command(h["path"])[1])
            return 2
    if (args.canary or args.pause or args.keep_going) and not args.batch:
        _err("--canary, --pause and --keep-going go with --batch N")
        return 2
    if (args.ask_sudo or args.sudo_each) and not command:
        _err("--ask-sudo and --sudo-each work with a command (not --script, --put or --get)")
        return 2

    chosen, everything, problems = _select(args)
    if problems:
        return 2
    if saved_spec:
        chosen, gone = saved_job_servers(saved_spec, everything)
        for n in gone:
            _err("job '%s' lists %s, which isn't in the fleet file any more — skipping it" % (saved_spec["name"], n))
        if not chosen:
            _err("job '%s' has no servers left to run on" % saved_spec["name"])
            return 2
    c_out = Palette(sys.stdout)

    if args.shell:
        server = next((s for s in everything if s.name == args.shell), None)
        if not server:
            _err("no server named '%s' in the fleet file" % args.shell)
            return 2
        if not SSH_WRAPPER.is_file() and not shutil.which("ztr_ssh"):
            _err("ztr_ssh wasn't found in plugins/ or on your PATH")
            return 2
        KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
        wrapper = str(SSH_WRAPPER) if SSH_WRAPPER.is_file() else shutil.which("ztr_ssh")
        os.execv(wrapper, shell_argv(server, args.cp, wrapper))

    forward = FORWARD if FORWARD.is_file() else (Path(shutil.which("ztr_forward")) if shutil.which("ztr_forward") else None)
    if forward is None and not args.dry_run and not args.check:
        _err("ztr_forward wasn't found in plugins/ or on your PATH")
        return 2
    service = service_up(args.cp)
    if args.check:
        _print_check(chosen, service)
        return 0 if service else 1
    if not service and not args.dry_run:
        _err("the tunnel service isn't answering on port %d — start ztr_tunnel_lp.py first (the installer's --with-service sets it up)" % args.cp)
        return 2

    # what to run
    try:
        if command:
            job = make_job("cmd", command=command)
        elif args.script:
            job = make_job("script", script=args.script)
        elif args.put:
            if not os.path.exists(args.put):
                _err("%s doesn't exist" % args.put)
                return 2
            job = make_job("put", local=args.put, remote=args.to)
        else:
            job = make_job("get", remote=args.get, into=args.into)
    except OSError as e:
        _err("couldn't read %s: %s" % (args.script, e))
        return 2
    bad = job_problems(chosen, job)
    if bad:
        for name, message in bad:
            _err("%s: %s" % (name, message))
        return 2

    serious, notices = risks(job.get("command") or job.get("text") or "")
    if args.dry_run:
        print("Plan: %s" % describe_job(job))
        plan = batches(chosen, args.batch, args.canary)
        for i, group in enumerate(plan, 1):
            if len(plan) > 1:
                print("  batch %d:" % i)
            for s in group:
                argv_s, _stdin = build_argv(s, job, args.cp)
                shown = substitute(job["command"], s)[0] if job["kind"] == "cmd" else (
                    "%s (on %s)" % (describe_job(job), argv_s[argv_s.index("_") + 4])) if job["kind"] == "script" else describe_job(job)
                print("    %-12s via %-14s as %s@%s  →  %s" % (s.name, s.route, s.user, s.alias if len(s.alias) < 30 else s.alias[:14] + "…", shown))
        for why in serious:
            print("  ! this %s" % why)
        for why in notices:
            print("  · %s" % why)
        return 0
    if serious and not args.yes:
        if sys.stdin.isatty() and sys.stderr.isatty():
            print("This looks destructive — it %s." % "; it ".join(serious), file=sys.stderr)
            print("It would run on: %s" % ", ".join(s.name for s in chosen), file=sys.stderr)
            if input("Run it anyway? [y/N] ").strip().lower() not in ("y", "yes"):
                return 2
        else:
            _err("this %s — run it with --yes if you mean it" % "; it ".join(serious))
            return 2
    if args.ask_sudo or args.sudo_each:
        import getpass
        try:
            if args.ask_sudo:
                job["sudo_password"] = getpass.getpass("sudo password for all servers (sent over ssh; not stored): ")
                if not job["sudo_password"]:
                    _err("no password given")
                    return 2
            if args.sudo_each:
                same = "the shared password" if job.get("sudo_password") else "none"
                job["sudo_passwords"] = {}
                for s in chosen:
                    entered = getpass.getpass("sudo password for %s (Enter = %s): " % (s.name, same))
                    if entered:
                        job["sudo_passwords"][s.name] = entered
        except (EOFError, KeyboardInterrupt):
            return 2

    import queue
    events = queue.Queue()
    runner = Runner(chosen, job, args.jobs, args.timeout, events.put, args.cp, batch=args.batch, canary=args.canary, pause=args.pause,
                    stop_on_failure=not args.keep_going if args.batch else False, retries=args.retries, retry_wait=args.retry_wait,
                    hooks=hooks, hook_failed=args.hook_failed)
    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    order = [s.name for s in chosen]
    done, failed, finished, summary_hooks = {}, 0, False, []

    def show(result):
        nonlocal failed
        if result["status"] != "ok":
            failed += 1
        if args.json:
            print(json.dumps(dict(name=result["name"], status=result["status"], exit=result["rc"], seconds=result["secs"],
                                  attempts=result.get("attempts", 1), output=result["out"], error=result["err"],
                                  hooks=[dict(name=h["name"], exit=h["rc"], output=h["out"], error=h["err"]) for h in result.get("hooks", [])])), flush=True)
        else:
            print(_format_block(result, args.timeout, c_out), flush=True)
        if out_dir:
            (out_dir / (result["name"] + ".out")).write_text(result["out"] + "\n", encoding="utf-8")
            (out_dir / (result["name"] + ".err")).write_text(result["err"] + "\n", encoding="utf-8")
            (out_dir / (result["name"] + ".exit")).write_text(str(result["rc"]) + "\n", encoding="utf-8")

    runner.start()
    try:
        while not finished:
            kind, *payload = events.get()
            if kind == "done":
                done[payload[0]["name"]] = payload[0]
                if not args.ordered:
                    show(payload[0])
            elif kind == "note" and not args.json:
                print("%s── %s%s" % (c_out.dim, payload[0], c_out.off), file=sys.stderr, flush=True)
            elif kind == "retry" and not args.json:
                print("%s── %s: trying again (%d of %d)%s" % (c_out.dim, payload[0], payload[1], payload[2], c_out.off), file=sys.stderr, flush=True)
            elif kind == "summary":
                summary_hooks = payload[0]
                if not args.json:
                    for h in summary_hooks:
                        print("── %s (whole run): %s" % (h["name"], "ok" if h["rc"] == 0 else "exit %s" % h["rc"]))
                        for line in (h["out"] if h["rc"] == 0 else (h["err"] or h["out"])).splitlines()[-8:]:
                            print("   " + line)
            elif kind == "finished":
                finished = True
    except KeyboardInterrupt:
        print("\n[ztr_fleet] cancelling…", file=sys.stderr)
        runner.cancel()
        while not finished:
            kind, *payload = events.get()
            if kind == "done":
                done[payload[0]["name"]] = payload[0]
                if not args.ordered:
                    show(payload[0])
            elif kind == "finished":
                finished = True
        return 130
    if args.ordered:
        for name in order:
            if name in done:
                show(done[name])
    if saved_spec:
        try:
            add_history(describe_job(job), [done[n] for n in order if n in done], args.jobs, args.timeout, kind=job["kind"],
                        source="scheduled: %s" % saved_spec["name"])
        except OSError:
            pass
    summary = "%d server(s), %d did not succeed" % (len(order), failed)
    proposals = collect_followups(list(done.values()) + [dict(hooks=summary_hooks)])
    if args.json:
        print(json.dumps(dict(summary=dict(servers=len(order), ok=len(order) - failed, failed=failed),
                              followups=[dict(title=n["title"], command=n["command"], servers=n["servers"], group=n["group"], all=n["all"],
                                              source=n["source"]) for n in proposals])), flush=True)
    else:
        print("── " + summary)
        for n in proposals:
            targets, missing = followup_targets(n, chosen if False else everything)
            print("── next step suggested by %s: %s" % (n["source"], n["title"]))
            print("   %s" % followup_cli(n, args.file))
            if missing:
                print("   (not in the fleet file: %s)" % ", ".join(missing))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(cli())
