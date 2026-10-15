#!/usr/bin/env python3
"""A blocklist, an alert list, and a few detection rules for ztr_proxy.

Three things live here, all driven by what the proxy actually sees (host names
and ports, when connections start and end, and how many bytes they carried):

  * The blocklist. A blocked host is refused before any tunnel is opened, so
    nothing leaves this computer and the route is not used for it.
  * The alert list. Hosts you want to hear about whenever anything contacts
    them. They are not blocked.
  * Detection rules. They look for behaviour that is typical of malware or of
    data leaving by the back door: connections at suspiciously regular
    intervals, far more data sent than received, bursts of machine-generated
    looking names, remote-access ports, and a few more. Every alert states the
    evidence it is based on.

The proxy never sees inside HTTPS, so a rule can only say that behaviour looks
suspicious, not that a program is malicious. A host you recognise can be
marked trusted, which silences the rules for it (a blocklist or alert-list
entry still applies).

Blocklist and alert-list patterns:  example.com  (that name and everything
under it), example.com:8443 (one port only), 203.0.113.9, 203.0.113.0/24.
Names are never looked up on this computer, so an address entry only matches
when a program connects to that bare address.
"""
import collections
import csv
import ipaddress
import json
import math
import os
import re
import threading
import time
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("ZTR_PROXY_HOME") or Path.home() / ".config" / "ztr_proxy")
GUARD_PATH = CONFIG_DIR / "guard.json"
ALERTS_PATH = CONFIG_DIR / "alerts.json"

SEVERITIES = ("info", "low", "medium", "high")
SEV_RANK = {name: i for i, name in enumerate(SEVERITIES)}

# name: (title, what it looks for, on by default)
RULES = {
    "blocked": ("Blocked attempts", "Something tried to reach a host on your blocklist.", True),
    "watch": ("Alert list", "A connection to a host on your alert list.", True),
    "beacon": ("Beaconing", "Connections to one host at suspiciously regular intervals, the way malware often checks in.", True),
    "exfil": ("Large uploads", "Far more data sent to one host than received from it.", True),
    "dga": ("Random-looking names", "Many new hosts with machine-generated looking names in a short time.", True),
    "port": ("Risky ports", "Connections to ports used by remote-access tools, IRC bots, or Tor.", True),
    "ip": ("Direct addresses", "A program connecting to a bare IP address instead of a name.", True),
    "failures": ("Repeated failures", "Many failed attempts to one host, or to many hosts at once.", True),
    "lookalike": ("Look-alike names", "International (punycode) or unusually long host names.", True),
}

ADVICE = {
    "blocked": "Something on this computer tried to reach a host you blocked. If you don't know what, look at the other alerts for the same time.",
    "watch": "A host on your alert list was contacted. Open the Connections tab to see when and how much.",
    "beacon": "Programs that check in with a server on a fixed schedule are normal (updates, mail) and so is some malware. If you don't recognise the host, block it and find out what keeps connecting.",
    "exfil": "A lot more data left this computer than came back. Uploads to cloud storage look like this too; if you didn't start one, block the host and investigate.",
    "dga": "Some malware invents many random host names to find its server. Several unrelated sites can also look like this (content networks), so check the examples.",
    "port": "These ports are rarely used by ordinary programs. If you didn't start a remote-desktop, chat or file-sharing tool, treat it as suspicious.",
    "ip": "Browsers use names. A program that goes straight to an address may be avoiding name-based blocking.",
    "failures": "Repeated failures can mean something is probing for a reachable host, or a program is retrying a server that is gone.",
    "lookalike": "International characters can imitate a familiar site's name; very long names are sometimes used to hide the real host.",
}

# Content networks whose host names look random but are ordinary.
COMMON_SUFFIXES = ("cloudfront.net", "akamaiedge.net", "akamaized.net", "akamai.net", "fastly.net", "fastlylb.net",
                   "googleusercontent.com", "gstatic.com", "googlevideo.com", "amazonaws.com", "azureedge.net",
                   "windows.net", "msedge.net", "cdn77.org", "b-cdn.net", "edgekey.net", "edgesuite.net",
                   "cloudflare.net", "trafficmanager.net", "githubusercontent.com", "fbcdn.net", "ytimg.com")
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "com.br", "co.in", "com.mx", "co.nz",
             "co.za", "com.cn", "com.tr", "com.ar", "co.kr"}
# port -> (severity, what it is usually used for)
RISKY_PORTS = {
    23: ("medium", "Telnet, which sends everything unencrypted"), 135: ("medium", "Windows remote procedure calls"),
    139: ("medium", "Windows file sharing (NetBIOS)"), 445: ("medium", "Windows file sharing (SMB)"),
    3389: ("medium", "Windows Remote Desktop"), 4444: ("medium", "the default listener port of Metasploit and many reverse shells"),
    5555: ("low", "Android debugging (adb)"), 12345: ("medium", "a classic backdoor port"),
    31337: ("medium", "a classic backdoor port"), 54321: ("medium", "a classic backdoor port"),
    9001: ("low", "Tor relay traffic"), 9030: ("low", "Tor directory traffic"), 9050: ("low", "the Tor SOCKS port"),
    9150: ("low", "the Tor Browser SOCKS port"),
}
for _p in list(range(6660, 6670)) + [6697]:
    RISKY_PORTS[_p] = ("medium", "IRC, which botnets use for control")

MB = 1024 * 1024


def fmt_span(seconds):
    seconds = max(0.0, float(seconds))
    if seconds < 90:
        return f"{seconds:.0f} s" if seconds >= 10 else f"{seconds:.1f} s"
    if seconds < 5400:
        return f"{seconds / 60:.0f} min"
    return f"{seconds / 3600:.1f} h"


# ── patterns ─────────────────────────────────────────────────────────────────

_HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_.-]*[a-z0-9_])?$")


class Pattern:
    """One blocklist / alert-list entry: a name (covering everything under it), an address, or an address range,
    optionally limited to one port."""

    def __init__(self, kind, value, port=None):
        self.kind, self.value, self.port = kind, value, port

    @property
    def text(self):
        base = str(self.value)
        return f"{base}:{self.port}" if self.port else base

    def matches(self, host, port):
        if self.port and self.port != port:
            return False
        host = (host or "").lower().rstrip(".")
        if self.kind == "domain":
            return host == self.value or host.endswith("." + self.value)
        try:
            addr = ipaddress.ip_address(host.strip("[]"))
        except ValueError:
            return False
        if self.kind == "ip":
            return addr == self.value
        return addr.version == self.value.version and addr in self.value


def parse_pattern(text):
    """Turns what a person typed (a host, a URL, host:port, an address or a range) into a Pattern, or raises ValueError."""
    t = (text or "").strip().lower()
    if not t:
        raise ValueError("empty")
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t)
    t = re.split(r"[/?#]", t, maxsplit=1)[0] if not re.fullmatch(r"[0-9a-f:.]+/\d{1,3}", t) else t
    t = t.rsplit("@", 1)[-1]
    if "/" in t:
        try:
            return Pattern("net", ipaddress.ip_network(t, strict=False))
        except ValueError:
            raise ValueError("that range isn't valid")
    port = None
    if t.startswith("[") and "]" in t:  # [v6]:port
        host, _, rest = t[1:].partition("]")
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else None
    elif t.count(":") == 1:
        host, _, p = t.partition(":")
        if not p.isdigit() or not 1 <= int(p) <= 65535:
            raise ValueError("the port should be a number from 1 to 65535")
        port = int(p)
    else:
        host = t
    host = host.lstrip("*.").strip(".")
    if not host:
        raise ValueError("empty")
    try:
        return Pattern("ip", ipaddress.ip_address(host), port)
    except ValueError:
        pass
    if len(host) > 253 or not _HOST_RE.match(host) or ".." in host:
        raise ValueError("that doesn't look like a host name")
    return Pattern("domain", host, port)


def parse_list_text(text):
    """Reads a block list in the formats found in the wild (one entry per line, hosts files, ad-block style lines,
    Spamhaus 'range ; reference' lines). Returns ([Pattern], skipped_count)."""
    found, skipped, seen = [], 0, set()
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line[0] in "#!;[" or line.startswith("//"):
            continue
        line = re.split(r"\s+#|\s*;\s*", line, maxsplit=1)[0].strip()
        m = re.fullmatch(r"\|\|([^/^*]+)\^?.*", line)  # ||example.com^
        if m:
            line = m.group(1)
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"(0\.0\.0\.0|127\.0\.0\.1|::1?)", parts[0]):  # hosts-file line
            line = parts[1]
            if line in ("localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback"):
                continue
        elif len(parts) > 1:  # not a format we know: better to skip it than to guess which word was meant
            skipped += 1
            continue
        try:
            p = parse_pattern(line)
        except ValueError:
            skipped += 1
            continue
        if p.text not in seen:
            seen.add(p.text)
            found.append(p)
    return found, skipped


class PatternSet:
    """Entries ({'pattern': text, ...}) indexed so a lookup costs a few dictionary hits however long the list is."""

    def __init__(self, entries=()):
        self.entries = {}
        self._domains = {}      # name -> entry, no port limit
        self._ported = []       # (Pattern, entry) with a port, or an address
        for entry in entries:
            self.add(entry, rebuild=False)

    def add(self, entry, rebuild=True):
        pat = parse_pattern(entry["pattern"])
        entry = dict(entry, pattern=pat.text)
        self.entries[pat.text] = entry
        if pat.kind == "domain" and pat.port is None:
            self._domains[pat.value] = entry
        else:
            self._ported = [(p, e) for p, e in self._ported if p.text != pat.text] + [(pat, entry)]
        return entry

    def remove(self, text):
        pat = parse_pattern(text)
        gone = self.entries.pop(pat.text, None)
        self._domains.pop(pat.value, None) if pat.kind == "domain" and pat.port is None else None
        self._ported = [(p, e) for p, e in self._ported if p.text != pat.text]
        return gone is not None

    def match(self, host, port):
        host = (host or "").lower().rstrip(".")
        labels = host.split(".")
        for i in range(len(labels)):
            hit = self._domains.get(".".join(labels[i:]))
            if hit:
                return hit
        for pat, entry in self._ported:
            if pat.matches(host, port):
                return entry
        return None

    def __len__(self):
        return len(self.entries)


# ── alerts ───────────────────────────────────────────────────────────────────

class AlertStore:
    """The alerts raised so far. A repeat of the same finding about the same host updates its alert (count, last seen,
    latest evidence) rather than adding a new row. Dismissed alerts stay quiet unless the finding gets more serious."""

    def __init__(self, path=None, limit=500, clock=time.time):
        self._lock = threading.RLock()
        self.path, self.limit, self.clock = path, limit, clock
        self.items = {}    # id -> alert
        self._index = {}   # (rule, host, port) -> id
        self._next = 1
        self._dirty = False

    def add(self, rule, severity, host, port, title, evidence, action=""):
        """Returns (alert, created, escalated)."""
        now = self.clock()
        key = (rule, host, int(port or 0))
        with self._lock:
            aid = self._index.get(key)
            alert = self.items.get(aid) if aid else None
            if alert is None:
                alert = {"id": self._next, "rule": rule, "severity": severity, "host": host, "port": int(port or 0), "title": title,
                         "evidence": evidence, "count": 1, "first": now, "last": now, "state": "new", "action": action}
                self._next += 1
                self.items[alert["id"]] = alert
                self._index[key] = alert["id"]
                self._trim()
                self._dirty = True
                return dict(alert), True, False
            escalated = SEV_RANK[severity] > SEV_RANK[alert["severity"]]
            alert["count"] += 1
            alert["last"] = now
            alert["evidence"] = evidence
            alert["title"] = title
            if escalated:
                alert["severity"] = severity
                if alert["state"] != "new":
                    alert["state"] = "new"
            if action:
                alert["action"] = action
            self._dirty = True
            return dict(alert), False, escalated

    def _trim(self):
        if len(self.items) <= self.limit:
            return
        for aid in sorted(self.items, key=lambda a: (self.items[a]["state"] == "new", self.items[a]["last"]))[:len(self.items) - self.limit]:
            alert = self.items.pop(aid)
            self._index.pop((alert["rule"], alert["host"], alert["port"]), None)

    def list(self):
        with self._lock:
            return sorted((dict(a) for a in self.items.values()), key=lambda a: -a["last"])

    def get(self, aid):
        with self._lock:
            a = self.items.get(aid)
            return dict(a) if a else None

    def set_state(self, aid, state):
        with self._lock:
            if aid in self.items:
                self.items[aid]["state"] = state
                self._dirty = True
                return True
        return False

    def mark_all(self, state, where=None):
        with self._lock:
            for a in self.items.values():
                if where is None or where(a):
                    a["state"] = state
            self._dirty = True

    def remove_dismissed(self):
        with self._lock:
            for aid in [i for i, a in self.items.items() if a["state"] == "dismissed"]:
                a = self.items.pop(aid)
                self._index.pop((a["rule"], a["host"], a["port"]), None)
            self._dirty = True

    def counts(self):
        """{'new': n, 'high': n, 'medium': n, ...} over alerts that are not dismissed."""
        out = collections.Counter()
        with self._lock:
            for a in self.items.values():
                if a["state"] == "dismissed":
                    continue
                out[a["severity"]] += 1
                if a["state"] == "new":
                    out["new"] += 1
                    out["new_" + a["severity"]] += 1
        return dict(out)

    def clear(self):
        with self._lock:
            self.items.clear()
            self._index.clear()
            self._dirty = True

    def load(self):
        if not self.path:
            return
        try:
            data = json.loads(Path(self.path).read_text())
        except (OSError, ValueError):
            return
        with self._lock:
            for a in data.get("alerts", []):
                try:
                    a = {"id": int(a["id"]), "rule": a["rule"], "severity": a["severity"], "host": a["host"], "port": int(a["port"]),
                         "title": a["title"], "evidence": a["evidence"], "count": int(a["count"]), "first": float(a["first"]),
                         "last": float(a["last"]), "state": a["state"], "action": a.get("action", "")}
                except (KeyError, TypeError, ValueError):
                    continue
                if a["severity"] not in SEV_RANK or a["state"] not in ("new", "acknowledged", "dismissed"):
                    continue
                self.items[a["id"]] = a
                self._index[(a["rule"], a["host"], a["port"])] = a["id"]
            self._next = max([self._next] + [i + 1 for i in self.items])

    def save(self, force=False):
        if not self.path:
            return
        with self._lock:
            if not (self._dirty or force):
                return
            payload = json.dumps({"alerts": list(self.items.values())}, indent=1)
            self._dirty = False
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(self.path).with_suffix(".tmp")
            tmp.write_text(payload)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def export(self, path, fmt="csv"):
        rows = self.list()
        cols = ["id", "first", "last", "severity", "rule", "host", "port", "count", "state", "action", "title", "evidence"]
        if fmt == "json":
            Path(path).write_text(json.dumps(rows, indent=1))
            return len(rows)
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for a in rows:
                w.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(a[c])) if c in ("first", "last") else a[c] for c in cols])
        return len(rows)


# ── detection ────────────────────────────────────────────────────────────────

def registrable(host):
    """The name a person would register: example.com for a.b.example.com (and example.co.uk for the longer ones)."""
    labels = host.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def second_label(host):
    reg = registrable(host).split(".")
    return reg[-3] if ".".join(reg[-2:]) in TWO_LEVEL and len(reg) >= 3 else (reg[-2] if len(reg) >= 2 else reg[0])


def entropy(text):
    if not text:
        return 0.0
    counts = collections.Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def looks_random(label):
    """A name that reads like a machine made it: long, high in variety, short on vowels or heavy on digits."""
    label = label.lower()
    if len(label) < 10 or "-" in label.strip("-") and label.count("-") >= 2 and not re.search(r"\d", label):
        return False
    letters = [c for c in label if c.isalpha()]
    vowels = sum(1 for c in letters if c in "aeiou")
    digits = sum(1 for c in label if c.isdigit())
    run = max((len(m) for m in re.findall(r"[^aeiou\d\W_]+", label)), default=0)
    return entropy(label) >= 3.2 and (digits / len(label) >= 0.2 or (letters and vowels / len(letters) <= 0.25) or run >= 6)


def is_ip(host):
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def is_global_ip(host):
    try:
        a = ipaddress.ip_address((host or "").strip("[]"))
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


class Detector:
    """Watches connections as they start, fail and end, and raises alerts. Every threshold can be changed through
    `params` (tests, or someone with a noisy network)."""

    DEFAULTS = dict(
        beacon_min=6, beacon_cv=0.20, beacon_hi_n=8, beacon_hi_cv=0.08, beacon_min_mean=5.0, beacon_window=3600.0,
        exfil_bytes=25 * MB, exfil_ratio=5.0, exfil_window=600.0,
        dga_count=5, dga_window=120.0,
        fail_count=6, fail_window=600.0, scan_hosts=15, scan_window=60.0,
        sweep_every=5.0,
    )

    def __init__(self, policy_ref, store, clock=time.time):
        self.guard = policy_ref        # the Guard (for trusted hosts, auto-block)
        self.store, self.clock = store, clock
        self.params = dict(self.DEFAULTS)
        self.enabled = {name: spec[2] for name, spec in RULES.items()}
        self.auto_block = False
        self.lock = threading.RLock()
        self.starts = collections.defaultdict(lambda: collections.deque(maxlen=60))   # (host, port) -> start times
        self.traffic = collections.defaultdict(collections.deque)                      # host -> (time, up, down) per finished connection
        self.randoms = collections.deque(maxlen=200)                                   # (time, registrable, host)
        self.fails = collections.defaultdict(collections.deque)                        # host -> failure times
        self.fail_hosts = collections.deque(maxlen=400)                                # (time, host)
        self._last_sweep = 0.0
        self.listeners = []   # called with (alert, created, escalated)

    # -- plumbing
    def _alert(self, rule, severity, host, port, title, evidence):
        if not self.enabled.get(rule, True):
            return None
        if rule not in ("blocked", "watch") and self.guard.is_trusted(host):
            return None
        action = ""
        if (self.auto_block and severity == "high" and rule not in ("blocked", "watch") and host and host != "(many hosts)"
                and not self.guard.is_blocked(host, port)):
            self.guard.block(host, note=f"added automatically: {RULES[rule][0].lower()}", source="auto")
            action = "blocked automatically"
        alert, created, escalated = self.store.add(rule, severity, host, port, title, evidence, action=action)
        for fn in list(self.listeners):
            try:
                fn(alert, created, escalated)
            except Exception:
                pass
        return alert

    # -- events (c is a connection record: kind, host, port, started, up, down, error ...)
    def on_blocked(self, c, entry):
        sev = entry.get("severity") if entry.get("severity") in SEV_RANK else "medium"
        note = f" ({entry['note']})" if entry.get("note") else ""
        self._alert("blocked", sev, c["host"], c["port"], f"Blocked a connection to {c['host']}",
                    f"Refused a {c['kind']} connection to {c['host']}:{c['port']}; it matches your blocklist entry {entry['pattern']}{note}.")

    def on_start(self, c):
        host, port, now = c["host"], c["port"], c.get("started") or self.clock()
        watch = self.guard.watch_match(host, port)
        if watch:
            sev = watch.get("severity") if watch.get("severity") in SEV_RANK else "medium"
            note = f" ({watch['note']})" if watch.get("note") else ""
            self._alert("watch", sev, host, port, f"Alert list host contacted: {host}",
                        f"A {c['kind']} connection to {host}:{port} matches your alert list entry {watch['pattern']}{note}.")
        if is_global_ip(host):
            self._alert("ip", "low", host, port, f"Direct connection to the address {host}",
                        f"A program connected to the bare address {host}:{port} instead of a host name.")
        risky = RISKY_PORTS.get(port)
        if risky:
            self._alert("port", risky[0], host, port, f"Connection to port {port}",
                        f"Port {port} is {risky[1]}. A {c['kind']} connection to {host}:{port} was made.")
        self._lookalike(host, port)
        self._record_start(host, port, now)
        self._dga(host, port, now)

    def on_fail(self, c):
        host, now = c["host"], c.get("ended") or self.clock()
        with self.lock:
            q = self.fails[host]
            q.append(now)
            while q and now - q[0] > self.params["fail_window"]:
                q.popleft()
            n = len(q)
            self.fail_hosts.append((now, host))
            recent = {h for t, h in self.fail_hosts if now - t <= self.params["scan_window"]}
        if n >= self.params["fail_count"]:
            self._alert("failures", "low", host, c["port"], f"{host} keeps failing",
                        f"{n} connection attempts to {host} failed in the last {fmt_span(self.params['fail_window'])}. Last error: {str(c.get('error') or 'unknown')[:120]}")
        if len(recent) >= self.params["scan_hosts"]:
            self._alert("failures", "medium", "(many hosts)", 0, "Many different hosts failed at once",
                        f"{len(recent)} different hosts could not be reached within {fmt_span(self.params['scan_window'])}. "
                        "That can be a program scanning for a reachable server, or a list of dead addresses.")

    def on_end(self, c):
        host, now = c["host"], c.get("ended") or self.clock()
        up, down = c.get("up", 0), c.get("down", 0)
        if up or down:
            with self.lock:
                q = self.traffic[host]
                q.append((now, up, down))
                while q and now - q[0][0] > self.params["exfil_window"]:
                    q.popleft()
            self._exfil(host, c["port"], now)

    def sweep(self, active):
        """Called about once a second with the connections open right now; does the work that can't wait for a
        connection to end (a long upload), and forgets old history."""
        now = self.clock()
        if now - self._last_sweep < self.params["sweep_every"]:
            return
        self._last_sweep = now
        by_host = collections.defaultdict(lambda: [0, 0, 0])
        for c in active:
            agg = by_host[c["host"]]
            agg[0] += c.get("up", 0)
            agg[1] += c.get("down", 0)
            agg[2] = c["port"]
        for host, (up, down, port) in by_host.items():
            self._exfil(host, port, now, extra=(up, down))
        with self.lock:
            for key in [k for k, q in self.starts.items() if not q or now - q[-1] > self.params["beacon_window"]]:
                del self.starts[key]
            for host in [h for h, q in self.traffic.items() if not q or now - q[-1][0] > self.params["exfil_window"]]:
                del self.traffic[host]
            for host in [h for h, q in self.fails.items() if not q or now - q[-1] > self.params["fail_window"]]:
                del self.fails[host]

    # -- rules
    def _record_start(self, host, port, now):
        p = self.params
        with self.lock:
            q = self.starts[(host, port)]
            q.append(now)
            times = [t for t in q if now - t <= p["beacon_window"]]
        if len(times) < p["beacon_min"]:
            return
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = sum(gaps) / len(gaps)
        if mean < p["beacon_min_mean"] or min(gaps) < p["beacon_min_mean"] * 0.4:
            return
        std = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps))
        cv = std / mean
        if cv > p["beacon_cv"]:
            return
        severity = "high" if (cv <= p["beacon_hi_cv"] and len(times) >= p["beacon_hi_n"]) else "medium"
        self._alert("beacon", severity, host, port, f"{host} is contacted on a fixed schedule",
                    f"{len(times)} connections to {host}:{port}, one about every {fmt_span(mean)} "
                    f"({'almost to the second' if std < 0.15 else 'give or take ' + fmt_span(std)}), "
                    f"over {fmt_span(times[-1] - times[0])}. Ordinary browsing is not this regular.")

    def _exfil(self, host, port, now, extra=(0, 0)):
        p = self.params
        with self.lock:
            rows = [r for r in self.traffic.get(host, ()) if now - r[0] <= p["exfil_window"]]
        up = sum(r[1] for r in rows) + extra[0]
        down = sum(r[2] for r in rows) + extra[1]
        if up >= p["exfil_bytes"] and up >= p["exfil_ratio"] * max(down, 1):
            self._alert("exfil", "high", host, port, f"Large upload to {host}",
                        f"{up / MB:.1f} MB sent to {host} in the last {fmt_span(p['exfil_window'])} against {down / MB:.1f} MB received "
                        f"(about {up / max(down, 1):.0f} times more going out than coming in).")

    def _dga(self, host, port, now):
        p = self.params
        if is_ip(host) or host.endswith(COMMON_SUFFIXES) or not looks_random(second_label(host)):
            return
        reg = registrable(host)
        with self.lock:
            self.randoms.append((now, reg, host))
            recent = {}
            for t, r, h in self.randoms:
                if now - t <= p["dga_window"]:
                    recent.setdefault(r, h)
        if len(recent) >= p["dga_count"]:
            examples = ", ".join(list(recent)[:3])
            self._alert("dga", "medium", "(many names)", 0, "Many random-looking host names",
                        f"{len(recent)} different hosts with machine-generated looking names in {fmt_span(p['dga_window'])}, "
                        f"for example {examples}. Malware sometimes tries names like these to find its server.")

    def _lookalike(self, host, port):
        if is_ip(host):
            return
        labels = host.split(".")
        if any(l.startswith("xn--") for l in labels):
            self._alert("lookalike", "low", host, port, f"International name: {host}",
                        "This host name uses international (punycode) characters, which can imitate a familiar site.")
        elif max(len(l) for l in labels) >= 40 or len(host) >= 80:
            self._alert("lookalike", "low", host, port, "Unusually long host name",
                        f"{host[:100]} is {len(host)} characters long; very long names are sometimes used to hide the real host.")


# ── the whole thing ──────────────────────────────────────────────────────────

class Guard:
    """The blocklist, alert list, trusted hosts, alerts and detector, with their settings saved to guard.json."""

    def __init__(self, config_path=None, alerts_path=None, clock=time.time):
        self._lock = threading.RLock()
        self.config_path = config_path if config_path is not None else GUARD_PATH
        self.blocklist = PatternSet()
        self.watchlist = PatternSet()
        self.trusted = PatternSet()
        self.store = AlertStore(alerts_path if alerts_path is not None else ALERTS_PATH, clock=clock)
        self.detector = Detector(self, self.store, clock=clock)
        self.clock = clock
        self.hits = collections.Counter()      # pattern -> times a connection matched it (this run)
        self.last_hit = {}
        self._loaded = False
        self._cfg_dirty = False

    # -- lookups used while a connection is being set up
    def check_block(self, host, port):
        entry = self.blocklist.match(host, port)
        if entry:
            self.hits[entry["pattern"]] += 1
            self.last_hit[entry["pattern"]] = self.clock()
        return entry

    def is_blocked(self, host, port=0):
        return self.blocklist.match(host, port) is not None

    def watch_match(self, host, port):
        entry = self.watchlist.match(host, port)
        if entry:
            self.hits[entry["pattern"]] += 1
            self.last_hit[entry["pattern"]] = self.clock()
        return entry

    def is_trusted(self, host):
        return self.trusted.match(host, 0) is not None

    # -- editing (each saves)
    def block(self, text, note="", source="user", severity="medium"):
        entry = self.blocklist.add({"pattern": text, "note": note, "added": self.clock(), "source": source, "severity": severity})
        self._changed()
        return entry

    def unblock(self, text):
        ok = self.blocklist.remove(text)
        self._changed()
        return ok

    def watch(self, text, severity="medium", note=""):
        entry = self.watchlist.add({"pattern": text, "severity": severity, "note": note, "added": self.clock()})
        self._changed()
        return entry

    def unwatch(self, text):
        ok = self.watchlist.remove(text)
        self._changed()
        return ok

    def trust(self, text, note=""):
        entry = self.trusted.add({"pattern": text, "note": note, "added": self.clock()})
        self._changed()
        return entry

    def untrust(self, text):
        ok = self.trusted.remove(text)
        self._changed()
        return ok

    def import_blocklist(self, text, source="import"):
        patterns, skipped = parse_list_text(text)
        added = 0
        for p in patterns:
            if p.text not in self.blocklist.entries:
                self.blocklist.add({"pattern": p.text, "note": "", "added": self.clock(), "source": source, "severity": "medium"})
                added += 1
        self._changed()
        return added, len(patterns) - added, skipped

    def configure(self, enabled=None, auto_block=None):
        if enabled is not None:
            self.detector.enabled.update({k: bool(v) for k, v in enabled.items() if k in RULES})
        if auto_block is not None:
            self.detector.auto_block = bool(auto_block)
        self._changed()

    # -- saving and loading
    def _changed(self):
        self._cfg_dirty = True

    def save(self, force=False):
        self.store.save(force)
        with self._lock:
            if not (self._cfg_dirty or force) or not self.config_path:
                return
            self._cfg_dirty = False
            data = {"blocklist": list(self.blocklist.entries.values()), "watchlist": list(self.watchlist.entries.values()),
                    "trusted": list(self.trusted.entries.values()), "rules": dict(self.detector.enabled),
                    "auto_block": self.detector.auto_block}
        try:
            Path(self.config_path).parent.mkdir(parents=True, exist_ok=True)
            tmp = Path(self.config_path).with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=1))
            os.replace(tmp, self.config_path)
        except OSError:
            pass

    def load(self):
        self._loaded = True
        self.store.load()
        try:
            data = json.loads(Path(self.config_path).read_text())
        except (OSError, ValueError, TypeError):
            return
        for name, target in (("blocklist", self.blocklist), ("watchlist", self.watchlist), ("trusted", self.trusted)):
            for entry in data.get(name, []) if isinstance(data, dict) else []:
                try:
                    target.add(entry)
                except (ValueError, KeyError, TypeError):
                    continue
        if isinstance(data, dict):
            self.detector.enabled.update({k: bool(v) for k, v in (data.get("rules") or {}).items() if k in RULES})
            self.detector.auto_block = bool(data.get("auto_block", False))

    def ensure_loaded(self):
        if not self._loaded:
            self.load()

    # -- called by the proxy (through Telemetry)
    def on_blocked(self, c, entry):
        self.detector.on_blocked(c, entry)

    def on_start(self, c):
        self.detector.on_start(c)

    def on_fail(self, c):
        self.detector.on_fail(c)

    def on_end(self, c):
        self.detector.on_end(c)

    def sweep(self, active):
        self.detector.sweep(active)
