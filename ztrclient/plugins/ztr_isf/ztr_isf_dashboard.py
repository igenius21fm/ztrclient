#!/usr/bin/env python3
"""
ztr_isf_dashboard.py — local dashboard for the ISFs you operate.

Shows the state of each of your ISFs — reachability and round-trip time, uptime, capacity, policy,
your sessions — and lets you create and end sessions, manage each ISF's allowlist, and manage the
list of ISFs itself (add, change route, remove, choose the default). Everything it learns comes from
the ISF's signed, end-to-end encrypted control channel, reached through your route like any other
ZTRelay traffic; the dashboard never connects to an ISF directly.

    python3 ztr_isf_dashboard.py

The ISF list is shared with `isf_ssh` and `ztr_isf_client.py isf ...` (~/.ztr_isf/isfs.json); a change
made by any of them shows up here within a few seconds. Listens on 10.10.15.10 if this machine has it,
otherwise 127.0.0.1. Every control call crosses the hop chain (a few seconds), so each ISF is polled in
the background and the page reads the latest result; "Refresh now" polls at once.
"""
import argparse
import hashlib
import http.server
import json
import os
import secrets
import socket
import socketserver
import sys
import threading
import time
from collections import deque
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ztr_isf_client as C  # noqa: E402

STATIC_DIR = os.path.join(HERE, "dashboard_static")
CONTENT_TYPES = {".css": "text/css", ".js": "application/javascript", ".html": "text/html; charset=utf-8"}
DEFAULT_HOST_CANDIDATE = "10.10.15.10"
FALLBACK_HOST = "127.0.0.1"


def fingerprint(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except OSError:
        return None


class Monitor:
    """Polls one ISF in the background and runs actions against it, one control call at a time."""

    def __init__(self, name, profile, make_channel, interval, route_info):
        self.name, self.profile = name, profile
        self._make = make_channel
        self._ch = None
        self.interval = max(5, interval)
        self._call_lock = threading.Lock()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._s = {
            "name": name, "isf_host": profile["host"], "route": route_info,
            "fingerprints": {"isf": fingerprint(profile["isf_pub"])},
            "status": "checking", "error": None, "overview": None,
            "last_attempt": None, "last_ok": None, "rtt_ms": None, "clock_skew": None,
            "history": deque(maxlen=60), "events": deque(maxlen=30), "interval": self.interval, "polling": False,
        }

    # -- state --
    def snapshot(self):
        with self._lock:
            s = dict(self._s)
            s["history"] = list(self._s["history"])
            s["events"] = list(self._s["events"])
            s["now"] = time.time()
            s["fingerprints"] = dict(self._s["fingerprints"], isf=fingerprint(self.profile["isf_pub"]))
            return s

    def _event(self, kind, msg):
        with self._lock:
            self._s["events"].appendleft({"t": time.time(), "kind": kind, "msg": msg})

    # -- control calls --
    def _channel(self):
        if self._ch is None:
            self._ch = self._make(self.profile)
        return self._ch

    def call(self, op, **fields):
        with self._call_lock:
            return self._channel().call(op, **fields)

    def poll(self):
        t0 = time.time()
        with self._lock:
            self._s["last_attempt"] = t0
            self._s["polling"] = True
        try:
            ov = self.call("overview")
            t1 = time.time()
            rtt = (t1 - t0) * 1000
            with self._lock:
                was = self._s["status"]
                self._s.update(status="online", error=None, overview=ov, last_ok=t1, rtt_ms=rtt,
                               clock_skew=ov["time"] - (t0 + t1) / 2)
                self._s["history"].append({"t": t1, "ok": True, "rtt": rtt})
            if was == "offline":
                self._event("ok", "ISF reachable again")
        except Exception as e:  # network, crypto, refusal, missing key: all mean "no usable answer"
            msg = str(e) or e.__class__.__name__
            with self._lock:
                was = self._s["status"]
                self._s.update(status="offline", error=msg)
                self._s["history"].append({"t": time.time(), "ok": False, "rtt": None})
            if was != "offline":
                self._event("error", f"ISF unreachable: {msg}")
        finally:
            with self._lock:
                self._s["polling"] = False

    def refresh_soon(self):
        self._wake.set()

    def run(self):
        while not self._stop.is_set():
            self.poll()
            self._wake.wait(self.interval)
            self._wake.clear()

    def start(self):
        threading.Thread(target=self.run, daemon=True).start()

    def stop(self):
        self._stop.set()
        self._wake.set()


def load_route_info(zdir, config_file):
    """Hop chain and exit country from the route file — never its secrets."""
    if not config_file:
        return None
    try:
        with open(os.path.join(zdir, "routes", config_file)) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    chain = []
    for h in d.get("chain", []):
        addr = str(h.get("address", ""))
        chain.append({"role": h.get("role"), "address": addr[:12] + "…" if len(addr) > 40 else addr})
    return {"file": config_file, "exit_country": d.get("exit_country"), "status": d.get("status"), "chain": chain}


class Fleet:
    """All of this machine's ISFs: the shared profile list plus one Monitor per ISF."""

    def __init__(self, zdir, make_channel, interval, client_pub, profiles_factory=None):
        self.zdir, self._make, self.interval = zdir, make_channel, interval
        self.client_pub = client_pub
        self._pf = profiles_factory or C.Profiles
        self._lock = threading.RLock()
        self.monitors = {}
        self._mtime = None
        self._routes_cache = (0, [])
        self.sync(force=True)

    # -- reconciling with the shared profile file --
    def _file_mtime(self):
        try:
            return os.stat(C.profiles_path()).st_mtime_ns
        except OSError:
            return None

    def sync(self, force=False):
        with self._lock:
            mt = self._file_mtime()
            if not force and mt == self._mtime:
                return
            self._mtime = mt
            self.profiles = self._pf()
            wanted = {n: self.profiles.get(n) for n in self.profiles.names}
            for n in list(self.monitors):
                if n not in wanted or self._differs(self.monitors[n].profile, wanted[n]):
                    self.monitors.pop(n).stop()
            for n, p in wanted.items():
                if n not in self.monitors:
                    m = Monitor(n, p, self._make, self.interval, load_route_info(self.zdir, p["route"]))
                    self.monitors[n] = m
                    m.start()

    @staticmethod
    def _differs(a, b):
        keys = ("host", "route", "ctrl_port", "data_port", "udp_port", "isf_pub", "timing_defense")
        return any(a.get(k) != b.get(k) for k in keys)

    def monitor(self, name=None):
        self.sync()
        with self._lock:
            name = name or self.profiles.default_name
            if name not in self.monitors:
                raise C.IsfError(f"no ISF named {name!r}" if name else "no ISF configured yet — add one below")
            return self.monitors[name]

    def reset(self, name):
        """Rebuild one ISF's monitor (e.g. after its public key changed)."""
        with self._lock:
            m = self.monitors.pop(name, None)
            if m:
                m.stop()
            self.sync(force=True)

    # -- summaries --
    def summary(self):
        self.sync()
        out = []
        with self._lock:
            default = self.profiles.default_name
            for n in self.profiles.names:
                p = self.profiles.get(n)
                m = self.monitors.get(n)
                s = m.snapshot() if m else {}
                ov = s.get("overview") or {}
                cap = ov.get("capacity") or {}
                out.append({"name": n, "host": p["host"], "route": p["route"], "ctrl_port": p["ctrl_port"], "data_port": p["data_port"],
                            "udp_port": p.get("udp_port", C.DEFAULT_UDP_PORT), "note": p.get("note", ""), "timing_defense": p.get("timing_defense", False),
                            "default": n == default, "status": s.get("status", "checking"), "error": s.get("error"),
                            "rtt_ms": s.get("rtt_ms"), "last_ok": s.get("last_ok"), "live_mine": cap.get("live_mine"),
                            "live_total": cap.get("live_total"), "version": ov.get("version"),
                            "key_installed": os.path.exists(p["isf_pub"]), "isf_pub": p["isf_pub"]})
        return out

    def routes(self):
        now = time.time()
        if now - self._routes_cache[0] > 10:
            self._routes_cache = (now, C.list_routes(self.zdir))
        return self._routes_cache[1]

    def client_info(self):
        try:
            with open(self.client_pub) as f:
                pem = f.read()
        except OSError:
            pem = None
        return {"fingerprint": fingerprint(self.client_pub), "public_key": pem}

    # -- changes --
    def save_isf(self, name, fields, pem=None, replace_key=False, make_default=False):
        with self._lock:
            self.sync()
            ps = self.profiles
            if "route" in fields and fields["route"]:
                fields["route"] = C.resolve_route(self.zdir, fields["route"])
            p = ps.upsert(name, **fields)
            if pem:
                text = C.validate_public_pem(pem)
                path = p["isf_pub"]
                if os.path.exists(path):
                    with open(path) as f:
                        same = f.read().strip() == text.strip()
                    if not same and not replace_key:
                        raise C.IsfError("an ISF public key is already installed for this ISF — tick \"replace the key\" to change it")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w") as f:
                    f.write(text)
            if make_default:
                ps.set_default(name)
            ps.save()
            self._mtime = None
            if pem:
                self.reset(name)
            else:
                self.sync(force=True)

    def delete_isf(self, name):
        with self._lock:
            self.sync()
            self.profiles.remove(name)
            self.profiles.save()
            self.sync(force=True)

    def set_default(self, name):
        with self._lock:
            self.sync()
            self.profiles.set_default(name)
            self.profiles.save()
            self.sync(force=True)

    def stop(self):
        for m in self.monitors.values():
            m.stop()


class Handler(http.server.BaseHTTPRequestHandler):
    fleet = None
    token = ""
    allowed_hosts = set()
    page = b""

    def log_message(self, *a):
        pass

    def _send(self, status, ctype, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, obj):
        self._send(status, "application/json", json.dumps(obj).encode())

    def _host_ok(self):
        # Refuses requests whose Host isn't ours: stops a web page from reaching this server by DNS rebinding.
        return (self.headers.get("Host") or "").lower() in self.allowed_hosts

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, "text/plain", b"forbidden")
        url = urlparse(self.path)
        if url.path == "/":
            return self._send(200, "text/html; charset=utf-8", self.page)
        if url.path == "/api/state":
            name = (parse_qs(url.query).get("isf") or [None])[0]
            payload = {"isfs": self.fleet.summary(), "routes": self.fleet.routes(), "client": self.fleet.client_info(), "now": time.time()}
            try:
                mon = self.fleet.monitor(name)
                payload["selected"] = mon.snapshot()
                payload["selected"]["profile"] = {k: mon.profile.get(k) for k in ("host", "route", "ctrl_port", "data_port", "udp_port", "note", "timing_defense")}
            except C.IsfError as e:
                payload["selected"] = None
                payload["problem"] = str(e)
            return self._json(200, payload)
        if url.path.startswith("/static/"):
            name = os.path.normpath(url.path[len("/static/"):]).lstrip(os.sep)
            path = os.path.abspath(os.path.join(STATIC_DIR, name))
            ctype = CONTENT_TYPES.get(os.path.splitext(path)[1])
            if path.startswith(STATIC_DIR + os.sep) and ctype and os.path.isfile(path):
                with open(path, "rb") as f:
                    return self._send(200, ctype, f.read())
        self._send(404, "text/plain", b"not found")

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, "text/plain", b"forbidden")
        origin = self.headers.get("Origin")
        if origin and origin.split("://", 1)[-1].lower() not in self.allowed_hosts:
            return self._send(403, "text/plain", b"forbidden")
        if not secrets.compare_digest(self.headers.get("X-Dashboard-Token", ""), self.token):
            return self._send(403, "text/plain", b"forbidden")
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 16384)) or b"{}")
            if not isinstance(body, dict):
                raise ValueError
        except (ValueError, OSError):
            return self._json(400, {"ok": False, "error": "bad request"})

        try:
            return self._json(200, self._act(self.path, body))
        except KeyError:
            return self._send(404, "text/plain", b"not found")
        except (C.IsfError, ValueError) as e:
            self._note(body, "error", str(e))
            return self._json(200, {"ok": False, "error": str(e)})
        except Exception as e:  # tunnel/network failures from RelayClient
            msg = str(e) or "request failed"
            self._note(body, "error", msg)
            return self._json(200, {"ok": False, "error": msg})

    def _note(self, body, kind, msg):
        try:
            self.fleet.monitor(body.get("isf") or None)._event(kind, msg)
        except C.IsfError:
            pass

    def _act(self, path, body):
        f = self.fleet
        name = str(body.get("isf") or "") or None
        if path == "/api/isf/save":
            fields = {"host": str(body.get("host") or "").strip() or None, "route": str(body.get("route") or "").strip() or None,
                      "ctrl_port": body.get("ctrl_port") or None, "data_port": body.get("data_port") or None,
                      "udp_port": body.get("udp_port") or None}
            if "note" in body:
                fields["note"] = str(body.get("note") or "")
            if "timing_defense" in body:
                fields["timing_defense"] = bool(body.get("timing_defense"))
            f.save_isf(str(body.get("name", "")).strip(), fields, pem=(str(body.get("isf_pub_pem") or "").strip() or None),
                       replace_key=bool(body.get("replace_key")), make_default=bool(body.get("make_default")))
            return {"ok": True}
        if path == "/api/isf/delete":
            f.delete_isf(str(body.get("name", "")))
            return {"ok": True}
        if path == "/api/isf/default":
            f.set_default(str(body.get("name", "")))
            return {"ok": True}
        mon = f.monitor(name)
        if path == "/api/refresh":
            mon.refresh_soon()
            return {"ok": True}
        if path == "/api/session/create":
            dest = str(body.get("destination", "")).strip()
            ttl = int(body.get("ttl") or 300)
            label = str(body.get("label", ""))[:64]
            if str(body.get("proto") or "tcp") == "udp":
                # A UDP session is made by the client that uses it (it opens it with the first datagram), so there is no
                # ticket to hand out: check that the ISF would accept the destination, and give the command to run.
                r = mon.call("create", destination=dest, ttl=60, label=label or "check", proto="udp")
                mon.call("delete", session_id=r["session_id"])
                mon.refresh_soon()
                cmd = (f"python3 ztr_isf_client.py udp --isf {mon.name} --listen 127.0.0.1:5353 --destination {dest}")
                return {"ok": True, "proto": "udp", "destination": r["destination"], "command": cmd}
            r = mon.call("create", destination=dest, ttl=ttl, label=label)
            ticket = C.make_ticket(r["session_id"], C._b64d(r["key"]))
            mon._event("ok", f"session {r['session_id'][:8]} created -> {r['destination']}")
            mon.refresh_soon()
            cmd = (f"python3 ztr_isf_client.py client --isf {mon.name} --ticket {ticket} --listen 127.0.0.1:2222")
            return {"ok": True, "session_id": r["session_id"], "destination": r["destination"],
                    "expires_at": r["expires_at"], "ticket": ticket, "command": cmd}
        if path == "/api/session/delete":
            sid = str(body.get("session_id", ""))
            mon.call("delete", session_id=sid)
            mon._event("ok", f"session {sid[:8]} ended")
            mon.refresh_soon()
            return {"ok": True}
        if path in ("/api/alias/add", "/api/alias/remove", "/api/alias/retarget"):
            op = path.rsplit("/", 1)[1]
            fields = {"name": str(body.get("name", "")).strip()}
            if op != "remove":
                fields["target"] = str(body.get("target", "")).strip()
            if op == "add":
                fields["note"] = str(body.get("note", ""))[:120]
            r = mon.call("alias_" + op, **fields)
            mon._event("ok", f"alias {op}: {r['alias'][:8]}…")
            mon.poll()  # show the result straight away
            return {"ok": True, "alias": r["alias"]}
        if path in ("/api/policy/add", "/api/policy/remove"):
            entry = str(body.get("entry", "")).strip()
            adding = path.endswith("add")
            mon.call("policy_add" if adding else "policy_remove", entry=entry)
            mon._event("ok", f"allowlist: {'added' if adding else 'removed'} {entry}")
            mon.poll()  # show the result straight away
            return {"ok": True}
        raise KeyError(path)


def resolve_host(explicit):
    if explicit:
        return explicit
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((DEFAULT_HOST_CANDIDATE, 0))
        return DEFAULT_HOST_CANDIDATE
    except OSError:
        return FALLBACK_HOST
    finally:
        probe.close()


def build_server(host, port, fleet):
    with open(os.path.join(STATIC_DIR, "index.html"), "rb") as f:
        template = f.read()
    token = secrets.token_urlsafe(32)

    class H(Handler):
        pass
    H.fleet, H.token = fleet, token
    H.page = template.replace(b"{{TOKEN}}", token.encode())
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    httpd = http.server.ThreadingHTTPServer((host, port), H)
    actual = httpd.server_address[1]
    H.allowed_hosts = {f"{host}:{actual}", f"127.0.0.1:{actual}", f"localhost:{actual}"}
    httpd.daemon_threads = True
    return httpd


def channel_maker(keys_dir, own_priv=None, own_pub=None):
    priv = own_priv or os.path.join(keys_dir, "client_private.pem")
    pub = own_pub or os.path.join(keys_dir, "client_public.pem")

    def make(profile):
        return C.ControlChannel(C.default_relay_factory(profile["route"], profile.get("timing_defense", False)), profile["host"],
                                profile["ctrl_port"], priv, pub, profile["isf_pub"])
    return make, pub


def main(argv=None):
    ap = argparse.ArgumentParser(description="Local dashboard for your ISFs, reached through ZTRelay.")
    ap.add_argument("--keys-dir", default=C.DEFAULT_KEYS_DIR)
    ap.add_argument("--own-priv"); ap.add_argument("--own-pub")
    ap.add_argument("--ztrclient-dir")
    ap.add_argument("--interval", type=int, default=30, help="seconds between background checks of each ISF (default 30)")
    ap.add_argument("--host"); ap.add_argument("--port", type=int, default=8096)
    ap.add_argument("--isf", help="with --isf-host and --route: add or update this ISF (saved, shared with isf_ssh) before starting")
    ap.add_argument("--isf-host"); ap.add_argument("--route", "--config-file", dest="route")
    a = ap.parse_args(argv)
    try:
        zdir = C.locate_ztrclient(a.ztrclient_dir)
        if a.isf_host or a.route:
            ps = C.Profiles()
            ps.upsert(a.isf or "default", host=a.isf_host, route=C.resolve_route(zdir, a.route) if a.route else None)
            ps.save()
            print(f"saved ISF {a.isf or 'default'!r} to {ps.path}", flush=True)
        make, client_pub = channel_maker(a.keys_dir, a.own_priv, a.own_pub)
        fleet = Fleet(zdir, make, a.interval, client_pub)
    except C.IsfError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    host = resolve_host(a.host)
    httpd = build_server(host, a.port, fleet)
    print(f"ISF dashboard at http://{host}:{httpd.server_address[1]}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
