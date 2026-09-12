"""
Local dashboard: active tunnels per port (from tunnel_cache.db), recent
hop-authorization errors (from logs/ztrclient_ra-error.log), a live feed of
this machine's traffic to its entry hop (--config-file + enough privileges),
plus a few hands-on tools — sign a dashboard nonce, list/reset cached
tunnels, and send a native-mode PING through an authorized tunnel.

    python3 plugins/ztr_dashboard.py --config-file 16efc170.ztr

Live traffic capture uses scapy and needs root/administrator privileges —
without them (or without scapy installed), the dashboard still works, it
just shows why that panel is off.
"""
import argparse
import http.server
import json
import os
import re
import socket
import socketserver
import sqlite3
import sys
import threading
import time
from collections import deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_ZTR_CLIENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, _ZTR_CLIENT_DIR)
sys.path.insert(0, os.path.join(_ZTR_CLIENT_DIR, "utils"))
from ztrClient import RelayClient
import crypt_bot as CB

DB_PATH = os.path.join(_ZTR_CLIENT_DIR, "tunnel_cache.db")
RA_ERROR_LOG = os.path.join(_ZTR_CLIENT_DIR, "logs", "ztrclient_ra-error.log")
STATIC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "static"))
_STATIC_CONTENT_TYPES = {".css": "text/css", ".js": "application/javascript", ".map": "application/json"}

DEFAULT_HOST_CANDIDATE = "10.10.15.10"
FALLBACK_HOST = "127.0.0.1"
ZTRAPPS_URL = "https://github.com/igenius21fm/ztrapps"

_state_lock = threading.Lock()
_recent_packets = deque(maxlen=30)
_traffic_status = {"enabled": False, "reason": "pass --config-file to enable this"}
_route = None
_config_file = None


def active_tunnels():
    if not os.path.exists(DB_PATH):
        return {"total": 0, "by_port": {}}
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "SELECT port, COUNT(*) FROM tunnel_cache WHERE expires_at > ? GROUP BY port",
            (time.time(),),
        )
        rows = cur.fetchall()
        conn.close()
    except sqlite3.Error:
        return {"total": 0, "by_port": {}}
    by_port = {(str(p) if p is not None else "unknown"): c for p, c in rows}
    return {"total": sum(by_port.values()), "by_port": by_port}


_RA_ERROR_RE = re.compile(r"^(?P<time>\S+ \S+) - ERROR - error_code=(?P<code>\S+) error=(?P<error>.*)$")


def recent_ra_errors(limit=20):
    if not os.path.exists(RA_ERROR_LOG):
        return []
    try:
        with open(RA_ERROR_LOG) as f:
            lines = f.readlines()[-limit:]
    except OSError:
        return []
    out = []
    for line in reversed(lines):
        m = _RA_ERROR_RE.match(line.strip())
        if m:
            out.append({"time": m.group("time"), "error_code": m.group("code"), "error": m.group("error")})
    return out


def load_route(config_file):
    """Reads the route straight from the .ztr JSON — no need for the full
    RelayConfig/RelayClient setup just to look at this. identifier/secret_key
    are shown on the page behind a reveal toggle, never logged or sent
    anywhere but this same-machine response."""
    if not config_file:
        return None
    path = os.path.join(_ZTR_CLIENT_DIR, "routes", config_file)
    try:
        with open(path) as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    chain = [
        {"address": h.get("address"), "status": h.get("status"), "pubkey": h.get("pubkey")}
        for h in config.get("chain", [])
    ]
    return {
        "chain": chain,
        "services_ports": config.get("hop_settings", {}).get("services_ports", []),
        "route_id": config.get("route_id"),
        "identifier": config.get("identifier"),
        "secret_key": config.get("secret_key"),
    }


def start_sniffer(entry_address, ports, iface=None):
    try:
        from scapy.all import sniff, IP, TCP
    except ImportError:
        _traffic_status.update(enabled=False, reason="scapy isn't installed")
        return

    bpf = f"host {entry_address} and (" + " or ".join(f"tcp port {p}" for p in ports) + ")"

    def on_packet(pkt):
        if IP in pkt and TCP in pkt:
            with _state_lock:
                _recent_packets.appendleft({
                    "time": time.strftime("%H:%M:%S"),
                    "src": f"{pkt[IP].src}:{pkt[TCP].sport}",
                    "dst": f"{pkt[IP].dst}:{pkt[TCP].dport}",
                    "length": len(pkt),
                })

    def run():
        try:
            _traffic_status.update(enabled=True, reason=None)
            sniff(filter=bpf, prn=on_packet, store=False, iface=iface)
        except PermissionError:
            _traffic_status.update(enabled=False, reason="needs root/administrator privileges to capture packets")
        except OSError as e:
            _traffic_status.update(enabled=False, reason=str(e))

    threading.Thread(target=run, daemon=True).start()


def resolve_host(explicit_host):
    if explicit_host:
        return explicit_host
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((DEFAULT_HOST_CANDIDATE, 0))
        return DEFAULT_HOST_CANDIDATE
    except OSError:
        return FALLBACK_HOST
    finally:
        probe.close()


def list_tunnels():
    if not os.path.exists(DB_PATH):
        return []
    now = time.time()
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "SELECT tunnel_id, session_id, port, expires_at FROM tunnel_cache WHERE expires_at > ? ORDER BY expires_at DESC",
            (now,),
        )
        rows = cur.fetchall()
        conn.close()
    except sqlite3.Error:
        return []
    return [
        {"tunnel_id": t, "session_id": s, "port": p, "expires_in": round(e - now, 1)}
        for t, s, p, e in rows
    ]


def reset_tunnels():
    """Clears tunnel_cache.db entirely — every ztrClient process sharing this
    database (which is every one by default, next to ztrClient.py) will
    re-authorize from scratch on its next request. Local, reversible in the
    sense that tunnels just get re-authorized; nothing on the relay side
    is touched."""
    if not os.path.exists(DB_PATH):
        return {"ok": True, "deleted": 0}
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM tunnel_cache")
        count = cur.fetchone()[0]
        cur.execute("DELETE FROM tunnel_cache")
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "deleted": count}


def sign_nonce(nonce):
    """Same identity keypair and signing call as launcher.py — this is that
    same nonce-signing step, just reachable from the dashboard instead of a
    separate terminal command."""
    if not nonce:
        return {"ok": False, "error": "nonce is required"}
    try:
        crypt = CB.CryptBot(
            pathPrivateKey=os.path.join(_ZTR_CLIENT_DIR, "privateKey.pem"),
            pathPublicKey=os.path.join(_ZTR_CLIENT_DIR, "publicKey.pem"),
            pathRecipientPublicKey="",
        )
        crypt.create_keys(rsa_size=2048, reuse=True)
        with open(crypt.pathPublicKey) as f:
            public_key = f.read()
        signature = crypt.sign_(nonce)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "public_key": public_key, "signature_hex": signature.hex()}


def run_ping(target_host, target_port=None, with_encryption=False, recipient_pubkey_path=None, with_timing_defense=False):
    """A real, native-mode round trip through an authorized tunnel — builds
    its own RelayClient (same route config the dashboard was started with),
    authorizes, sends b'PING', and returns whatever comes back. Every step
    can fail for real reasons (unreachable hop, rejected authorization, dead
    target) — those come back as {"ok": False, "error": ...} rather than a
    traceback, since this is meant to be clicked, not read as a stack trace."""
    if not _config_file:
        return {"ok": False, "error": "no route loaded — start the dashboard with --config-file"}
    if not target_host:
        return {"ok": False, "error": "target_host is required"}
    if with_encryption and not recipient_pubkey_path:
        return {"ok": False, "error": "with_encryption needs a recipient public key path"}

    try:
        client = RelayClient(target_host=target_host, config_file=_config_file)
    except Exception as e:
        return {"ok": False, "error": f"couldn't build client: {e}"}

    if with_timing_defense:
        client.with_timing_defense()
    if with_encryption:
        try:
            client.with_encryption(recipient_pubkey_path)
        except Exception as e:
            return {"ok": False, "error": f"couldn't set up encryption: {e}"}
    if target_port:
        client.set_target_port(int(target_port))

    started = time.time()
    try:
        result = client.set_tunnel(native=True)
    except Exception as e:
        return {"ok": False, "error": f"tunnel setup failed: {e}"}
    if not result or not result.get("status"):
        reason = f"{result.get('error_code')}: {result.get('error')}" if result else "no response from entry hop"
        return {"ok": False, "error": f"hop rejected the tunnel — {reason}"}

    try:
        with socket.create_connection((client.entry_hop, client.PORT), timeout=10) as sock:
            client.send_HTH(sock, b"PING", client.session_id)
            response, resp_session_id = client.recv_HTH(sock)
    except Exception as e:
        return {"ok": False, "error": f"PING failed: {e}"}

    try:
        response_text = response.decode("utf-8")
    except UnicodeDecodeError:
        response_text = response.hex()
    return {
        "ok": True,
        "response": response_text,
        "elapsed_ms": round((time.time() - started) * 1000, 1),
        "session_id": client.session_id,
        "port": client.PORT,
        # The exit hop marks a payload it relayed straight from the target
        # (rather than one it generated itself) by zeroing out the session
        # field instead of stamping a real session id — this is that check,
        # confirming the PING really reached the target and back.
        "from_target": resp_session_id == "0" * 64,
    }


ICONS = """
<svg style="display:none" aria-hidden="true">
  <symbol id="icon-shield" viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5.5 3.4 9.7 8 11 4.6-1.3 8-5.5 8-11V5l-8-3Z"/><path d="m9 12 2 2 4-4"/></symbol>
  <symbol id="icon-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></symbol>
  <symbol id="icon-link" viewBox="0 0 24 24"><path d="M10 14a4 4 0 0 0 6 0l3-3a4 4 0 0 0-6-6l-1 1"/><path d="M14 10a4 4 0 0 0-6 0l-3 3a4 4 0 0 0 6 6l1-1"/></symbol>
  <symbol id="icon-signal" viewBox="0 0 24 24"><path d="M4 18v-2"/><path d="M9 18v-6"/><path d="M14 18V8"/><path d="M19 18V4"/></symbol>
  <symbol id="icon-eye" viewBox="0 0 24 24"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></symbol>
  <symbol id="icon-eye-off" viewBox="0 0 24 24"><path d="M3 3l18 18"/><path d="M10.6 5.2A11 11 0 0 1 12 5c7 0 11 7 11 7a13.5 13.5 0 0 1-3.2 4"/><path d="M6.6 6.6C3.8 8.4 2 12 2 12s4 7 11 7a10 10 0 0 0 3.4-.6"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></symbol>
  <symbol id="icon-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="m10.8 12.2 8.2-8.2"/><path d="m16 6 2 2"/><path d="m13.5 8.5 2 2"/></symbol>
  <symbol id="icon-alert" viewBox="0 0 24 24"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v4"/><path d="M12 17h.01"/></symbol>
  <symbol id="icon-filter" viewBox="0 0 24 24"><path d="M4 5h16l-6 8v6l-4-2v-4L4 5Z"/></symbol>
  <symbol id="icon-terminal" viewBox="0 0 24 24"><path d="m5 7 5 5-5 5"/><path d="M12 17h7"/></symbol>
  <symbol id="icon-menu" viewBox="0 0 24 24"><path d="M4 6h16"/><path d="M4 12h16"/><path d="M4 18h16"/></symbol>
  <symbol id="icon-send" viewBox="0 0 24 24"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4Z"/></symbol>
  <symbol id="icon-trash" viewBox="0 0 24 24"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 14h10l1-14"/></symbol>
  <symbol id="icon-list" viewBox="0 0 24 24"><path d="M8 6h13"/><path d="M8 12h13"/><path d="M8 18h13"/><circle cx="3.5" cy="6" r="1"/><circle cx="3.5" cy="12" r="1"/><circle cx="3.5" cy="18" r="1"/></symbol>
  <symbol id="icon-ext-link" viewBox="0 0 24 24"><path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M18 14v6H4V6h6"/></symbol>
  <symbol id="icon-target" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1"/></symbol>
</svg>
"""

PAGE = """<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZTRelay client dashboard</title>
<link rel="stylesheet" href="/static/vendor/bootstrap.min.css">
<link rel="stylesheet" href="/static/dashboard.css">
</head>
<body>
""" + ICONS + """
  <div class="topbar">
    <h1><svg class="icon"><use href="#icon-shield"></use></svg> ZTRelay Dashboard</h1>
    <span class="sub d-none d-md-inline">this machine only &middot; read-only</span>
    <div class="status-badge">
      <span><svg class="icon"><use href="#icon-clock"></use></svg> <span class="clock" id="session-clock">T+00:00:00</span></span>
      <span id="route-status" class="route-status unknown">NO ROUTE</span>
      <button class="btn" data-bs-toggle="offcanvas" data-bs-target="#tools-menu">
        <svg class="icon"><use href="#icon-menu"></use></svg> Tools
      </button>
    </div>
  </div>

  <div class="toolbar">
    <button class="btn" id="pause-btn">Pause</button>
    <button class="btn" id="refresh-btn">Refresh now</button>
    <span class="d-none d-md-inline">hotkeys: <kbd>P</kbd> pause &middot; <kbd>R</kbd> refresh</span>
    <span id="last-updated"></span>
  </div>

  <div class="main-wrap">
    <div class="row g-4">
      <div class="col-lg-8">
        <div class="row g-3 mb-2">
          <div class="col-sm-6">
            <div class="mcard">
              <div class="label">Active tunnels</div>
              <div class="value ok" id="total-tunnels">&mdash;</div>
            </div>
          </div>
          <div class="col-sm-6">
            <div class="mcard">
              <div class="label">Live traffic capture</div>
              <div class="value off" id="traffic-status">&mdash;</div>
            </div>
          </div>
        </div>

        <section class="panel" id="creds-section" style="display:none">
          <h2><svg class="icon"><use href="#icon-key"></use></svg> Route credentials</h2>
          <div class="mcard">
            <div class="creds-row">
              <span class="creds-label">Route ID</span>
              <span class="creds-value" id="creds-route_id">&mdash;</span>
            </div>
            <div class="creds-row">
              <span class="creds-label">Client ID</span>
              <span class="creds-value masked" id="creds-identifier">&mdash;</span>
              <button class="reveal-btn" data-field="identifier" title="Toggle reveal">
                <svg class="icon icon-eye"><use href="#icon-eye"></use></svg>
                <svg class="icon icon-eye-off" style="display:none"><use href="#icon-eye-off"></use></svg>
              </button>
            </div>
            <div class="creds-row">
              <span class="creds-label">Secret key</span>
              <span class="creds-value masked" id="creds-secret_key">&mdash;</span>
              <button class="reveal-btn" data-field="secret_key" title="Toggle reveal">
                <svg class="icon icon-eye"><use href="#icon-eye"></use></svg>
                <svg class="icon icon-eye-off" style="display:none"><use href="#icon-eye-off"></use></svg>
              </button>
            </div>
          </div>
        </section>

        <section class="panel" id="chain-section" style="display:none">
          <h2><svg class="icon"><use href="#icon-link"></use></svg> Hop chain <span class="hint">click a hop for details</span></h2>
          <div class="chain" id="chain"></div>
        </section>

        <section class="panel">
          <h2><svg class="icon"><use href="#icon-signal"></use></svg> Tunnels by port <span class="hint">click a row to filter the traffic feed</span></h2>
          <table class="mtable" id="ports-table"><tbody></tbody></table>
        </section>

        <section class="panel">
          <h2><svg class="icon"><use href="#icon-alert"></use></svg> Recent hop-authorization errors</h2>
          <div class="input-group-icon">
            <input class="filter-input" id="error-filter" type="search" placeholder="Filter by code or message&hellip;">
          </div>
          <table class="mtable" id="errors-table"><tbody></tbody></table>
        </section>
      </div>

      <div class="col-lg-4">
        <div class="term-col">
          <section class="panel" id="traffic-section" style="display:none">
            <h2><svg class="icon"><use href="#icon-terminal"></use></svg> Live traffic <span class="hint" id="traffic-hint"></span></h2>
            <div class="term-window">
              <div class="term-titlebar"><span class="dot" id="term-live-dot"></span> entry-hop.feed</div>
              <div class="term-body" id="term-body"></div>
            </div>
          </section>
        </div>
      </div>
    </div>
  </div>

  <div class="modal fade" id="hop-modal" tabindex="-1">
    <div class="modal-dialog">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Hop &mdash; <span id="hop-modal-role"></span></h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <div class="creds-row"><span class="creds-label">Address</span><span class="creds-value" id="hop-modal-address"></span></div>
          <div class="creds-row"><span class="creds-label">Status</span><span class="creds-value" id="hop-modal-status"></span></div>
          <p class="hint mt-3 mb-1">Public key</p>
          <div class="pubkey-box" id="hop-modal-pubkey"></div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-check-mil" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>

  <div class="offcanvas offcanvas-end" tabindex="-1" id="tools-menu">
    <div class="offcanvas-header">
      <h5 class="offcanvas-title"><svg class="icon"><use href="#icon-menu"></use></svg> Tools</h5>
      <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas"></button>
    </div>
    <div class="offcanvas-body">
      <section class="tool-block">
        <h6><svg class="icon"><use href="#icon-key"></use></svg> Sign a nonce</h6>
        <p class="hint">Same identity keypair as <code>launcher.py</code> — signs whatever nonce your dashboard's Keys panel gives you.</p>
        <input class="filter-input" id="sign-nonce-input" placeholder="Paste the nonce here">
        <button class="btn mb-2" id="sign-nonce-btn">Sign</button>
        <div id="sign-result" style="display:none">
          <p class="hint mb-1">Public key</p>
          <div class="pubkey-box" id="sign-pubkey"></div>
          <p class="hint mt-2 mb-1">Signature (hex)</p>
          <div class="pubkey-box" id="sign-signature"></div>
        </div>
        <div class="error-code mt-1" id="sign-error" style="display:none"></div>
      </section>

      <hr>

      <section class="tool-block">
        <h6><svg class="icon"><use href="#icon-list"></use></svg> Active tunnels <span class="hint">tunnel_cache.db</span></h6>
        <div class="d-flex gap-2 mb-2">
          <button class="btn" id="tunnels-refresh-btn">Refresh</button>
          <button class="btn" id="tunnels-reset-btn"><svg class="icon"><use href="#icon-trash"></use></svg> Reset DB</button>
        </div>
        <table class="mtable" id="tunnels-table"><tbody></tbody></table>
      </section>

      <hr>

      <section class="tool-block">
        <h6><svg class="icon"><use href="#icon-send"></use></svg> Send PING <span class="hint">native mode only</span></h6>
        <input class="filter-input" id="ping-target-host" placeholder="target host (required)">
        <input class="filter-input" id="ping-target-port" type="number" placeholder="target port (optional)">
        <div class="form-check">
          <input class="form-check-input" type="checkbox" id="ping-with-encryption">
          <label class="form-check-label" for="ping-with-encryption">with_encryption</label>
        </div>
        <input class="filter-input" id="ping-pubkey-path" placeholder="recipient public key path" style="display:none">
        <div class="form-check mb-2">
          <input class="form-check-input" type="checkbox" id="ping-with-timing-defense">
          <label class="form-check-label" for="ping-with-timing-defense">with_timing_defense</label>
        </div>
        <button class="btn" id="ping-send-btn">Send PING</button>
        <div class="mt-2" id="ping-result"></div>
      </section>

      <hr>

      <a class="hint" href="{ztrapps_url}" target="_blank" rel="noopener">
        <svg class="icon"><use href="#icon-ext-link"></use></svg> ztrapps on GitHub
      </a>
    </div>
  </div>

<script src="/static/vendor/jquery.min.js"></script>
<script src="/static/vendor/bootstrap.bundle.min.js"></script>
<script src="/static/dashboard.js"></script>
</body>
</html>
""".format(ztrapps_url=ZTRAPPS_URL)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, status, content_type, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/":
            self._send(200, "text/html; charset=utf-8", PAGE.encode("utf-8"))
        elif self.path == "/api/data":
            with _state_lock:
                packets = list(_recent_packets)
            data = {
                "tunnels": active_tunnels(),
                "ra_errors": recent_ra_errors(),
                "traffic": {**_traffic_status, "recent": packets},
                "chain": _route["chain"] if _route else None,
                "route": {
                    "route_id": _route["route_id"],
                    "identifier": _route["identifier"],
                    "secret_key": _route["secret_key"],
                } if _route else None,
            }
            self._send(200, "application/json", json.dumps(data).encode("utf-8"))
        elif self.path == "/api/tunnels":
            self._send(200, "application/json", json.dumps(list_tunnels()).encode("utf-8"))
        elif self.path.startswith("/static/"):
            self._serve_static(self.path[len("/static/"):])
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {}

        if self.path == "/api/sign":
            result = sign_nonce(body.get("nonce", "").strip())
        elif self.path == "/api/tunnels/reset":
            result = reset_tunnels()
        elif self.path == "/api/ping":
            result = run_ping(
                target_host=body.get("target_host", "").strip(),
                target_port=body.get("target_port") or None,
                with_encryption=bool(body.get("with_encryption")),
                recipient_pubkey_path=(body.get("recipient_pubkey_path") or "").strip() or None,
                with_timing_defense=bool(body.get("with_timing_defense")),
            )
        else:
            self._send(404, "text/plain", b"not found")
            return
        self._send(200, "application/json", json.dumps(result).encode("utf-8"))

    def _serve_static(self, name):
        # normpath collapses any ../ first; the startswith check afterward
        # is belt-and-suspenders — together they mean this only ever serves
        # a file that resolves to somewhere inside STATIC_DIR, vendor/
        # subfolder included.
        path = os.path.abspath(os.path.join(STATIC_DIR, os.path.normpath(name).lstrip(os.sep)))
        if not path.startswith(STATIC_DIR + os.sep):
            self._send(404, "text/plain", b"not found")
            return
        content_type = _STATIC_CONTENT_TYPES.get(os.path.splitext(path)[1])
        if not content_type or not os.path.isfile(path):
            self._send(404, "text/plain", b"not found")
            return
        with open(path, "rb") as f:
            self._send(200, content_type, f.read())


def main():
    parser = argparse.ArgumentParser(description="Local dashboard for this machine's ZTRelay tunnel activity.")
    parser.add_argument("--host", default=None, help=f"defaults to {DEFAULT_HOST_CANDIDATE} if this machine has that address, else {FALLBACK_HOST}")
    parser.add_argument("--port", type=int, default=8088, help="dashboard's own HTTP port (default: 8088)")
    parser.add_argument("--config-file", default=None, help="a .ztr file in routes/ — shows its hop chain and enables live traffic capture")
    parser.add_argument("--iface", default=None, help="network interface for live traffic capture (default: let scapy pick)")
    args = parser.parse_args()

    global _route, _config_file
    _config_file = args.config_file
    _route = load_route(args.config_file)

    if _route and _route["chain"] and _route["services_ports"]:
        start_sniffer(_route["chain"][0]["address"], _route["services_ports"], args.iface)

    host = resolve_host(args.host)
    with socketserver.ThreadingTCPServer((host, args.port), Handler) as httpd:
        print(f"Dashboard running at http://{host}:{args.port}/")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
