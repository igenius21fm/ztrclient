"""
Local, read-only dashboard: active tunnels per port (from tunnel_cache.db),
recent hop-authorization errors (from logs/ztrclient_ra-error.log), and,
with --config-file and enough privileges, a live feed of this machine's
traffic to its entry hop.

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
import threading
import time
from collections import deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_ZTR_CLIENT_DIR = os.path.dirname(SCRIPT_DIR)
DB_PATH = os.path.join(_ZTR_CLIENT_DIR, "tunnel_cache.db")
RA_ERROR_LOG = os.path.join(_ZTR_CLIENT_DIR, "logs", "ztrclient_ra-error.log")
STATIC_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "static"))
_STATIC_CONTENT_TYPES = {".css": "text/css", ".js": "application/javascript", ".map": "application/json"}

DEFAULT_HOST_CANDIDATE = "10.10.15.10"
FALLBACK_HOST = "127.0.0.1"

_state_lock = threading.Lock()
_recent_packets = deque(maxlen=30)
_traffic_status = {"enabled": False, "reason": "pass --config-file to enable this"}
_route = None


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

<script src="/static/vendor/jquery.min.js"></script>
<script src="/static/vendor/bootstrap.bundle.min.js"></script>
<script src="/static/dashboard.js"></script>
</body>
</html>
"""


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
                "route": {"identifier": _route["identifier"], "secret_key": _route["secret_key"]} if _route else None,
            }
            self._send(200, "application/json", json.dumps(data).encode("utf-8"))
        elif self.path.startswith("/static/"):
            self._serve_static(self.path[len("/static/"):])
        else:
            self._send(404, "text/plain", b"not found")

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

    global _route
    _route = load_route(args.config_file)

    if _route and _route["chain"] and _route["services_ports"]:
        start_sniffer(_route["chain"][0]["address"], _route["services_ports"], args.iface)

    host = resolve_host(args.host)
    with socketserver.ThreadingTCPServer((host, args.port), Handler) as httpd:
        print(f"Dashboard running at http://{host}:{args.port}/")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
