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
STATIC_DIR = os.path.join(SCRIPT_DIR, "static")
_STATIC_CONTENT_TYPES = {".css": "text/css", ".js": "application/javascript"}

DEFAULT_HOST_CANDIDATE = "10.10.15.10"
FALLBACK_HOST = "127.0.0.1"

_state_lock = threading.Lock()
_recent_packets = deque(maxlen=30)
_traffic_status = {"enabled": False, "reason": "pass --config-file to enable this"}
_chain = None


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
    """Reads chain + services_ports straight from the .ztr JSON — no need
    for the full RelayConfig/RelayClient setup just to look at this."""
    if not config_file:
        return None, []
    path = os.path.join(_ZTR_CLIENT_DIR, "routes", config_file)
    try:
        with open(path) as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None, []
    chain = [{"address": h.get("address"), "status": h.get("status")} for h in config.get("chain", [])]
    ports = config.get("hop_settings", {}).get("services_ports", [])
    return chain, ports


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


PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>ZTRelay client dashboard</title>
<link rel="stylesheet" href="/static/dashboard.css">
</head>
<body>
  <h1>ZTRelay client dashboard</h1>
  <div class="sub">This machine only — read-only view of tunnel_cache.db and ztrclient_ra-error.log.</div>

  <div class="toolbar">
    <button id="pause-btn">Pause</button>
    <button id="refresh-btn">Refresh now</button>
    <span id="last-updated"></span>
  </div>

  <div class="grid">
    <div class="card">
      <div class="label">Active tunnels</div>
      <div class="value ok" id="total-tunnels">&mdash;</div>
    </div>
    <div class="card">
      <div class="label">Live traffic capture</div>
      <div class="value off" id="traffic-status">&mdash;</div>
    </div>
  </div>

  <section id="chain-section" style="display:none">
    <h2>Hop chain</h2>
    <div class="chain" id="chain"></div>
  </section>

  <section>
    <h2>Tunnels by port <span class="hint">click a row to filter live traffic below</span></h2>
    <table id="ports-table"><tbody></tbody></table>
  </section>

  <section>
    <h2>Recent hop-authorization errors</h2>
    <input class="filter-input" id="error-filter" type="search" placeholder="Filter by code or message&hellip;">
    <table id="errors-table"><tbody></tbody></table>
  </section>

  <section id="traffic-section" style="display:none">
    <h2>Live traffic to entry hop <span class="hint" id="traffic-hint"></span></h2>
    <table id="traffic-table"><tbody></tbody></table>
  </section>

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
                "chain": _chain,
            }
            self._send(200, "application/json", json.dumps(data).encode("utf-8"))
        elif self.path.startswith("/static/"):
            self._serve_static(self.path[len("/static/"):])
        else:
            self._send(404, "text/plain", b"not found")

    def _serve_static(self, name):
        # basename() strips any directory component (including ../) — this
        # only ever serves a file directly inside STATIC_DIR, never anything
        # a crafted path could walk it out of.
        ext = os.path.splitext(name)[1]
        content_type = _STATIC_CONTENT_TYPES.get(ext)
        path = os.path.join(STATIC_DIR, os.path.basename(name))
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

    global _chain
    _chain, services_ports = load_route(args.config_file)

    if _chain and services_ports:
        start_sniffer(_chain[0]["address"], services_ports, args.iface)

    host = resolve_host(args.host)
    with socketserver.ThreadingTCPServer((host, args.port), Handler) as httpd:
        print(f"Dashboard running at http://{host}:{args.port}/")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
