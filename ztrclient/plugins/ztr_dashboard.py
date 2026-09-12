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
<style>
  :root {
    --bg: #0f1417; --panel: #161d21; --border: #263038; --text: #dbe3e8;
    --muted: #7c8992; --accent: #4fb3a9; --danger: #e0705f;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    padding: 32px;
  }
  h1 { font-size: 18px; font-weight: 600; margin: 0 0 4px; }
  .sub { color: var(--muted); font-size: 13px; margin-bottom: 28px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 18px 20px;
  }
  .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
  .card .value { font-size: 28px; font-weight: 600; margin-top: 6px; font-variant-numeric: tabular-nums; }
  .card .value.ok { color: var(--accent); }
  .card .value.off { color: var(--muted); font-size: 15px; font-weight: 400; }
  section { margin-bottom: 28px; }
  section h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 0 0 10px; }
  table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  th, td { text-align: left; padding: 8px 14px; font-size: 13px; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 500; }
  tr:last-child td { border-bottom: none; }
  td.mono, th.mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  .error-code { color: var(--danger); }
  .empty { color: var(--muted); padding: 14px; text-align: center; }
  .chain { display: flex; align-items: center; gap: 0; overflow-x: auto; padding: 8px 0; }
  .hop {
    flex: 0 0 auto; background: var(--panel); border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 16px; font-family: ui-monospace, monospace; font-size: 12px; text-align: center;
  }
  .hop .role { color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: .04em; display: block; margin-bottom: 4px; }
  .arrow { flex: 0 0 auto; color: var(--border); font-size: 18px; padding: 0 8px; transition: color .3s; }
  .arrow.flowing { color: var(--accent); animation: pulse 1s ease-in-out infinite; }
  @keyframes pulse { 0%, 100% { opacity: .35; } 50% { opacity: 1; } }
</style>
</head>
<body>
  <h1>ZTRelay client dashboard</h1>
  <div class="sub">This machine only — read-only view of tunnel_cache.db and ztrclient_ra-error.log.</div>

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
    <h2>Tunnels by port</h2>
    <table id="ports-table"><tbody></tbody></table>
  </section>

  <section>
    <h2>Recent hop-authorization errors</h2>
    <table id="errors-table"><tbody></tbody></table>
  </section>

  <section id="traffic-section" style="display:none">
    <h2>Live traffic to entry hop</h2>
    <table id="traffic-table"><tbody></tbody></table>
  </section>

<script>
let lastPacketKey = null;
let flowingUntil = 0;
let lastData = null;

function emptyRow(cols, text) {
  return `<tr><td class="empty" colspan="${cols}">${text}</td></tr>`;
}

function render(data) {
  document.getElementById("total-tunnels").textContent = data.tunnels.total;

  const traffic = data.traffic;
  const statusEl = document.getElementById("traffic-status");
  if (traffic.enabled) {
    statusEl.textContent = "Live";
    statusEl.className = "value ok";
  } else {
    statusEl.textContent = traffic.reason || "off";
    statusEl.className = "value off";
  }

  const ports = Object.entries(data.tunnels.by_port);
  const portsBody = document.querySelector("#ports-table tbody");
  portsBody.innerHTML = ports.length
    ? ports.map(([p, c]) => `<tr><td class="mono">${p}</td><td>${c} active</td></tr>`).join("")
    : emptyRow(2, "No active tunnels right now.");

  const errorsBody = document.querySelector("#errors-table tbody");
  errorsBody.innerHTML = data.ra_errors.length
    ? data.ra_errors.map(e => `<tr><td class="mono">${e.time}</td><td class="error-code">${e.error_code}</td><td>${e.error}</td></tr>`).join("")
    : emptyRow(3, "No hop rejections logged.");

  const trafficSection = document.getElementById("traffic-section");
  if (traffic.enabled || traffic.recent.length) {
    trafficSection.style.display = "";
    const trafficBody = document.querySelector("#traffic-table tbody");
    trafficBody.innerHTML = traffic.recent.length
      ? traffic.recent.map(p => `<tr><td class="mono">${p.time}</td><td class="mono">${p.src}</td><td class="mono">${p.dst}</td><td>${p.length} bytes</td></tr>`).join("")
      : emptyRow(4, "Waiting for traffic...");
  } else {
    trafficSection.style.display = "none";
  }

  const chainSection = document.getElementById("chain-section");
  if (data.chain && data.chain.length) {
    chainSection.style.display = "";
    const chainEl = document.getElementById("chain");
    const roles = data.chain.map((h, i) => i === 0 ? "entry" : i === data.chain.length - 1 ? "exit" : "middle");

    if (traffic.recent.length) {
      const top = traffic.recent[0];
      const key = `${top.time}|${top.src}|${top.dst}|${top.length}`;
      if (key !== lastPacketKey) {
        lastPacketKey = key;
        flowingUntil = Date.now() + 4000;
      }
    }
    const arrowClass = Date.now() < flowingUntil ? "arrow flowing" : "arrow";

    chainEl.innerHTML = data.chain.map((h, i) =>
      (i > 0 ? `<span class="${arrowClass}">&rarr;</span>` : '') +
      `<div class="hop"><span class="role">${roles[i]}</span>${h.address}</div>`
    ).join("");
  } else {
    chainSection.style.display = "none";
  }
}

function poll() {
  fetch("/api/data").then(r => r.json()).then(data => { lastData = data; render(data); }).catch(() => {});
}
poll();
setInterval(poll, 3000);
// Redraws with the last known data more often than we re-fetch, purely so
// the chain's flow animation fades out on time instead of jumping every 3s.
setInterval(() => { if (lastData) render(lastData); }, 500);
</script>
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
        else:
            self._send(404, "text/plain", b"not found")


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
