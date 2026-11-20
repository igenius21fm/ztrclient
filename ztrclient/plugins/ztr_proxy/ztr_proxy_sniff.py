"""
ZTR Proxy — ZTR traffic sniffer (Scapy).

This watches the packets that travel between this computer and your ZTRelay hops
— the tunnel itself — on the wire, with Scapy. It is scoped to **ZTR traffic**:
the proxy's control port and the data lanes to your route's hops, not the rest of
the machine's internet traffic.

For each tunnel flow you see its hop, lane, direction, byte counts and timing;
select one and you can open its **payloads** — the actual on-the-wire bytes, as a
hex + ASCII dump — and save them (as a pcap, a hex dump, or raw bytes) if you want
to. ZTR frames are encrypted, so a lane's body is ciphertext; the sizes, timing,
lane and direction are still meaningful, and the control-port handshake is here
too.

An optional switch (`ztr_only=False`) widens the capture to everything, which also
tags web traffic that left the machine *outside* your route — a leak check — but
the default and the point of this tab is the ZTR tunnel.

Capturing packets needs privilege: run as root, or grant the Python binary
`CAP_NET_RAW` (`sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which
python3))`). Without it the engine reports a clear, non-fatal error and the proxy
keeps running untouched.

Nothing here sends a packet, writes to the network, or changes what the proxy
does. It only reads.
"""

from __future__ import annotations

import ipaddress
import math
import os
import shutil
import socket
import struct
import threading
import time
from collections import deque

# Scapy is imported lazily (in Sniffer.start) so the proxy and its window load
# fine on a machine that doesn't have it.
_scapy = None
_scapy_err = None

# The ports that carry ZTR traffic: the hop control ports, the five TCP data
# lanes, the health-test ports, and the five UDP data lanes.
ZTR_TCP_PORTS = {3477, 3478, 3489, 3490, 7781, 7783, 7784, 7785, 7786}
ZTR_UDP_PORTS = {6081, 6082, 6083, 6084, 6085}

PAYLOAD_CAP = 4096       # bytes kept per packet for the hex view
SAMPLES_PER_FLOW = 500   # packets kept per flow (for the viewer and pcap save)


def _load_scapy():
    global _scapy, _scapy_err
    if _scapy is not None or _scapy_err is not None:
        return _scapy
    try:
        import scapy.all as scapy  # noqa: E402
        _scapy = scapy
    except Exception as e:  # pragma: no cover - environment dependent
        _scapy_err = e
    return _scapy


def scapy_available():
    return _load_scapy() is not None


# ── Wireshark discovery ────────────────────────────────────────────────────────

# A capture we hand to Wireshark can be opened with the Wireshark GUI (best) or,
# failing that, read in a terminal with tshark. We look for either.
_WIRESHARK_CANDIDATES = (
    # macOS
    "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
    # Linux / Homebrew
    "/usr/bin/wireshark", "/usr/local/bin/wireshark", "/opt/homebrew/bin/wireshark",
    "/snap/bin/wireshark",
    # Windows
    r"C:\Program Files\Wireshark\Wireshark.exe",
    r"C:\Program Files (x86)\Wireshark\Wireshark.exe",
)

_TSHARK_CANDIDATES = (
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/homebrew/bin/tshark",
    r"C:\Program Files\Wireshark\tshark.exe",
)


def wireshark_path():
    """Best-effort absolute path to the Wireshark GUI, or None. Checks PATH first,
    then the usual install locations on macOS, Linux and Windows."""
    exe = shutil.which("wireshark")
    if exe:
        return exe
    for c in _WIRESHARK_CANDIDATES:
        if os.path.exists(c):
            return c
    return None


def tshark_path():
    """Best-effort absolute path to tshark (the terminal Wireshark), or None."""
    exe = shutil.which("tshark")
    if exe:
        return exe
    for c in _TSHARK_CANDIDATES:
        if os.path.exists(c):
            return c
    return None


# ── byte statistics ────────────────────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Entropy of `data` in bits per byte, 0.0–8.0. A value near 8.0 means the
    bytes look random — encrypted or compressed; a low value means there's
    structure (plaintext, headers, padding). Handy for confirming a ZTR lane's
    body really is ciphertext at a glance."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def entropy_verdict(ent: float) -> str:
    """A one-word read on an entropy value."""
    if ent >= 7.5:
        return "looks encrypted"
    if ent >= 6.0:
        return "high / likely encrypted"
    if ent >= 4.0:
        return "mixed"
    return "structured / plaintext"


def flow_crypto(kind, entropy, nbytes):
    """A per-flow read on whether the payload looks encrypted, for the flow list.
    Returns (label, level) where level is 'ok' | 'warn' | 'bad' | 'none'.

    Only **data lanes** raise a warning: their bodies are supposed to be
    ciphertext, so low entropy there is the signal that something is travelling
    in the clear. Control/health exchanges carry structure by design, so they're
    described but never flagged. Short samples are left unjudged ('—')."""
    if nbytes < 128:
        return ("—", "none")
    if kind != "data":
        if entropy >= 7.0:
            return ("encrypted", "none")
        if entropy >= 5.2:
            return ("mixed", "none")
        return ("plaintext", "none")
    # a ZTR data lane — this is where plaintext would be a leak
    if entropy >= 7.0:
        return ("encrypted ✓", "ok")
    if nbytes >= 512:
        if entropy < 5.2:
            return ("plaintext ⚠", "bad")
        return ("low entropy ⚠", "warn")
    return ("—", "none")


def extract_strings(data: bytes, minlen=4):
    """Printable ASCII runs of at least `minlen` characters — the classic
    `strings(1)`. On a ciphertext lane this is usually empty; on the control
    handshake or any plaintext it surfaces hostnames, headers and tokens."""
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minlen:
        out.append("".join(cur))
    return out


# ── address helpers ───────────────────────────────────────────────────────────

_PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "127.0.0.0/8", "::1/128", "fc00::/7", "fe80::/10",
    )
]


def _ip_obj(ip):
    try:
        return ipaddress.ip_address(ip)
    except ValueError:
        return None


def is_private(ip):
    obj = _ip_obj(ip)
    if obj is None:
        return False
    return any(obj in net for net in _PRIVATE_NETS)


def local_ipv4s():
    """Best-effort set of this machine's own IP addresses, so egress can be told
    from ingress. Uses the OS first, then Scapy's interface table if present."""
    ips = set()
    try:
        host = socket.gethostname()
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                for info in socket.getaddrinfo(host, None, fam):
                    ips.add(info[4][0])
            except OSError:
                pass
    except OSError:
        pass
    for probe in (("8.8.8.8", 80), ("2001:4860:4860::8888", 80)):
        try:
            s = socket.socket(socket.AF_INET if ":" not in probe[0] else socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(probe)
            ips.add(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    sc = _scapy
    if sc is not None:
        try:
            for iface in sc.get_if_list():
                try:
                    a = sc.get_if_addr(iface)
                    if a and a != "0.0.0.0":
                        ips.add(a)
                except Exception:
                    pass
        except Exception:
            pass
    ips.add("127.0.0.1")
    ips.add("::1")
    return ips


def ztr_bpf(hop_ips):
    """A capture filter that keeps only ZTR traffic — the route's hop IPs if we
    know them, otherwise the ZTR ports."""
    ips = [h for h in (hop_ips or ()) if h]
    if ips:
        return " or ".join(f"host {h}" for h in ips)
    tcp = " or ".join(f"tcp port {p}" for p in sorted(ZTR_TCP_PORTS))
    udp = " or ".join(f"udp port {p}" for p in sorted(ZTR_UDP_PORTS))
    return f"({tcp} or {udp})"


# ── name extraction (SNI / DNS), used only when ztr_only is off ────────────────

def parse_tls_sni(payload: bytes):
    """Return the SNI host from a TLS ClientHello in `payload`, or None."""
    try:
        if len(payload) < 6 or payload[0] != 0x16:
            return None
        pos = 5
        if payload[pos] != 0x01:
            return None
        pos += 4 + 2 + 32
        if pos >= len(payload):
            return None
        sid_len = payload[pos]; pos += 1 + sid_len
        if pos + 2 > len(payload):
            return None
        cs_len = struct.unpack("!H", payload[pos:pos + 2])[0]; pos += 2 + cs_len
        if pos + 1 > len(payload):
            return None
        comp_len = payload[pos]; pos += 1 + comp_len
        if pos + 2 > len(payload):
            return None
        ext_total = struct.unpack("!H", payload[pos:pos + 2])[0]; pos += 2
        end = min(len(payload), pos + ext_total)
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", payload[pos:pos + 4]); pos += 4
            if etype == 0x0000:
                if pos + 5 > len(payload):
                    return None
                name_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                name = payload[pos + 5:pos + 5 + name_len]
                try:
                    host = name.decode("idna") if name else None
                except Exception:
                    host = name.decode("latin-1", "ignore") or None
                return host or None
            pos += elen
    except Exception:
        return None
    return None


def _http_host(payload: bytes):
    try:
        text = payload[:2048].decode("latin-1", "ignore")
        for line in text.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip().split(":")[0] or None
    except Exception:
        return None
    return None


def hexdump(data: bytes, width=16, limit=PAYLOAD_CAP):
    """Classic offset / hex / ASCII dump of `data`, capped at `limit` bytes."""
    out = []
    data = data[:limit]
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        hexs = f"{hexs:<{width * 3 - 1}}"
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off:08x}  {hexs}  {asc}")
    if len(data) == limit:
        out.append(f"… (showing first {limit} bytes)")
    return "\n".join(out)


PAYLOAD_VIEWS = ("hex", "utf-8", "text", "strings")


def render_payload(data: bytes, mode: str = "hex") -> str:
    """A segment's bytes rendered for the payload viewer.
      hex     — offset / hex / ASCII dump (the default; always readable).
      utf-8   — decoded as UTF-8, undecodable bytes shown as the replacement
                character; useful where the payload really is text.
      text    — every byte shown as a Latin-1 character (tabs and newlines
                kept, other control bytes shown as '.'), so nothing is hidden.
      strings — just the printable runs (like `strings(1)`), one per line.
    ZTR data-lane frames are encrypted, so utf-8/text/strings will mostly look
    like noise there — the control-port handshake and any plaintext are where
    they pay off."""
    if not data:
        return "(no payload in this segment — header only)"
    if mode == "utf-8":
        return data.decode("utf-8", errors="replace")
    if mode == "text":
        return "".join(
            c if (c in "\t\n\r" or 32 <= ord(c) < 127 or ord(c) >= 160) else "."
            for c in data.decode("latin-1")
        )
    if mode == "strings":
        found = extract_strings(data)
        if not found:
            return "(no printable strings — this segment looks like ciphertext)"
        return "\n".join(found)
    return hexdump(data)


# ── the analyzer ──────────────────────────────────────────────────────────────

class Analyzer:
    """Aggregates ZTR packets into flows, keeping recent packets per flow so their
    payloads can be inspected and saved. Thread-safe."""

    MAX_FLOWS = 600

    def __init__(self):
        self._lock = threading.Lock()
        self.ztr_only = True
        self.hop_ips = set()
        self.listen_host = None
        self.listen_port = None
        self.local_ips = set()
        self.reset()

    def reset(self):
        with self._lock:
            self.flows = {}
            self.names = {}
            self.started = time.time()
            self.pkts = 0
            self.bytes = 0
            self.kept = 0           # packets within ZTR scope (what we store)
            self._rate_window = deque(maxlen=20)
            self._rate_window.append((time.time(), 0))
            self.proto_counts = {}

    def set_context(self, listen_host=None, listen_port=None, hop_ips=None,
                    local_ips=None, ztr_only=None):
        with self._lock:
            if listen_host is not None:
                self.listen_host = listen_host
            if listen_port is not None:
                self.listen_port = listen_port
            if hop_ips is not None:
                self.hop_ips = set(hop_ips)
            if local_ips is not None:
                self.local_ips = set(local_ips)
            if ztr_only is not None:
                self.ztr_only = bool(ztr_only)

    # -- classification ---------------------------------------------------------

    def _is_ztr(self, src, dst, sport, dport, l4):
        if src in self.hop_ips or dst in self.hop_ips:
            return True
        ports = ZTR_TCP_PORTS if l4 == "TCP" else (ZTR_UDP_PORTS if l4 == "UDP" else set())
        return bool(ports & {sport, dport})

    @staticmethod
    def _lane(port):
        if port in (3477, 3478):
            return "control"
        if port in (3489, 3490):
            return "health"
        if port in (7781, 7783, 7784, 7785, 7786):
            return f"lane {port}"
        if port in ZTR_UDP_PORTS:
            return f"udp {port}"
        return ""

    def _hop_side(self, src, dst, sport, dport):
        """(hop_ip, hop_port, direction) — direction 'up' is toward the hop."""
        if dst in self.hop_ips or dport in ZTR_TCP_PORTS or dport in ZTR_UDP_PORTS:
            return dst, dport, "up"
        if src in self.hop_ips or sport in ZTR_TCP_PORTS or sport in ZTR_UDP_PORTS:
            return src, sport, "down"
        # non-ZTR (only reached when ztr_only is off): up if we sent it
        if src in self.local_ips:
            return dst, dport, "up"
        return src, sport, "down"

    def _leak_tag(self, src, dst):
        """Only used when ztr_only is off: where a non-ZTR flow is going."""
        src_local, dst_local = src in self.local_ips, dst in self.local_ips
        if self.listen_host and dst == self.listen_host and not src_local:
            return "ingress"
        if src_local and not dst_local:
            return "local" if is_private(dst) else "direct"
        if dst_local and not src_local:
            return "local" if is_private(src) else "direct"
        return "local" if (is_private(src) and is_private(dst)) else "other"

    @staticmethod
    def _flow_entropy(f, cap=4096, max_segs=24):
        """Shannon entropy over a bounded sample of a flow's recent payload
        bytes — enough to tell ciphertext from plaintext without scanning
        everything. Returns (entropy, bytes_sampled)."""
        buf = bytearray()
        segs = 0
        for s in reversed(f["samples"]):
            d = s["data"]
            if d:
                buf += d
                segs += 1
                if len(buf) >= cap or segs >= max_segs:
                    break
        data = bytes(buf[:cap])
        return shannon_entropy(data), len(data)

    def _note_name(self, host, via):
        if not host:
            return
        host = host.lower().strip(".")
        now = time.time()
        n = self.names.get(host)
        if n:
            n["last"] = now; n["count"] += 1; n["via"].add(via)
        elif len(self.names) < 400:
            self.names[host] = {"first": now, "last": now, "count": 1, "via": {via}}

    # -- ingest -----------------------------------------------------------------

    def handle(self, pkt):
        sc = _scapy
        if sc is None:
            return
        try:
            if pkt.haslayer(sc.IP):
                ip = pkt[sc.IP]; src, dst = ip.src, ip.dst
            elif pkt.haslayer(sc.IPv6):
                ip = pkt[sc.IPv6]; src, dst = ip.src, ip.dst
            else:
                return
            size = len(pkt)
            sport = dport = 0
            payload = b""
            if pkt.haslayer(sc.TCP):
                l4 = "TCP"; seg = pkt[sc.TCP]; sport, dport = int(seg.sport), int(seg.dport)
                payload = bytes(seg.payload)
            elif pkt.haslayer(sc.UDP):
                l4 = "UDP"; seg = pkt[sc.UDP]; sport, dport = int(seg.sport), int(seg.dport)
                payload = bytes(seg.payload)
            else:
                l4 = "IP"

            now = time.time()
            with self._lock:
                self.pkts += 1
                self.bytes += size

                ztr = self._is_ztr(src, dst, sport, dport, l4)
                if self.ztr_only and not ztr:
                    # count it toward totals/rate but don't store it
                    self._rate_window and None
                    return
                self.kept += 1

                hop_ip, hop_port, direction = self._hop_side(src, dst, sport, dport)
                lane = self._lane(hop_port) if ztr else ""
                if ztr:
                    kind = "control" if hop_port in (3477, 3478) else ("health" if hop_port in (3489, 3490) else "data")
                    proto = "ZTR"
                    tag = "ztr"
                else:
                    kind = "web"
                    proto = self._proto_for(sport, dport, l4)
                    tag = self._leak_tag(src, dst)
                self.proto_counts[kind] = self.proto_counts.get(kind, 0) + 1

                # flow key: hop side + local side, so both directions share a row
                local_ip = src if direction == "up" else dst
                local_port = sport if direction == "up" else dport
                fid = f"{l4}|{hop_ip}:{hop_port}|{local_ip}:{local_port}"
                f = self.flows.get(fid)
                if f is None:
                    if len(self.flows) >= self.MAX_FLOWS:
                        oldest = min(self.flows, key=lambda k: self.flows[k]["last"])
                        self.flows.pop(oldest, None)
                    f = {
                        "fid": fid, "l4": l4, "ztr": ztr, "kind": kind, "lane": lane,
                        "proto": proto, "tag": tag,
                        "hop": hop_ip, "hop_port": hop_port,
                        "local": local_ip, "local_port": local_port,
                        "first": now, "last": now,
                        "pkts_up": 0, "pkts_down": 0, "bytes_up": 0, "bytes_down": 0,
                        "name": None,
                        "samples": deque(maxlen=SAMPLES_PER_FLOW),
                    }
                    self.flows[fid] = f
                f["last"] = now
                if direction == "up":
                    f["pkts_up"] += 1; f["bytes_up"] += size
                else:
                    f["pkts_down"] += 1; f["bytes_down"] += size
                f["samples"].append({"ts": now, "dir": direction, "port": hop_port,
                                     "size": size, "plen": len(payload),
                                     "data": payload[:PAYLOAD_CAP], "pkt": pkt})

                if not ztr:
                    if dport == 443 and payload[:1] == b"\x16":
                        host = parse_tls_sni(payload)
                        if host:
                            f["name"] = host; self._note_name(host, "TLS")
                    elif dport == 80:
                        host = _http_host(payload)
                        if host:
                            f["name"] = host; self._note_name(host, "HTTP")
                    elif (sport == 53 or dport == 53) and pkt.haslayer(getattr(sc, "DNS", ())):
                        try:
                            dns = pkt[sc.DNS]
                            if getattr(dns, "qd", None) is not None:
                                q = dns.qd.qname
                                q = q.decode("idna", "ignore") if isinstance(q, bytes) else str(q)
                                q = q.rstrip(".")
                                if q:
                                    f["name"] = q; self._note_name(q, "DNS")
                        except Exception:
                            pass
        except Exception:
            return

    @staticmethod
    def _proto_for(sport, dport, l4):
        if l4 == "UDP":
            if 53 in (sport, dport):
                return "DNS"
            if 443 in (sport, dport):
                return "QUIC"
            return "UDP"
        if 443 in (sport, dport):
            return "TLS"
        if 80 in (sport, dport):
            return "HTTP"
        return "TCP"

    # -- read-out ---------------------------------------------------------------

    def snapshot(self, top=300):
        with self._lock:
            now = time.time()
            self._rate_window.append((now, self.pkts))
            rate = 0.0
            if len(self._rate_window) >= 2:
                t0, p0 = self._rate_window[0]
                dt = now - t0
                if dt > 0:
                    rate = (self.pkts - p0) / dt
            rows, up_tot, down_tot, hops = [], 0, 0, set()
            lane_counts = {}
            for f in self.flows.values():
                up_tot += f["bytes_up"]; down_tot += f["bytes_down"]
                if f["ztr"]:
                    hops.add(f["hop"])
                    lane_counts[f["lane"] or f["kind"]] = lane_counts.get(f["lane"] or f["kind"], 0) + 1
                ent, nb = self._flow_entropy(f)
                clabel, clevel = flow_crypto(f["kind"], ent, nb)
                rows.append({
                    "fid": f["fid"], "l4": f["l4"], "ztr": f["ztr"], "kind": f["kind"],
                    "lane": f["lane"], "proto": f["proto"], "tag": f["tag"],
                    "hop": f["hop"], "hop_port": f["hop_port"],
                    "local": f["local"], "name": f["name"],
                    "pkts": f["pkts_up"] + f["pkts_down"],
                    "up": f["bytes_up"], "down": f["bytes_down"],
                    "bytes": f["bytes_up"] + f["bytes_down"],
                    "first": f["first"], "last": f["last"], "age": now - f["last"],
                    "entropy": ent, "crypto": clabel, "crypto_level": clevel,
                })
            rows.sort(key=lambda r: r["last"], reverse=True)
            direct = [r for r in rows if r["tag"] == "direct"]
            leaky = [r for r in rows if r["crypto_level"] == "bad"]
            return {
                "running": True,
                "started": self.started,
                "elapsed": now - self.started,
                "ztr_only": self.ztr_only,
                "pkts": self.pkts, "kept": self.kept, "bytes": self.bytes,
                "up": up_tot, "down": down_tot, "rate": rate,
                "flow_count": len(self.flows),
                "hops": sorted(hops),
                "lane_counts": lane_counts,
                "proto_counts": dict(self.proto_counts),
                "flows": rows[:top],
                "direct": direct[:50], "direct_count": len(direct),
                "leaky_count": len(leaky),
                "insight": self._insight(hops, lane_counts, direct, leaky),
            }

    def _insight(self, hops, lanes, direct, leaky=()):
        if leaky:
            lanes_hit = sorted({r["lane"] or "data lane" for r in leaky})
            return ("warn", f"{len(leaky)} data lane(s) carrying readable payload — not ciphertext: "
                    + ", ".join(lanes_hit[:4]) + (" …" if len(lanes_hit) > 4 else "")
                    + ". Open the payload to see what's in the clear.")
        if not self.ztr_only and direct:
            names = sorted({r["name"] or r["hop"] for r in direct})
            return ("warn", f"{len(direct)} flow(s) left this machine outside your route: " +
                    ", ".join(names[:4]) + (" …" if len(names) > 4 else ""))
        if hops:
            lane_n = sum(1 for k in lanes if k.startswith(("lane", "udp")))
            ctrl = lanes.get("control", 0)
            return ("ok", f"Watching ZTR traffic to {len(hops)} hop(s) — {lane_n} data lane(s) and "
                          f"{ctrl} control exchange(s). Select a flow to open its payloads.")
        return ("info", "No ZTR traffic captured yet. Start the proxy and send something through it.")

    # -- payload inspection / save ---------------------------------------------

    def flow_detail(self, fid, max_samples=400):
        with self._lock:
            f = self.flows.get(fid)
            if not f:
                return None
            samples = list(f["samples"])[-max_samples:]
            return {
                "fid": fid, "l4": f["l4"], "ztr": f["ztr"], "kind": f["kind"],
                "lane": f["lane"], "hop": f["hop"], "hop_port": f["hop_port"],
                "local": f["local"], "name": f["name"],
                "pkts": f["pkts_up"] + f["pkts_down"],
                "up": f["bytes_up"], "down": f["bytes_down"],
                "first": f["first"], "last": f["last"],
                "samples": [{"ts": s["ts"], "dir": s["dir"], "port": s["port"],
                             "size": s["size"], "plen": s["plen"], "data": s["data"]}
                            for s in samples],
            }

    def save_flow(self, fid, path, fmt="pcap"):
        """Write a flow's captured packets to `path`. fmt: pcap | hex | raw.
        Returns the number of packets/segments written."""
        with self._lock:
            f = self.flows.get(fid)
            samples = list(f["samples"]) if f else []
        if not samples:
            return 0
        if fmt == "pcap":
            sc = _load_scapy()
            if sc is None:
                raise RuntimeError("Scapy isn't available to write a pcap.")
            sc.wrpcap(path, [s["pkt"] for s in samples])
            return len(samples)
        if fmt == "raw":
            with open(path, "wb") as fh:
                for s in samples:
                    fh.write(s["data"])
            return len(samples)
        # hex dump (text, with a per-segment header)
        with open(path, "w") as fh:
            fh.write(f"# ZTR flow {fid}\n# {len(samples)} segments\n\n")
            for i, s in enumerate(samples):
                arrow = "->" if s["dir"] == "up" else "<-"
                fh.write(f"--- #{i} {arrow} hop  {s['size']} B on wire, {s['plen']} B payload  "
                         f"@ {time.strftime('%H:%M:%S', time.localtime(s['ts']))}\n")
                fh.write(hexdump(s["data"]) + "\n\n")
        return len(samples)

    def packet_count(self):
        """Total packets held across every flow (what save_all would write)."""
        with self._lock:
            return sum(len(f["samples"]) for f in self.flows.values())

    def save_all(self, path):
        """Write every captured packet across all flows to a single pcap, in
        time order — the whole ZTR conversation in one file for Wireshark.
        Returns the packet count."""
        with self._lock:
            tagged = []
            for f in self.flows.values():
                for s in f["samples"]:
                    pkt = s.get("pkt")
                    if pkt is not None:
                        tagged.append((s["ts"], pkt))
        if not tagged:
            return 0
        tagged.sort(key=lambda t: t[0])
        sc = _load_scapy()
        if sc is None:
            raise RuntimeError("Scapy isn't available to write a pcap.")
        sc.wrpcap(path, [p for _, p in tagged])
        return len(tagged)


# ── the sniffer ───────────────────────────────────────────────────────────────

class Sniffer:
    """Owns a Scapy AsyncSniffer and an Analyzer. Safe to start/stop repeatedly."""

    def __init__(self):
        self.analyzer = Analyzer()
        self._sniffer = None
        self.iface = None
        self.bpf = ""
        self.ztr_only = True
        self.error = None
        self.running = False

    def interfaces(self):
        sc = _load_scapy()
        if sc is None:
            return []
        try:
            return list(sc.get_if_list())
        except Exception:
            return []

    def start(self, iface=None, bpf="", listen_host=None, listen_port=None,
              hop_ips=None, ztr_only=True):
        if self.running:
            return True
        sc = _load_scapy()
        if sc is None:
            self.error = f"Scapy isn't installed ({_scapy_err}). Install it with: pip install scapy"
            return False
        self.error = None
        self.iface = iface or None
        self.ztr_only = bool(ztr_only)
        hop_ips = set(hop_ips or ())
        # default the filter to ZTR scope unless the user gave one
        self.bpf = (bpf or "").strip() or (ztr_bpf(hop_ips) if ztr_only else "")
        self.analyzer.reset()
        self.analyzer.set_context(listen_host=listen_host, listen_port=listen_port,
                                  hop_ips=hop_ips, local_ips=local_ipv4s(), ztr_only=ztr_only)

        # Pre-flight: open a capture socket synchronously so the real cause (no
        # permission, a bad interface) surfaces here instead of in the thread.
        try:
            listen = sc.conf.L2listen
            sock = listen(iface=self.iface) if self.iface else listen()
            sock.close()
        except PermissionError:
            self.error = ("No permission to capture packets. Run the proxy as root, or grant capture rights once:\n"
                          "  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))")
            return False
        except OSError as e:
            if getattr(e, "errno", None) in (1, 13):
                self.error = ("No permission to capture packets. Run the proxy as root, or grant capture rights once:\n"
                              "  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))")
            else:
                self.error = f"Couldn't open a capture on {self.iface or 'the default interface'}: {e}"
            return False
        except Exception as e:
            self.error = f"Couldn't open a capture on {self.iface or 'the default interface'}: {e}"
            return False

        try:
            kwargs = dict(prn=self.analyzer.handle, store=False)
            if self.iface:
                kwargs["iface"] = self.iface
            if self.bpf:
                kwargs["filter"] = self.bpf
            self._sniffer = sc.AsyncSniffer(**kwargs)
            self._sniffer.start()
            self.running = True
            return True
        except Exception as e:
            self.error = f"Couldn't start the sniffer: {e}"
            self._sniffer = None
            return False

    def stop(self):
        self.running = False
        s, self._sniffer = self._sniffer, None
        if s is not None:
            try:
                s.stop()
            except Exception:
                pass

    def update_context(self, **kw):
        self.analyzer.set_context(**kw)

    def snapshot(self):
        if not self.running:
            return {"running": False, "error": self.error}
        snap = self.analyzer.snapshot()
        snap["iface"] = self.iface or "(default)"
        snap["bpf"] = self.bpf or "(all IP)"
        snap["error"] = self.error
        return snap

    def flow_detail(self, fid):
        return self.analyzer.flow_detail(fid)

    def save_flow(self, fid, path, fmt="pcap"):
        return self.analyzer.save_flow(fid, path, fmt)

    def save_all(self, path):
        return self.analyzer.save_all(path)

    def packet_count(self):
        return self.analyzer.packet_count()


# ── tiny CLI for testing on a box without the window ──────────────────────────

def _cli(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="ZTR Proxy Scapy sniffer — standalone test")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--filter", default="")
    ap.add_argument("--seconds", type=float, default=10.0)
    ap.add_argument("--hop", action="append", default=[], help="ZTR hop IP (repeatable)")
    ap.add_argument("--all", action="store_true", help="capture everything, not just ZTR")
    ap.add_argument("--save", default=None, help="write the busiest flow's packets to this pcap")
    args = ap.parse_args(argv)

    s = Sniffer()
    if not s.start(iface=args.iface, bpf=args.filter, hop_ips=set(args.hop), ztr_only=not args.all):
        print("ERROR:", s.error)
        return 1
    print(f"capturing {'all' if args.all else 'ZTR'} on {s.iface or '(default)'} "
          f"(filter: {s.bpf or 'none'}) for {args.seconds:.0f}s …")
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    snap = s.snapshot()
    print(f"\n{snap['pkts']} packets seen, {snap['kept']} in scope, {snap['flow_count']} flows, {snap['rate']:.1f} pkt/s")
    print("hops:", snap["hops"], "| lanes:", snap["lane_counts"])
    lvl, msg = snap["insight"]
    print(f"insight [{lvl}]: {msg}")
    print("\nflows:")
    for r in snap["flows"][:15]:
        print(f"  {r['kind']:<7} {r['lane'] or r['proto']:<10} hop {r['hop']}:{r['hop_port']:<5} "
              f"up {r['up']:>8} down {r['down']:>8}  pkts {r['pkts']:>4}  {r['name'] or ''}")
    if args.save and snap["flows"]:
        busiest = max(snap["flows"], key=lambda r: r["bytes"])
        n = s.save_flow(busiest["fid"], args.save, "pcap")
        print(f"\nsaved {n} packets of {busiest['fid']} -> {args.save}")
    s.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
