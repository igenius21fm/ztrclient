"""
A local proxy backed by ztr_https.py — point curl, a browser, or any other
proxy-aware client at it and its traffic goes through an authorized ZTRelay
tunnel instead of your real network path. One port speaks both HTTP-proxy and
SOCKS5.

    python3 plugins/ztr_proxy/ztr_proxy.py --config-file route.ztr

    curl -x http://10.10.15.10:8095 https://example.com/path
    curl -x http://10.10.15.10:8095 http://example.com/path
    curl --socks5-hostname 10.10.15.10:8095 https://example.com/path

The proxy listens on 10.10.15.10 (the local address ZTRelay's installer sets
up) when this machine has it, and on 127.0.0.1 otherwise; the address it chose
is printed when it starts. --host picks a different one.

Use socks5h / --socks5-hostname (the proxy resolves the name), not plain
socks5: with plain socks5 the client looks the name up itself, outside the
tunnel, which defeats the point.

Three request shapes, handled differently:

- Plain HTTP (an absolute-URI request line, e.g. "GET http://host/path
  HTTP/1.1") is fully proxied: this process makes the real request itself,
  through the tunnel, via ztr_https.Session.request(), and relays the real
  response — status, headers, streamed body — straight back to the client.
  It behaves like a proxy hop, not like a browser: redirects are passed to
  the client rather than followed, cookies pass through untouched and are
  never kept or shared between clients, and the body is relayed exactly as
  the target sent it (a gzip body stays gzip, with a matching
  Content-Encoding and Content-Length) so the client decodes it itself.

- HTTPS goes through CONNECT (e.g. "CONNECT host:443 HTTP/1.1") the normal
  way any forward proxy handles it: this process opens the tunnel to
  host:443 and then just splices raw bytes between the client and that
  tunnel, unmodified, in both directions. The TLS handshake happens
  directly between the client and the real target, right through that
  raw pipe — this process never touches the decrypted content and
  couldn't, since it never terminates that TLS session at all. That's not
  interception; it's exactly the same blind byte-relay relationship the
  ZTRelay hops themselves already have to the traffic, just ending one hop
  earlier, at this machine.

- SOCKS5 (CONNECT only) is the same blind splice, for clients that speak
  SOCKS instead — most browsers' proxy settings, ssh's ProxyCommand, and
  anything that can't do an HTTP proxy. No authentication (it listens on
  the local machine only, by default).

This process is not, and cannot be turned into, a traffic-inspecting MITM
proxy — that needs terminating TLS toward the client with a locally
generated, on-the-fly certificate (a local CA, dynamic per-domain signing,
the client configured to trust it) which nothing here builds. ztr_https.py
only ever drives TLS as a client, by hand, over the tunnel — it has no
server-side TLS/certificate machinery to give this the other half of that.
"""
import argparse
import collections
import http.server
import itertools
import os
import select
import socket
import socketserver
import struct
import sys
import threading
import time
from urllib.parse import urlsplit

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PLUGINS_DIR = os.path.dirname(SCRIPT_DIR)
_ZTR_CLIENT_DIR = os.path.dirname(_PLUGINS_DIR)
sys.path.insert(0, _ZTR_CLIENT_DIR)
sys.path.insert(0, os.path.join(_ZTR_CLIENT_DIR, "utils"))
sys.path.insert(0, _PLUGINS_DIR)  # ztr_https.py lives beside this folder
sys.path.insert(0, SCRIPT_DIR)

import ztr_https  # noqa: E402
import ztr_proxy_guard  # noqa: E402
from ztrClient import ZTRClientError, TunnelError, NetworkError  # noqa: E402

# Headers that describe one hop (client<->proxy, or proxy<->target) rather than
# the message itself — never passed on in either direction. Anything the
# Connection header names is hop-by-hop too (see _connection_listed()).
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
DEFAULT_HOST_CANDIDATE = "10.10.15.10"
FALLBACK_HOST = "127.0.0.1"
MAX_REQUEST_BODY = 512 * 1024 * 1024  # a request body is held in memory while it's sent through the tunnel
# What a hop says when it could not reach the next hop, or could not reach the registry to check the route. A setup
# that ends in "None" got no usable answer at all: the entry hop was slow to answer, hung up, or refused the request
# in a way the client cannot read (for instance because it arrived more than a few seconds after being stamped).
TRANSIENT_HOP_ERRORS = ("ERROR_CONNECTION", "REGISTRY_UNAVAILABLE")
# Opening a tunnel occasionally fails because a hop couldn't reach the next one ("ERROR_CONNECTION"). That happens
# while the tunnel is being authorized, before a single request byte is sent, so trying again is always safe — and
# a new attempt picks a lane afresh, which usually avoids whatever just failed.
OPEN_ATTEMPTS = 3
OPEN_RETRY_PAUSE = 0.4
# Warm tunnels: authorizing a tunnel takes seconds, so after a connection to host:port is handed out, one more is
# authorized in the background for that same target. The next connection to it starts instantly. (A tunnel is bound
# to its target when it's authorized, so a spare can only serve the same host and port.)
WARM_MAX_AGE = 150      # seconds a spare may wait unused before it's thrown away
WARM_MAX_TARGETS = 16   # how many different targets keep a spare at once
# A spare costs every hop on the route real work (a few hundred milliseconds of CPU each), and a page load touches
# dozens of hosts that are never contacted again. So a spare is prepared only for a target that has proved to be
# reused: asked for at least WARM_MIN_USES times within WARM_REPEAT_WINDOW seconds, or one whose spare was just used.
WARM_MIN_USES = 2
WARM_REPEAT_WINDOW = 60
# Pinned targets (see ProxySession.pin) are renewed once their spare has used this share of its allowed age.
PIN_RENEW_AT = 0.7
PIN_CHECK_EVERY = 5  # seconds
# A spare the relay turns away (typically because the public address changed since it was authorized) shows itself by
# the tunnel ending without a single reply byte. Within this window, and while what the client sent still fits in the
# buffer, the connection is quietly re-authorized and the client's bytes replayed.
RECOVERY_WINDOW = 3.0
RECOVERY_BUFFER = 64 * 1024


def _status_text(text):
    """An error message made safe for an HTTP status line, which can only carry plain Latin-1 on one line."""
    return " ".join(str(text).split()).encode("latin-1", "replace").decode("latin-1")


class Telemetry:
    """What the proxy has been doing: counters, the connections open right now, the last few hundred that ended,
    per-host totals, a log, and two short time series. Nothing here affects how traffic is handled; a window (the GUI)
    reads it with snapshot(). Each connection costs a few updates under one lock."""

    RECENT = 400
    LOG_LINES = 1000
    SERIES = 240  # seconds of history kept for the charts

    def __init__(self):
        self._lock = threading.Lock()
        self.guard = None  # the blocklist / alert rules (set below); told about each connection as it starts, fails, ends
        self.reset()

    def reset(self):
        with self._lock:
            self.started = time.time()
            self.counters = collections.Counter()
            self.active = {}
            self.recent = collections.deque(maxlen=self.RECENT)
            self.hosts = {}
            self.logs = collections.deque(maxlen=self.LOG_LINES)
            self.setup_series = collections.deque(maxlen=self.SERIES)   # (time, seconds to get a tunnel, warm?)
            self.rate_series = collections.deque(maxlen=self.SERIES)    # (time, bytes up in the last second, bytes down)
            self._ids = itertools.count(1)
            self._sampled = (time.time(), 0, 0)
            self._closers = {}

    # -- connections
    def conn_start(self, kind, host, port, detail="", observe=True):
        with self._lock:
            cid = next(self._ids)
            record = {"id": cid, "kind": kind, "host": host, "port": port, "detail": detail, "state": "opening",
                      "started": time.time(), "setup": None, "warm": False, "up": 0, "down": 0,
                      "status": None, "error": None, "ended": None}
            self.active[cid] = record
            self.counters["connections"] += 1
            snapshot = dict(record)
        if observe and self.guard:
            self.guard.on_start(snapshot)
        return cid

    def conn_blocked(self, cid, entry):
        """The connection was refused because its host is on the blocklist (no tunnel was opened for it)."""
        with self._lock:
            c = self.active.pop(cid, None)
            self._closers.pop(cid, None)
            if c is None:
                return
            c.update(state="blocked", error=f"blocked: {entry['pattern']}", ended=time.time())
            self.counters["blocked"] += 1
            self.recent.appendleft(c)
            snapshot = dict(c)
        if self.guard:
            self.guard.on_blocked(snapshot, entry)

    def conn_ready(self, cid, setup, warm, tunnel=True):
        """A connection is usable. `setup` is how long getting its tunnel took; for a plain-HTTP request (tunnel=False,
        carried over a tunnel that may already exist) it is the wait for the response, kept out of the tunnel statistics."""
        with self._lock:
            c = self.active.get(cid)
            if c is None:
                return
            c.update(state="open", setup=setup, warm=bool(warm))
            h = self.hosts.setdefault(c["host"], {"host": c["host"], "count": 0, "warm": 0, "setup_total": 0.0, "setup_n": 0,
                                                   "up": 0, "down": 0, "last": 0.0, "failed": 0})
            h["count"] += 1
            h["last"] = time.time()
            if tunnel:
                self.counters["warm_used" if warm else "cold_opened"] += 1
                self.setup_series.append((time.time(), setup, bool(warm)))
                h["warm"] += 1 if warm else 0
                h["setup_total"] += setup
                h["setup_n"] += 1

    def conn_fail(self, cid, error):
        with self._lock:
            c = self.active.pop(cid, None)
            self._closers.pop(cid, None)
            if c is None:
                return
            c.update(state="failed", error=str(error), ended=time.time())
            self.counters["failed"] += 1
            self.hosts.setdefault(c["host"], {"host": c["host"], "count": 0, "warm": 0, "setup_total": 0.0, "setup_n": 0,
                                               "up": 0, "down": 0, "last": 0.0, "failed": 0})["failed"] += 1
            self.recent.appendleft(c)
            snapshot = dict(c)
        if self.guard:
            self.guard.on_fail(snapshot)

    def add_bytes(self, cid, up=0, down=0):
        with self._lock:
            self.counters["bytes_up"] += up
            self.counters["bytes_down"] += down
            c = self.active.get(cid)
            if c is not None:
                c["up"] += up
                c["down"] += down
                h = self.hosts.get(c["host"])
                if h is not None:
                    h["up"] += up
                    h["down"] += down

    def conn_end(self, cid, status=None):
        with self._lock:
            c = self.active.pop(cid, None)
            self._closers.pop(cid, None)
            if c is None:
                return
            c.update(state="closed", ended=time.time())
            if status is not None:
                c["status"] = status
            self.recent.appendleft(c)
            snapshot = dict(c)
        if self.guard:
            self.guard.on_end(snapshot)

    def set_closer(self, cid, fn):
        with self._lock:
            if cid in self.active:
                self._closers[cid] = fn

    def close_connection(self, cid):
        """Cuts one open connection (the browser sees it reset). True if it was open."""
        with self._lock:
            fn = self._closers.get(cid)
        if fn is None:
            return False
        try:
            fn()
        except OSError:
            pass
        return True

    def close_all(self):
        with self._lock:
            fns = list(self._closers.values())
        for fn in fns:
            try:
                fn()
            except OSError:
                pass

    # -- counters, log, series
    def note(self, name, n=1):
        with self._lock:
            self.counters[name] += n

    def log(self, text, level="info"):
        with self._lock:
            self.logs.append((time.time(), level, text))
            self.counters["log_lines"] += 1  # lets a reader tell how many lines are new since it last looked

    def sample(self):
        """Called about once a second: records how many bytes moved since the last call."""
        with self._lock:
            now = time.time()
            t0, up0, down0 = self._sampled
            span = max(0.001, now - t0)
            up, down = self.counters["bytes_up"], self.counters["bytes_down"]
            self.rate_series.append((now, (up - up0) / span, (down - down0) / span))
            self._sampled = (now, up, down)

    def snapshot_active(self):
        with self._lock:
            return [dict(c) for c in self.active.values()]

    def snapshot(self):
        with self._lock:
            return {
                "started": self.started,
                "counters": dict(self.counters),
                "active": [dict(c) for c in self.active.values()],
                "recent": [dict(c) for c in list(self.recent)[:200]],
                "hosts": [dict(h) for h in self.hosts.values()],
                "logs": list(self.logs)[-400:],
                "setup_series": list(self.setup_series),
                "rate_series": list(self.rate_series),
            }


TELEMETRY = Telemetry()
GUARD = ztr_proxy_guard.Guard()
TELEMETRY.guard = GUARD


def _log(message, level="info"):
    sys.stderr.write(f"[ztr_proxy] {message}\n")
    TELEMETRY.log(message, level)


def _connection_listed(headers):
    """Header names the message's own Connection header declares hop-by-hop."""
    names = set()
    for key, value in headers.items():
        if key.lower() == "connection":
            names.update(token.strip().lower() for token in value.split(",") if token.strip())
    return names


def _merge_duplicates(items):
    """A header that arrived on several lines becomes one (Cookie joins with '; ', the rest with ', ')."""
    merged = {}
    names = {}
    for key, value in items:
        low = key.lower()
        if low in merged:
            merged[low] += ("; " if low == "cookie" else ", ") + value
        else:
            merged[low] = value
            names[low] = key
    return {names[low]: value for low, value in merged.items()}


class ProxySession(ztr_https.Session):
    """A Session that acts as a proxy hop for other people's traffic rather than as a client of its own."""

    def __init__(self, *args, warm_pool=True, warm_max_age=WARM_MAX_AGE, **kwargs):
        super().__init__(*args, **kwargs)
        # Bodies are relayed as the target sent them, still gzip/deflate-encoded if they were, so Content-Encoding and
        # Content-Length stay true and the client does the decoding. (Applies to this process only.)
        ztr_https._decode_body_chunks = lambda raw_chunks, content_encoding: raw_chunks
        self._warm = warm_pool
        self._warm_max_age = warm_max_age
        self._spares = {}        # (domain, port) -> (conn, client, authorized_at)
        self._uses = {}          # (domain, port) -> recent request times, for deciding which targets earn a spare
        self._refilling = set()  # targets with a spare being authorized right now
        self._spare_lock = threading.Lock()
        self._closing = False
        self._pinned = set()     # (domain, port) the user wants kept ready at all times
        self._keeper = None

    # ---- opening tunnels

    def _open_once(self, scheme, domain, port):
        return super()._open_connection(scheme, domain, port)

    def _open_with_retry(self, scheme, domain, port):
        """Opens a tunnel, trying again when a hop reports it couldn't reach the next one (see OPEN_ATTEMPTS)."""
        for attempt in range(1, OPEN_ATTEMPTS + 1):
            try:
                return self._open_once(scheme, domain, port)
            except TunnelError as e:
                msg = str(e)
                transient = msg.startswith("tunnel authorization failed") and (
                    any(t in msg for t in TRANSIENT_HOP_ERRORS) or msg.endswith(": None"))
                if not transient or attempt == OPEN_ATTEMPTS:
                    raise
                TELEMETRY.note("retries")
                _log(f"tunnel to {domain}:{port} failed (a hop couldn't reach the next one) — retrying ({attempt}/{OPEN_ATTEMPTS - 1})", "warn")
                time.sleep(OPEN_RETRY_PAUSE)

    def _open_connection(self, scheme, domain, port):
        """Used by the Session's own request path (plain HTTP): always a new tunnel, with the retry."""
        return self._open_with_retry(scheme, domain, port)

    def open_tunnel(self, domain, port):
        """A raw tunnel for CONNECT / SOCKS5: a warm spare for this target if there is one, else a new tunnel.
        Either way, the next connection to this target is prepared in the background."""
        spare = self._take_spare(domain, port) if self._warm and not self._closing else None
        if spare is not None:
            conn, client = spare
            conn.from_spare = True  # lets the splice know that a tunnel which dies unanswered may just be a stale spare
        else:
            conn, client = self._open_with_retry("http", domain, port)
            conn.from_spare = False
        if self._warm and (conn.from_spare or self._is_repeat_target(domain, port)):
            self._refill_later(domain, port)
        return conn, client

    def _is_repeat_target(self, domain, port):
        """Records this request and says whether the target has been asked for often enough to earn a spare."""
        now = time.time()
        key = (domain, port)
        with self._spare_lock:
            recent = [t for t in self._uses.get(key, ()) if now - t <= WARM_REPEAT_WINDOW]
            recent.append(now)
            self._uses[key] = recent
            if len(self._uses) > 512:  # forget the oldest targets rather than grow without bound
                for k in sorted(self._uses, key=lambda k: self._uses[k][-1])[:128]:
                    del self._uses[k]
        return len(recent) >= WARM_MIN_USES

    def reopen_fresh(self, domain, port):
        """A brand-new tunnel, never a spare — for replacing a spare that turned out to be dead."""
        conn, client = self._open_with_retry("http", domain, port)
        conn.from_spare = False
        return conn, client

    # ---- the spare pool

    @staticmethod
    def _spare_is_alive(conn):
        """An idle, authorized tunnel has nothing to say: if its socket is readable, the far end closed it (or sent
        something unexpected), and it can't be used."""
        sock = getattr(conn, "_sock", None)
        if sock is None:
            return True
        try:
            readable, _, _ = select.select([sock], [], [], 0)
        except (OSError, ValueError):
            return False
        return not readable

    def _take_spare(self, domain, port):
        with self._spare_lock:
            entry = self._spares.pop((domain, port), None)
        if entry is None:
            return None
        conn, client, born = entry
        if time.time() - born > self._warm_max_age or not self._spare_is_alive(conn):
            conn.close()
            TELEMETRY.note("spares_discarded")
            return None
        return conn, client

    def _refill_later(self, domain, port, replace=False):
        key = (domain, port)
        with self._spare_lock:
            if key in self._refilling or self._closing or (key in self._spares and not replace):
                return
            if key not in self._pinned and len(self._spares) + len(self._refilling) >= WARM_MAX_TARGETS:
                return
            self._refilling.add(key)
        threading.Thread(target=self._refill, args=(domain, port), daemon=True).start()

    def _refill(self, domain, port):
        key = (domain, port)
        try:
            conn, client = self._open_with_retry("http", domain, port)
        except Exception:
            conn = None  # a failed spare is just no spare; the next real connection opens its own
        with self._spare_lock:
            self._refilling.discard(key)
            if conn is None:
                return
            if self._closing:
                conn.close()
                return
            old = self._spares.pop(key, None)
            self._spares[key] = (conn, client, time.time())
        TELEMETRY.note("spares_made")
        if old is not None:
            old[0].close()

    # ---- hosts kept ready on purpose

    def pin(self, domain, port=443):
        """Keeps a ready tunnel for this target at all times (renewed before it ages out), so the first connection
        to it is instant. Costs the route's hops one authorization about every PIN_RENEW seconds per pinned target."""
        with self._spare_lock:
            self._pinned.add((domain, int(port)))
            start = self._keeper is None and not self._closing
            if start:
                self._keeper = threading.Thread(target=self._keep_pinned, daemon=True)
        if start:
            self._keeper.start()
        self._refill_later(domain, int(port))

    def unpin(self, domain, port=443):
        with self._spare_lock:
            self._pinned.discard((domain, int(port)))

    def pinned(self):
        with self._spare_lock:
            return sorted(self._pinned)

    def _keep_pinned(self):
        while not self._closing:
            now = time.time()
            for domain, port in self.pinned():
                with self._spare_lock:
                    entry = self._spares.get((domain, port))
                    idle = (domain, port) in self._refilling
                if idle:
                    continue
                if entry is None or now - entry[2] > self._warm_max_age * PIN_RENEW_AT:
                    self._refill_later(domain, port, replace=True)
            for _ in range(PIN_CHECK_EVERY * 10):
                if self._closing:
                    return
                time.sleep(0.1)

    def status(self):
        """For a window: how many ready tunnels exist, which targets, and how old each is."""
        now = time.time()
        with self._spare_lock:
            return {"spares": [{"host": k[0], "port": k[1], "age": now - v[2]} for k, v in self._spares.items()],
                    "refilling": sorted(self._refilling), "pinned": sorted(self._pinned), "warm": self._warm,
                    "max_age": self._warm_max_age}

    def close(self):
        with self._spare_lock:
            self._closing = True
            spares, self._spares = list(self._spares.values()), {}
        for conn, _client, _born in spares:
            conn.close()
        super().close()

    # No cookie jar: a proxy passes each client's own Cookie header through and must never replay one client's
    # cookies to another. Set-Cookie lines are relayed to the client as received.
    def _cookie_header_for(self, hostname):
        return None

    def _store_cookies(self, hostname, cookies):
        return None


def _close_tunnel(conn):
    """Closes a tunnel so that a thread blocked reading it wakes up at once: close() alone doesn't interrupt a
    recv() running in another thread, which would leave the tunnel (and the hops' end of it) open until the target
    chose to hang up."""
    sock = getattr(conn, "_sock", None)
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    try:
        conn.close()
    except OSError:
        pass


def splice(client_sock, conn, reopen=None, meter=None):
    """Copies bytes between a client socket and a tunnel connection, both ways, until either side closes.

    With `reopen` (given when the tunnel came from the warm pool): if that tunnel ends before sending a single byte
    back — a stale spare the relay turned away — it is replaced by a fresh one, the client's bytes so far are
    replayed, and the client never notices. This happens at most once per connection.

    `meter(up, down)`, if given, is told how many bytes crossed in each direction as they do."""
    conn.set_timeout(None)  # tunnels open with a read timeout; an idle but healthy connection must not be dropped
    state = {"conn": conn, "buf": bytearray(), "overflow": False, "replied": False, "recovered": False}
    lock = threading.Lock()
    started = time.time()

    def recover(dead):
        """True if `dead` has been (or just was) replaced by a fresh tunnel."""
        with lock:
            if state["conn"] is not dead:  # the other direction already swapped it
                return True
            if (reopen is None or state["recovered"] or state["replied"] or state["overflow"]
                    or time.time() - started > RECOVERY_WINDOW):
                return False
            try:
                fresh, _client = reopen()
                fresh.set_timeout(None)
                if state["buf"]:
                    fresh.send(bytes(state["buf"]))
            except (ZTRClientError, ValueError, OSError):
                return False
            state["conn"], state["recovered"] = fresh, True
        TELEMETRY.note("recoveries")
        _close_tunnel(dead)
        return True

    def close_client():
        try:
            client_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def up():  # client -> tunnel
        try:
            while True:
                chunk = client_sock.recv(65536)
                if not chunk:
                    break
                if meter:
                    meter(len(chunk), 0)
                with lock:
                    if not state["replied"]:
                        if len(state["buf"]) + len(chunk) <= RECOVERY_BUFFER:
                            state["buf"] += chunk
                        else:
                            state["overflow"] = True  # too much sent to replay, so no quiet recovery any more
                    current = state["conn"]
                try:
                    current.send(chunk)
                except (OSError, NetworkError):
                    if not recover(current):
                        break
        except OSError:
            pass
        finally:
            _close_tunnel(state["conn"])

    def down():  # tunnel -> client
        try:
            while True:
                with lock:
                    current = state["conn"]
                try:
                    chunk = current.recv(65536)
                except (OSError, NetworkError):
                    chunk = b""
                if chunk:
                    state["replied"] = True
                    client_sock.sendall(chunk)
                    if meter:
                        meter(0, len(chunk))
                    continue
                if not recover(current):
                    break
        except OSError:
            pass
        finally:
            close_client()

    threads = [threading.Thread(target=up, daemon=True), threading.Thread(target=down, daemon=True)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def _splice_reopener(session, conn, host, port):
    """A function that opens a replacement tunnel, if this connection came from the warm pool (else None)."""
    if getattr(conn, "from_spare", False):
        return lambda: session.reopen_fresh(host, port)
    return None


# ---------------- SOCKS5 (RFC 1928, CONNECT only, no authentication) ----------------

_SOCKS_NO_AUTH, _SOCKS_NO_ACCEPTABLE = 0x00, 0xFF
_SOCKS_OK, _SOCKS_FAILURE, _SOCKS_HOST_UNREACHABLE = 0x00, 0x01, 0x04
_SOCKS_NOT_ALLOWED = 0x02
_SOCKS_COMMAND_UNSUPPORTED, _SOCKS_ADDRESS_UNSUPPORTED = 0x07, 0x08
_warned_ip_target = False


def _recv_exact(sock, count):
    data = b""
    while len(data) < count:
        piece = sock.recv(count - len(data))
        if not piece:
            raise ConnectionError("client closed during the SOCKS5 handshake")
        data += piece
    return data


def _socks_reply(sock, code):
    sock.sendall(b"\x05" + bytes([code]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")


def serve_socks5(sock, session):
    """Handles one SOCKS5 client on an accepted socket (its first byte, the version, is still unread)."""
    global _warned_ip_target
    try:
        version, method_count = _recv_exact(sock, 2)
        methods = _recv_exact(sock, method_count)
        if version != 5 or _SOCKS_NO_AUTH not in methods:
            sock.sendall(bytes([5, _SOCKS_NO_ACCEPTABLE]))
            return
        sock.sendall(bytes([5, _SOCKS_NO_AUTH]))

        version, command, _reserved, address_type = _recv_exact(sock, 4)
        if version != 5:
            return
        literal = False
        if address_type == 1:
            host, literal = socket.inet_ntoa(_recv_exact(sock, 4)), True
        elif address_type == 3:
            host = _recv_exact(sock, _recv_exact(sock, 1)[0]).decode("ascii", errors="replace")
        elif address_type == 4:
            host, literal = socket.inet_ntop(socket.AF_INET6, _recv_exact(sock, 16)), True
        else:
            _socks_reply(sock, _SOCKS_ADDRESS_UNSUPPORTED)
            return
        port = struct.unpack(">H", _recv_exact(sock, 2))[0]
        if command != 1:  # BIND and UDP ASSOCIATE aren't offered
            _socks_reply(sock, _SOCKS_COMMAND_UNSUPPORTED)
            return
    except (OSError, ConnectionError, struct.error):
        return

    if literal and not _warned_ip_target:
        _warned_ip_target = True
        _log(f"a client asked for the address {host} directly — it resolved the name itself, outside the tunnel. "
             "Use socks5h:// (curl: --socks5-hostname) so this proxy resolves names instead.")
    blocked = GUARD.check_block(host, port)
    if blocked:
        TELEMETRY.conn_blocked(TELEMETRY.conn_start("SOCKS5", host, port, observe=False), blocked)
        _log(f"socks5 CONNECT {host}:{port} refused: on the blocklist ({blocked['pattern']})", "warn")
        _socks_reply(sock, _SOCKS_NOT_ALLOWED)
        return
    cid = TELEMETRY.conn_start("SOCKS5", host, port)
    try:
        began = time.time()
        conn, _client = session.open_tunnel(host, port)
    except (TunnelError, NetworkError) as e:
        _log(f"socks5 CONNECT {host}:{port} failed: {e}", "error")
        TELEMETRY.conn_fail(cid, e)
        _socks_reply(sock, _SOCKS_HOST_UNREACHABLE)
        return
    except (ZTRClientError, ValueError, OSError) as e:
        _log(f"socks5 CONNECT {host}:{port} failed: {e}", "error")
        TELEMETRY.conn_fail(cid, e)
        _socks_reply(sock, _SOCKS_FAILURE)
        return

    setup = time.time() - began
    warm = getattr(conn, "from_spare", False)
    _log(f"socks5 CONNECT {host}:{port} ready in {setup:.1f}s" + (" (warm tunnel)" if warm else ""))
    TELEMETRY.conn_ready(cid, setup, warm)
    try:
        _socks_reply(sock, _SOCKS_OK)
        sock.settimeout(None)
    except OSError:
        conn.close()
        TELEMETRY.conn_end(cid)
        return
    TELEMETRY.set_closer(cid, lambda: sock.shutdown(socket.SHUT_RDWR))
    try:
        splice(sock, conn, _splice_reopener(session, conn, host, port), meter=lambda u, d: TELEMETRY.add_bytes(cid, u, d))
    finally:
        TELEMETRY.conn_end(cid)


class ProxyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        # One port serves both: a SOCKS5 client opens with the version byte 0x05, an HTTP request with a letter.
        try:
            first = self.connection.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if first == b"\x05":
            serve_socks5(self.connection, self.server.session)
            return
        super().handle()

    def _refuse(self, entry):
        try:
            self.send_error(403, _status_text(f"Blocked by ZTR Proxy ({entry['pattern']})"))
        except OSError:
            pass
        self.close_connection = True

    def _gateway_error(self, error):
        timed_out = "timed out" in str(error).lower()
        try:
            self.send_error(504 if timed_out else 502, _status_text(str(error)))
        except OSError:
            pass  # the client gave up waiting and hung up first; nothing left to tell it
        self.close_connection = True

    # ---------------- CONNECT (HTTPS passthrough) ----------------

    def do_CONNECT(self):
        try:
            host, port_str = self.path.rsplit(":", 1)
            port = int(port_str)
        except ValueError:
            self.send_error(400, "malformed CONNECT target")
            return

        blocked = GUARD.check_block(host, port)
        if blocked:
            TELEMETRY.conn_blocked(TELEMETRY.conn_start("CONNECT", host, port, observe=False), blocked)
            _log(f"CONNECT {host}:{port} refused: on the blocklist ({blocked['pattern']})", "warn")
            self._refuse(blocked)
            return
        cid = TELEMETRY.conn_start("CONNECT", host, port)
        began = time.time()
        try:
            conn, _client = self.server.session.open_tunnel(host, port)
        except (ZTRClientError, ValueError, OSError) as e:
            TELEMETRY.conn_fail(cid, e)
            self._gateway_error(e)
            return
        setup = time.time() - began
        _log(f"CONNECT {host}:{port} ready in {setup:.1f}s" + (" (warm tunnel)" if conn.from_spare else ""))
        TELEMETRY.conn_ready(cid, setup, conn.from_spare)

        try:
            self.send_response(200, "Connection Established")
            self.end_headers()
        except OSError:
            conn.close()
            TELEMETRY.conn_end(cid)
            return
        self.close_connection = True

        client_sock = self.connection
        client_sock.settimeout(None)
        TELEMETRY.set_closer(cid, lambda: client_sock.shutdown(socket.SHUT_RDWR))
        try:
            splice(client_sock, conn, _splice_reopener(self.server.session, conn, host, port),
                   meter=lambda u, d: TELEMETRY.add_bytes(cid, u, d))
        finally:
            TELEMETRY.conn_end(cid)

    # ---------------- plain HTTP (fully proxied) ----------------

    def _read_chunked_body(self):
        body = bytearray()
        while True:
            size = int(self.rfile.readline(65537).split(b";", 1)[0].strip(), 16)
            if size == 0:
                while self.rfile.readline(65537).strip():  # optional trailer lines, then the blank line
                    pass
                return bytes(body)
            if len(body) + size > MAX_REQUEST_BODY:
                raise OverflowError
            body += self.rfile.read(size)
            self.rfile.readline(3)  # the CRLF that ends each chunk

    def _read_request_body(self):
        if "chunked" in self.headers.get("Transfer-Encoding", "").lower():
            return self._read_chunked_body()
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_REQUEST_BODY:
            raise OverflowError
        return self.rfile.read(length) if length else None

    def _handle_proxied_request(self):
        parts = urlsplit(self.path)
        if not parts.scheme or not parts.netloc:
            self.send_error(400, "not an absolute-URI proxy request (point a client's proxy setting at this, don't browse to it directly)")
            return

        try:
            body = self._read_request_body()
        except OverflowError:
            self.send_error(413, "request body too large for this proxy")
            return
        except ValueError:
            self.send_error(400, "malformed request body")
            return

        host, port = parts.hostname or parts.netloc, parts.port or (443 if parts.scheme == "https" else 80)
        blocked = GUARD.check_block(host, port)
        if blocked:
            TELEMETRY.conn_blocked(TELEMETRY.conn_start("HTTP", host, port, detail=f"{self.command} {parts.path or '/'}", observe=False), blocked)
            _log(f"{self.command} {host} refused: on the blocklist ({blocked['pattern']})", "warn")
            self._refuse(blocked)
            return
        cid = TELEMETRY.conn_start("HTTP", host, port, detail=f"{self.command} {parts.path or '/'}")
        TELEMETRY.add_bytes(cid, len(body or b""), 0)
        try:
            self._relay_proxied_request(parts, body, cid)
        finally:
            TELEMETRY.conn_end(cid)

    def _relay_proxied_request(self, parts, body, cid):

        skip = _HOP_BY_HOP | _connection_listed(self.headers) | {"host", "content-length", "expect"}
        forwarded = {k: v for k, v in _merge_duplicates(self.headers.items()).items() if k.lower() not in skip}

        asked = time.time()
        try:
            result = self.server.session.request(
                self.command, self.path, headers=forwarded, data=body, stream=True, allow_redirects=False,
            )
        except (ZTRClientError, ValueError, OSError) as e:
            TELEMETRY.conn_fail(cid, e)
            self._gateway_error(e)
            return

        status = result.status_code
        TELEMETRY.conn_ready(cid, time.time() - asked, False, tunnel=False)
        with TELEMETRY._lock:
            if cid in TELEMETRY.active:
                TELEMETRY.active[cid]["status"] = status
        headers = result.headers or {}
        skip = _HOP_BY_HOP | _connection_listed(headers)
        no_body = self.command == "HEAD" or status in (204, 304) or 100 <= status < 200
        length = headers.get("content-length")
        upstream_chunked = "chunked" in headers.get("transfer-encoding", "").lower()

        self.send_response_only(status, result.reason or "")
        for name, value in headers.items():
            if name.lower() in skip or name.lower() in ("content-length", "set-cookie"):
                continue
            self.send_header(name, value)
        for cookie in result.set_cookie_headers:
            self.send_header("Set-Cookie", cookie)

        # Tell the client where the body ends, however the target did it: a known length is passed on, otherwise
        # (chunked or close-delimited upstream) the body is re-chunked for an HTTP/1.1 client, or ends when we
        # close for an HTTP/1.0 one. Without this a keep-alive client would wait forever for an end that never comes.
        chunked_out = False
        if no_body:
            if length is not None and status not in (204, 304) and not 100 <= status < 200:
                self.send_header("Content-Length", length)  # HEAD: the length the body would have had
            self.end_headers()
            return
        if length is not None and not upstream_chunked:
            self.send_header("Content-Length", length)
        elif self.request_version == "HTTP/1.1":
            self.send_header("Transfer-Encoding", "chunked")
            chunked_out = True
        else:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.end_headers()

        promised = None if (chunked_out or length is None or upstream_chunked) else int(length)
        relayed = 0
        try:
            for chunk in result.iter_content():
                if not chunk:
                    continue
                relayed += len(chunk)
                TELEMETRY.add_bytes(cid, 0, len(chunk))
                self.wfile.write((b"%x\r\n" % len(chunk) + chunk + b"\r\n") if chunked_out else chunk)
            if promised is not None and relayed != promised:
                # ztr_https treats a connection that closes early as the end of the body; a client that was promised
                # more would wait for it forever, so cut it off instead.
                raise ConnectionError(f"body ended after {relayed} of {promised} bytes")
            if chunked_out:
                self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (ZTRClientError, ValueError, OSError):
            # The client went away, or the tunnel failed after headers were sent. Stop pulling the body, drop the
            # half-read connection, and end abruptly so the client sees a cut-off response, never a "complete" one.
            try:
                result.abort()
            except (OSError, NetworkError):
                pass
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def do_GET(self):
        self._handle_proxied_request()

    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_GET
    do_HEAD = do_GET
    do_OPTIONS = do_GET

    def log_message(self, fmt, *args):
        _log(f"{self.address_string()} - {fmt % args}")


def resolve_host(explicit_host):
    """The address to listen on: the one asked for, else ZTRelay's local address if this machine has it, else loopback."""
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


class ProxyServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    # A browser opens many connections at once; the default listen queue of 5 makes the rest wait for a retransmitted
    # SYN (a full second) instead of being accepted at once.
    request_queue_size = 128


DEFAULT_PORT = 8095


class ProxyService:
    """Starts and stops the proxy inside another program (the window) — everything main() does, minus the command
    line. start() raises OSError if the address is taken."""

    def __init__(self, config_file, host=None, port=DEFAULT_PORT, warm_pool=True, warm_max_age=WARM_MAX_AGE,
                 warm_min_uses=WARM_MIN_USES, timing_defense=False, pinned=(), telemetry=None, session_factory=None):
        self.config_file, self.host_arg, self.port = config_file, host, int(port)
        self.warm_pool, self.warm_max_age, self.warm_min_uses = warm_pool, warm_max_age, warm_min_uses
        self.timing_defense, self.initial_pins = timing_defense, list(pinned)
        self.telemetry = telemetry or TELEMETRY
        self.session_factory = session_factory or ProxySession
        self.session = self.httpd = None
        self.host = None
        self._threads = []
        self._stop = threading.Event()

    @property
    def running(self):
        return self.httpd is not None

    def start(self):
        if self.running:
            return self.host, self.port
        globals()["WARM_MIN_USES"] = self.warm_min_uses
        GUARD.ensure_loaded()
        host = resolve_host(self.host_arg)
        session = self.session_factory(config_file=self.config_file, with_timing_defense=self.timing_defense,
                                       warm_pool=self.warm_pool, warm_max_age=self.warm_max_age)
        try:
            httpd = ProxyServer((host, self.port), ProxyHandler)
        except OSError:
            session.close()
            raise
        httpd.session = session
        self.session, self.httpd, self.host = session, httpd, host
        self._stop.clear()
        for domain, port in self.initial_pins:
            session.pin(domain, port)
        self.telemetry.reset()
        serve = threading.Thread(target=httpd.serve_forever, daemon=True, name="ztr-proxy-serve")
        sampler = threading.Thread(target=self._sample, daemon=True, name="ztr-proxy-sampler")
        self._threads = [serve, sampler]
        for t in self._threads:
            t.start()
        _log(f"listening on {host}:{self.port}")
        return host, self.port

    def _sample(self):
        while not self._stop.wait(1.0):
            self.telemetry.sample()
            GUARD.sweep(self.telemetry.snapshot_active())
            GUARD.save()

    def stop(self):
        if not self.running:
            return
        self._stop.set()
        httpd, session = self.httpd, self.session
        self.httpd = None
        try:
            httpd.shutdown()
        finally:
            httpd.server_close()
        self.telemetry.close_all()
        session.close()
        GUARD.save(force=True)
        _log("stopped")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=None, help=f"this proxy's own bind address (default: {DEFAULT_HOST_CANDIDATE} if this machine has that address, else {FALLBACK_HOST} — both are local-machine-only, since the proxy can carry your route's real credentials)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"this proxy's own port, for both HTTP-proxy and SOCKS5 (default: {DEFAULT_PORT})")
    parser.add_argument("--config-file", required=True, help="a .ztr file in routes/ — every request goes through this route's tunnel")
    parser.add_argument("--with-timing-defense", action="store_true", help="enable the hops' own jitter/decoy traffic for every tunnel this proxy opens")
    parser.add_argument("--no-warm-pool", action="store_true", help="don't keep a ready tunnel per target (by default one is authorized in the background after each connection, so the next one to the same host starts instantly)")
    parser.add_argument("--warm-max-age", type=float, default=WARM_MAX_AGE, help=f"seconds a ready tunnel may wait unused before it's discarded (default: {WARM_MAX_AGE})")
    parser.add_argument("--warm-min-uses", type=int, default=WARM_MIN_USES, help=f"a ready tunnel is prepared for a host once it has been asked for this many times within {WARM_REPEAT_WINDOW}s — 1 prepares one after every connection, higher spares the route's hops the work for hosts you only touch once (default: {WARM_MIN_USES})")
    parser.add_argument("--keep-ready", action="append", default=[], metavar="HOST[:PORT]", help="keep a ready tunnel to this host at all times (repeatable; port defaults to 443)")
    args = parser.parse_args()
    pins = []
    for item in args.keep_ready:
        name, _, port = item.partition(":")
        pins.append((name, int(port or 443)))
    host = resolve_host(args.host)
    if host not in (DEFAULT_HOST_CANDIDATE, FALLBACK_HOST, "localhost", "::1"):
        _log(f"WARNING: listening on {host} — anyone who can reach this address can send traffic through your route.")

    service = ProxyService(args.config_file, host=host, port=args.port, warm_pool=not args.no_warm_pool,
                           warm_max_age=args.warm_max_age, warm_min_uses=args.warm_min_uses,
                           timing_defense=args.with_timing_defense, pinned=pins)
    service.start()
    print(f"ztr_proxy listening on {service.host}:{service.port} — HTTP proxy: -x http://{service.host}:{service.port}   "
          f"SOCKS5: --socks5-hostname {service.host}:{service.port}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()


if __name__ == "__main__":
    main()
