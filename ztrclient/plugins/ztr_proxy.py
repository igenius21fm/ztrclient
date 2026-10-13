"""
A local proxy backed by ztr_https.py — point curl, a browser, or any other
proxy-aware client at it and its traffic goes through an authorized ZTRelay
tunnel instead of your real network path. One port speaks both HTTP-proxy and
SOCKS5.

    python3 plugins/ztr_proxy.py --config-file route.ztr

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
import http.server
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
_ZTR_CLIENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, _ZTR_CLIENT_DIR)
sys.path.insert(0, os.path.join(_ZTR_CLIENT_DIR, "utils"))
sys.path.insert(0, SCRIPT_DIR)

import ztr_https  # noqa: E402
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
# What a hop says when it could not reach the next hop, or could not reach the registry to check the route.
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
# A spare the relay turns away (typically because the public address changed since it was authorized) shows itself by
# the tunnel ending without a single reply byte. Within this window, and while what the client sent still fits in the
# buffer, the connection is quietly re-authorized and the client's bytes replayed.
RECOVERY_WINDOW = 3.0
RECOVERY_BUFFER = 64 * 1024


def _log(message):
    sys.stderr.write(f"[ztr_proxy] {message}\n")


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

    # ---- opening tunnels

    def _open_once(self, scheme, domain, port):
        return super()._open_connection(scheme, domain, port)

    def _open_with_retry(self, scheme, domain, port):
        """Opens a tunnel, trying again when a hop reports it couldn't reach the next one (see OPEN_ATTEMPTS)."""
        for attempt in range(1, OPEN_ATTEMPTS + 1):
            try:
                return self._open_once(scheme, domain, port)
            except TunnelError as e:
                transient = str(e).startswith("tunnel authorization failed") and any(t in str(e) for t in TRANSIENT_HOP_ERRORS)
                if not transient or attempt == OPEN_ATTEMPTS:
                    raise
                _log(f"tunnel to {domain}:{port} failed (a hop couldn't reach the next one) — retrying ({attempt}/{OPEN_ATTEMPTS - 1})")
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
            return None
        return conn, client

    def _refill_later(self, domain, port):
        key = (domain, port)
        with self._spare_lock:
            if key in self._refilling or key in self._spares or self._closing:
                return
            if len(self._spares) + len(self._refilling) >= WARM_MAX_TARGETS:
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
        if old is not None:
            old[0].close()

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


def splice(client_sock, conn, reopen=None):
    """Copies bytes between a client socket and a tunnel connection, both ways, until either side closes.

    With `reopen` (given when the tunnel came from the warm pool): if that tunnel ends before sending a single byte
    back — a stale spare the relay turned away — it is replaced by a fresh one, the client's bytes so far are
    replayed, and the client never notices. This happens at most once per connection."""
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
        try:
            dead.close()
        except OSError:
            pass
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
            try:
                state["conn"].close()
            except OSError:
                pass

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
    try:
        began = time.time()
        conn, _client = session.open_tunnel(host, port)
    except (TunnelError, NetworkError) as e:
        _log(f"socks5 CONNECT {host}:{port} failed: {e}")
        _socks_reply(sock, _SOCKS_HOST_UNREACHABLE)
        return
    except (ZTRClientError, ValueError, OSError) as e:
        _log(f"socks5 CONNECT {host}:{port} failed: {e}")
        _socks_reply(sock, _SOCKS_FAILURE)
        return

    _log(f"socks5 CONNECT {host}:{port} ready in {time.time() - began:.1f}s" + (" (warm tunnel)" if getattr(conn, "from_spare", False) else ""))
    try:
        _socks_reply(sock, _SOCKS_OK)
        sock.settimeout(None)
    except OSError:
        conn.close()
        return
    splice(sock, conn, _splice_reopener(session, conn, host, port))


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

    def _gateway_error(self, error):
        timed_out = "timed out" in str(error).lower()
        self.send_error(504 if timed_out else 502, str(error))

    # ---------------- CONNECT (HTTPS passthrough) ----------------

    def do_CONNECT(self):
        try:
            host, port_str = self.path.rsplit(":", 1)
            port = int(port_str)
        except ValueError:
            self.send_error(400, "malformed CONNECT target")
            return

        began = time.time()
        try:
            conn, _client = self.server.session.open_tunnel(host, port)
        except (ZTRClientError, ValueError, OSError) as e:
            self._gateway_error(e)
            return
        _log(f"CONNECT {host}:{port} ready in {time.time() - began:.1f}s" + (" (warm tunnel)" if conn.from_spare else ""))

        self.send_response(200, "Connection Established")
        self.end_headers()
        self.close_connection = True

        client_sock = self.connection
        client_sock.settimeout(None)
        splice(client_sock, conn, _splice_reopener(self.server.session, conn, host, port))

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

        skip = _HOP_BY_HOP | _connection_listed(self.headers) | {"host", "content-length", "expect"}
        forwarded = {k: v for k, v in _merge_duplicates(self.headers.items()).items() if k.lower() not in skip}

        try:
            result = self.server.session.request(
                self.command, self.path, headers=forwarded, data=body, stream=True, allow_redirects=False,
            )
        except (ZTRClientError, ValueError, OSError) as e:
            self._gateway_error(e)
            return

        status = result.status_code
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=None, help=f"this proxy's own bind address (default: {DEFAULT_HOST_CANDIDATE} if this machine has that address, else {FALLBACK_HOST} — both are local-machine-only, since the proxy can carry your route's real credentials)")
    parser.add_argument("--port", type=int, default=8095, help="this proxy's own port, for both HTTP-proxy and SOCKS5 (default: 8095)")
    parser.add_argument("--config-file", required=True, help="a .ztr file in routes/ — every request goes through this route's tunnel")
    parser.add_argument("--with-timing-defense", action="store_true", help="enable the hops' own jitter/decoy traffic for every tunnel this proxy opens")
    parser.add_argument("--no-warm-pool", action="store_true", help="don't keep a ready tunnel per target (by default one is authorized in the background after each connection, so the next one to the same host starts instantly)")
    parser.add_argument("--warm-max-age", type=float, default=WARM_MAX_AGE, help=f"seconds a ready tunnel may wait unused before it's discarded (default: {WARM_MAX_AGE})")
    parser.add_argument("--warm-min-uses", type=int, default=WARM_MIN_USES, help=f"a ready tunnel is prepared for a host once it has been asked for this many times within {WARM_REPEAT_WINDOW}s — 1 prepares one after every connection, higher spares the route's hops the work for hosts you only touch once (default: {WARM_MIN_USES})")
    args = parser.parse_args()
    globals()["WARM_MIN_USES"] = args.warm_min_uses
    args.host = resolve_host(args.host)

    if args.host not in (DEFAULT_HOST_CANDIDATE, FALLBACK_HOST, "localhost", "::1"):
        _log(f"WARNING: listening on {args.host} — anyone who can reach this address can send traffic through your route.")

    session = ProxySession(config_file=args.config_file, with_timing_defense=args.with_timing_defense,
                           warm_pool=not args.no_warm_pool, warm_max_age=args.warm_max_age)

    httpd = ProxyServer((args.host, args.port), ProxyHandler)
    httpd.session = session
    print(f"ztr_proxy listening on {args.host}:{args.port} — HTTP proxy: -x http://{args.host}:{args.port}   "
          f"SOCKS5: --socks5-hostname {args.host}:{args.port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        session.close()


if __name__ == "__main__":
    main()
