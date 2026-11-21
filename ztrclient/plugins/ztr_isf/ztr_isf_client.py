#!/usr/bin/env python3
"""
ztr_isf_client.py — use your own ISF (Intermediate Server Forwarder) through ZTRelay.

A normal ZTRelay route ends at the exit hop, which decides where traffic
finally goes. With an ISF the route ends at a forwarder *you* run: the exit
only ever connects to the ISF, and you tell the ISF — over a signed,
end-to-end encrypted control channel — where each session really goes. The
data path to the ISF is encrypted end to end as well, so the exit sees
neither the destination nor the payload.

Commands
  gen-keys   create this machine's ISF keypair
  ctrl       one control operation: create / list / get / set-destination / delete / health / aliases
  client     open the data tunnel for a ticket and bridge it to a local port
  connect    create + client in one step
  udp        a local UDP port whose datagrams go through the ISF to a UDP destination (DNS, QUIC, WireGuard ...)

Typical use
  ztr_isf_client.py gen-keys
  ztr_isf_client.py connect --config-file route.ztr --isf-host 203.0.113.7 \\
        --destination 10.0.0.5:22 --listen 127.0.0.1:2222
  ssh -p 2222 user@127.0.0.1

UDP (the ISF must have been started with --udp-bind)
  ztr_isf_client.py udp --isf work --listen 127.0.0.1:5353 --destination 8.8.8.8:53
  dig @127.0.0.1 -p 5353 example.com

Aliases (the ISF must have been started with --alias-file): names that only your ISF understands
  ztr_isf_client.py ctrl alias-add example.com           # -> 3f9c...(64 characters).isf
  isf_ssh me@3f9c...(64 characters).isf                   # the ISF turns it back into example.com
"""
import argparse
import base64
import json
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time


def _use_installer_venv():
    """Started as a command with an interpreter that has no pycryptodome: run again under the ZTRelay installer's Python."""
    if __name__ != "__main__":
        return
    try:
        import Crypto  # noqa: F401
        return
    except ImportError:
        pass
    if os.environ.get("ZTR_ISF_REEXEC"):
        return
    venv = os.environ.get("ZTR_VENV_DIR") or os.path.join(os.path.expanduser("~"), ".local", "share", "ztr", "ztr_venv")
    py = os.path.join(venv, "bin", "python3")
    if os.path.isfile(py):
        os.environ["ZTR_ISF_REEXEC"] = "1"
        os.execv(py, [py, os.path.realpath(__file__)] + sys.argv[1:])


_use_installer_venv()

from Crypto.Cipher import ChaCha20_Poly1305

# ---- protocol constants (kept in step with server/src/proto.rs) -------------
MAGIC = b"ISF1"
SESSION_ID_LEN = 16
KEY_LEN = 32
TAG_LEN = 16
MAX_CHUNK = 16 * 1024
MAX_FRAME = MAX_CHUNK + 1 + TAG_LEN
MAX_CTRL_FRAME = 64 * 1024

T_DATA, T_FIN, T_OK, T_ERR, T_OPEN = 0, 1, 2, 3, 4
T_PING, T_PONG = 5, 6            # UDP sessions only
DIR_C2S, DIR_S2C = 0, 1

UDP_MAGIC = b"ISU1"
UDP_HEADER = SESSION_ID_LEN + 8            # session id || counter
UDP_MIN = UDP_HEADER + 1 + TAG_LEN
DEFAULT_UDP_PORT = 7782
DEFAULT_UDP_MAX_PAYLOAD = 4096             # the ISF's default; it drops anything bigger either way
REPLAY_WINDOW = 1024

DEFAULT_KEYS_DIR = os.path.join(os.path.expanduser("~"), ".ztr_isf")


class IsfError(Exception):
    pass


# ---- data-plane crypto -------------------------------------------------------
def _nonce(direction: int, counter: int) -> bytes:
    return bytes([direction, 0, 0, 0]) + struct.pack(">Q", counter)


def _aad(session_id: bytes) -> bytes:
    return MAGIC + session_id


class Sealer:
    def __init__(self, key: bytes, session_id: bytes, direction: int):
        self._key, self._aad, self._dir, self._ctr = key, _aad(session_id), direction, 0

    def seal(self, ftype: int, data: bytes = b"") -> bytes:
        """Returns `u32 BE len || ciphertext`."""
        if len(data) > MAX_CHUNK:
            raise IsfError("chunk too large")
        c = ChaCha20_Poly1305.new(key=self._key, nonce=_nonce(self._dir, self._ctr))
        c.update(self._aad)
        ct, tag = c.encrypt_and_digest(bytes([ftype]) + data)
        self._ctr += 1
        body = ct + tag
        return struct.pack(">I", len(body)) + body


class Opener:
    def __init__(self, key: bytes, session_id: bytes, direction: int):
        self._key, self._aad, self._dir, self._ctr = key, _aad(session_id), direction, 0

    def open(self, body: bytes):
        """Takes the ciphertext (length prefix already removed). Returns (type, data)."""
        if len(body) < TAG_LEN + 1:
            raise IsfError("short frame")
        c = ChaCha20_Poly1305.new(key=self._key, nonce=_nonce(self._dir, self._ctr))
        c.update(self._aad)
        try:
            pt = c.decrypt_and_verify(body[:-TAG_LEN], body[-TAG_LEN:])
        except ValueError as e:
            raise IsfError("data frame failed authentication") from e
        self._ctr += 1
        return pt[0], pt[1:]


# ---- UDP datagram crypto (server/src/proto.rs: UdpCipher, ReplayWindow) -----------------------
class UdpCipher:
    """Seals datagrams this side sends (direction `send_dir`) and opens the other direction's. One datagram is
    `session_id(16) || counter(8, BE) || ChaCha20-Poly1305(type || payload) || tag(16)`."""

    def __init__(self, key: bytes, session_id: bytes, send_dir: int = DIR_C2S):
        self._key, self._sid, self._send_dir = key, session_id, send_dir
        self._aad = UDP_MAGIC + session_id
        self._ctr = 0
        self._lock = threading.Lock()

    def seal(self, ftype: int, data: bytes = b"") -> bytes:
        with self._lock:
            ctr = self._ctr
            self._ctr += 1
        c = ChaCha20_Poly1305.new(key=self._key, nonce=_nonce(self._send_dir, ctr))
        c.update(self._aad)
        ct, tag = c.encrypt_and_digest(bytes([ftype]) + data)
        return self._sid + struct.pack(">Q", ctr) + ct + tag

    @staticmethod
    def counter_of(datagram: bytes):
        return struct.unpack(">Q", datagram[SESSION_ID_LEN:UDP_HEADER])[0] if len(datagram) >= UDP_HEADER else None

    def open(self, datagram: bytes):
        """Returns (counter, type, payload); raises IsfError if it isn't an authentic datagram of this session."""
        if len(datagram) < UDP_MIN or datagram[:SESSION_ID_LEN] != self._sid:
            raise IsfError("not a datagram of this session")
        ctr = self.counter_of(datagram)
        c = ChaCha20_Poly1305.new(key=self._key, nonce=_nonce(self._send_dir ^ 1, ctr))
        c.update(self._aad)
        body = datagram[UDP_HEADER:]
        try:
            pt = c.decrypt_and_verify(body[:-TAG_LEN], body[-TAG_LEN:])
        except ValueError as e:
            raise IsfError("datagram failed authentication") from e
        if not pt:
            raise IsfError("empty datagram")
        return ctr, pt[0], pt[1:]


class ReplayWindow:
    """Anti-replay for datagrams: each counter is accepted once, late ones are fine up to REPLAY_WINDOW back."""

    def __init__(self):
        self._max = None
        self._seen = set()

    def accept(self, ctr: int) -> bool:
        if self._max is None:
            self._max = ctr
            self._seen = {ctr}
            return True
        if ctr > self._max:
            self._max = ctr
            self._seen = {c for c in self._seen if self._max - c < REPLAY_WINDOW}
            self._seen.add(ctr)
            return True
        if self._max - ctr >= REPLAY_WINDOW or ctr in self._seen:
            return False
        self._seen.add(ctr)
        return True


# ---- tickets -----------------------------------------------------------------
def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_ticket(session_id_hex: str, key: bytes) -> str:
    return "isf1." + session_id_hex + "." + base64.urlsafe_b64encode(key).rstrip(b"=").decode()


def parse_ticket(ticket: str):
    try:
        tag, sid_hex, key_b64 = ticket.strip().split(".")
        if tag != "isf1":
            raise ValueError
        sid = bytes.fromhex(sid_hex)
        key = _b64d(key_b64)
        if len(sid) != SESSION_ID_LEN or len(key) != KEY_LEN:
            raise ValueError
    except ValueError:
        raise IsfError("not a valid ISF ticket") from None
    return sid, key


# ---- locating ztrclient ------------------------------------------------------
def locate_ztrclient(explicit: str = None) -> str:
    """Finds the directory holding ztrClient.py and puts it on sys.path."""
    here = os.path.dirname(os.path.realpath(__file__))
    try:
        saved = Profiles().data.get("ztrclient_dir")  # also reads settings saved by earlier single-ISF versions
    except Exception:
        saved = None
    candidates = [explicit, os.environ.get("ZTRCLIENT_DIR"), saved, here, os.path.dirname(here),
                  os.path.dirname(os.path.dirname(here)),  # plugins/ztr_isf/ inside the ZTRelay client
                  os.path.join(os.path.dirname(here), "ztrclient")]
    for c in candidates:
        if c and os.path.isfile(os.path.join(c, "ztrClient.py")):
            if c not in sys.path:
                sys.path.insert(0, c)
            return c
    raise IsfError("can't find ztrClient.py — pass --ztrclient-dir or set ZTRCLIENT_DIR")


def default_relay_factory(config_file: str, timing_defense: bool = False, transport: str = "tcp"):
    """Returns make(host, port) -> RelayClient aimed at host:port. transport "udp" uses the route's UDP lanes."""
    def make(host: str, port: int):
        from ztrClient import RelayClient  # noqa: imported late so tests can run without a route
        c = RelayClient(target_host=host, config_file=config_file, transport_type=transport)
        c.set_target_port(port)
        if timing_defense:
            c.with_timing_defense()
        return c
    return make


# ---- control plane -----------------------------------------------------------
class ControlChannel:
    """One signed + encrypted request/response per call, through a native tunnel."""

    def __init__(self, relay_factory, isf_host, ctrl_port, own_priv, own_pub, isf_pub, ttl=86400, io_timeout=30):
        from utils.crypt_bot import CryptBot  # ztrclient's own CryptBot
        self._make = relay_factory
        self.isf_host, self.ctrl_port, self.ttl, self.io_timeout = isf_host, ctrl_port, ttl, io_timeout
        # Dedicated identity for the ISF — never the hop-authorization keypair.
        self._crypt = CryptBot(pathPrivateKey=own_priv, pathPublicKey=own_pub, pathRecipientPublicKey=isf_pub)
        if not self._crypt.check_keys():
            raise IsfError(f"missing ISF keys ({own_priv} / {own_pub}) — run gen-keys first")
        if not os.path.exists(isf_pub):
            raise IsfError(f"missing the ISF's public key at {isf_pub}")

    def call(self, op: str, **fields) -> dict:
        relay = self._make(self.isf_host, self.ctrl_port)

        def attempt():
            req = dict(fields, op=op, ts=int(time.time()), nonce=secrets.token_hex(16))
            ct = self._crypt.encrypt_sign_BytesPayload(json.dumps(req).encode())
            inner = struct.pack(">I", len(ct)) + ct
            res = relay.set_tunnel(ttl=self.ttl, native=True)
            if not res or not res.get("status"):
                raise IsfError(f"couldn't authorize the tunnel to the ISF: {res}")
            sock = socket.create_connection((relay.entry_hop, relay.PORT), timeout=self.io_timeout)
            try:
                sock.settimeout(self.io_timeout)
                relay.send_HTH(sock, inner, relay.session_id)
                payload, _ = relay.recv_HTH(sock)
            finally:
                sock.close()
            return req, payload

        try:
            req, payload = relay.call_with_recovery(attempt)
        except IsfError:
            raise
        except Exception as e:
            from ztrClient import StaleTunnelError, TunnelError
            if not isinstance(e, (TunnelError, OSError)):
                raise
            # A silent close right after sending is what the exit does when it can't reach the ISF, so
            # that is the likelier cause here than the stale-session wording the relay client reports.
            detail = "the connection was closed with no reply" if isinstance(e, StaleTunnelError) else str(e)
            raise IsfError(f"couldn't reach the ISF through your route — it may be down, or unreachable from the exit ({detail})") from e
        if len(payload) < 4:
            raise IsfError("empty reply from the ISF")
        (n,) = struct.unpack(">I", payload[:4])
        body = payload[4:4 + n]
        if len(body) != n:
            raise IsfError("truncated reply from the ISF")
        try:
            plain = self._crypt.decrypt_msg_verifyBytesPayload(body, as_="bytes")
        except Exception as e:  # malformed ciphertext
            raise IsfError(f"couldn't decrypt the ISF's reply: {e}") from e
        if plain is None:
            raise IsfError("the reply's signature didn't verify — is isf_public.pem really this ISF's key?")
        resp = json.loads(plain.decode())
        if resp.get("nonce") != req["nonce"]:
            raise IsfError("reply doesn't match the request")
        if not resp.get("ok"):
            raise IsfError(resp.get("error", "request refused"))
        return resp


# ---- data plane --------------------------------------------------------------
class DataTunnel:
    """Raw tunnel to the ISF carrying authenticated, encrypted frames."""

    def __init__(self, relay_factory, isf_host, data_port, session_id: bytes, key: bytes, ttl=86400, io_timeout=30):
        self._relay = relay_factory(isf_host, data_port)
        self._sid, self._key, self.ttl, self.io_timeout = session_id, key, ttl, io_timeout
        self._sock = None
        self._buf = bytearray()
        self._sealer = Sealer(key, session_id, DIR_C2S)
        self._opener = Opener(key, session_id, DIR_S2C)
        self.bytes_sent = 0
        self.bytes_received = 0

    def _send_raw(self, data: bytes):
        # Raw tunnels: every outgoing chunk is HTH-framed, replies come back as plain bytes.
        self._relay.send_HTH(self._sock, data, self._relay.session_id)

    def _recv_into_buf(self) -> bool:
        chunk = self._sock.recv(65536)
        if not chunk:
            return False
        self._buf += chunk
        return True

    def _read_body(self) -> bytes:
        while True:
            if len(self._buf) >= 4:
                (n,) = struct.unpack(">I", bytes(self._buf[:4]))
                if n > MAX_FRAME:
                    raise IsfError("oversized frame from the ISF")
                if len(self._buf) >= 4 + n:
                    body = bytes(self._buf[4:4 + n])
                    del self._buf[:4 + n]
                    return body
            if not self._recv_into_buf():
                raise ConnectionError("tunnel closed")

    def _connect_once(self):
        res = self._relay.set_tunnel(ttl=self.ttl, native=False)
        if not res or not res.get("status"):
            raise IsfError(f"couldn't authorize the tunnel to the ISF: {res}")
        self._sock = socket.create_connection((self._relay.entry_hop, self._relay.PORT), timeout=self.io_timeout)
        self._sock.settimeout(self.io_timeout)
        self._buf.clear()
        self._send_raw(MAGIC + self._sid + self._sealer.seal(T_OPEN))
        try:
            ftype, data = self._opener.open(self._read_body())
        except ConnectionError:
            return "closed"
        if ftype == T_ERR:
            raise IsfError("the ISF couldn't open the session: " + data.decode("utf-8", "replace"))
        if ftype != T_OK:
            raise IsfError("unexpected reply while opening the session")
        return "ok"

    def open(self):
        """Opens the tunnel and waits for the ISF to confirm it reached the destination."""
        outcome = self._connect_once()
        if outcome == "closed":
            # Closed with no reply: either the saved route authorization went stale, or the ticket is
            # unknown/expired/used (the ISF closes silently on those). Re-authorize once, then report.
            if getattr(self._relay, "tunnel_from_cache", False) and self._relay.reauthorize():
                self._sock.close()
                self._sealer = Sealer(self._key, self._sid, DIR_C2S)
                self._opener = Opener(self._key, self._sid, DIR_S2C)
                outcome = self._connect_once()
            if outcome == "closed":
                raise IsfError("the ISF closed the connection — the ticket is unknown, expired or already used")
        self._sock.settimeout(None)

    @property
    def relay(self):
        """The RelayClient carrying this tunnel (route, entry hop, ...)."""
        return self._relay

    def set_timeout(self, seconds):
        """Per-read timeout for recv() (None = block). recv() then raises socket.timeout."""
        if self._sock is not None:
            self._sock.settimeout(seconds)

    def send_data(self, data: bytes):
        self.bytes_sent += len(data)
        for i in range(0, len(data), MAX_CHUNK):
            self._send_raw(self._sealer.seal(T_DATA, data[i:i + MAX_CHUNK]))

    def send_fin(self):
        self._send_raw(self._sealer.seal(T_FIN))

    def recv(self):
        """Returns (type, data); (T_FIN, b'') on clean end."""
        try:
            ftype, data = self._opener.open(self._read_body())
        except ConnectionError:
            return T_FIN, b""
        if ftype == T_DATA:
            self.bytes_received += len(data)
        return ftype, data

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass


def bridge_local(tunnel: DataTunnel, local: socket.socket):
    """Pumps a local TCP connection <-> the data tunnel until both directions end."""
    def up():
        try:
            while True:
                data = local.recv(MAX_CHUNK)
                if not data:
                    tunnel.send_fin()
                    return
                tunnel.send_data(data)
        except OSError:
            pass

    def down():
        try:
            while True:
                ftype, data = tunnel.recv()
                if ftype == T_DATA:
                    local.sendall(data)
                else:
                    try:
                        local.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
        except (OSError, IsfError):
            pass

    t = threading.Thread(target=up, daemon=True)
    t.start()
    down()
    # the remote side finished; give the local side a moment to flush then stop
    t.join(timeout=2)
    tunnel.close()
    local.close()


def _write_all(fd, data: bytes):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def bridge_stdio(tunnel: DataTunnel, in_fd: int = 0, out_fd: int = 1):
    """Pumps stdin/stdout <-> the data tunnel — what ssh needs from a ProxyCommand.
    Returns when the remote side ends the stream or the tunnel drops."""
    def up():
        try:
            while True:
                data = os.read(in_fd, MAX_CHUNK)
                if not data:
                    tunnel.send_fin()
                    return
                tunnel.send_data(data)
        except (OSError, IsfError):
            pass

    t = threading.Thread(target=up, daemon=True)
    t.start()
    try:
        while True:
            ftype, data = tunnel.recv()
            if ftype != T_DATA:
                break
            _write_all(out_fd, data)
    except (OSError, IsfError):
        pass
    tunnel.close()


def split_hostport(s: str):
    host, _, port = s.rpartition(":")
    if not host or not port.isdigit():
        raise IsfError(f"expected HOST:PORT, got {s!r}")
    return host, int(port)


def _say(msg):
    print(msg, flush=True)


def serve_one(tunnel: DataTunnel, listen: str, allow_remote: bool, announce=_say):
    host, port = split_hostport(listen)
    if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote:
        raise IsfError("refusing to listen on a non-loopback address without --allow-remote-listen")
    srv = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        tunnel.close()
        raise IsfError(f"can't listen on {host}:{port}: {e.strerror or e}") from e
    srv.listen(1)
    announce(f"ready: connect to {host}:{srv.getsockname()[1]} (one connection per session)")
    local, _ = srv.accept()
    srv.close()
    bridge_local(tunnel, local)


# ---- UDP data plane ------------------------------------------------------------
class UdpTunnel:
    """One UDP session with the ISF: datagrams in, datagrams out, over the route's UDP lanes.

    Every datagram is sealed under the session key (see UdpCipher), HTH-framed for the route on the way out and
    plain on the way back, exactly like the TCP data tunnel's raw mode. UDP can lose, duplicate and reorder
    datagrams, so opening retries the OPEN until the ISF answers, a keep-alive keeps the session (and the route's
    own UDP state) alive while idle, and replayed datagrams are dropped."""

    def __init__(self, relay_factory, isf_host, udp_port, session_id: bytes, key: bytes, ttl=86400, open_timeout=15.0,
                 keepalive=20.0, max_payload=DEFAULT_UDP_MAX_PAYLOAD):
        self._relay = relay_factory(isf_host, udp_port)
        self._cipher = UdpCipher(key, session_id, DIR_C2S)
        self._replay = ReplayWindow()
        self.ttl, self.open_timeout, self.keepalive, self.max_payload = ttl, open_timeout, keepalive, max_payload
        self._sock = None
        self._closed = threading.Event()
        self._sent_at = time.monotonic()
        self._send_lock = threading.Lock()
        self.bytes_sent = self.bytes_received = 0
        self.datagrams_sent = self.datagrams_received = 0

    @property
    def relay(self):
        """The RelayClient carrying this tunnel (route, entry hop, ...)."""
        return self._relay

    def _send_raw(self, datagram: bytes):
        with self._send_lock:
            self._relay.send_HTH(self._sock, datagram, self._relay.session_id)
            self._sent_at = time.monotonic()

    def _recv_datagram(self, timeout):
        """The next authentic, fresh datagram as (type, data), or None on timeout. Rubbish and replays are skipped."""
        end = None if timeout is None else time.monotonic() + timeout
        while True:
            left = None if end is None else max(0.0, end - time.monotonic())
            if left is not None and left <= 0 and end is not None:
                return None
            self._sock.settimeout(left)
            try:
                d = self._sock.recv(65535)
            except socket.timeout:
                return None
            except OSError:
                if self._closed.is_set():
                    return None
                continue  # an ICMP error from an earlier datagram; keep waiting
            try:
                ctr, ftype, data = self._cipher.open(d)
            except IsfError:
                continue
            if not self._replay.accept(ctr):
                continue
            return ftype, data

    def open(self):
        """Authorises the route's UDP lane and asks the ISF to open the session; raises IsfError if it can't."""
        res = self._relay.set_tunnel(ttl=self.ttl, native=False)
        if not res or not res.get("status"):
            raise IsfError(f"couldn't authorize the tunnel to the ISF: {res}")
        fam = socket.AF_INET6 if ":" in str(self._relay.entry_hop) else socket.AF_INET
        self._sock = socket.socket(fam, socket.SOCK_DGRAM)
        self._sock.connect((self._relay.entry_hop, self._relay.PORT))
        end = time.monotonic() + self.open_timeout
        while time.monotonic() < end:
            self._send_raw(self._cipher.seal(T_OPEN))
            wait_until = min(end, time.monotonic() + 1.5)
            while time.monotonic() < wait_until:
                got = self._recv_datagram(max(0.05, wait_until - time.monotonic()))
                if got is None:
                    break
                ftype, data = got
                if ftype == T_OK:
                    threading.Thread(target=self._keepalive_loop, daemon=True).start()
                    return
                if ftype == T_ERR:
                    self.close(send_fin=False)
                    raise IsfError("the ISF couldn't open the session: " + data.decode("utf-8", "replace"))
        self.close(send_fin=False)
        raise IsfError("the ISF didn't answer — it may be down, have no UDP port open, or the route's UDP lanes may be unreachable")

    def _keepalive_loop(self):
        while not self._closed.wait(max(1.0, self.keepalive / 2)):
            if time.monotonic() - self._sent_at >= self.keepalive:
                try:
                    self._send_raw(self._cipher.seal(T_PING))
                except Exception:
                    return

    def send(self, data: bytes):
        """Sends one datagram to the destination. Datagrams over `max_payload` are refused (the ISF would drop them)."""
        if len(data) > self.max_payload:
            raise IsfError(f"datagram of {len(data)} bytes exceeds the {self.max_payload} byte limit")
        if self._sock is None or self._closed.is_set():
            raise IsfError("the UDP tunnel is closed")
        self._send_raw(self._cipher.seal(T_DATA, data))
        self.datagrams_sent += 1
        self.bytes_sent += len(data)

    def recv(self, timeout=None):
        """The next datagram from the destination, or None on timeout / when closed. Raises IsfError if the ISF
        reports a problem."""
        while True:
            if self._closed.is_set() or self._sock is None:
                return None
            got = self._recv_datagram(timeout)
            if got is None:
                return None
            ftype, data = got
            if ftype == T_DATA:
                self.datagrams_received += 1
                self.bytes_received += len(data)
                return data
            if ftype == T_ERR:
                raise IsfError("the ISF reported: " + data.decode("utf-8", "replace"))
            # PONG / a repeated OK: nothing for the caller

    def close(self, send_fin=True):
        if self._closed.is_set():
            return
        if send_fin and self._sock is not None:
            try:
                self._send_raw(self._cipher.seal(T_FIN))
            except Exception:
                pass
        self._closed.set()
        try:
            self._sock.close()
        except Exception:
            pass


def create_session(target, destination, ttl=60, label="", proto="tcp"):
    """Asks the ISF for a session (one control round trip): the reply has session_id, key, destination, alias."""
    fields = {"destination": destination, "ttl": ttl, "label": label}
    if proto != "tcp":
        fields["proto"] = proto
    return target.control().call("create", **fields)


class UdpForwarder:
    """A local UDP port whose datagrams travel through the ISF to one UDP destination.

    Every local sender (address and port) gets its own ISF session, so each one's replies find their way back
    to it; a session ends after `idle` seconds without traffic. Datagrams that arrive while a session is still
    being opened (about two seconds the first time) are held, up to a short queue, and sent when it is ready."""

    QUEUE = 64
    SWEEP = 5.0   # seconds between looks for idle senders

    def __init__(self, target, destination, listen="127.0.0.1:5353", idle=120.0, max_peers=64, label="isf_udp", ttl=60,
                 keepalive=20.0, allow_remote_listen=False, log=None):
        self.target, self.destination, self.idle, self.max_peers = target, destination, idle, max_peers
        self.label, self.ttl, self.keepalive = label, ttl, keepalive
        self.log = log or (lambda m: None)
        host, port = split_hostport(listen)
        if host not in ("127.0.0.1", "localhost", "::1") and not allow_remote_listen:
            raise IsfError("refusing to listen on a non-loopback address without --allow-remote-listen")
        fam = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.sock = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            self.sock.bind((host, port))
        except OSError as e:
            self.sock.close()
            raise IsfError(f"can't listen on {host}:{port}: {e.strerror or e}") from e
        self.address = self.sock.getsockname()
        self._peers = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.stats = {"sessions": 0, "up": 0, "down": 0, "dropped": 0}

    # -- peers
    def _open_peer(self, peer):
        try:
            made = create_session(self.target, self.destination, self.ttl, self.label, "udp")
            tun = UdpTunnel(self.target.udp_relay_factory(), self.target.host, self.target.udp_port,
                            bytes.fromhex(made["session_id"]), _b64d(made["key"]), keepalive=self.keepalive)
            tun.open()
        except IsfError as e:
            self.log(f"{peer['addr'][0]}:{peer['addr'][1]}: {e}")
            with self._lock:
                peer["failed_at"] = time.monotonic()
                self._peers.pop(peer["addr"], None)
            return
        with self._lock:
            peer["tunnel"] = tun
            queued, peer["queue"] = peer["queue"], []
        self.stats["sessions"] += 1
        self.log(f"session for {peer['addr'][0]}:{peer['addr'][1]} open ({made['session_id'][:8]})")
        for d in queued:
            self._to_isf(peer, d)
        threading.Thread(target=self._from_isf, args=(peer,), daemon=True).start()

    def _to_isf(self, peer, data):
        try:
            peer["tunnel"].send(data)
            self.stats["up"] += len(data)
        except IsfError as e:
            self.stats["dropped"] += 1
            self.log(f"dropped a datagram: {e}")

    def _from_isf(self, peer):
        tun = peer["tunnel"]
        try:
            while not self._stop.is_set() and peer.get("tunnel") is tun:
                d = tun.recv(1.0)
                if d is None:
                    if tun._closed.is_set():
                        break
                    continue
                peer["last"] = time.monotonic()
                self.stats["down"] += len(d)
                try:
                    self.sock.sendto(d, peer["addr"])
                except OSError:
                    pass
        except IsfError as e:
            self.log(f"{peer['addr'][0]}:{peer['addr'][1]}: {e}")
        finally:
            self._drop(peer)

    def _drop(self, peer):
        """Forgets a sender and closes its session; False if it was already gone."""
        with self._lock:
            if self._peers.get(peer["addr"]) is not peer:
                return False
            del self._peers[peer["addr"]]
        tun = peer.get("tunnel")
        if tun is not None:
            tun.close()
        return True

    def _sweep(self):
        while not self._stop.wait(self.SWEEP):
            now = time.monotonic()
            with self._lock:
                old = [p for p in self._peers.values() if now - p["last"] > self.idle and p.get("tunnel") is not None]
            for p in old:
                if self._drop(p):
                    self.log(f"session for {p['addr'][0]}:{p['addr'][1]} closed (idle)")

    # -- main loop
    def serve_forever(self):
        threading.Thread(target=self._sweep, daemon=True).start()
        self.sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                peer = self._peers.get(addr)
                if peer is None:
                    if len(self._peers) >= self.max_peers:
                        self.stats["dropped"] += 1
                        continue
                    peer = {"addr": addr, "tunnel": None, "queue": [], "last": time.monotonic()}
                    self._peers[addr] = peer
                    threading.Thread(target=self._open_peer, args=(peer,), daemon=True).start()
                peer["last"] = time.monotonic()
                if peer["tunnel"] is None:
                    if len(peer["queue"]) < self.QUEUE:
                        peer["queue"].append(data)
                    else:
                        self.stats["dropped"] += 1
                    continue
            self._to_isf(peer, data)

    def stop(self):
        self._stop.set()
        with self._lock:
            peers = list(self._peers.values())
        for p in peers:
            self._drop(p)
        try:
            self.sock.close()
        except OSError:
            pass


# ---- ISF profiles and routes ---------------------------------------------------
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def profiles_path():
    return os.environ.get("ISF_PROFILES") or os.path.join(DEFAULT_KEYS_DIR, "isfs.json")


def default_isf_pub(name):
    return os.path.join(DEFAULT_KEYS_DIR, "isf_public.pem" if name == "default" else f"{name}_isf_public.pem")


def validate_public_pem(text: str) -> str:
    """Returns the PEM text if it is a usable RSA *public* key; raises IsfError otherwise."""
    from Crypto.PublicKey import RSA
    try:
        key = RSA.import_key(text.strip())
    except (ValueError, IndexError, TypeError):
        raise IsfError("that is not a valid RSA public key (PEM)") from None
    if key.has_private():
        raise IsfError("that is a PRIVATE key — never share it; give only the public key")
    if key.size_in_bits() < 2048:
        raise IsfError("the key is smaller than 2048 bits")
    return text.strip() + "\n"


class Profiles:
    """The ISFs this machine uses: name -> address, route, ports, the ISF's public key.

    Lives in ~/.ztr_isf/isfs.json (mode 0600). One client key pair serves all of them; each ISF has
    its own public key file. A pre-existing single-ISF ~/.ztr_isf/isf_ssh.json is read as "default"."""

    def __init__(self, path=None):
        self.path = path or profiles_path()
        self.data = self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                d = json.load(f)
            if isinstance(d, dict) and isinstance(d.get("isfs"), dict):
                return d
        except (OSError, ValueError):
            pass
        return self._from_legacy()

    @staticmethod
    def _from_legacy():
        out = {"default": None, "isfs": {}}
        legacy = os.environ.get("ISF_SSH_CONFIG") or os.path.join(DEFAULT_KEYS_DIR, "isf_ssh.json")
        try:
            with open(legacy) as f:
                old = json.load(f)
            if old.get("isf_host") and old.get("config_file"):
                kd = old.get("keys_dir") or DEFAULT_KEYS_DIR
                out["isfs"]["default"] = {"host": old["isf_host"], "route": old["config_file"],
                                          "ctrl_port": int(old.get("ctrl_port", 7700)), "data_port": int(old.get("data_port", 7781)),
                                          "isf_pub": os.path.join(kd, "isf_public.pem"),
                                          "timing_defense": bool(old.get("timing_defense")), "note": ""}
                out["default"] = "default"
                if old.get("ztrclient_dir"):
                    out["ztrclient_dir"] = old["ztrclient_dir"]
        except (OSError, ValueError, TypeError):
            pass
        return out

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.data, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    @property
    def names(self):
        return sorted(self.data["isfs"])

    @property
    def default_name(self):
        d = self.data.get("default")
        return d if d in self.data["isfs"] else (self.names[0] if self.names else None)

    def get(self, name=None):
        name = name or self.default_name
        if not name:
            raise IsfError("no ISF configured yet — add one with: ztr_isf_client.py isf add NAME --host IP --route FILE")
        p = self.data["isfs"].get(name)
        if p is None:
            raise IsfError(f"no ISF named {name!r} (known: {', '.join(self.names) or 'none'})")
        return dict(p, name=name)

    def upsert(self, name, **fields):
        if not NAME_RE.match(name or ""):
            raise IsfError("an ISF name is 1-32 letters, digits, dot, dash or underscore, starting with a letter or digit")
        cur = dict(self.data["isfs"].get(name) or {})
        cur.update({k: v for k, v in fields.items() if v is not None})
        host = str(cur.get("host", "")).strip()
        if not HOST_RE.match(host):
            raise IsfError("the ISF address must be an IP address or host name")
        route = str(cur.get("route", "")).strip()
        if not route or "/" in route or "\\" in route:
            raise IsfError("pick a route (a file name from routes/)")
        for k, d in (("ctrl_port", 7700), ("data_port", 7781), ("udp_port", DEFAULT_UDP_PORT)):
            try:
                v = int(cur.get(k, d))
            except (TypeError, ValueError):
                raise IsfError(f"{k.replace('_', ' ')} must be a number") from None
            if not 1 <= v <= 65535:
                raise IsfError(f"{k.replace('_', ' ')} must be between 1 and 65535")
            cur[k] = v
        cur.update(host=host, route=route, isf_pub=cur.get("isf_pub") or default_isf_pub(name),
                   timing_defense=bool(cur.get("timing_defense")), note=str(cur.get("note", ""))[:120])
        self.data["isfs"][name] = cur
        if not self.data.get("default") or self.data["default"] not in self.data["isfs"]:
            self.data["default"] = name
        return dict(cur, name=name)

    def remove(self, name):
        if name not in self.data["isfs"]:
            raise IsfError(f"no ISF named {name!r}")
        del self.data["isfs"][name]
        if self.data.get("default") == name:
            self.data["default"] = self.names[0] if self.names else None

    def set_default(self, name):
        if name not in self.data["isfs"]:
            raise IsfError(f"no ISF named {name!r}")
        self.data["default"] = name


def list_routes(zdir):
    """Routes in <ztrclient>/routes/: file, exit country, status, entry and exit address."""
    out = []
    rdir = os.path.join(zdir, "routes")
    try:
        names = sorted(os.listdir(rdir))
    except OSError:
        return out
    for fn in names:
        if not fn.endswith(".ztr"):
            continue
        try:
            with open(os.path.join(rdir, fn)) as f:
                d = json.load(f)
        except (OSError, ValueError):
            continue
        chain = d.get("chain") or []
        role = {h.get("role"): str(h.get("address", "")) for h in chain if isinstance(h, dict)}
        out.append({"file": fn, "exit_country": d.get("exit_country"), "status": d.get("status"),
                    "entry": role.get("entry"), "exit": role.get("exit"), "hops": len(chain)})
    return out


def resolve_route(zdir, text):
    """Accepts a route file name with or without .ztr, or the id part of its name (e.g. c6c0ed68)."""
    routes = [r["file"] for r in list_routes(zdir)]
    if text in routes:
        return text
    cands = [r for r in routes if r == text + ".ztr" or r.endswith("_" + text + ".ztr") or r[:-4].endswith(text)] if len(text) >= 4 else []
    if len(cands) == 1:
        return cands[0]
    if len(cands) > 1:
        raise IsfError(f"{text!r} matches several routes ({', '.join(cands)}) — be more specific")
    return text  # unknown here: let the relay client report the missing file


def route_summary(zdir, route_file):
    """Entry / middle / exit for the path log. Falls back gracefully if the file isn't readable."""
    info = {"entry": None, "exit": None, "exit_country": None, "middle": False}
    try:
        with open(os.path.join(zdir, "routes", route_file)) as f:
            d = json.load(f)
        for h in d.get("chain", []):
            if h.get("role") in ("entry", "exit"):
                info[h["role"]] = str(h.get("address", ""))
            elif h.get("role") == "middle":
                info["middle"] = True
        info["exit_country"] = d.get("exit_country")
    except (OSError, ValueError, AttributeError):
        pass
    return info


# ---- path log (stderr) ----------------------------------------------------------
LOG_TAG = "isf_ssh"


def _color(code, text):
    return f"\033[{code}m{text}\033[0m" if sys.stderr.isatty() else text


def log(msg, quiet=False):
    if quiet or os.environ.get("ISF_SSH_QUIET"):
        return
    print(f"{_color('0;36', '[' + LOG_TAG + ']')} {msg}", file=sys.stderr, flush=True)


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def mask_host(h):
    """Hides the address of a hop or an ISF in what is printed: 138.197.149.249 -> 138.197.x.x,
    a host name -> its first two letters and last label (ex***.com). Anything else becomes ***."""
    h = str(h or "")
    if _IPV4.match(h):
        a = h.split(".")
        return f"{a[0]}.{a[1]}.x.x"
    if h.endswith("._ztr"):
        return "***._ztr"
    if re.match(r"^[A-Za-z0-9.-]+$", h) and "." in h:
        label = h.rsplit(".", 1)[1]
        return f"{h[:2]}***.{label}"
    return "***"


def path_log_lines(t, zdir, dest, reveal=False):
    """What the user should see: this is NOT a direct connection. The addresses of the ZTRelay hops and of the
    ISF are masked unless `reveal` (the destination is shown as typed)."""
    show = (lambda h: h) if reveal else mask_host
    arrow = " -> " if (sys.stderr.encoding or "").lower() not in ("utf-8", "utf8") else " → "
    s = route_summary(zdir, t.route)
    hops = ["you", f"entry {show(s['entry'])}" if s["entry"] else "entry"]
    if s["middle"]:
        hops.append("middle")
    exit_txt = f"exit {show(s['exit'])}" if s["exit"] else "exit"
    if s["exit_country"]:
        exit_txt += f" ({s['exit_country']})"
    hops += [exit_txt, f"ISF {show(t.host)}" + (f" [{t.name}]" if t.name else ""), dest]
    return [_color("1", "not a direct connection — via ZTRelay and your ISF"),
            arrow.join(hops),
            f"route {t.route}: the exit only sees the ISF; {dest.split(':')[0]} sees the ISF's IP, not yours"]


class Target:
    """Everything needed to reach one ISF: address, route, ports, keys."""

    def __init__(self, host, route, ctrl_port, data_port, priv, pub, isf_pub, timing_defense=False, name=None, udp_port=DEFAULT_UDP_PORT):
        self.host, self.route, self.ctrl_port, self.data_port, self.udp_port = host, route, ctrl_port, data_port, udp_port
        self.priv, self.pub, self.isf_pub, self.timing_defense, self.name = priv, pub, isf_pub, timing_defense, name

    def control(self):
        return ControlChannel(default_relay_factory(self.route, self.timing_defense), self.host, self.ctrl_port,
                              self.priv, self.pub, self.isf_pub)

    def relay_factory(self):
        return default_relay_factory(self.route, self.timing_defense)

    def udp_relay_factory(self):
        return default_relay_factory(self.route, self.timing_defense, transport="udp")


def resolve_target(a, zdir=None):
    """Merges --isf NAME (or the default ISF) with explicit flags; flags win."""
    profs = Profiles()
    prof = None
    if getattr(a, "isf", None):
        prof = profs.get(a.isf)
    elif not getattr(a, "isf_host", None):
        prof = profs.get(None)
    host = a.isf_host or (prof or {}).get("host")
    route = a.config_file or (prof or {}).get("route")
    if not host or not route:
        raise IsfError("need an ISF address and a route (use --isf NAME, or --isf-host and --config-file)")
    if zdir:
        route = resolve_route(zdir, route)
    d = a.keys_dir
    return Target(host=host, route=route,
                  ctrl_port=a.ctrl_port or (prof or {}).get("ctrl_port", 7700),
                  data_port=a.data_port or (prof or {}).get("data_port", 7781),
                  udp_port=getattr(a, "udp_port", None) or (prof or {}).get("udp_port", DEFAULT_UDP_PORT),
                  priv=a.own_priv or os.path.join(d, "client_private.pem"),
                  pub=a.own_pub or os.path.join(d, "client_public.pem"),
                  isf_pub=a.isf_pub or (prof or {}).get("isf_pub") or os.path.join(d, "isf_public.pem"),
                  timing_defense=bool(a.timing_defense or (prof or {}).get("timing_defense")),
                  name=(prof or {}).get("name"))


# ---- key management -----------------------------------------------------------
def gen_keys(prefix: str, out_dir: str, bits: int = 2048):
    from utils.crypt_bot import CryptBot
    os.makedirs(out_dir, exist_ok=True)
    priv = os.path.join(out_dir, f"{prefix}_private.pem")
    pub = os.path.join(out_dir, f"{prefix}_public.pem")
    for p in (priv, pub):
        if os.path.exists(p):
            raise IsfError(f"{p} already exists — refusing to overwrite")
    CryptBot(pathPrivateKey=priv, pathPublicKey=pub, pathRecipientPublicKey=pub).create_keys(rsa_size=bits, reuse=False)
    os.chmod(priv, 0o600)
    return priv, pub


# ---- CLI ----------------------------------------------------------------------
def _add_common(p):
    p.add_argument("--ztrclient-dir", help="directory containing ztrClient.py (default: $ZTRCLIENT_DIR, the saved one, or next to this script)")
    p.add_argument("--keys-dir", default=DEFAULT_KEYS_DIR, help=f"where client_private.pem / client_public.pem live (default {DEFAULT_KEYS_DIR})")
    p.add_argument("--own-priv"); p.add_argument("--own-pub")
    p.add_argument("--isf-pub", help="the ISF's public key (default: the ISF profile's, or <keys-dir>/isf_public.pem)")
    p.add_argument("--isf", metavar="NAME", help="which of your ISFs (default: the default one — see `isf list`)")
    p.add_argument("--isf-host", help="public address of the ISF (overrides the ISF profile)")
    p.add_argument("--config-file", "--route", dest="config_file", metavar="ROUTE",
                   help="your route: a file name in routes/ (overrides the ISF profile; see `routes`)")
    p.add_argument("--timing-defense", action="store_true", help="ask the hops for jitter + decoy traffic")
    p.add_argument("--ctrl-port", type=int); p.add_argument("--data-port", type=int)
    p.add_argument("--udp-port", type=int, help=f"the ISF's UDP port (default {DEFAULT_UDP_PORT})")


def target_for(isf=None, route=None, timing_defense=False, keys_dir=None, zdir=None):
    """Library entry point for other tools (ztr_https): the Target for a named ISF (None = the default one),
    optionally on a different route, using the same profile list as isf_ssh and the dashboard."""
    ns = argparse.Namespace(isf=isf or None, isf_host=None, config_file=route, ctrl_port=None, data_port=None,
                            keys_dir=keys_dir or DEFAULT_KEYS_DIR, own_priv=None, own_pub=None, isf_pub=None,
                            timing_defense=bool(timing_defense), udp_port=None)
    return resolve_target(ns, zdir)


def _target(a, zdir):
    return resolve_target(a, zdir)


def _print_routes(zdir):
    rows = list_routes(zdir)
    if not rows:
        print(f"no routes in {os.path.join(zdir, 'routes')}")
        return
    w = max(len(r["file"]) for r in rows)
    print(f"{'ROUTE'.ljust(w)}  EXIT  STATUS    ENTRY             EXIT ADDRESS")
    for r in rows:
        print(f"{r['file'].ljust(w)}  {str(r['exit_country'] or '-').ljust(4)}  {str(r['status'] or '-').ljust(8)}  "
              f"{str(r['entry'] or '-').ljust(16)}  {r['exit'] or '-'}")


def _isf_command(a, zdir):
    ps = Profiles()
    if a.isf_cmd == "list":
        if not ps.names:
            print("no ISFs configured. Add one: ztr_isf_client.py isf add NAME --host IP --route FILE")
            return 0
        for n in ps.names:
            p = ps.data["isfs"][n]
            mark = "*" if n == ps.default_name else " "
            have = "key ok" if os.path.exists(p["isf_pub"]) else "ISF public key MISSING"
            print(f"{mark} {n:<14} {p['host']:<18} route {p['route']:<18} ports {p['ctrl_port']}/{p['data_port']}/{p.get('udp_port', DEFAULT_UDP_PORT)}udp  {have}"
                  + (f"  — {p['note']}" if p.get("note") else ""))
        print("(* = default)")
    elif a.isf_cmd in ("add", "set"):
        if a.isf_cmd == "add" and a.name in ps.data["isfs"]:
            raise IsfError(f"{a.name!r} already exists — use `isf set` to change it")
        if a.isf_cmd == "set" and a.name not in ps.data["isfs"]:
            raise IsfError(f"no ISF named {a.name!r} — use `isf add`")
        if a.route:
            a.route = resolve_route(zdir, a.route)
        p = ps.upsert(a.name, host=a.host, route=a.route, ctrl_port=a.ctrl_port, data_port=a.data_port, udp_port=a.udp_port, isf_pub=a.isf_pub,
                      timing_defense=True if a.timing_defense else None, note=a.note)
        if a.default:
            ps.set_default(a.name)
        ps.save()
        print(f"saved {a.name}: {p['host']} via {p['route']}" + ("" if os.path.exists(p["isf_pub"]) else
              f"\nnote: put the ISF's public key at {p['isf_pub']} (the ISF operator's isf_public.pem)"))
    elif a.isf_cmd == "remove":
        ps.remove(a.name); ps.save(); print(f"removed {a.name}")
    elif a.isf_cmd == "default":
        ps.set_default(a.name); ps.save(); print(f"default ISF is now {a.name}")
    elif a.isf_cmd == "show":
        print(json.dumps(ps.get(a.name), indent=2))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(prog="ztr_isf_client", description="Use your own ISF through ZTRelay.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen-keys", help="create this machine's ISF keypair")
    g.add_argument("--prefix", default="client"); g.add_argument("--out-dir", default=DEFAULT_KEYS_DIR)
    g.add_argument("--bits", type=int, default=2048); g.add_argument("--ztrclient-dir")

    r = sub.add_parser("routes", help="list your routes (the files in routes/)")
    r.add_argument("--ztrclient-dir")

    i = sub.add_parser("isf", help="manage the ISFs you use (several are fine)")
    i.add_argument("--ztrclient-dir")
    isub = i.add_subparsers(dest="isf_cmd", required=True)
    isub.add_parser("list")
    for nm in ("add", "set"):
        x = isub.add_parser(nm, help="add a new ISF" if nm == "add" else "change an ISF's settings")
        x.add_argument("name"); x.add_argument("--host", required=(nm == "add")); x.add_argument("--route", required=(nm == "add"))
        x.add_argument("--ctrl-port", type=int); x.add_argument("--data-port", type=int)
        x.add_argument("--udp-port", type=int, help=f"the ISF's UDP port (default {DEFAULT_UDP_PORT})")
        x.add_argument("--isf-pub", help="path of the ISF's public key file")
        x.add_argument("--timing-defense", action="store_true"); x.add_argument("--note"); x.add_argument("--default", action="store_true")
    for nm in ("remove", "default", "show"):
        x = isub.add_parser(nm)
        x.add_argument("name", nargs="?" if nm == "show" else None)

    c = sub.add_parser("ctrl", help="one control operation")
    _add_common(c)
    c.add_argument("-q", "--quiet", action="store_true", help="create: print only the ticket")
    ops = c.add_subparsers(dest="op", required=True)
    ops.add_parser("health"); ops.add_parser("list"); ops.add_parser("overview")
    ops.add_parser("allowlist", help="show the allowlist")
    for nm, h in (("allow-add", "add an entry to the ISF's allowlist (host:port or host:*)"), ("allow-remove", "remove an entry that was added remotely")):
        ops.add_parser(nm, help=h).add_argument("entry")
    ops.add_parser("alias-list", help="the .isf aliases defined on the ISF")
    aa = ops.add_parser("alias-add", help="create an alias: <64 random characters>.isf (or --name) -> a real host name or address")
    aa.add_argument("target", help="the real host name or address the alias stands for")
    aa.add_argument("--name", default="", help="your own short name instead of 64 random characters (letters, digits, dashes)")
    aa.add_argument("--note", default="")
    ar = ops.add_parser("alias-remove", help="remove an alias"); ar.add_argument("name")
    at = ops.add_parser("alias-retarget", help="point an existing alias at another host"); at.add_argument("name"); at.add_argument("target")
    cr = ops.add_parser("create")
    cr.add_argument("--destination", required=True, help="HOST:PORT the ISF should connect to")
    cr.add_argument("--ttl", type=int, default=300, help="seconds the ticket stays usable before it is opened")
    cr.add_argument("--label", default="")
    cr.add_argument("--proto", choices=("tcp", "udp"), default="tcp", help="udp: a datagram session (needs an ISF started with --udp-bind)")
    for name in ("get", "delete"):
        o = ops.add_parser(name); o.add_argument("session_id")
    sd = ops.add_parser("set-destination"); sd.add_argument("session_id"); sd.add_argument("--destination", required=True)

    cl = sub.add_parser("client", help="open the data tunnel for a ticket and bridge it to a local port")
    _add_common(cl)
    cl.add_argument("--ticket", required=True)
    cl.add_argument("--listen", default="127.0.0.1:2222")
    cl.add_argument("--allow-remote-listen", action="store_true")

    px = sub.add_parser("proxy", help="create a session and bridge it to stdin/stdout (for ssh -o ProxyCommand)")
    _add_common(px)
    px.add_argument("--destination", required=True, help="HOST:PORT")
    px.add_argument("--ttl", type=int, default=60); px.add_argument("--label", default="isf_ssh")
    px.add_argument("--quiet", action="store_true", help="don't print the path log")
    px.add_argument("--show-ips", action="store_true", help="show the real addresses of the hops and the ISF in the path log (masked by default)")

    ud = sub.add_parser("udp", help="a local UDP port whose datagrams go through the ISF to a UDP destination")
    _add_common(ud)
    ud.add_argument("--destination", required=True, help="HOST:PORT the ISF should send the datagrams to (UDP)")
    ud.add_argument("--listen", default="127.0.0.1:5353", help="local address to listen on (default 127.0.0.1:5353)")
    ud.add_argument("--allow-remote-listen", action="store_true")
    ud.add_argument("--idle", type=float, default=120.0, help="seconds without traffic before a local sender's session ends (default 120)")
    ud.add_argument("--max-peers", type=int, default=64, help="most local senders served at once (default 64)")
    ud.add_argument("--keepalive", type=float, default=20.0)
    ud.add_argument("--quiet", action="store_true", help="don't print the path log and session messages")
    ud.add_argument("--show-ips", action="store_true", help="show the real addresses of the hops and the ISF in the path log")

    co = sub.add_parser("connect", help="create a session and bridge it, in one step")
    _add_common(co)
    co.add_argument("--destination", required=True)
    co.add_argument("--ttl", type=int, default=300); co.add_argument("--label", default="")
    co.add_argument("--listen", default="127.0.0.1:2222")
    co.add_argument("--allow-remote-listen", action="store_true")
    return ap


def _fmt_bytes(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024


def main(argv=None):
    a = build_parser().parse_args(argv)
    try:
        zdir = locate_ztrclient(getattr(a, "ztrclient_dir", None)) if a.cmd != "gen-keys" else None
        if a.cmd == "gen-keys":
            locate_ztrclient(a.ztrclient_dir)
            priv, pub = gen_keys(a.prefix, a.out_dir, a.bits)
            print(f"wrote {priv}\nwrote {pub}")
            print("Give the public key to your ISF's operator as a --peer-pub, then add the ISF with: "
                  "ztr_isf_client.py isf add NAME --host IP --route FILE --isf-pub PATH_TO_ITS_isf_public.pem")
            return 0
        if a.cmd == "routes":
            _print_routes(zdir)
            return 0
        if a.cmd == "isf":
            return _isf_command(a, zdir)

        t = _target(a, zdir)
        if a.cmd == "ctrl":
            ch = t.control()
            if a.op in ("health", "list", "overview"):
                r = ch.call(a.op)
            elif a.op == "allowlist":
                r = ch.call("overview")["policy"]
            elif a.op in ("allow-add", "allow-remove"):
                r = ch.call("policy_add" if a.op == "allow-add" else "policy_remove", entry=a.entry)
            elif a.op == "alias-list":
                r = ch.call("alias_list")
            elif a.op == "alias-add":
                r = ch.call("alias_add", target=a.target, name=a.name, note=a.note)
                if a.quiet:
                    print(r["alias"]); return 0
            elif a.op == "alias-remove":
                r = ch.call("alias_remove", name=a.name)
            elif a.op == "alias-retarget":
                r = ch.call("alias_retarget", name=a.name, target=a.target)
            elif a.op == "create":
                r = create_session(t, a.destination, a.ttl, a.label, a.proto)
                r["ticket"] = make_ticket(r["session_id"], _b64d(r.pop("key")))
                if a.quiet:
                    print(r["ticket"]); return 0
            elif a.op == "set-destination":
                r = ch.call("set_destination", session_id=a.session_id, destination=a.destination)
            else:
                r = ch.call(a.op.replace("-", "_"), session_id=a.session_id)
            print(json.dumps(r, indent=2))
            return 0

        if a.cmd == "udp":
            quiet = bool(a.quiet)
            reveal = bool(a.show_ips or os.environ.get("ISF_SSH_SHOW_IPS"))
            for line in path_log_lines(t, zdir, a.destination, reveal):
                log(line, quiet)
            fwd = UdpForwarder(t, a.destination, a.listen, idle=a.idle, max_peers=a.max_peers, keepalive=a.keepalive,
                               allow_remote_listen=a.allow_remote_listen, log=lambda m: log(m, quiet))
            log(f"UDP ready: send datagrams to {fwd.address[0]}:{fwd.address[1]} — they go through the ISF to {a.destination} (Ctrl+C to stop)", quiet)
            import signal
            for sig in (signal.SIGTERM, signal.SIGHUP):
                signal.signal(sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
            try:
                fwd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                fwd.stop()
                log(f"stopped · {fwd.stats['sessions']} session(s), {_fmt_bytes(fwd.stats['up'])} sent, {_fmt_bytes(fwd.stats['down'])} received, "
                    f"{fwd.stats['dropped']} dropped", quiet)
            return 0

        quiet = bool(getattr(a, "quiet", False)) and a.cmd == "proxy"
        if a.cmd == "proxy":
            reveal = bool(a.show_ips or os.environ.get("ISF_SSH_SHOW_IPS"))
            for line in path_log_lines(t, zdir, a.destination, reveal):
                log(line, quiet)
            log("asking the ISF for a session…", quiet)
        if a.cmd in ("connect", "proxy"):
            r = t.control().call("create", destination=a.destination, ttl=a.ttl, label=a.label)
            sid = bytes.fromhex(r["session_id"]); key = _b64d(r["key"])
            if a.cmd == "proxy":
                log(f"session {r['session_id'][:8]} ready — opening the encrypted tunnel…", quiet)
        else:
            sid, key = parse_ticket(a.ticket)
        tunnel = DataTunnel(t.relay_factory(), t.host, t.data_port, sid, key)
        tunnel.open()
        if a.cmd == "proxy":
            log(f"connected: the ISF reached {a.destination} — the SSH handshake starts now", quiet)
            started = time.time()
            # ssh ends a ProxyCommand with a signal, so make that a normal exit that still prints the summary
            import signal
            for sig in (signal.SIGTERM, signal.SIGHUP):
                signal.signal(sig, lambda *_: sys.exit(0))
            try:
                bridge_stdio(tunnel)
            finally:
                log(f"session closed · {_fmt_bytes(tunnel.bytes_sent)} sent, {_fmt_bytes(tunnel.bytes_received)} received, "
                    f"{time.time() - started:.1f} s", quiet)
        else:
            serve_one(tunnel, a.listen, a.allow_remote_listen)
        return 0
    except IsfError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
