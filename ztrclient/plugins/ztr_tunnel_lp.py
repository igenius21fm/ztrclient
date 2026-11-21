import asyncio
import itertools
import json
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
from collections import OrderedDict

# ztrClient.py lives one directory up (package root), not next to this
# file — plain `from ztrClient import ...` only resolves by accident of
# CWD, and fails with ModuleNotFoundError when this is run the way the
# docs and the installer's service definition actually invoke it
# (`python3 plugins/ztr_tunnel_lp.py`, which puts plugins/ on sys.path,
# not its parent).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ztrClient import ConfigError, ConfigFieldError, ConfigNotFoundError, ConfigParseError, RelayClient, RelayConfig

"""
    Generic ztrRelay local proxy service — forwards raw TCP through the
    relay to any target_host:target_port a session authorizes. Nothing here
    is protocol-specific; it just moves bytes. SSH is one thing that runs
    over it (see plugins/ztr_ssh), not the only thing.

    One persistent process, started with a default route (--config-file). A
    START request can name a different .ztr from routes/ for just that one
    session (see below); without one, it uses the default. Run it
    standalone, or as a background service
    (the installer's --with-service sets that up for you: systemd on Linux,
    launchd on macOS).
    Either way it needs pycryptodome, which is why the
    installers create a dedicated venv for it instead of relying on
    whatever's on the system python3:

        ~/.local/share/ztr/venv/bin/python3 ztr_tunnel_lp.py --config-file route.ztr

    --config-file is the default route, and a bare filename, not a path — RelayConfig (ztrClient.py)
    always resolves it inside routes/, next to ztrClient.py itself, so put
    your downloaded config at routes/route.ztr, not next to ztrClient.py
    directly and not wherever you happen to be running this from.

    It does not listen on a fixed port itself. Instead it opens a small
    control server (default 127.0.0.1:2223) that speaks newline-delimited
    JSON, one request/response object per line:

        START {"cmd": "start", "relay_name": "example._ztr", "target_port": 22}
              optional: "config_file": "other.ztr"  (a bare filename in routes/ —
              this session uses that route instead of the service's default)
          -> {"status": true, "session_id": "...", "local_ip": "10.10.15.10", "local_port": 51234, "warm": false}
          -> {"status": false, "error": "..."}

        START through your own ISF (Intermediate Server Forwarder — see ztr_isf_client.py):
              {"cmd": "start", "relay_name": "host.example.com", "target_port": 22, "isf": "work"}
              "isf" is the name of one of your ISFs ("@default" = your default one); "relay_name" is then the
              server's real host name or address — an ISF can't look up ._ztr aliases. optional: "config_file"
              (the route that carries the traffic to the ISF; default: the route saved with that ISF).
              The ISF is asked for the connection when START arrives, so a destination it refuses fails right
              here; the answer carries "isf": "work" and "path": [...] (what the connection goes through, with
              the addresses masked). Every connection to the local port then goes your machine -> ZTRelay -> your
              ISF -> the server, and the exit hop only ever sees the ISF. There's no spare-tunnel pool for these
              (each connection asks the ISF for its own single-use session), so each takes a moment longer to open.
              A caller that asked for an ISF must check that the answer says "isf" — a service from before this
              existed would ignore the field and connect without it.

        END   {"cmd": "end", "session_id": "..."}
          -> {"status": true}
          -> {"status": false, "error": "unknown session"}

        LIST  {"cmd": "list"}
          -> {"status": true, "sessions": [
                {"session_id": "...", "relay_name": "...", "target_port": 22,
                 "config_file": "route.ztr",
                 "local_ip": "10.10.15.10", "local_port": 51234,
                 "active_connections": 1, "idle_seconds": 0.0}
              ]}

    Per-session listeners bind to --local-ip (default 10.10.15.10), a
    dedicated address instead of the generic 127.0.0.1 — set it up once
    with the installer's --with-local-ip. Every wrapper reads local_ip back
    from the START response rather than assuming a hardcoded default, so
    the service's actual bind address is always the single source of
    truth. Falls back to 127.0.0.1 with --local-ip 127.0.0.1 if you'd
    rather not set up the dedicated address at all. The control port
    itself stays on 127.0.0.1 regardless — only the per-session
    data-plane listeners move.

    Each START authorizes a fresh tunnel for that target and opens a new
    ephemeral local listener just for that session — so N concurrent
    sessions (different terminals, different targets, doesn't matter) each
    get their own local port instead of fighting over one fixed port. END
    tears down that one session only; the service and every other session
    keep running. See plugins/ztr_ssh (always runs a real `ssh`) and
    plugins/ztr_forward (generic — waits, or runs any command you give it)
    for the two client-side wrappers that drive this over the control port.

    Warm pool: authorizing a tunnel takes a couple of seconds (the hops do
    the work), so after every START the service quietly authorizes one spare
    tunnel for that same route and target. The next START for it takes the
    spare and answers immediately ("warm": true), and a replacement is
    authorized in the background. A spare is single-use and short-lived: it's
    discarded after --warm-max-age seconds, and also if this machine's local
    address towards the entry hop has changed (a sign you've switched
    network, which makes the authorization useless). Only targets you've
    already used get a spare, and the pool is capped, so it winds down when
    you stop using them. Turn it off with --no-warm-pool.

    Stale spares: an authorization is tied to the public address the entry hop
    saw when it was made. If that address changes while a spare is waiting
    (a new network, a VPN, a roaming ISP), the relay turns the spare away the
    moment it's used. When a connection on a spare tunnel is closed by the
    relay within a few seconds with nothing ever coming back, the service
    drops every spare, authorizes a fresh tunnel, replays what the client had
    already sent, and carries on — the client never sees the failure. This is
    only attempted for spares, only for that early empty close, and only if
    the client sent no more than 64 KB before the first reply.

    A background reaper also closes any session that's had zero active
    connections for longer than --idle-timeout — the safety net for a
    client that dies hard enough to skip sending END (a plain process kill,
    for instance, doesn't run the wrapper's EXIT trap). A session with a
    live connection is never touched, no matter how long it's been open.
"""


class Route:
    """The per-route settings a session needs, read from one .ztr config."""

    __slots__ = ("config_file", "relay_port", "header_format", "raw_max_size")

    def __init__(self, config_file: str):
        conf = RelayConfig(config_file=config_file)
        data_streams = conf.settings("data_streams")
        self.config_file = config_file
        self.header_format = data_streams["native"]["header_format"]
        self.raw_max_size = data_streams["raw"]["max_size"]
        # "ssh" here is the .ztr config's own service key (see
        # routes.controller.js's getConfig()) — it names the relay-side
        # channel every session in this file uses, not a protocol
        # restriction. Nothing downstream cares what's actually forwarded.
        self.relay_port = conf.service("ssh")["port"]


def _is_bare_filename(name) -> bool:
    """routes/ is flat — a config is named, never addressed by path. This is
    the trust boundary: the control port takes input from any local process,
    and RelayConfig joins whatever it's given onto routes/ as-is."""
    return (
        isinstance(name, str)
        and 0 < len(name) <= 255
        and name == os.path.basename(name)
        and not name.startswith(".")
        and "\x00" not in name
        and "\\" not in name
    )


class Spare:
    """A tunnel that's already authorized but has no local listener yet."""

    __slots__ = ("client", "route", "created", "local_addr")

    def __init__(self, client: RelayClient, route: Route, local_addr):
        self.client = client
        self.route = route
        self.created = time.monotonic()
        self.local_addr = local_addr


def _ts():
    return time.strftime("%H:%M:%S")


def _fmt_bytes(n):
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KB"


def _local_addr_towards(host, port):
    """The local address this machine would use to reach (host, port) — what
    changes when you move to another network. A UDP connect() only picks a
    route; it sends nothing."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, int(port)))
            return sock.getsockname()[0]
    except (OSError, TypeError, ValueError):
        return None


class Session:
    __slots__ = ("client", "route", "server", "local_port", "active_connections", "idle_since", "warm", "generation", "recover_lock")

    def __init__(self, client: RelayClient, route: Route, server: asyncio.AbstractServer, local_port: int, warm: bool = False):
        self.client = client
        self.route = route
        self.server = server
        self.local_port = local_port
        # True while this session still runs on a spare tunnel nobody has
        # proven works yet. `generation` counts tunnel swaps, so connections
        # that all fail on the same stale spare re-authorize only once.
        self.warm = warm
        self.generation = 0
        self.recover_lock = asyncio.Lock()
        self.active_connections = 0
        # A session is "idle" whenever it has zero active connections — this
        # is the monotonic timestamp of when that most recently became
        # true. Starts idle at creation (nothing has connected yet); reset
        # every time a connection drops back to zero. The reaper only ever
        # looks at this when active_connections == 0, so a long-running
        # connection is never reaped no matter how old this timestamp gets.
        self.idle_since = time.monotonic()


# ---------- ISF: sessions that go through one of your own Intermediate Server Forwarders ----------

PLUGINS_DIR = os.path.dirname(os.path.abspath(__file__))
_ISF_CLIENT = None
_ISF_NAME_RE = re.compile(r"^(@default|[A-Za-z0-9][A-Za-z0-9_.-]{0,31})$")
_ISF_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _load_isf_client():
    """Imports ztr_isf_client on first use of an ISF, from next to this file, ~/isf, or $ISF_CLIENT_DIR."""
    global _ISF_CLIENT
    if _ISF_CLIENT is not None:
        return _ISF_CLIENT
    for d in (os.environ.get("ISF_CLIENT_DIR"), PLUGINS_DIR, os.path.join(PLUGINS_DIR, "ztr_isf"),
              os.path.join(os.path.expanduser("~"), "isf")):
        if d and os.path.isfile(os.path.join(d, "ztr_isf_client.py")):
            if d not in sys.path:
                sys.path.insert(0, d)
            import ztr_isf_client
            _ISF_CLIENT = ztr_isf_client
            return _ISF_CLIENT
    raise ValueError("an ISF needs ztr_isf_client.py — put it next to ztr_tunnel_lp.py, in ~/isf, or set ISF_CLIENT_DIR")


class _NoCache:
    def delete(self, _tunnel_id):
        pass


class _IsfClient:
    """The few RelayClient fields the session list and END look at."""

    def __init__(self, session_id, host, port):
        self.session_id, self.TARGET_HOST, self.TARGET_PORT = session_id, host, port
        self.tunnel_id, self.tunnel_cache = "", _NoCache()


class _IsfRoute:
    def __init__(self, config_file):
        self.config_file = config_file


class IsfSession:
    """A local listener whose every connection goes ZTRelay -> your ISF -> host:port. Each connection asks the ISF
    for its own single-use session; the one made when the session started (so a refused destination fails at START)
    is used by the first connection if that comes soon enough."""

    PREPARED_MAX_AGE = 45  # seconds; the ISF keeps an unused session for 60
    ACCEPT_BACKLOG = 32

    def __init__(self, C, target, host, port, sock, prepared):
        self.C, self.target, self.host, self.port = C, target, host, port
        self.client = _IsfClient("isf-" + secrets.token_hex(8), host, port)
        self.route = _IsfRoute(target.route)
        self.isf = target.name or "default"
        self.server = self  # END closes session.server and waits for it
        self.local_port = sock.getsockname()[1]
        self.warm = False
        self.active_connections = 0
        self.idle_since = time.monotonic()
        self._sock = sock
        self._lock = threading.Lock()
        self._closed = False
        self._prepared = (prepared, time.monotonic())
        threading.Thread(target=self._accept_loop, daemon=True).start()

    # -- what END / the reaper call
    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            prepared, self._prepared = self._prepared, None
        try:
            self._sock.close()
        except OSError:
            pass
        if prepared:  # never used: don't leave it pending on the ISF
            threading.Thread(target=self._discard, args=(prepared[0],), daemon=True).start()

    async def wait_closed(self):
        return None

    def _discard(self, made):
        try:
            self.target.control().call("delete", session_id=made["session_id"])
        except Exception:
            pass  # it expires on its own

    # -- connections
    def _accept_loop(self):
        while not self._closed:
            try:
                conn, addr = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn, addr), daemon=True).start()

    def _take_prepared(self):
        with self._lock:
            held, self._prepared = self._prepared, None
        if held and time.monotonic() - held[1] < self.PREPARED_MAX_AGE:
            return held[0]
        if held:
            self._discard(held[0])
        return None

    def _create(self):
        return self.target.control().call("create", destination=f"{self.host}:{self.port}", ttl=60, label="ztr_tunnel")

    def _open(self):
        C, t = self.C, self.target
        made = self._take_prepared()
        used_prepared = made is not None
        for attempt in (1, 2):
            if made is None:
                made = self._create()
            tunnel = C.DataTunnel(t.relay_factory(), t.host, t.data_port, bytes.fromhex(made["session_id"]),
                                  C._b64d(made["key"]), io_timeout=15)
            try:
                tunnel.open()
                return tunnel
            except C.IsfError:
                tunnel.close()
                if not (used_prepared and attempt == 1):
                    raise
                made, used_prepared = None, False  # the held session had gone stale: one more, fresh

    def _serve(self, conn, addr):
        started = time.monotonic()
        with self._lock:
            self.active_connections += 1
        tunnel = None
        try:
            print(f"[+] {_ts()} Local connection from {addr} (session {self.client.session_id}, via ISF {self.isf})")
            tunnel = self._open()
            self.C.bridge_local(tunnel, conn)
            print(f"[-] {_ts()} Connection closed after {time.monotonic() - started:.1f}s "
                  f"({_fmt_bytes(tunnel.bytes_sent)} up, {_fmt_bytes(tunnel.bytes_received)} down, via ISF {self.isf})")
        except Exception as e:
            hint = " — add it to the ISF's allowlist (the ISF dashboard, or ztr_isf_client.py ctrl allow-add)" if "allowlist" in str(e) else ""
            print(f"[-] {_ts()} ISF {self.isf}: couldn't connect to {self.host}:{self.port}: {e}{hint}")
            try:
                conn.close()
            except OSError:
                pass
        finally:
            with self._lock:
                self.active_connections -= 1
                self.idle_since = time.monotonic()


class TunnelProxyServer:
    def __init__(
        self,
        config_file: str,
        control_host: str = "127.0.0.1",
        control_port: int = 2223,
        local_ip: str = "10.10.15.10",
        idle_timeout: float = 120,
        warm_pool: bool = True,
        warm_max_age: float = 180,
    ):
        self.config_file = config_file
        self.control_host = control_host
        self.control_port = control_port
        # Per-session data-plane listeners bind here, not the control
        # server — a dedicated address so tunneled traffic is visually
        # distinct from ordinary 127.0.0.1 localhost traffic (netstat, ps,
        # logs). Must already exist on some interface (the installer's
        # --with-local-ip sets it up: a dummy interface on Linux, a lo0 alias
        # on macOS) or asyncio's
        # start_server below fails with "Cannot assign requested address".
        self.local_ip = local_ip
        self.idle_timeout = idle_timeout
        self.warm_pool = warm_pool
        self.warm_max_age = warm_max_age
        # (route, relay_name, target_port) -> Spare, oldest first. Capped so a
        # long-lived service that has touched many targets can't pile up
        # authorizations on the hops.
        self._spares: "OrderedDict[tuple, Spare]" = OrderedDict()
        self._refilling: set = set()
        self._bg_tasks: set = set()
        # Distinct worker id per session, so create_tunnel_id() (ztrClient.py)
        # produces a distinct tunnel_id/session_id per session instead of
        # concurrent sessions sharing one and getting their byte streams
        # crossed. The counter alone only separates sessions within this
        # process: it restarts at 1 whenever the service does, and a second
        # service for the same route would count from 1 too — either would
        # rebuild an identical tunnel_id and pick up the other's cached
        # session. The per-process token keeps ids unique across restarts
        # and across services. (Different routes already differ: the route
        # id is part of tunnel_id.)
        self._instance_id = secrets.token_hex(4)
        self._worker_ids = itertools.count(1)
        self._sessions: dict[str, Session] = {}

        # The default route, loaded once at startup so a bad config fails
        # here, not on the first session. A session's target
        # (relay_name/target_port) — and, optionally, a different route —
        # is supplied per START request instead.
        self.default_route = Route(config_file)

    def _resolve_route(self, config_file) -> Route:
        """The route a START uses: the default one unless it names another
        .ztr in routes/. Raises ValueError with a message safe to hand back
        to the caller."""
        if not config_file or config_file == self.config_file:
            return self.default_route
        if not _is_bare_filename(config_file):
            raise ValueError("config_file must be a bare filename in routes/, not a path")
        try:
            return Route(config_file)
        except ConfigNotFoundError:
            raise ValueError(f"no routes/{config_file} — place the .ztr file in routes/ first") from None
        except ConfigParseError:
            raise ValueError(f"routes/{config_file} isn't valid JSON") from None
        except ConfigFieldError as e:
            raise ValueError(f"routes/{config_file}: {e}") from None
        except (ConfigError, KeyError, TypeError):
            raise ValueError(f"routes/{config_file} isn't a usable .ztr config") from None

    def _new_client(self, relay_name: str, target_port: int, route: Route) -> RelayClient:
        client = RelayClient(relay_name, route.relay_port, config_file=route.config_file)
        client.with_worker_id(f"{self._instance_id}-{next(self._worker_ids)}")
        client.set_target_port(target_port)
        return client

    def setup_tunnel(self, client: RelayClient, native: bool = False) -> bool:
        state = client.set_tunnel(native=native)
        if not state or not state.get("status"):
            # One retry excluding whatever hop just failed, before giving up.
            state = client.set_tunnel(reset=True, native=native)
        if state and state.get("status"):
            print(f"[*] Tunnel is active with session_id => {client.session_id}")
            return True
        print("[-] Failed to activate tunnel.")
        return False

    async def recv_raw_HTH(self, reader: asyncio.StreamReader, route: Route):
        return await reader.read(route.raw_max_size), None

    async def send_HTH(self, writer: asyncio.StreamWriter, data: bytes, session_id: str, route: Route):
        # 'c' (clear/not-for-exit) — this plugin tunnels raw, already-plaintext
        # local traffic (SSH or otherwise); it never encrypts for the exit hop.
        header = struct.pack(route.header_format, len(data), session_id.encode("utf-8"), b'c')
        writer.write(header + data)
        await writer.drain()

    # ---------- per-session data forwarding ----------

    # A spare the relay turns away at once (nothing ever comes back) was almost
    # certainly authorized under a different public address than this
    # connection now comes from. These bound when it's safe to quietly
    # re-authorize and replay what the client already sent.
    RECOVERY_WINDOW = 3.0  # seconds after connecting
    RECOVERY_BUFFER = 64 * 1024  # bytes the client may send before the first reply

    async def forward(self, session: Session, route: Route, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, origin: str = ""):
        """Handles one local connection against an already-authorized
        session — set_tunnel() already ran back in start_session(), so this
        only ever moves bytes, whatever protocol they happen to be. `origin`
        is only for the log line that summarizes the connection when it ends
        (where the tunnel came from, e.g. a spare and how old).

        If the session is still on a spare and the relay rejects it at once,
        the connection is moved onto a freshly authorized tunnel (see the
        "Stale spares" note in the module docstring)."""
        client_addr = writer.get_extra_info('peername')
        started = time.monotonic()
        stats = {"up": 0, "down": 0, "closed_by": None, "recovered": False}
        sent = bytearray()  # what the client has sent since the tunnel last answered
        state = {"overflow": False}
        print(f"[+] {_ts()} Local connection from {client_addr} (session {session.client.session_id})")

        try:
            while True:
                gen = session.generation
                outcome = await self._carry(
                    session, route, reader, writer, stats, sent, state,
                    may_recover=session.warm and not stats["recovered"],
                )
                if outcome != "retry":
                    break
                print(f"[~] {_ts()} {client_addr} the relay turned this spare tunnel away — your public address has probably changed. Re-authorizing and retrying…")
                t0 = time.monotonic()
                if not await self._recover(session, gen, route):
                    stats["closed_by"] = "a failed re-authorization"
                    writer.close()
                    break
                stats["recovered"] = True
                print(f"[~] {_ts()} {client_addr} re-authorized in {time.monotonic() - t0:.1f}s — carrying on")
        except Exception as e:
            stats["closed_by"] = stats["closed_by"] or "an error"
            print(f"[-] Connection handler error: {e}")
        finally:
            writer.close()
            lasted = time.monotonic() - started
            who = stats["closed_by"] or "unknown"
            hint = ""
            if who == "the relay" and stats["down"] == 0:
                hint = "  <- nothing ever came back: the relay rejected it, or the exit couldn't reach the target"
            elif who == "the relay" and lasted < 10:
                hint = "  <- the relay ended this connection early"
            extra = " · recovered from a stale spare" if stats["recovered"] else ""
            print(
                f"[~] {_ts()} {client_addr}{(' · ' + origin) if origin else ''}{extra} closed by {who} after {lasted:.1f}s "
                f"— sent {_fmt_bytes(stats['up'])}, received {_fmt_bytes(stats['down'])}{hint}"
            )
            print(f"[-] Local connection closed: {client_addr}")

    async def _carry(self, session: Session, route: Route, reader, writer, stats, sent: bytearray, state, may_recover: bool) -> str:
        """Moves bytes between the local connection and one tunnel until
        either side closes. Returns "done", or "retry" when the relay turned
        a spare away before answering and the caller should move the
        connection onto a fresh tunnel (the local side is then left open)."""
        client = session.client
        tunnel_reader, tunnel_writer = await asyncio.open_connection(client.__ENTRY__, client.PORT)
        print(f"[+] Connected to tunnel backend {client.__ENTRY__}:{client.PORT} (session {client.session_id})")
        attempt_started = time.monotonic()
        got = {"down": 0}
        retry = {"flag": False}

        # On a retry, what the client already sent goes first.
        if sent:
            for i in range(0, len(sent), route.raw_max_size):
                await self.send_HTH(tunnel_writer, bytes(sent[i:i + route.raw_max_size]), client.session_id, route)

        def recoverable() -> bool:
            return (
                may_recover
                and got["down"] == 0
                and len(sent) > 0
                and not state["overflow"]
                and time.monotonic() - attempt_started <= self.RECOVERY_WINDOW
            )

        async def forward_client_to_tunnel():
            try:
                while True:
                    data = await reader.read(route.raw_max_size)
                    if not data:
                        stats["closed_by"] = stats["closed_by"] or "your local client"
                        break
                    stats["up"] += len(data)
                    if may_recover and got["down"] == 0 and not state["overflow"]:
                        if len(sent) + len(data) > self.RECOVERY_BUFFER:
                            state["overflow"] = True
                            sent.clear()
                        else:
                            sent.extend(data)
                    await self.send_HTH(tunnel_writer, data, client.session_id, route)
            except Exception as e:
                stats["closed_by"] = stats["closed_by"] or "an error"
                print(f"[-] Error in client->tunnel forwarder: {e}")
            finally:
                tunnel_writer.close()

        async def forward_tunnel_to_client():
            try:
                while True:
                    data, _ = await self.recv_raw_HTH(tunnel_reader, route)
                    if not data:
                        if recoverable():
                            retry["flag"] = True
                            return
                        stats["closed_by"] = stats["closed_by"] or "the relay"
                        break
                    got["down"] += len(data)
                    stats["down"] += len(data)
                    if sent:
                        sent.clear()  # it answered, so this tunnel works — nothing left to replay
                    writer.write(data)
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError) as e:
                if recoverable():
                    retry["flag"] = True
                    return
                stats["closed_by"] = stats["closed_by"] or "the relay"
                print(f"[-] Error in tunnel->client forwarder: {e}")
            except Exception as e:
                stats["closed_by"] = stats["closed_by"] or "an error"
                print(f"[-] Error in tunnel->client forwarder: {e}")
            finally:
                if not retry["flag"]:
                    writer.close()

        up = asyncio.create_task(forward_client_to_tunnel())
        down = asyncio.create_task(forward_tunnel_to_client())
        await asyncio.wait({up, down}, return_when=asyncio.FIRST_COMPLETED)
        if retry["flag"]:
            up.cancel()  # safe: unread data stays in the reader, and what was already read is in `sent`
            await asyncio.gather(up, return_exceptions=True)
            return "retry"
        await asyncio.gather(up, down)
        return "done"

    async def _recover(self, session: Session, gen: int, route: Route) -> bool:
        """Swaps the session onto a freshly authorized tunnel. Connections
        that failed on the same stale spare at the same time share one
        re-authorization: whoever gets the lock first does it, the rest see
        the generation has moved on."""
        async with session.recover_lock:
            if session.generation != gen:
                return True
            self._drop_all_spares("a spare was turned away, so the others are probably stale too")
            old = session.client
            new = await asyncio.to_thread(self._authorize_new, old.TARGET_HOST, old.TARGET_PORT, route)
            if new is None:
                print(f"[-] Couldn't re-authorize a tunnel for {old.TARGET_HOST}:{old.TARGET_PORT}")
                return False
            try:
                old.tunnel_cache.delete(old.tunnel_id)
            except Exception:
                pass
            session.client = new
            session.warm = False
            session.generation += 1
            self._schedule_refill((route.config_file, new.TARGET_HOST, new.TARGET_PORT), new.TARGET_HOST, new.TARGET_PORT, route)
            return True

    # ---------- warm pool ----------

    MAX_WARM_TARGETS = 16

    def _authorize_new(self, relay_name: str, target_port: int, route: Route):
        """Builds a client and authorizes its tunnel. Blocking — run it in a
        worker thread, never on the event loop (it takes seconds, and the
        loop is also what moves every open session's bytes)."""
        client = self._new_client(relay_name, target_port, route)
        if not self.setup_tunnel(client, native=False):
            return None
        return client

    def _discard_spare(self, spare: Spare, why: str):
        print(f"[*] Dropping a spare tunnel for {spare.client.TARGET_HOST}:{spare.client.TARGET_PORT} — {why}")
        try:
            spare.client.tunnel_cache.delete(spare.client.tunnel_id)
        except Exception:
            pass

    def _take_spare(self, key):
        """A usable spare for this target, or None. Never hands out one that
        has aged out or whose local network has changed."""
        spare = self._spares.pop(key, None)
        if spare is None:
            return None
        if time.monotonic() - spare.created > self.warm_max_age:
            self._discard_spare(spare, "too old")
            return None
        now_addr = _local_addr_towards(spare.client.__ENTRY__, spare.client.PORT)
        if spare.local_addr and now_addr and spare.local_addr != now_addr:
            self._discard_spare(spare, "this machine's network address changed")
            return None
        return spare

    def _drop_all_spares(self, why: str):
        for key in list(self._spares):
            self._discard_spare(self._spares.pop(key), why)

    def _expire_spares(self):
        now = time.monotonic()
        for key in [k for k, sp in self._spares.items() if now - sp.created > self.warm_max_age]:
            self._discard_spare(self._spares.pop(key), "unused for too long")

    async def _refill(self, key, relay_name: str, target_port: int, route: Route):
        """Authorizes one spare for this target in the background. A failure
        just means the next START pays the full wait — no retry loop."""
        if not self.warm_pool or key in self._spares or key in self._refilling:
            return
        self._refilling.add(key)
        try:
            client = await asyncio.to_thread(self._authorize_new, relay_name, target_port, route)
            if client is None:
                print(f"[-] Couldn't pre-authorize a spare for {relay_name}:{target_port}")
                return
            self._spares[key] = Spare(client, route, _local_addr_towards(client.__ENTRY__, client.PORT))
            while len(self._spares) > self.MAX_WARM_TARGETS:
                _, oldest = self._spares.popitem(last=False)
                self._discard_spare(oldest, "pool is full")
            print(f"[*] Spare tunnel ready for {relay_name}:{target_port} (route {route.config_file})")
        except Exception as e:
            print(f"[-] Spare tunnel for {relay_name}:{target_port} failed: {e}")
        finally:
            self._refilling.discard(key)

    def _schedule_refill(self, key, relay_name: str, target_port: int, route: Route):
        if not self.warm_pool:
            return
        task = asyncio.create_task(self._refill(key, relay_name, target_port, route))
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    # ---------- session lifecycle (START / END) ----------

    async def _start_isf_session(self, relay_name: str, target_port: int, config_file, isf) -> dict:
        """START through one of the caller's own ISFs (see the module docstring)."""
        host = relay_name if isinstance(relay_name, str) else ""
        if not isinstance(isf, str) or not _ISF_NAME_RE.match(isf):
            return {"status": False, "error": "isf must be the name of one of your ISFs (or \"@default\")"}
        if host.endswith("._ztr"):
            return {"status": False, "error": "an ISF can't look up ._ztr aliases — give the server's real host name or address"}
        if not _ISF_HOST_RE.match(host):
            return {"status": False, "error": "with an ISF the server must be a plain host name or address"}
        if not 1 <= target_port <= 65535:
            return {"status": False, "error": "the port must be between 1 and 65535"}
        if config_file and not _is_bare_filename(config_file):
            return {"status": False, "error": "config_file must be a bare filename in routes/, not a path"}
        try:
            C = _load_isf_client()
        except ValueError as e:
            return {"status": False, "error": str(e)}
        zdir = os.path.dirname(PLUGINS_DIR)

        def prepare():
            t = C.target_for(None if isf == "@default" else isf, route=config_file or None, zdir=zdir)
            made = t.control().call("create", destination=f"{host}:{target_port}", ttl=60, label="ztr_tunnel")
            return t, made

        try:
            target, made = await asyncio.to_thread(prepare)
        except C.IsfError as e:
            hint = " (add it to the ISF's allowlist: the ISF dashboard, or ztr_isf_client.py ctrl allow-add)" if "allowlist" in str(e) else ""
            return {"status": False, "error": f"ISF: {e}{hint}"}
        except Exception as e:
            return {"status": False, "error": f"ISF: {e}"}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.local_ip, 0))
            sock.listen(IsfSession.ACCEPT_BACKLOG)
        except OSError as e:
            sock.close()
            print(f"[-] Failed to bind {self.local_ip}: {e}")
            await asyncio.to_thread(lambda: target.control().call("delete", session_id=made["session_id"]))
            return {"status": False, "error": f"failed to bind {self.local_ip}: {e}"}
        session = IsfSession(C, target, host, target_port, sock, made)
        self._sessions[session.client.session_id] = session
        dest = f"{host}:{target_port}"
        try:
            path = [_ANSI_RE.sub("", line) for line in C.path_log_lines(target, zdir, dest)]
        except Exception:
            path = []
        print(f"[*] {_ts()} Session {session.client.session_id} ready on {self.local_ip}:{session.local_port} -> {dest} "
              f"(via ISF {session.isf}, route {target.route})")
        return {"status": True, "session_id": session.client.session_id, "local_ip": self.local_ip, "local_port": session.local_port,
                "warm": False, "isf": session.isf, "path": path}

    async def start_session(self, relay_name: str, target_port: int, config_file=None, isf=None) -> dict:
        if isf:
            return await self._start_isf_session(relay_name, target_port, config_file, isf)
        try:
            route = self._resolve_route(config_file)
        except ValueError as e:
            return {"status": False, "error": str(e)}
        key = (route.config_file, relay_name, target_port)
        spare = self._take_spare(key) if self.warm_pool else None
        warm = spare is not None
        origin = "fresh tunnel"
        if warm:
            client = spare.client
            origin = f"spare tunnel, {time.monotonic() - spare.created:.0f}s old"
            print(f"[*] {_ts()} Using a spare tunnel for {relay_name}:{target_port} ({origin}) — no authorization wait")
        else:
            client = await asyncio.to_thread(self._authorize_new, relay_name, target_port, route)
            if client is None:
                return {"status": False, "error": "failed to activate tunnel"}

        session_id = client.session_id

        async def handler(reader, writer):
            session = self._sessions.get(session_id)
            if session is None:
                writer.close()
                return
            session.active_connections += 1
            try:
                await self.forward(session, route, reader, writer, origin)
            finally:
                session.active_connections -= 1
                session.idle_since = time.monotonic()

        # Port 0 -> OS picks a free ephemeral port; that's the whole fix for
        # "port already in use" when more than one session is open at once.
        try:
            server = await asyncio.start_server(handler, self.local_ip, 0)
        except OSError as e:
            print(f"[-] Failed to bind {self.local_ip}: {e}")
            print(f"[-] Run the installer (installer-linux.sh / installer-macos.sh) with --with-local-ip to set up {self.local_ip}, "
                  f"or restart this service with --local-ip 127.0.0.1 to skip the dedicated address entirely.")
            client.tunnel_cache.delete(client.tunnel_id)  # nothing will use this authorization now
            return {"status": False, "error": f"failed to bind {self.local_ip}: {e}"}
        local_port = server.sockets[0].getsockname()[1]
        self._sessions[session_id] = Session(client=client, route=route, server=server, local_port=local_port, warm=warm)

        print(f"[*] {_ts()} Session {session_id} ready on {self.local_ip}:{local_port} -> {relay_name}:{target_port} (route {route.config_file}, {origin})")
        self._schedule_refill(key, relay_name, target_port, route)
        return {"status": True, "session_id": session_id, "local_ip": self.local_ip, "local_port": local_port, "warm": warm}

    async def end_session(self, session_id: str) -> dict:
        session = self._sessions.pop(session_id, None)
        if not session:
            return {"status": False, "error": "unknown session"}

        session.server.close()
        await session.server.wait_closed()
        # The tunnel cache doubles as the record of live tunnels (the
        # dashboard's active-tunnels view, per-port load for port selection),
        # so an ended session's row has to go too — left alone it would keep
        # showing as active until its TTL runs out.
        session.client.tunnel_cache.delete(session.client.tunnel_id)
        print(f"[*] {_ts()} Session {session_id} ended")
        return {"status": True}

    def list_sessions(self) -> dict:
        """Read-only snapshot for anything wanting to show what's currently
        open — a GUI dashboard, a status CLI, whatever. relay_name and
        target_port aren't stored on Session itself; they're read
        straight off each session's already-authorized RelayClient."""
        now = time.monotonic()
        sessions = [
            {
                "session_id": session_id,
                "relay_name": session.client.TARGET_HOST,
                "target_port": session.client.TARGET_PORT,
                "config_file": session.route.config_file,
                "local_ip": self.local_ip,
                "local_port": session.local_port,
                "active_connections": session.active_connections,
                "idle_seconds": round(now - session.idle_since, 1) if session.active_connections == 0 else 0.0,
                **({"isf": session.isf} if getattr(session, "isf", None) else {}),
            }
            for session_id, session in self._sessions.items()
        ]
        warm = [
            {
                "relay_name": sp.client.TARGET_HOST,
                "target_port": sp.client.TARGET_PORT,
                "config_file": sp.route.config_file,
                "age_seconds": round(now - sp.created, 1),
            }
            for sp in self._spares.values()
        ]
        return {"status": True, "sessions": sessions, "warm": warm}

    # ---------- idle session reaper ----------

    async def _reap_idle_sessions(self, scan_interval: float = 30):
        """Safety net for a client that dies without sending END (e.g. a
        plain `kill -9` skips a wrapper's EXIT trap entirely, whether it's
        ztr_ssh or ztr_forward). Runs for the life of the service; only ever
        touches sessions currently sitting at zero active connections."""
        while True:
            await asyncio.sleep(scan_interval)
            self._expire_spares()
            now = time.monotonic()
            stale = [
                session_id
                for session_id, session in self._sessions.items()
                if session.active_connections == 0 and (now - session.idle_since) > self.idle_timeout
            ]
            for session_id in stale:
                idle_for = int(now - self._sessions[session_id].idle_since)
                print(f"[*] Reaping session {session_id} — idle {idle_for}s with no active connection")
                await self.end_session(session_id)

    # ---------- control server ----------

    async def handle_control(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        response = {"status": False, "error": "no request received"}
        try:
            line = await reader.readline()
            if not line:
                return

            try:
                request = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as e:
                response = {"status": False, "error": f"invalid JSON: {e}"}
            else:
                cmd = request.get("cmd")
                if cmd == "start":
                    response = await self.start_session(
                        request["relay_name"], int(request.get("target_port", 22)), request.get("config_file"), request.get("isf")
                    )
                elif cmd == "end":
                    response = await self.end_session(request["session_id"])
                elif cmd == "list":
                    response = self.list_sessions()
                else:
                    response = {"status": False, "error": f"unknown cmd: {cmd!r}"}
        except Exception as e:
            response = {"status": False, "error": str(e)}
        finally:
            try:
                writer.write(json.dumps(response).encode("utf-8") + b"\n")
                await writer.drain()
            except Exception:
                pass
            writer.close()

    async def start(self):
        control_server = await asyncio.start_server(self.handle_control, self.control_host, self.control_port)
        print(f"[*] Control server listening on {self.control_host}:{self.control_port}")
        print(f"[*] Idle session reaper active — timeout {self.idle_timeout}s")
        print(f"[*] Warm pool {'on — spares expire after ' + str(int(self.warm_max_age)) + 's' if self.warm_pool else 'off'}")

        reaper_task = asyncio.create_task(self._reap_idle_sessions())
        try:
            async with control_server:
                await control_server.serve_forever()
        finally:
            reaper_task.cancel()


def _build_arg_parser():
    import argparse

    parser = argparse.ArgumentParser(
        description="ZTRelay local proxy service — one persistent process per route, "
        "many on-demand tunneled sessions through it via the control port."
    )
    parser.add_argument("--config-file", required=True, help="Default route: the filename of your downloaded .ztr config — must already be in routes/ (e.g. route.ztr resolves to routes/route.ztr). Sessions use it unless a START request names another one.")
    parser.add_argument("--control-host", default="127.0.0.1", help="Control server bind address (default: 127.0.0.1)")
    parser.add_argument("--control-port", type=int, default=2223, help="Control server port (default: 2223)")
    parser.add_argument(
        "--local-ip",
        default="10.10.15.10",
        help="Bind address for per-session data-plane listeners (default: 10.10.15.10, a dedicated "
        "dedicated address set up by the installer's --with-local-ip). Pass 127.0.0.1 to skip the dedicated "
        "address and use plain localhost instead.",
    )
    parser.add_argument(
        "--idle-timeout",
        type=float,
        default=120,
        help="Seconds a session may sit with zero active connections before the reaper closes it (default: 120)",
    )
    parser.add_argument(
        "--no-warm-pool",
        action="store_true",
        help="Don't pre-authorize a spare tunnel after each session. Every start then waits for its own authorization.",
    )
    parser.add_argument(
        "--warm-max-age",
        type=float,
        default=180,
        help="Seconds a spare tunnel may wait unused before it's discarded (default: 180)",
    )
    return parser


if __name__ == "__main__":
    args = _build_arg_parser().parse_args()
    proxy_server = TunnelProxyServer(
        config_file=args.config_file,
        control_host=args.control_host,
        control_port=args.control_port,
        local_ip=args.local_ip,
        idle_timeout=args.idle_timeout,
        warm_pool=not args.no_warm_pool,
        warm_max_age=args.warm_max_age,
    )
    try:
        asyncio.run(proxy_server.start())
    except KeyboardInterrupt:
        print("\n[*] Proxy server stopped by user.")
