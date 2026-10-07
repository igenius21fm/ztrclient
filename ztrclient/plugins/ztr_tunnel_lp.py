import asyncio
import itertools
import json
import os
import struct
import sys
import time

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
          -> {"status": true, "session_id": "...", "local_ip": "10.10.15.10", "local_port": 51234}
          -> {"status": false, "error": "..."}

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


class Session:
    __slots__ = ("client", "route", "server", "local_port", "active_connections", "idle_since")

    def __init__(self, client: RelayClient, route: Route, server: asyncio.AbstractServer, local_port: int):
        self.client = client
        self.route = route
        self.server = server
        self.local_port = local_port
        self.active_connections = 0
        # A session is "idle" whenever it has zero active connections — this
        # is the monotonic timestamp of when that most recently became
        # true. Starts idle at creation (nothing has connected yet); reset
        # every time a connection drops back to zero. The reaper only ever
        # looks at this when active_connections == 0, so a long-running
        # connection is never reaped no matter how old this timestamp gets.
        self.idle_since = time.monotonic()


class TunnelProxyServer:
    def __init__(
        self,
        config_file: str,
        control_host: str = "127.0.0.1",
        control_port: int = 2223,
        local_ip: str = "10.10.15.10",
        idle_timeout: float = 120,
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
        # Distinct worker id per session, so create_tunnel_id() (ztrClient.py)
        # produces a distinct tunnel_id/session_id per session instead of
        # concurrent sessions sharing one and getting their byte streams
        # crossed.
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
        client.with_worker_id(next(self._worker_ids))
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

    async def forward(self, client: RelayClient, route: Route, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handles one local connection against an already-authorized
        session — set_tunnel() already ran back in start_session(), so this
        only ever moves bytes, whatever protocol they happen to be."""
        client_addr = writer.get_extra_info('peername')
        print(f"[+] Local connection from {client_addr} (session {client.session_id})")

        try:
            tunnel_reader, tunnel_writer = await asyncio.open_connection(client.__ENTRY__, client.PORT)
            print(f"[+] Connected to tunnel backend {client.__ENTRY__}:{client.PORT} (session {client.session_id})")

            async def forward_client_to_tunnel():
                try:
                    while True:
                        data = await reader.read(route.raw_max_size)
                        if not data:
                            break
                        await self.send_HTH(tunnel_writer, data, client.session_id, route)
                except Exception as e:
                    print(f"[-] Error in client->tunnel forwarder: {e}")
                finally:
                    tunnel_writer.close()

            async def forward_tunnel_to_client():
                try:
                    while True:
                        data, _ = await self.recv_raw_HTH(tunnel_reader, route)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                except Exception as e:
                    print(f"[-] Error in tunnel->client forwarder: {e}")
                finally:
                    writer.close()

            await asyncio.gather(
                forward_client_to_tunnel(),
                forward_tunnel_to_client()
            )

        except Exception as e:
            print(f"[-] Connection handler error: {e}")
        finally:
            writer.close()
            print(f"[-] Local connection closed: {client_addr}")

    # ---------- session lifecycle (START / END) ----------

    async def start_session(self, relay_name: str, target_port: int, config_file=None) -> dict:
        try:
            route = self._resolve_route(config_file)
        except ValueError as e:
            return {"status": False, "error": str(e)}
        client = self._new_client(relay_name, target_port, route)
        if not self.setup_tunnel(client, native=False):
            return {"status": False, "error": "failed to activate tunnel"}

        session_id = client.session_id

        async def handler(reader, writer):
            session = self._sessions.get(session_id)
            if session:
                session.active_connections += 1
            try:
                await self.forward(client, route, reader, writer)
            finally:
                session = self._sessions.get(session_id)
                if session:
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
            return {"status": False, "error": f"failed to bind {self.local_ip}: {e}"}
        local_port = server.sockets[0].getsockname()[1]
        self._sessions[session_id] = Session(client=client, route=route, server=server, local_port=local_port)

        print(f"[*] Session {session_id} ready on {self.local_ip}:{local_port} -> {relay_name}:{target_port} (route {route.config_file})")
        return {"status": True, "session_id": session_id, "local_ip": self.local_ip, "local_port": local_port}

    async def end_session(self, session_id: str) -> dict:
        session = self._sessions.pop(session_id, None)
        if not session:
            return {"status": False, "error": "unknown session"}

        session.server.close()
        await session.server.wait_closed()
        print(f"[*] Session {session_id} ended")
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
            }
            for session_id, session in self._sessions.items()
        ]
        return {"status": True, "sessions": sessions}

    # ---------- idle session reaper ----------

    async def _reap_idle_sessions(self, scan_interval: float = 30):
        """Safety net for a client that dies without sending END (e.g. a
        plain `kill -9` skips a wrapper's EXIT trap entirely, whether it's
        ztr_ssh or ztr_forward). Runs for the life of the service; only ever
        touches sessions currently sitting at zero active connections."""
        while True:
            await asyncio.sleep(scan_interval)
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
                        request["relay_name"], int(request.get("target_port", 22)), request.get("config_file")
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
    return parser


if __name__ == "__main__":
    args = _build_arg_parser().parse_args()
    proxy_server = TunnelProxyServer(
        config_file=args.config_file,
        control_host=args.control_host,
        control_port=args.control_port,
        local_ip=args.local_ip,
        idle_timeout=args.idle_timeout,
    )
    try:
        asyncio.run(proxy_server.start())
    except KeyboardInterrupt:
        print("\n[*] Proxy server stopped by user.")
