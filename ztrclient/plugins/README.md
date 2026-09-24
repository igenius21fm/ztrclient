# plugins

Everything here builds on `ztrClient.py` (one directory up). Three thin CLI
wrappers — `ztr_ssh`, `ztr_forward`, `ztr_pg` — drive tunnels through a
shared background service, `ztr_tunnel_lp.py`; `ztr_dashboard.py` and
`ztr_requests/` are separate, standalone tools with no dependency on that
service. `ztr_https.py` is a library the others (and your own scripts) can
import — not something you run on its own.

The normal way to get all of this installed and on your `PATH` is the
top-level [installer-linux.sh](../installer-linux.sh) — see the repo's
[main README](../../README.md) for that (`--with-service`,
`--with-dashboard`, `--with-requests` set up the three optional background
services below). This one documents what each piece actually does, either
for running something by hand or for understanding what the installer set up
for you.

## ztr_tunnel_lp.py — the shared tunnel service

One persistent process per route — its `.ztr` config is fixed for the
service's whole lifetime; point it at a different route by editing the file
and restarting, not by passing a different one per session. Doesn't listen
on a fixed data port itself. Instead it opens a small control server
(default `127.0.0.1:2223`) that speaks newline-delimited JSON, one
request/response object per line, and the three wrappers below all talk to
it the same way:

| Request | Response |
|---|---|
| `{"cmd": "start", "relay_name": "example._ztr", "target_port": 22}` | `{"status": true, "session_id": "...", "local_ip": "10.10.15.10", "local_port": 51234}` |
| `{"cmd": "end", "session_id": "..."}` | `{"status": true}` |
| `{"cmd": "list"}` | `{"status": true, "sessions": [{"session_id": "...", "relay_name": "...", "target_port": 22, "local_ip": "10.10.15.10", "local_port": 51234, "active_connections": 1, "idle_seconds": 0.0}]}` |

Each `start` authorizes a fresh tunnel for that target and opens a new
ephemeral local listener just for that session — so several sessions
(different terminals, different targets, doesn't matter) each get their own
local port instead of fighting over one fixed one. `end` tears down that
one session only; the service and every other session keep running. A
background reaper also closes any session that's sat with zero active
connections longer than `--idle-timeout` — the safety net for a client that
dies hard enough to skip sending `end` (a plain process kill doesn't run a
wrapper's cleanup trap). A session with a live connection is never touched,
no matter how long it's been open.

```bash
~/.local/share/ztr/venv/bin/python3 ztr_tunnel_lp.py --config-file route.ztr
```

| Flag | Effect |
|---|---|
| `--config-file` (required) | Bare filename of your downloaded route config — resolved inside `routes/`, e.g. `route.ztr` → `routes/route.ztr`. |
| `--control-host` | Control server bind address. Default `127.0.0.1` — this one never moves, only the per-session data listeners do. |
| `--control-port` | Control server port. Default `2223` — matches every wrapper's own `--cp` default. |
| `--local-ip` | Bind address for per-session data listeners. Default `10.10.15.10`, a dedicated dummy address so tunneled traffic is visually distinct from ordinary `127.0.0.1` localhost traffic (`netstat`, `ps`, logs) — set up once by `installer-linux.sh --with-local-ip`. Pass `127.0.0.1` to skip the dedicated address and use plain localhost instead. |
| `--idle-timeout` | Seconds a session may sit with zero active connections before the reaper closes it. Default `120`. |

Run it standalone in a terminal, or let the installer set it up as a
`systemd --user` service (`--with-service`) so it survives reboots and
logins without you having to start it yourself.

## ztr_ssh, ztr_forward, ztr_pg — CLI wrappers

All three do the same thing at heart: ask `ztr_tunnel_lp.py` (already
running — none of these start or stop that service) for an on-demand
session against a target, run something real through the ephemeral local
port it hands back, and tell it to close that session again once that real
program exits — clean exit, Ctrl+C, dropped connection, doesn't matter.
Every invocation gets its own session and its own local port, so running
several of these at once (same or different targets, doesn't matter) never
collides on "port already in use".

| Wrapper | Runs | Default `--rp` |
|---|---|---|
| `ztr_ssh` | `ssh` | `22` |
| `ztr_pg` | `psql` | `5432` |
| `ztr_forward` | either nothing (you point your own client at the printed address) or a command you give it after `--` | none — `--rp` is required |

```bash
ztr_ssh --rh "example._ztr" --rp 22
ztr_pg -U myuser -d mydb --rh "example._ztr"

# ztr_forward: wait, and point something else at the tunnel yourself
ztr_forward --rh "example._ztr" --rp 5432
# -> tunnel ready on 10.10.15.10:51234 — point your client there, Ctrl+C to close

# ztr_forward: or run a command against it directly
ztr_forward --rh "example._ztr" --rp 5432 -- bash -c 'psql -h "$ZTR_LOCAL_IP" -p "$ZTR_LOCAL_PORT" -U myuser'
```

`--rh` is always a route's `._ztr` alias (or a real address for a
single-hop target), never a destination you supply directly — the actual
local address (`$ZTR_LOCAL_IP`/`$ZTR_LOCAL_PORT` in `ztr_forward`'s wrapped
command, or the address these print in wait mode) is only known once the
tunnel is actually up, so quote it in single quotes as shown above rather
than letting your own shell expand it too early. `$ZTR_LOCAL_IP` is
whatever `ztr_tunnel_lp.py` is actually bound to — don't hardcode
`127.0.0.1`, since that's often `10.10.15.10` instead.

`ssh_flags`/`psql_flags` are plain options for that program (`-i`
identity, `-l`/`-U` user, etc.) — never `-p`/`-h`/a destination; these
scripts always supply those themselves.

### Host-key prompts (`ztr_ssh` only)

Every session gets a fresh ephemeral port, so `ssh` sees a "new host" every
time and both asks to verify it and adds a fresh `known_hosts` entry for
it. `ztr_ssh` removes its own entry on exit (`ssh-keygen -R`) unless you
pass `--keep-host-key`, so those never pile up — but it still means you get
asked to confirm a "new" host on every single session by default.

The first time it resolves a real (non-`127.0.0.1`) local address, it
offers, once, to add this to your `~/.ssh/config`:

```
Host 10.10.15.10
    StrictHostKeyChecking accept-new
    UserKnownHostsFile ~/.ssh/known_hosts_ztr
```

scoped to exactly that one address, so that prompt goes away for `ztr_ssh`
sessions specifically without changing how `ssh` treats any other host.
This doesn't weaken what's actually being verified — the real host-key
exchange still happens end-to-end with your actual target, carried through
the tunnel untouched; it only skips a locally-redundant confirmation for an
entry that gets deleted again as soon as the session ends anyway. Decline
once and it won't ask again; add the block yourself later if you change
your mind.

## ztr_dashboard.py — local tunnel/traffic dashboard

Standalone — doesn't need `ztr_tunnel_lp.py` running. A local, read-only
web page showing this machine's active tunnels (from the wrappers' shared
session cache), recent hop-authorization errors, and — with `--config-file`
and root/administrator privileges for live packet capture — a live feed of
this machine's traffic to its entry hop. Without those, the dashboard still
works; it just shows why that one panel is off. Also has a few hands-on
tools: sign a dashboard nonce, list or reset cached tunnels, send a
native-mode PING through an authorized tunnel.

```bash
python3 plugins/ztr_dashboard.py --config-file route.ztr
```

| Flag | Effect |
|---|---|
| `--host` | Dashboard's own bind address. Defaults to `10.10.15.10` if this machine has that address, else `127.0.0.1`. |
| `--port` | Dashboard's own HTTP port. Default `8088`. |
| `--config-file` | A `.ztr` file already in `routes/` — shows its hop chain and enables live traffic capture. Omit to run the dashboard without a specific route in view. |
| `--iface` | Network interface for live traffic capture. Default: let `scapy` pick. |

`static/` next to this file is its frontend — plain CSS/JS, no build step.

## ztr_https.py — HTTP(S) client library over a ZTRelay tunnel

Not a tool you run — a library `import ztr_https` gives you, `requests`-shaped:

```python
import ztr_https

resp = ztr_https.get("https://example.com/path", config_file="route.ztr")
print(resp.status_code, resp.json())

with ztr_https.Session(config_file="route.ztr") as s:
    s.get("https://example.com/a")
    s.get("https://example.com/b")  # same origin -> tunnel/TLS connection reused
```

Handles tunnel authorization and the entry hop's wire format for you, drives
TLS by hand over the tunnel (`ssl.MemoryBIO`, not a real socket — there's no
code path where it could bypass the tunnel even by accident), and hands the
target domain to `RelayClient` exactly as given rather than resolving it
locally — resolution happens at the exit hop, over the registry, so a
client-side DNS lookup never leaks which domain you're about to reach.
Supports redirects, cookies (including from an intermediate redirect hop),
streaming responses, multipart uploads, an explicit `port=` override for a
target not on 443/80, and exposes what actually happened on the wire
(`resp.tls_info` — negotiated protocol/cipher/peer certificate,
`resp.route_info` — the hop chain the request ran through) rather than
just the response body. `ztr_requests/` (below) is the reference consumer.

## ztr_requests/ — request-composer web UI

A small Postman-style local web app for firing one-off HTTP/HTTPS requests
straight through an authorized tunnel to their own real target, built on
`ztr_https.py`. Point it at a route file (or several — supports multiple
named `{{var}}`-substitution environments, so switching targets doesn't
mean retyping the same variable names with different values), compose a
request, hit Send, see the response — headers, cookies, TLS certificate
details, the relay path it actually took, and (for an image response)
decoded EXIF metadata.

```bash
python3 plugins/ztr_requests/server.py
```

| Flag | Effect |
|---|---|
| `--host` | This app's own bind address. Defaults to `10.10.15.10` if this machine has that address, else `127.0.0.1` — deliberately not the open LAN by default, since a request built here can carry a route's real identifier/secret_key-backed tunnel plus whatever headers/body you type into it. |
| `--port` | This app's own HTTP port. Default `8994`. |

No `--config-file` — unlike the dashboard, it isn't tied to one route at
startup; pick whichever's in `routes/` per request, from the UI itself.
`static/` next to `server.py` is its frontend (plain CSS/JS, no build
step); `session_manager.py`/`history_store.py`/`environment_store.py`/
`collection_store.py` are its own small sqlite-backed state (one
`ztr_https.Session` per route+timing-defense combination, request history,
named environments, saved requests) — all local to this directory, no
shared database with anything else here.

## Layout

- `ztr_tunnel_lp.py` — the shared tunnel service every wrapper below talks to.
- `ztr_ssh`, `ztr_forward`, `ztr_pg` — CLI wrappers around it.
- `ztr_dashboard.py` + `static/` — the standalone local dashboard.
- `ztr_https.py` — HTTP(S)-over-tunnel client library.
- `ztr_requests/` — the standalone request-composer web UI, built on it.
