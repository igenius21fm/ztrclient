# plugins

Everything here builds on `ztrClient.py` (one directory up). Three thin CLI
wrappers — `ztr_ssh`, `ztr_forward`, `ztr_pg` — drive tunnels through a
shared background service, `ztr_tunnel_lp.py`, and so does Ferry
(`ztr_ferry.py`), a desktop file manager, and ZTR Fleet (`ztr_fleet/`), which
runs commands, scripts and file transfers on several servers at once; `ztr_dashboard.py` and
`ztr_requests/` are separate, standalone tools with no dependency on that
service. `ztr_https.py` is a library the others (and your own scripts) can
import — not something you run on its own.

The normal way to get all of this installed and on your `PATH` is the
top-level [installer-linux.sh](../installer-linux.sh) /
[installer-macos.sh](../installer-macos.sh) — see the repo's
[main README](../../README.md) for that (`--with-service`,
`--with-dashboard`, `--with-requests` set up the three optional background
services below). This one documents what each piece actually does, either
for running something by hand or for understanding what the installer set up
for you.

## ztr_tunnel_lp.py — the shared tunnel service

One persistent process, started with a default route (`--config-file`).
Each session uses that route unless its `start` request names a different
`.ztr` from `routes/` — one service can serve several routes at once.
Doesn't listen on a fixed data port itself. Instead it opens a small control server
(default `127.0.0.1:2223`) that speaks newline-delimited JSON, one
request/response object per line, and the three wrappers below all talk to
it the same way:

| Request | Response |
|---|---|
| `{"cmd": "start", "relay_name": "example._ztr", "target_port": 22}` — optionally with `"config_file": "other.ztr"` | `{"status": true, "session_id": "...", "local_ip": "10.10.15.10", "local_port": 51234, "warm": false}` |
| `{"cmd": "end", "session_id": "..."}` | `{"status": true}` |
| `{"cmd": "list"}` | `{"status": true, "sessions": [{"session_id": "...", "relay_name": "...", "target_port": 22, "config_file": "route.ztr", "local_ip": "10.10.15.10", "local_port": 51234, "active_connections": 1, "idle_seconds": 0.0}], "warm": [{"relay_name": "...", "target_port": 22, "config_file": "route.ztr", "age_seconds": 12.4}]}` |

Each `start` hands out a freshly authorized tunnel for that target and opens a new
ephemeral local listener just for that session — so several sessions
(different terminals, different targets, doesn't matter) each get their own
local port instead of fighting over one fixed one. `end` tears down that
one session only; the service and every other session keep running. A
background reaper also closes any session that's sat with zero active
connections longer than `--idle-timeout` — the safety net for a client that
dies hard enough to skip sending `end` (a plain process kill doesn't run a
wrapper's cleanup trap). A session with a live connection is never touched,
no matter how long it's been open.

### Warm pool

Authorizing a tunnel takes a couple of seconds — the hops do the work — so
after every `start` the service quietly authorizes one spare tunnel for that
same route and target. The next `start` for it takes the spare and answers
immediately (`"warm": true`), and a replacement is authorized in the
background. The first `start` for a target you haven't used yet still waits.

A spare is single-use and short-lived. It's discarded after
`--warm-max-age` seconds unused, and also if this machine's local address
towards the entry hop has changed — a sign you've switched network, which
would make the authorization useless. The pool only keeps spares for targets
you've used recently and is capped, so it winds down when you stop. The
`warm` list in `list` shows what's waiting. Turn it off with `--no-warm-pool`.

#### Stale spares

An authorization is tied to the public address the entry hop saw when it was
made. If that address changes while a spare is waiting — a new network, a VPN,
a roaming ISP — the relay turns the spare away the moment it's used. When a
connection on a spare tunnel is closed by the relay within about three seconds
with nothing coming back, the service drops every spare, authorizes a fresh
tunnel, replays what the client had already sent, and carries on, so the client
never sees the failure. It's only attempted for spares, only for that early
empty close, and only if the client sent no more than 64 KB before the first
reply. The service log says when it happens (`the relay turned this spare
tunnel away… re-authorized in 0.6s`).

A connection that is already open when your address changes can't be moved —
it's gone with the old address — but starting a new one works straight away.

```bash
~/.local/share/ztr/ztr_venv/bin/python3 ztr_tunnel_lp.py --config-file route.ztr
```

| Flag | Effect |
|---|---|
| `--config-file` (required) | The service's default route: bare filename of your downloaded route config — resolved inside `routes/`, e.g. `route.ztr` → `routes/route.ztr`. Used by every session that doesn't name another one. |
| `--control-host` | Control server bind address. Default `127.0.0.1` — this one never moves, only the per-session data listeners do. |
| `--control-port` | Control server port. Default `2223` — matches every wrapper's own `--cp` default. |
| `--local-ip` | Bind address for per-session data listeners. Default `10.10.15.10`, a dedicated dummy address so tunneled traffic is visually distinct from ordinary `127.0.0.1` localhost traffic (`netstat`, `ps`, logs) — set up once by the installer's `--with-local-ip` (a dummy interface on Linux, a `lo0` alias on macOS). Pass `127.0.0.1` to skip the dedicated address and use plain localhost instead. |
| `--idle-timeout` | Seconds a session may sit with zero active connections before the reaper closes it. Default `120`. |
| `--warm-max-age` | Seconds a pre-authorized spare tunnel may wait unused before it's discarded. Default `180`. |
| `--no-warm-pool` | Don't pre-authorize spares; every `start` waits for its own authorization. |

Run it standalone in a terminal, or let the installer set it up as a
`systemd --user` service on Linux or a launchd user agent on macOS (`--with-service`) so it survives reboots and
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

# use a different route for just this session
ztr_ssh --rh "example._ztr" --rp 22 --config-file other.ztr

# ztr_forward: wait, and point something else at the tunnel yourself
ztr_forward --rh "example._ztr" --rp 5432
# -> tunnel ready on 10.10.15.10:51234 — point your client there, Ctrl+C to close

# ztr_forward: or run a command against it directly
ztr_forward --rh "example._ztr" --rp 5432 -- bash -c 'psql -h "$ZTR_LOCAL_IP" -p "$ZTR_LOCAL_PORT" -U myuser'
```

All three take an optional `--config-file <name>.ztr` (`--config_file` works
too): the filename of a config in `routes/`, used for just that session.
Leave it off and the session goes through the route `ztr_tunnel_lp.py` was
started with. It's a bare filename, never a path, and the file has to
already be in `routes/` — otherwise the wrapper prints what the service
reported (for example `no routes/other.ztr`) and exits.

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

### Installing your key (`ztr_ssh --copy-id`)

`--copy-id` runs `ssh-copy-id` through the tunnel instead of opening a shell, so
you can switch a server from password to key login without it ever seeing your
own address:

```bash
ztr_ssh --copy-id -l myuser -i ~/.ssh/id_ed25519.pub --rh "example._ztr" --rp 22
# asks for myuser's password once, installs the key, then prints the command
# that logs in with it:  ztr_ssh -i ~/.ssh/id_ed25519 -l myuser --rh "example._ztr" --rp 22
```

The flags it takes are `-l user`, `-i key` (the key to install; by default the
newest `~/.ssh/id*.pub`), `-o option`, `-F ssh_config`, and `ssh-copy-id`'s own
`-f`, `-n` (a dry run that changes nothing), `-s` and `-t path`. It needs
`ssh-copy-id` (part of OpenSSH; on a Mac, `brew install ssh-copy-id`) and a
server that still allows password login.

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
target not on 443/80, a per-request `timeout=` (`Session`'s own default is
30s), `verify=False`/a CA bundle path to control certificate checking, and
`cert=` for a client certificate. `Response.abort()` closes a `stream=True`
response's connection outright without draining it, for when headers alone
(`Content-Type`) are enough to decide the body isn't worth downloading — a
video response never gets its body pulled through the tunnel at all this
way. Content-Length is always computed from the body actually being sent on
a given call, never trusted from a caller-supplied header, so a stale value
(e.g. from a reloaded saved request, or a later line in a batch run with a
different body) can't silently truncate or corrupt the request. Exposes
what actually happened on the wire (`resp.tls_info` — negotiated
protocol/cipher/peer certificate, `resp.route_info` — the hop chain the
request ran through) rather than just the response body. `ztr_requests/`
(below) is the reference consumer.

## ztr_requests/ — request-composer web UI

A small Postman-style local web app for firing one-off HTTP/HTTPS requests
straight through an authorized tunnel to their own real target, built on
`ztr_https.py`. Point it at a route file (or several — supports multiple
named `{{var}}`-substitution environments, so switching targets doesn't
mean retyping the same variable names with different values), compose a
request, hit Send, see the response — headers, cookies, a Relay Path
diagram and TLS certificate details, and (for an image response) decoded
EXIF metadata. A video response streams back through a Range-aware GET
instead of being buffered through the same request/response cycle as
everything else. Per-request timeout, TLS verification, and client
certificate are all composer options, not just `ztr_https.py` defaults.

Attach a `.txt` query file (one value per line) and reference it anywhere
in the request as `$$QF$$` to fire one request per line instead of one.
`$$QF::<...>$$` — `code`/`body_contains`/`headers[Name]` predicates, `=
!= >= <= > <`, combined with `AND`/`OR`/parens — either stops the run
early on a match, or (`$$QF::<...>::om$$`) keeps running every line but
only saves the matching ones. Full syntax is documented in-app (the `?`
button next to "Query file…"). Batch runs land in their own **Batch** tab,
separate from **History**: history's row only ever kept enough to
repopulate the composer, never the full response a batch line needs, so
by the time a run finished only the last line's detail was still visible
anywhere — Batch keeps everything for every line.

```bash
python3 plugins/ztr_requests/server.py
```

| Flag | Effect |
|---|---|
| `--host` | This app's own bind address. Default `127.0.0.1` — local-machine-only, deliberately not the open LAN by default, since a request built here can carry a route's real identifier/secret_key-backed tunnel plus whatever headers/body you type into it. |
| `--port` | This app's own HTTP port. Default `8089`. |

No `--config-file` — unlike the dashboard, it isn't tied to one route at
startup; pick whichever's in `routes/` per request, from the UI itself.
`static/` next to `server.py` is its frontend (plain CSS/JS, no build
step); `session_manager.py`/`history_store.py`/`environment_store.py`/
`collection_store.py`/`batch_store.py` are its own small sqlite-backed
state (one `ztr_https.Session` per route+timing-defense+verify+cert
combination, request history, named environments, saved requests, batch
run results) — all local to this directory, no shared database with
anything else here.

## ztr_ferry.py — Ferry, a file manager

Ferry is a two-pane file manager for servers you reach through a route: your
computer on the left, the server on the right. Connect once, then browse,
drag files across (or double-click them), rename, delete, change permissions,
search, and open a server file in your editor — saving it uploads it again.
It needs the tunnel service (`ztr_tunnel_lp.py`) to be running, the same as
`ztr_ssh` does. A route whose `.ztr` has an `exit_country` shows it in the Route
list and in the "Connected" bar (`US  ·  route.ztr`).

```bash
ztr_ferry                 # opens Ferry; the terminal comes straight back
ztr_ferry --foreground    # stay attached to the terminal and show errors live
```

With `--with-ferry` the installer also adds Ferry to your applications menu
(`Ferry.app` in `~/Applications` on a Mac). It runs on a Linux or macOS
desktop and needs Python's Tk (Linux: `sudo apt install python3-tk`; macOS:
a Python with Tk 8.6 or newer, such as `brew install python-tk@3.13`),
`rsync` and `ssh`; GNU `tar` is used for a faster path on small transfers
when it's there (on a Mac that is `gtar`, from `brew install gnu-tar`). It
needs no pip packages. On a Mac the shortcuts use the Command key
(`⌘T`, `⌘W`, `⌘,`) and the `ztr_ssh` button opens a Terminal window.

**How it connects.** Each tab asks the tunnel service for one session to the
server and opens a single ssh connection through it. Listings, folder
changes and every transfer reuse that connection, so you sign in once per
tab. Passwords are handed to ssh through a throwaway helper and never saved
or written to disk.

**What it does for you.**

- **Tabs.** One connection per tab (`Ctrl+T` opens one, `Ctrl+W` closes it; `⌘` on a Mac),
  each with its own queue and log. Saved sites and bookmarks are shared.
- **Transfers.** Everything goes through a queue you can cancel, retry and
  clear. Queued transfers headed the same way are merged into one rsync, so
  five files cost one start-up instead of five. A few small files (up to 40
  files / 8 MB from one folder) skip rsync and stream as one tar over the open
  connection — much quicker on a slow route, where rsync's start-up alone
  can take several seconds. Elapsed time and the average speed are shown for
  each transfer.
- **Settings** (the cog in the header, or `Ctrl+,`). What to do when a file
  already exists (skip, overwrite if newer, overwrite), a speed limit,
  compression, preview-only, folder comparison and hidden files. *Parallel
  batches* splits a large transfer into streams that run together; it is off
  by default because on a single route the streams share its bandwidth and
  measured slower than one stream.
- **The `ztr_ssh` button** opens a terminal on the server you're connected
  to, running `ztr_ssh` with the same user, key and route. It passes
  host-key options that keep each terminal session's host key out of your
  `~/.ssh/known_hosts`, so several servers behind the same tunnel address
  never trip "remote host identification has changed".
- **Host keys** for Ferry's own connections go in a throwaway file that is
  deleted with the connection; nothing about the servers you visit is kept on
  disk. A changed key between sessions is therefore not detected — the same
  trade-off `ztr_ssh` makes.
- **Tidying up.** Each connection's temporary folder is deleted when the
  connection closes. If Ferry is killed or crashes, the next Ferry to start
  clears what it left behind (connection folders whose ssh connection is
  gone, old password-helper folders, and day-old "View / Edit"
  copies) and never touches another running Ferry's.

**Where things live.** Saved sites, bookmarks and settings are in
`~/.config/ztr_ferry/` (no passwords). `FERRY_TERMINAL` (for example
`xterm -e`) chooses the terminal the `ztr_ssh` button opens, `FERRY_ZTR_SSH`
points it at a different `ztr_ssh`, and `ZTR_FERRY_HOME` moves the settings
folder.

## ztr_proxy/ — the browser proxy

A local proxy that sends the traffic of anything pointed at it through one of
your routes, with a window to run and watch it. One port speaks both an HTTP
proxy and SOCKS5. It does not use the tunnel service the other wrappers rely
on: it authorizes its own tunnels from a route file in `routes/`.

```bash
ztr_proxy                    # opens the window; the terminal comes straight back
ztr_proxy --foreground       # stay attached to the terminal and show errors live
ztr_proxy --route NAME.ztr   # open it with that route (a file in routes/) chosen
ztr_proxy --start            # start the proxy as soon as the window opens
ztr_proxy --cli --config-file NAME.ztr   # no window: run the proxy in this terminal
```

With `--with-proxy` the installer also adds ZTR Proxy to your applications
menu (`ZTR Proxy.app` in `~/Applications` on a Mac). The window runs on a
Linux or macOS desktop and needs Python's Tk (Linux: `sudo apt install
python3-tk`; macOS: Tk 8.6 or newer, such as `brew install python-tk@3.13`);
`ztr_proxy --cli` needs nothing beyond what the rest of the client already
uses. The launcher uses the installer's Python environment, or any Python 3.12
or newer that has `pycryptodome`; set `ZTR_VENV_DIR` if you put that
environment somewhere else.

By default it listens on `10.10.15.10` when this computer has that address
(the one `--with-local-ip` sets up) and on `127.0.0.1` otherwise, port `8095`.
The address in use is shown in the window and printed by `ztr_proxy --cli`.
Use `socks5h://` (curl: `--socks5-hostname`) so the proxy looks names up for
you instead of your computer.

**What passes through.** Plain HTTP is fully proxied: redirects reach the
client instead of being followed, and cookies pass straight through and are
never kept. HTTPS (`CONNECT`) and SOCKS5 are a blind byte relay — the TLS
session runs between your program and the site, and the proxy never sees
inside it.

**The window.**

- **Overview, Connections and Hosts** show each connection as it opens and
  closes, how long its tunnel took, the bytes each way, and the hosts you use
  most. A host can be kept ready ("Keep ready") so its first connection
  starts at once, and a route card shows each hop's direct round-trip time.
- **Browser** gives the proxy address (with copy buttons), a connection test,
  and "Open *browser* through ZTR". It lists the browsers it finds — Firefox,
  Chromium, Chrome, Brave, Edge and Vivaldi (including Snap and Flatpak
  installs on Linux, and the apps in `/Applications` on a Mac) — and opens the one you pick in a separate profile with the proxy
  set. Two options apply to the browser it opens: quieting the browser's own
  background connections (updates, telemetry and sync checks each open a
  tunnel of their own), and blocking WebRTC, which can reveal your real
  address to a website. For Firefox the page can also add the proxy settings
  to a profile you already use, and remove them again.
- **Blocklist and Alerts.** A blocked host is refused before any tunnel is
  opened. Patterns are `example.com` (that name and everything under it),
  `example.com:8443`, an address, or a CIDR range; lists in hosts-file or
  adblock format can be imported. The alert list names hosts you want to hear
  about without blocking them. Detection rules flag regular beaconing, far
  more data sent than received, bursts of random-looking names, remote-access
  ports, direct-to-address connections and repeated failures; every alert
  shows the evidence behind it, and a host you recognise can be marked
  trusted.

**Where things live.** Settings, the blocklist and the alerts are in
`~/.config/ztr_proxy/` (`ZTR_PROXY_HOME` moves them). The window's log is at
`~/.local/state/ztr/proxy.log` while it runs from the launcher.

## ztr_fleet/ — run things on many servers

Runs a command, a script or a file transfer on several servers at once, each
through its own route, with a command line and a window.

```bash
ztr_fleet 'uptime'                            # one command on every server
ztr_fleet --group web 'df -h /'               # only the servers in a group
ztr_fleet --script deploy.sh --batch 2 --canary   # one server first, then two at a time
ztr_fleet --put app.conf --to /tmp/           # send a file to every server
ztr_fleet --get /var/log/syslog --into logs   # fetch a file from every server
ztr_fleet --shell web1                        # a terminal on one server
ztr_fleet --gui                               # the window
```

The servers are listed in `fleet.conf` (`ztr_fleet --example` prints a
sample): a name, the route file, the alias, the ssh user and port, and optional
`group=`, `key=` and variables a command can use as `{name}`. It uses the
tunnel service the other wrappers use, and ssh key login to the servers. It can
roll out in batches that stop at the first failure, retry failed servers, ask
before a destructive command, send a sudo password once over ssh, give each
answer to a local script (**hooks**), and repeat a run on a schedule. The
window adds Compare (which servers answered differently), History, a hook
manager and a Schedules tab. See [ztr_fleet/README.md](ztr_fleet/README.md).

## Layout

- `ztr_tunnel_lp.py` — the shared tunnel service every wrapper below talks to.
- `ztr_ssh`, `ztr_forward`, `ztr_pg` — CLI wrappers around it.
- `ztr_ferry` + `ztr_ferry.py` — the Ferry file manager and its launcher.
- `ztr_proxy/` — the browser proxy: `ztr_proxy` (launcher), `ztr_proxy.py`
  (the proxy), `ztr_proxy_gui.py` (the window) and `ztr_proxy_guard.py`
  (blocklist, alert list and detection rules).
- `ztr_fleet/` — run things on many servers: `ztr_fleet` (launcher),
  `ztr_fleet_core.py` (the command line and the engine) and `ztr_fleet_gui.py`
  (the window).
- `ztr_dashboard.py` + `static/` — the standalone local dashboard.
- `ztr_https.py` — HTTP(S)-over-tunnel client library.
- `ztr_requests/` — the standalone request-composer web UI, built on it.
