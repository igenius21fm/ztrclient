# ZTR Proxy

A local proxy that sends the traffic of anything pointed at it through one of
your ZTRelay routes, with a window to run it and watch what it does. One port
speaks both an HTTP proxy and SOCKS5, so browsers, `curl`, `ssh` and most other
programs can use it.

```bash
ztr_proxy                    # opens the window; the terminal comes straight back
ztr_proxy --foreground       # stay attached to the terminal and show errors live
ztr_proxy --route NAME.ztr   # open it with that route (a file in routes/) chosen
ztr_proxy --start            # start the proxy as soon as the window opens
ztr_proxy --cli --config-file NAME.ztr   # no window: run the proxy in this terminal
```

Run it as `plugins/ztr_proxy/ztr_proxy` from the client folder, or let the
installer's `--with-proxy` put it on your `PATH` and add **ZTR Proxy** to your
applications menu (`ZTR Proxy.app` in `~/Applications` on a Mac).

## Using it

Start the proxy from the window (or with `--cli`), then point a program at the
address it shows. By default that is `10.10.15.10` when this computer has that
address (the one `--with-local-ip` sets up) and `127.0.0.1` otherwise, port
`8095`.

```bash
curl -x http://10.10.15.10:8095 https://example.com/
curl --socks5-hostname 10.10.15.10:8095 https://example.com/
```

Use `socks5h://` (curl: `--socks5-hostname`) so the proxy looks the name up for
you. With plain `socks5` your computer looks it up first, outside the tunnel.

The proxy listens on this computer only, because it carries your route's
credentials. `--host` and `--port` change where.

**What passes through.** Plain HTTP is fully proxied: redirects reach your
program instead of being followed, and cookies pass straight through and are
never kept. HTTPS (`CONNECT`) and SOCKS5 are a blind byte relay — the TLS
session runs between your program and the site, and the proxy never sees
inside it. It can't inspect or alter that traffic.

## What you need

- A route file in `routes/`.
- Python 3.12 or newer with `pycryptodome`. The launcher uses the installer's
  Python environment, or any Python that qualifies; set `ZTR_VENV_DIR` if you
  keep that environment elsewhere.
- For the window: Python's Tk 8.6 or newer (Linux: `sudo apt install
  python3-tk`; macOS: `brew install python-tk@3.13`). `ztr_proxy --cli` needs
  nothing more than the rest of the client.

The proxy opens its own tunnels from the route file. It does not use the
tunnel service the other wrappers rely on.

## The window

- **Overview, Connections and Hosts** show each connection as it opens and
  closes, how long its tunnel took to set up, the bytes each way and the hosts
  you use most. A route card shows the chain of hops with the direct round-trip
  time to each. A host can be marked **Keep ready**, so its first connection
  starts at once.
- **Browser** gives the proxy address with copy buttons, a connection test, and
  **Open *browser* through ZTR**. It lists the browsers it finds — Firefox,
  Chromium, Chrome, Brave, Edge and Vivaldi, including Snap and Flatpak
  installs on Linux and the apps in `/Applications` on a Mac — and opens the one
  you pick in a separate profile with the proxy set. Two options apply to that
  browser: quieting its own background connections (updates, telemetry and sync
  checks each open a tunnel of their own), and blocking WebRTC, which can
  reveal your real address to a website. For Firefox the page can also add the
  proxy settings to a profile you already use, and remove them again.
- **Blocklist and Alerts.** A blocked host is refused before any tunnel is
  opened. Patterns are `example.com` (that name and everything under it),
  `example.com:8443`, an address, or a CIDR range; lists in hosts-file or
  adblock format can be imported. The alert list names hosts you want to hear
  about without blocking them. Detection rules flag regular beaconing, far
  more data sent than received, bursts of random-looking names, remote-access
  ports, direct-to-address connections and repeated failures; every alert shows
  the evidence behind it, and a host you recognise can be marked trusted.
- **Rules** say what to do when a host name contains some text: block it, alert
  you, or trust it. `tracker` matches `ad-tracker.net` and `tracker.example.com`;
  the text needs at least three characters. As you type, the page shows which
  of the hosts seen so far the rule would have matched. A rule can also match a
  name and everything under it, or an address or range, like the Blocklist
  entries. Everything on the Blocklist, Alert list and Trusted tabs is listed on
  this page too, and if several rules match, Block wins. In the entry boxes the
  same rule is written `contains:tracker`.
- **Route names show the country.** If a route's `.ztr` has an `exit_country`
  (newer downloads do), the route list reads `US  ·  route.ztr` and the exit hop
  on the route card is labelled `Exit · US`.
- **Hide names** (the button in the top bar) shows host names and addresses
  abbreviated everywhere in the window, like `w•••.e•••.com` and
  `203.•••.•••.•••`, so a screen share or a photo of the screen doesn't show what
  you visit. It changes only what is displayed: filters and the Copy buttons
  still use the real names, and traffic is untouched.
- **Log** shows what the proxy is doing, as it happens.

## Command-line options

`ztr_proxy --cli --help` lists them all:

| Option | What it does |
|---|---|
| `--config-file NAME.ztr` | the route to use (a file in `routes/`) |
| `--host`, `--port` | the address and port to listen on |
| `--keep-ready HOST[:PORT]` | keep a ready tunnel to this host at all times (repeatable; port defaults to 443) |
| `--no-warm-pool` | don't prepare tunnels ahead of time |
| `--warm-max-age SECONDS` | how long a ready tunnel may wait unused (default 150) |
| `--warm-min-uses N` | prepare a tunnel for a host once it has been asked for N times within a minute (default 2) |
| `--idle-timeout SECONDS` | close a connection that has sent nothing, either way, for this many seconds (0 = never, the default; otherwise at least 10) |
| `--with-timing-defense` | turn on the hops' own jitter and decoy traffic for every tunnel this proxy opens |

Browsers keep a connection open for a while after you close the page that
used it, and each one holds a tunnel through your route until it is closed. With
`--idle-timeout` (or **Settings → Close idle connections after**) the proxy closes a
connection that has been quiet for that long; the browser just opens a new one
when it needs it. It is off by default, because anything that sits quiet on
purpose — an ssh session, a chat page — would be cut too. The Connections tab
shows how long each connection has been idle, and **Close idle** closes every
connection that has been quiet for 30 seconds.

Setting up a tunnel takes a moment, so after a host has been used the proxy
prepares a spare one in the background. The next connection to that host then
starts straight away.

## Where things live

Settings, the blocklist and the alerts are in `~/.config/ztr_proxy/`
(`ZTR_PROXY_HOME` moves them). While it runs from the launcher, the log is at
`~/.local/state/ztr/proxy.log`.

## Files

- `ztr_proxy` — the launcher.
- `ztr_proxy.py` — the proxy itself.
- `ztr_proxy_gui.py` — the window.
- `ztr_proxy_guard.py` — the blocklist, alert list and detection rules.
