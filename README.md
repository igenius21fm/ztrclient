# ztrclient

The ZTRelay client — authorizes and drives an encrypted multi-hop tunnel
through the ZTRelay network. Turns a `.ztr` route config (downloaded from
your dashboard) into a live connection, and ships with three ready-to-use
plugin wrappers (`ztr_ssh`, `ztr_forward`, `ztr_pg`) so you don't have to
write any code to use it.

Full API reference and walkthroughs: see the ztrClient.py docs on the
ZTRelay platform (Downloads page → "Read the docs").

## Requirements

- Python 3.8+
- **Linux** (systemd) or **macOS** — the installers are OS-specific; there's
  no Windows installer yet.
- No manual `pip install` — the installer sets up its own isolated venv.

## Install

Either clone the repo:

```bash
git clone https://github.com/igenius21fm/ztrclient.git
cd ztrclient/ztrclient
```

or grab a specific [release](https://github.com/igenius21fm/ztrclient/releases)
zip instead, if you'd rather pin a version than track `main`:

```bash
curl -LO https://github.com/igenius21fm/ztrclient/releases/download/v1.0.2/ztrclient-v1.0.2.zip
unzip ztrclient-v1.0.2.zip
cd ztrclient
```

Then run the installer for your OS:

```bash
# Linux
./installer-linux.sh

# macOS
./installer-macos.sh
```

Both installers, with no flags, walk you through everything interactively
(see [Installer prompts](#installer-prompts) below) — no flags are required
for a normal install. Under the hood, each one:

1. Makes `plugins/{ztr_ssh,ztr_forward,ztr_pg}` executable — a zip download
   or fresh `git clone` doesn't reliably preserve the executable bit.
2. Creates a dedicated venv (default `~/.local/share/ztr/venv`) and installs
   `pycryptodome` into it, isolated from your system Python.
3. Creates `routes/` next to `ztrClient.py` — every `.ztr` config you
   download has to live there.
4. Symlinks the three wrappers into `~/.local/bin` (or `--prefix`), and
   optionally adds that to your `PATH` plus shell aliases.
5. Optionally sets up a persistent background service (systemd `--user` on
   Linux, a launchd agent on macOS) for `ztr_tunnel_lp.py`, and a dedicated
   IP for its tunneled sessions to bind to.

### Flags

Skip a prompt by passing its answer directly — useful for scripted/CI
installs, where the interactive prompts are skipped automatically anyway
(no flag needed) since there's no terminal to read from:

| Flag | Effect |
|---|---|
| `--prefix DIR` | Install the wrappers into `DIR` instead of `~/.local/bin`. |
| `--venv-dir DIR` | Put the venv at `DIR` instead of `~/.local/share/ztr/venv`. |
| `--with-service` | Set up the persistent background service non-interactively (implies `--with-local-ip`). |
| `--with-local-ip` | Set up the dedicated dummy IP non-interactively. |
| `--local-ip IP` | Use `IP` instead of the default `10.10.15.10`. |
| `--uninstall` | Remove everything the installer set up — wrappers, venv, service, PATH/alias lines, dummy IP. |
| `-h`, `--help` | Print the full usage text. |

```bash
# fully non-interactive install, custom prefix, service + custom IP
./installer-linux.sh --with-service --local-ip 10.10.15.20 --prefix "$HOME/bin"
```

## Installer prompts

Run with no flags in a real terminal, you'll be asked up to four questions —
each one only appears if it's actually relevant to your setup, so you may
see fewer than four.

**1. `Set up ztr_tunnel_lp.py as a persistent systemd --user service? [y/N]:`**
*(macOS: "...as a persistent launchd agent?")*
Always asked first, unless you already passed `--with-service` (or you're
running `--uninstall`, or non-interactively). This sets up a background
service that keeps a tunnel alive across reboots/logins, instead of you
running `ztr_tunnel_lp.py` yourself in a terminal each time.
→ **Answer `N`** (or just press Enter) if you're only using the
`ztr_ssh`/`ztr_forward`/`ztr_pg` wrappers directly — they don't need this.
→ **Answer `y`** if you want a long-running local proxy for tunneled
sessions to bind to, always on in the background.

**2. `Dummy IP for tunneled sessions to bind to [10.10.15.10]:`**
Only appears if you answered `y` above (or passed `--with-local-ip`). This
sets up a real dedicated network interface (not just a loopback alias) that
`ztr_tunnel_lp.py`'s listeners bind to, instead of the generic `127.0.0.1`.
→ **Just press Enter** to accept the default (`10.10.15.10`) unless that
address conflicts with something else on your network.

**3. `<prefix> isn't on your PATH yet — add PATH + shell aliases for ztr_ssh/ztr_forward/ztr_pg to <rc file>? [y/N]:`**
Only appears if `~/.local/bin` (or your `--prefix`) isn't already on your
`PATH` — common on a fresh machine. It detects your shell's rc file
(`.zshrc`, `.bashrc`, or `.bash_profile`) automatically.
→ **Answer `y`** unless you'd rather manage your `PATH` and aliases
yourself — the exact lines it would have added are printed either way if
you say no, so you can copy them in by hand later.

**4. `Path to your downloaded .ztr route config:`**
Only appears if the service is being set up (question 1 was `y`, or
`--with-service` was passed). Give it the path to a `.ztr` file you
downloaded from a route in your dashboard — it gets copied into `routes/`
and wired into the service unit.
→ There's no sensible default here; if you don't have a route config yet,
answer with a garbage/nonexistent path — the installer skips service setup
cleanly and tells you to re-run with `--with-service` once you have one.

## Getting connected

Five steps, in this order — skipping ahead (e.g. creating a route before
your key is verified, or running the client before the config is in place)
is the single most common way to get stuck. Each step links to its
[Troubleshooting](#troubleshooting) entry.

**1. Run the installer** (see [Install](#install) above) — it needs to run
first: it's what creates the venv `launcher.py` and every plugin depend on,
and the `routes/` folder your config goes into later.
→ Stuck here? See [Installing](#installing).

**2. Register an RSA key.** In your dashboard's Keys panel, click **Nonce**
to get a one-time challenge, then sign it — **using the venv the installer
just set up**, not your system `python3`:

```bash
~/.local/share/ztr/venv/bin/python3 launcher.py
```

It prints your public key, then prompts `Nonce To Sign:` — paste in the
nonce the panel just gave you. It prints back a signature (hex); paste
*that*, plus the public key it printed and your account's secret key, into
the form and submit. It reuses the same keypair every time you run it,
generating one on first run if none exists yet (`privateKey.pem` /
`publicKey.pem`, next to `ztrClient.py` — unique per install, never shipped
in this repo).
→ Stuck here? See [Registering a key](#registering-a-key).

**3. Create a route, bound to that key.** In the Routes panel, pick the key
you just registered, an exit country, and a hop count.
→ Stuck here? See [Creating a route](#creating-a-route).

**4. Download the route's config and place it correctly.** Click
**Download .ztr** on the route, then:

```bash
mv ~/Downloads/<name>.ztr ztrclient/routes/
```

Open it and replace the `"secret_key": "<your secret_key>"` placeholder
with your real account secret key (the same one used in step 2 — shown
once at account registration, or after **Account → Regenerate secret
key**) — the server only ever stores a hash of it, so it can't fill this
in for you.
→ Stuck here? See [The config file](#the-config-file).

**5. Run it.** Easiest: use one of the plugin wrappers directly — after
step 1, these are already on your `PATH`:

```bash
ztr_ssh --rh "example._ztr" --rp 22
```

Or, writing your own script against `RelayClient` directly:

```python
from ztrClient import RelayClient

client = RelayClient(target_host="example._ztr", port=22, config_file="<name>.ztr")
result = client.set_tunnel()
if result and result.get("status"):
    print("Tunnel established:", client.session_id)
else:
    print("Failed to establish tunnel:", result)
```

run with the venv's interpreter, same as everything else here:
`~/.local/share/ztr/venv/bin/python3 your_script.py`.

## Troubleshooting

### Installing

**`Failed to connect to user scope bus via local transport... XDG_RUNTIME_DIR
not defined`** — you ran the installer with `sudo`. Run it as your normal
user instead; it prompts for `sudo` itself on the one piece that actually
needs it (the dummy network interface).

**`permission denied` on `./installer-linux.sh`** — you're on a release zip
built before v1.0.2, which shipped without the executable bit. Either
`chmod +x installer-linux.sh installer-macos.sh` yourself, or re-download
the [latest release](https://github.com/igenius21fm/ztrclient/releases/latest).

**`couldn't create the venv — ... sudo apt install python3-venv`** (Linux)
— Debian/Ubuntu split the stdlib `venv` module into its own package; the
installer already tells you the exact command, just run it and re-run the
installer.

### Registering a key

**`ModuleNotFoundError: No module named 'Crypto'`** running `launcher.py`
— you used your system `python3` instead of the venv's. Use
`~/.local/share/ztr/venv/bin/python3 launcher.py` instead.

**`invalid_nonce` / "Nonce is unknown, already used, or expired"** — nonces
are single-use and expire 5 minutes after you click **Nonce**. If you
clicked it more than once, sign and submit the *most recent* one, not an
earlier one still sitting in your terminal history. Just click **Nonce**
again and re-sign if it's been a few minutes.

**`invalid_signature` / "Signature does not match public key"** — usually
one of: you signed a different nonce than the one currently shown in the
form (re-fetch and re-sign to be sure they match), you pasted an
incomplete PEM (missing the `-----BEGIN/END PUBLIC KEY-----` lines
`launcher.py` printed), or you copied the signature with extra
whitespace/newlines around it.

**`invalid_secret_key`** — the account secret key you entered doesn't match.
It's shown once, either right after registration or after **Account →
Regenerate secret key** — if you don't have it saved, regenerate it (this
invalidates the old one).

### Creating a route

**`invalid_pubkey` / "That key isn't a verified key on your account"** —
either your key registration from step 2 didn't actually succeed (check the
Keys panel — it should be listed there), or you're picking a key that's
since been revoked.

**`no_active_plan`** — you need an active paid plan before you can create
any route.

**`account_suspended`** — your balance ran out (or a payment failed) and
your account was suspended; top up your balance to reactivate it.

**`route_limit_reached`** — you're at your plan's concurrent-route cap;
delete an existing route or upgrade your plan.

### The config file

**`ConfigNotFoundError: no .ztr config at .../routes/<name>.ztr — place it
in routes/ next to ztrClient.py`** — the file has to be inside `ztrclient`'s
own `routes/` folder specifically, not your current directory, not
`~/Downloads`, and not `ztrclient`'s own top-level folder either.

**Connects, but nothing happens / hangs / fails silently** — the single
most common cause is forgetting to replace the `"secret_key": "<your
secret_key>"` placeholder in the downloaded file with your real one. This
doesn't raise a Python exception — bad tunnel authorization is caught
internally and logged, not raised, so check `ztrclient.log` (next to
`ztrClient.py`) for what actually went wrong instead of expecting a
traceback.

## Uninstall

```bash
./installer-linux.sh --uninstall   # or installer-macos.sh
```

Removes the symlinked wrappers, the venv, the background service (if any),
the PATH/alias lines from your rc file, and the dummy IP/interface (if any)
— everything the installer added, and nothing else. Your `routes/` folder
and any `.ztr` configs in it are left alone.

## Layout

- `ztrClient.py` — the core relay client (`RelayConfig`/`RelayClient`).
- `launcher.py` — standalone tool for signing a dashboard nonce with your
  RSA key (see [Getting connected](#getting-connected)) — not the client
  entry point itself.
- `plugins/` — `ztr_ssh`, `ztr_forward`, `ztr_pg`, and `ztr_tunnel_lp.py`
  (the persistent-service target).
- `utils/crypt_bot.py` — RSA/AES helper used for signing and encrypting
  messages to the relay.
- `routes/` — where your downloaded `.ztr` route configs go (see
  [Getting connected](#getting-connected)). Ships empty (aside from its own
  README) — the installer's `mkdir -p` would create it anyway, but it's
  here from the start so it's not a surprise.
- `installer-linux.sh` / `installer-macos.sh` — see [Install](#install).

## Example apps

Reference target/client apps built on this client — an HTTP proxy, a video
streamer, an async drop-box, and a worker pool — live in
[ztrapps](https://github.com/igenius21fm/ztrapps).
