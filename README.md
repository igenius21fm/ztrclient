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

## Registering your RSA key

Before you can create a route, register an RSA key from your dashboard's
Keys panel. It'll give you a one-time nonce to sign, proving you hold the
matching private key. Sign it with `launcher.py` — **using the venv the
installer just set up**, not your system `python3`:

```bash
~/.local/share/ztr/venv/bin/python3 launcher.py
```

(Running it with your system `python3` instead fails with
`ModuleNotFoundError: No module named 'Crypto'` — `pycryptodome` only lives
in that venv.) It prints your public key, then prompts `Nonce To Sign:` —
paste in the nonce from the dashboard, and it prints back a signature (hex)
to paste into the form. It reuses the same keypair every time you run it,
generating one on first run if none exists yet (`privateKey.pem` /
`publicKey.pem`, next to `ztrClient.py` — unique per install, never shipped
in this repo).

## Uninstall

```bash
./installer-linux.sh --uninstall   # or installer-macos.sh
```

Removes the symlinked wrappers, the venv, the background service (if any),
the PATH/alias lines from your rc file, and the dummy IP/interface (if any)
— everything the installer added, and nothing else. Your `routes/` folder
and any `.ztr` configs in it are left alone.

## Troubleshooting

**`Failed to connect to user scope bus via local transport... XDG_RUNTIME_DIR
not defined`** — you ran the installer with `sudo`. Run it as your normal
user instead; it prompts for `sudo` itself on the one piece that actually
needs it (the dummy network interface).

**`ModuleNotFoundError: No module named 'Crypto'`** running `launcher.py`
(or any plugin) directly — you're using your system `python3` instead of
the venv's. Use `~/.local/share/ztr/venv/bin/python3` instead (see
[Registering your RSA key](#registering-your-rsa-key) above).

## Layout

- `ztrClient.py` — the core relay client (`RelayConfig`/`RelayClient`).
- `launcher.py` — standalone tool for signing a dashboard nonce with your
  RSA key (see above) — not the client entry point itself.
- `plugins/` — `ztr_ssh`, `ztr_forward`, `ztr_pg`, and `ztr_tunnel_lp.py`
  (the persistent-service target).
- `utils/crypt_bot.py` — RSA/AES helper used for signing and encrypting
  messages to the relay.
- `installer-linux.sh` / `installer-macos.sh` — see [Install](#install).

## Example apps

Reference target/client apps built on this client — an HTTP proxy, a video
streamer, an async drop-box, and a worker pool — live in
[ztrapps](https://github.com/igenius21fm/ztrapps).
