# ztrclient

The ZTRelay client — connects to the ZTRelay network and exposes local plugin
wrappers (`ztr_ssh`, `ztr_forward`, `ztr_pg`) for tunneling traffic through it.

## Install

```bash
git clone https://github.com/igenius21fm/ztrclient.git
cd ztrclient/ztrclient
```

**macOS:**
```bash
./installer-macos.sh
```

**Linux:**
```bash
./installer-linux.sh
```

Both installers set up a dedicated Python venv, install dependencies, and
symlink the plugin wrappers so they run from any shell. Run with `--help`
for the full list of flags (custom install prefix, background service,
loopback IP, uninstall).

## Layout

- `ztrclient/ztrClient.py` — the core relay client (`RelayClient`).
- `ztrclient/launcher.py` — entry point that loads a `.ztr` config and starts the client.
- `ztrclient/plugins/` — `ztr_ssh`, `ztr_forward`, `ztr_pg`, and the tunnel launch-point script.
- `ztrclient/utils/crypt_bot.py` — RSA/AES helper used for signing and encrypting messages to the relay.

On first run, the client generates its own RSA keypair (`privateKey.pem` /
`publicKey.pem`) next to `ztrClient.py` — these are unique per install and
are never shipped in this repo.
