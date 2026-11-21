# ztr_isf — use your own ISF

An **ISF** (Intermediate Server Forwarder) is a small server that you run
yourself. Your route ends at your ISF instead of at the exit hop's choice of
destination: the exit only ever connects to the ISF, and you tell the ISF —
over a signed, end-to-end encrypted control channel — where each session
really goes. The exit sees neither the destination nor the payload.

The ISF server comes as a package you download from the **ISF server** panel
of your ZTRelay dashboard. This folder is the client side.

## Set up (once)

1. Install the server on a machine of yours with the package's `installer.sh`.
   It prints the path of the ISF's public key (`isf_public.pem`); copy that
   file to this machine.
2. Create this machine's keypair and register the ISF:

   ```
   ztr_isf_client gen-keys
   ```

   Paste the printed `client_public.pem` into the server installer when it
   asks for your client's public key (or run the installer again later with
   `--peer-pub`).

   ```
   ztr_isf_client isf add work \
       --host <your ISF's public IP> --route routes/route.ztr \
       --isf-pub <path to isf_public.pem>
   ```

3. Check it:

   ```
   ztr_isf_client ctrl --isf work health
   ```

Several ISFs are fine; each keeps its own route. `isf list` shows them and
`isf set` / `isf remove` change them.

## What you can do

`isf_ssh` and `ztr_isf_client` are on your `PATH` once the installer has run. The dashboard is run from the client folder as `python3 plugins/ztr_isf/ztr_isf_dashboard.py`. Below, `ztr_isf_client.py` and `ztr_isf_client` are the same program.

| | |
|---|---|
| `ztr_isf_client.py connect --isf work --destination host:port --listen 127.0.0.1:2222` | a local TCP port that reaches `host:port` through your ISF |
| `ztr_isf_client.py udp --isf work --destination 8.8.8.8:53 --listen 127.0.0.1:5353` | the same for UDP (DNS, QUIC, WireGuard…); the ISF must have UDP on, which the installer does by default |
| `ztr_isf_client.py ctrl alias-add example.com` | a name that only your ISF understands: `<64 characters>.isf` stands for `example.com` |
| `isf_ssh me@example.com` | ssh (and `--scp`, `--sftp`, `--copy-id`) through your ISF in one command; the installer puts it on your `PATH` |
| `ztr_isf_dashboard.py` | a local web page (default port 8096) to manage your ISFs: sessions, allowlist, aliases |

`ztr_ssh`, `ztr_forward`, ZTR Fleet, Ferry, ZTR Requests and ZTR Proxy also
accept an ISF: `--isf [NAME]` on the command line, or the "Via ISF" choice in
their windows. A bare `--isf` means your default ISF.

## Good to know

- Allow the destinations you need on the ISF (the dashboard's Allowlist panel,
  or `ztr_isf_client.py ctrl allow-add host:port`). Private addresses stay
  blocked unless you allow them.
- Each TCP connection through an ISF takes a couple of seconds to open; the
  first datagram from a new UDP sender takes about as long.
- An alias hides the real host name from your scripts, but TLS certificates are
  checked against the name you connect to: for HTTPS use the real name.
- `ztr_isf_dashboard.py --help` lists its options. Keys live in `~/.ztr_isf/`.
