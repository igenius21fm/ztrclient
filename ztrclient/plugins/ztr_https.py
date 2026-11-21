"""ztr_https — general-purpose HTTPS (and plain HTTP) client over a
ZTRelay tunnel, `requests`-shaped:

    import ztr_https

    resp = ztr_https.get("https://example.com/path", config_file="route.ztr")
    print(resp.status_code, resp.json())

    with ztr_https.Session(config_file="route.ztr") as s:
        s.get("https://example.com/a")
        s.get("https://example.com/b")  # same origin -> same tunnel/TLS
                                         # connection reused, no second
                                         # authorization round trip

Handles two things a caller shouldn't have to know about, each verified
against a real route/exit hop, not just inferred from reading the source:

1. Tunnel authorization + the entry hop's asymmetric native=False wire
   format. Traced directly from hop_router.py's relay(): a read from the
   client is UNCONDITIONALLY read_HTH_frame(), regardless of native, but
   the entry-hop-to-client reply leg is raw when native=False. So every
   outgoing chunk has to be individually HTH-framed (send_HTH) while every
   incoming chunk is a plain raw socket read — confirmed by a real
   "Payload length ... exceeds maximum allowed size" from a live entry hop
   the one time this wasn't done right.

2. TLS driven by hand via ssl.MemoryBIO instead of ssl.wrap_socket() —
   wrap_socket()'s automatic handshake talks to a real socket directly,
   giving no way to frame each outgoing TLS record via send_HTH the way
   the entry hop requires.

3. What the hops in between can read. A TLS ClientHello names the target
   (SNI) in cleartext, and a plain-HTTP request is readable text
   throughout, so both are wrapped for the exit hop's eyes only before
   they leave (send_HTH's for_exit) — the entry and middle hops relay
   ciphertext. Once a TLS handshake is finished, everything after it is a
   TLS record and already opaque to them, so those chunks go out
   unwrapped. The switch is the handshake state this module itself
   drives, not a look at the bytes.

Target domains are handed to RelayClient exactly as given — never resolved
locally. The whole point of routing a request through ZTRelay is that
*everything* about it, including which domain it's even for, goes through
the tunnel; a client-side socket.gethostbyname() would leak that to the
user's own local network/DNS resolver before a single byte of the actual
request ever reached the relay. Resolution happens at the exit hop instead
(dns_records.get_ip(), registry-side — falls back to real DNS for anything
that isn't one of the registry's own registered ._ztr aliases, gated
through the same SSRF check a registered alias's own IP already goes
through, and cached there). Confirmed end-to-end with the client-side
resolver deliberately disabled: the bare domain went in, tunnel
authorization and the request both still succeeded.

Real HTTP/1.1 response parsing (Content-Length, chunked
Transfer-Encoding, gzip/deflate Content-Encoding) — not read-until-close,
since Session keeps connections alive across requests to the same origin
whenever the target allows it, and a keep-alive response has to be read
exactly as long as it says it is, not until the socket happens to close.

Also handles: redirect following, per-host cookies, per-request read
timeouts, multipart/form-data uploads (files=), streaming responses
(stream=True, Session-based only — see request()'s docstring), and a
verify=/cert= knob for TLS validation.

Through your own ISF — `isf=`:

    resp = ztr_https.get("https://example.com/", isf="home")   # a named ISF
    resp = ztr_https.get("https://example.com/", isf=True)     # your default ISF
    with ztr_https.Session(isf="home", config_file="US_c6c0ed68.ztr") as s:   # another route
        s.get("https://example.com/a")
        s.get("https://example.com/b")   # same origin -> same ISF session, same TLS connection

The route no longer ends at the exit hop's own connection to the site: it ends at an ISF you run
(see ztr_isf_client.py / isf_ssh), which opens the connection to the site. Each connection this
Session makes is one single-use ISF session, created through the ISF's signed, end-to-end
encrypted control channel and closed with the connection. The ISF's list of destinations must
allow the host:port (the dashboard's Allowlist panel, or `ztr_isf_client.py ctrl allow-add`).

TLS is still driven here, end to end with the site: the ISF carries TLS records and never sees the
request, the response or the certificate exchange in the clear, and the exit hop sees only the
ISF's own encrypted frames. The site's address is named only inside the encrypted ISF channel, so
the exit-hop wrapper for the ClientHello (for_exit) isn't needed and isn't used. Name resolution
happens on the ISF. `isf=` needs ztr_isf_client.py importable (next to this file, in ~/isf, or via
$ISF_CLIENT_DIR) and the ISF list set up with isf_ssh --save / the dashboard.
"""
import gzip
import json as _json
import os
import secrets
import socket
import ssl
import sys
import zlib
from urllib.parse import urlencode, urljoin, urlsplit

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# This file lives at plugins/ alongside ztr_dashboard.py etc — the package
# root (ztrClient.py's real home) is SCRIPT_DIR's parent, same one-level-up
# shape every other plugin here uses.
_ZTR_CLIENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, _ZTR_CLIENT_DIR)
sys.path.insert(0, os.path.join(_ZTR_CLIENT_DIR, "utils"))
from ztrClient import RelayClient, TunnelError, NetworkError  # noqa: E402


class HTTPProtocolError(TunnelError):
    """The target's own HTTP response couldn't be parsed — malformed
    status line/headers, or a body whose length can't be determined."""


class _TunnelIO:
    """The one primitive both the plain-HTTP and TLS-over-tunnel paths
    build on — see this module's docstring, point 1, for why send() and
    recv() are asymmetric (framed vs. raw) rather than a matched pair."""

    def __init__(self, sock: socket.socket, client: RelayClient):
        self._sock = sock
        self._client = client

    def send(self, data: bytes, for_exit: bool = True) -> None:
        # Nothing an entry or middle hop needs to read to do its job ever
        # goes through here, so anything that would tell them something
        # about the target is wrapped for the exit hop's eyes only
        # (for_exit=True, the default — a caller has to opt OUT of the
        # protection, never into it):
        #   - a plain-HTTP request: the Host header, cookies, auth headers
        #     and body are all readable text.
        #   - a TLS handshake's records: the ClientHello names the target
        #     in its SNI extension, and TLS never encrypts SNI.
        # The one thing that opts out is _TLSTunnel's post-handshake
        # traffic, which is TLS ciphertext already — see _TLSTunnel._flush.
        self._client.send_HTH(self._sock, data, self._client.session_id, encrypt_payload=False, for_exit=for_exit)

    def recv(self, nbytes: int) -> bytes:
        try:
            return self._sock.recv(nbytes)
        except socket.timeout:
            raise NetworkError("read timed out")

    def set_timeout(self, seconds) -> None:
        self._sock.settimeout(seconds)

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


_ISF_CLIENT = None


def _load_isf_client():
    """Imports ztr_isf_client on first use of isf=, from next to this file, ~/isf, or $ISF_CLIENT_DIR."""
    global _ISF_CLIENT
    if _ISF_CLIENT is not None:
        return _ISF_CLIENT
    for d in (os.environ.get("ISF_CLIENT_DIR"), SCRIPT_DIR, os.path.join(SCRIPT_DIR, "ztr_isf"),
              os.path.join(os.path.expanduser("~"), "isf")):
        if d and os.path.isfile(os.path.join(d, "ztr_isf_client.py")):
            if d not in sys.path:
                sys.path.insert(0, d)
            import ztr_isf_client
            _ISF_CLIENT = ztr_isf_client
            return _ISF_CLIENT
    raise TunnelError("isf= needs ztr_isf_client.py — put it next to ztr_https.py, in ~/isf, or set ISF_CLIENT_DIR")


def list_isfs():
    """The ISFs set up on this machine (the list isf_ssh and the ISF dashboard manage), for plugins that offer a
    choice: name, masked address, route, whether it is the default, whether its public key is installed.
    [] when there are none or ztr_isf_client isn't available. Addresses are masked (138.197.x.x) on purpose."""
    try:
        C = _load_isf_client()
        ps = C.Profiles()
        out = []
        for name in ps.names:
            p = ps.get(name)
            out.append({"name": name, "host": C.mask_host(p["host"]), "route": p["route"], "default": name == ps.default_name,
                        "key_installed": os.path.exists(p["isf_pub"]), "note": p.get("note", "")})
        return out
    except Exception:
        return []


def check_isf(value):
    """Normalises an ISF choice coming from a UI, a file or a command line: None / "" / False -> None (no ISF),
    True or "@default" -> the default ISF's name, a name -> that name if it exists. Anything else raises ValueError
    with a message fit to show the user."""
    if value in (None, "", False):
        return None
    names = [i["name"] for i in list_isfs()]
    if value is True or value == "@default":
        default = next((i["name"] for i in list_isfs() if i["default"]), None)
        if not default:
            raise ValueError("no ISF is set up yet — add one with isf_ssh --save or the ISF dashboard")
        return default
    if not isinstance(value, str) or value not in names:
        raise ValueError(f"no ISF named {value!r}" + (f" (known: {', '.join(names)})" if names else " — none is set up yet"))
    return value


class _IsfIO:
    """Same send()/recv()/set_timeout()/close() shape as _TunnelIO, over one ISF data tunnel (a
    ztr_isf_client.DataTunnel): bytes in, encrypted frames to the ISF, which bridges them to the site.
    recv() hands back the decrypted stream like a socket would, so _TLSTunnel and the HTTP reader
    above don't know the difference."""

    def __init__(self, tunnel, isf_error):
        self._t = tunnel
        self._isf_error = isf_error
        self._buf = bytearray()
        self._eof = False

    def send(self, data: bytes, for_exit: bool = True) -> None:
        # for_exit is a hop-chain concern (hiding the target from entry/middle hops). Here the site is only ever
        # named inside the end-to-end encrypted ISF channel, so there is nothing for the exit to be shown.
        try:
            self._t.send_data(data)
        except (OSError, TunnelError, self._isf_error) as e:
            raise NetworkError(f"failed to send through the ISF tunnel: {e}") from e

    def recv(self, nbytes: int) -> bytes:
        while not self._buf and not self._eof:
            try:
                ftype, data = self._t.recv()
            except socket.timeout:
                raise NetworkError("read timed out")
            except (OSError, TunnelError, self._isf_error) as e:
                raise NetworkError(f"connection through the ISF dropped: {e}") from e
            if ftype == 0:  # data frame
                self._buf += data
            else:           # FIN or ERR: the site (or the ISF) ended the stream
                self._eof = True
        out = bytes(self._buf[:nbytes])
        del self._buf[:nbytes]
        return out

    @property
    def _sock(self):
        """The data tunnel's socket. ztr_proxy shuts it down to wake a thread blocked in recv() (close() alone
        doesn't), the same as it does for a _TunnelIO's socket."""
        return self._t._sock

    def set_timeout(self, seconds) -> None:
        self._t.set_timeout(seconds)

    def close(self) -> None:
        try:
            self._t.send_fin()
        except Exception:
            pass
        self._t.close()


def _dn_to_dict(rdn_sequence) -> dict:
    """ssl's getpeercert() represents a distinguished name (subject/issuer)
    as ((("commonName", "x"),), (("organizationName", "y"),), ...) — RDNs
    of attribute/value pairs, occasionally with more than one pair in an
    RDN. Flattened here into a plain {attribute: value} dict, which is all
    a subject/issuer display ever actually needs."""
    out = {}
    for rdn in rdn_sequence or ():
        for key, value in rdn:
            out[key] = value
    return out


def _extract_tls_info(ssl_obj: ssl.SSLObject) -> dict:
    """Negotiated protocol/cipher plus — when the handshake actually
    validated one, i.e. verify wasn't disabled — the peer certificate's
    own details. getpeercert() returns {} under verify=False (CERT_NONE):
    that's an ssl module limitation, not a bug here, so `certificate`
    just stays absent in that case rather than raising."""
    cipher = ssl_obj.cipher()
    info = {
        "protocol": ssl_obj.version(),
        "cipher": {"name": cipher[0], "protocol": cipher[1], "secret_bits": cipher[2]} if cipher else None,
        "certificate": None,
    }

    cert = ssl_obj.getpeercert()
    if not cert:
        return info

    subject = _dn_to_dict(cert.get("subject"))
    issuer = _dn_to_dict(cert.get("issuer"))
    info["certificate"] = {
        "subject": subject,
        "subject_cn": subject.get("commonName"),
        "issuer": issuer,
        "issuer_cn": issuer.get("commonName"),
        "issuer_o": issuer.get("organizationName"),
        "serial_number": cert.get("serialNumber"),
        "version": cert.get("version"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [value for (kind, value) in cert.get("subjectAltName", ()) if kind == "DNS"],
    }
    return info


def _extract_route_info(client: RelayClient) -> dict:
    """The configured ZTRelay hop chain this request's tunnel actually
    ran through — sourced from the route file itself (client.config
    ["chain"]), not a network round trip, so it's always available and
    always accurate to what was actually authorized hop-by-hop. Each
    hop's pubkey is dropped (a large PEM blob, not useful for display)."""
    chain = (client.config or {}).get("chain") or []
    hops = [
        {"hop": hop.get("hop"), "role": hop.get("role"), "address": hop.get("address"), "status": hop.get("status")}
        for hop in chain
    ]
    info = {
        "entry_hop": client.entry_hop,
        "entry_port": client.PORT,
        "exit_hop": client.exit_hop,
        "hops": hops,
    }
    isf = getattr(client, "isf_info", None)  # set only for connections made with isf=
    if isf:
        info["isf"] = dict(isf)
    return info


class _TLSTunnel:
    """Drives TLS by hand over a _TunnelIO via ssl.MemoryBIO — see this
    module's docstring, point 2. Exposes the same send()/recv()/
    set_timeout() shape as _TunnelIO so the HTTP layer above doesn't need
    to know which one it's actually talking to."""

    def __init__(self, io: _TunnelIO, server_hostname: str, ssl_context: ssl.SSLContext = None):
        self._io = io
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        context = ssl_context or ssl.create_default_context()
        self._obj = context.wrap_bio(self._incoming, self._outgoing, server_hostname=server_hostname)
        self.tls_info = None
        self._handshaking = True
        self._handshake()

    def _flush(self) -> None:
        pending = self._outgoing.read()
        if pending:
            # Only the handshake needs the exit-hop wrapper: it's where the
            # ClientHello's SNI (the target's hostname) goes out in the
            # clear, and it's every handshake flush, not just the first —
            # a TLS 1.3 HelloRetryRequest makes the client send a second
            # ClientHello with the SNI again. After it, everything this
            # object writes is a TLS application-data record, already
            # ciphertext to any hop, so wrapping it again would only cost
            # a signature here and a decrypt + verify at the exit per chunk.
            # This is known from where we are in our own handshake, not
            # inferred by inspecting the bytes.
            self._io.send(pending, for_exit=self._handshaking)

    def _fill(self) -> None:
        chunk = self._io.recv(65536)
        if not chunk:
            raise NetworkError("connection closed during TLS handshake/read")
        self._incoming.write(chunk)

    def _handshake(self) -> None:
        while True:
            try:
                self._obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                self._flush()
                self._fill()
            except ssl.SSLWantWriteError:
                self._flush()
        self._flush()  # the client's own last handshake flight (Finished) — still handshake
        self._handshaking = False
        self.tls_info = _extract_tls_info(self._obj)

    def send(self, data: bytes) -> None:
        self._obj.write(data)
        self._flush()

    def recv(self, nbytes: int) -> bytes:
        while True:
            try:
                return self._obj.read(nbytes)
            except ssl.SSLWantReadError:
                self._fill()
            except ssl.SSLZeroReturnError:
                return b""

    def set_timeout(self, seconds) -> None:
        self._io.set_timeout(seconds)

    def close(self) -> None:
        self._io.close()


def _decode_body_chunks(raw_chunks, content_encoding: str):
    """Wraps a raw (still content-encoded) chunk generator, decompressing
    incrementally so a streamed response never has to be buffered whole
    just to gzip-decode it."""
    if content_encoding == "gzip":
        decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
    elif content_encoding == "deflate":
        decompressor = zlib.decompressobj()
    else:
        decompressor = None

    for chunk in raw_chunks:
        if decompressor is None:
            yield chunk
        else:
            data = decompressor.decompress(chunk)
            if data:
                yield data
    if decompressor is not None:
        tail = decompressor.flush()
        if tail:
            yield tail


class Response:
    def __init__(self, status_code: int, reason: str, headers: dict, cookies: dict = None):
        self.status_code = status_code
        self.reason = reason
        self.headers = headers
        self.cookies = cookies or {}
        self.set_cookie_headers = []  # each Set-Cookie header's full raw value
                                       # (name=value plus attributes), for
                                       # anything that needs more than the
                                       # bare value .cookies keeps
        self.url = None
        self.history = []
        self.request_headers = {}  # the exact headers sent on the wire for
                                    # this response's own request — including
                                    # anything Session added itself (a Cookie
                                    # header from its jar, the default
                                    # User-Agent, Content-Length), not just
                                    # what the caller passed in
        self.tls_info = None  # protocol/cipher/peer certificate — see
                               # _extract_tls_info; None for a plain http://
                               # request, which never negotiates TLS at all
        self.route_info = None  # the configured ZTRelay hop chain this
                                 # request's tunnel actually ran through —
                                 # see _extract_route_info
        self._content = None  # bytes once fully known; None means not (yet) drained
        self._body_chunks = None  # decoded-chunk generator, set only for stream=True responses
        self._discard = None  # closes this response's connection outright
                               # instead of pooling it — see abort()

    def abort(self) -> None:
        """For when headers alone were enough to decide you don't want
        this body at all (e.g. it turned out to be a large video you're
        about to fetch through something else instead) — closes the
        underlying connection for real rather than draining it first.
        iter_content()/close() drain fully specifically so the connection
        can go back in the Session's pool afterward; a body abandoned
        partway through can never be safely pooled (the next request
        would read this one's leftover bytes), so abort() always closes
        it instead, even for a keep-alive-capable target."""
        if self._discard is not None:
            self._discard()
            self._discard = None
        self._body_chunks = None
        if self._content is None:
            self._content = b""

    def iter_content(self, chunk_size=None):
        """Yields decoded body chunks as they arrive off the wire. Sizes
        follow whatever the network/decompressor produced naturally —
        `chunk_size` isn't reshaped to match, to avoid an extra buffering
        pass that nothing here needs. Safe to call more than once; later
        calls just replay the now-fully-buffered content."""
        if self._content is not None:
            yield self._content
            return
        parts = []
        for chunk in self._body_chunks:
            parts.append(chunk)
            yield chunk
        self._content = b"".join(parts)
        self._body_chunks = None

    @property
    def content(self) -> bytes:
        if self._content is None:
            for _ in self.iter_content():
                pass
        return self._content

    @property
    def text(self) -> str:
        charset = "utf-8"
        content_type = self.headers.get("content-type", "")
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
        return self.content.decode(charset, errors="replace")

    def json(self):
        return _json.loads(self.text)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    def raise_for_status(self) -> None:
        if not self.ok:
            raise HTTPProtocolError(f"{self.status_code} {self.reason}")

    def close(self) -> None:
        """Drains and releases the underlying connection. Only meaningful
        for a stream=True response that wasn't fully iterated — a
        non-streamed response is already fully read."""
        for _ in self.iter_content():
            pass

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"


class _HTTPReader:
    """Reads one HTTP/1.1 response off an io-like object (a _TunnelIO or
    _TLSTunnel — anything with recv(nbytes)). Split into read_headers()
    and iter_raw_body() so a caller can inspect the status/headers (e.g.
    to follow a redirect) before deciding whether to buffer the body
    eagerly or hand back a lazy iterator for it."""

    def __init__(self, io):
        self._io = io
        self._buf = bytearray()

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self._buf:
            chunk = self._io.recv(4096)
            if not chunk:
                break
            self._buf.extend(chunk)
        idx = self._buf.find(marker)
        if idx == -1:
            result, self._buf[:] = bytes(self._buf), bytearray()
            return result
        result = bytes(self._buf[:idx])
        del self._buf[: idx + len(marker)]
        return result

    def _read_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._io.recv(4096)
            if not chunk:
                break
            self._buf.extend(chunk)
        result = bytes(self._buf[:n])
        del self._buf[:n]
        return result

    def read_headers(self):
        header_blob = self._read_until(b"\r\n\r\n")
        if not header_blob:
            raise HTTPProtocolError("connection closed before any response headers arrived")
        lines = header_blob.split(b"\r\n")
        status_line = lines[0].decode("iso-8859-1", errors="replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].isdigit():
            raise HTTPProtocolError(f"malformed status line: {status_line!r}")
        http_version = parts[0]
        status_code = int(parts[1])
        reason = parts[2] if len(parts) > 2 else ""

        # Set-Cookie can't be comma-joined like other repeated headers —
        # commas appear inside its own Expires attribute — so it's pulled
        # out instead of folded into the headers dict. `cookies` is the
        # plain name->value jar (what Session actually sends back on the
        # next request); `set_cookie_headers` keeps each full raw line
        # (attributes included — Path, HttpOnly, Secure, SameSite, ...)
        # for a caller that needs more than just the value.
        cookies = {}
        set_cookie_headers = []
        headers = {}
        for line in lines[1:]:
            if b":" not in line:
                continue
            name, _, value = line.partition(b":")
            name = name.decode("iso-8859-1").strip().lower()
            value = value.decode("iso-8859-1").strip()
            if name == "set-cookie":
                set_cookie_headers.append(value)
                cname, _, crest = value.partition("=")
                cookies[cname.strip()] = crest.split(";", 1)[0].strip()
                continue
            headers[name] = headers[name] + ", " + value if name in headers else value

        return http_version, status_code, reason, headers, cookies, set_cookie_headers

    def iter_raw_body(self, http_version, status_code, headers, has_body):
        """Yields raw (still content-encoded) body chunks per whichever
        framing the response declares — Content-Length, chunked
        Transfer-Encoding, or close-terminated."""
        if not has_body or status_code in (204, 304) or 100 <= status_code < 200:
            return

        transfer_encoding = headers.get("transfer-encoding", "").lower()
        content_length = headers.get("content-length")

        if transfer_encoding == "chunked":
            while True:
                size_line = self._read_until(b"\r\n").split(b";", 1)[0]
                try:
                    size = int(size_line, 16)
                except ValueError:
                    raise HTTPProtocolError(f"malformed chunk size: {size_line!r}")
                if size == 0:
                    # After the last chunk comes a trailer section: zero or
                    # more header lines, ended by an empty line. Read it line
                    # by line until that empty line. Waiting for "\r\n\r\n"
                    # instead only works when there's at least one trailer —
                    # in the normal no-trailer case just a single "\r\n" is
                    # left, so on a keep-alive connection (nothing closes the
                    # socket) that read would block until the timeout.
                    while self._read_until(b"\r\n"):
                        pass
                    break
                chunk = self._read_exact(size)
                self._read_exact(2)  # the \r\n after each chunk's data
                if chunk:
                    yield chunk
        elif content_length is not None:
            try:
                remaining = int(content_length)
            except ValueError:
                raise HTTPProtocolError(f"malformed Content-Length: {content_length!r}")
            if self._buf:
                take = bytes(self._buf[:remaining])
                del self._buf[: len(take)]
                remaining -= len(take)
                if take:
                    yield take
            while remaining > 0:
                chunk = self._io.recv(min(65536, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
        else:
            conn_header = headers.get("connection", "").lower()
            will_close = conn_header == "close" or (http_version == "HTTP/1.0" and conn_header != "keep-alive")
            if not will_close:
                raise HTTPProtocolError(
                    "response has no Content-Length or chunked Transfer-Encoding, and doesn't "
                    "declare Connection: close — can't safely determine where the body ends"
                )
            if self._buf:
                yield bytes(self._buf)
                self._buf.clear()
            while True:
                chunk = self._io.recv(4096)
                if not chunk:
                    break
                yield chunk


def _build_multipart(fields: dict, files: dict) -> tuple:
    """Builds a multipart/form-data body. `files` values are either raw
    bytes/str (filename defaults to the field name) or a
    (filename, content, content_type) tuple; a file-like object for
    `content` is read() in full — this module has no streaming-upload
    path, matching its buffered-response default."""
    boundary = "ztr-http-" + secrets.token_hex(16)
    parts = []

    for name, value in (fields or {}).items():
        value_bytes = value if isinstance(value, (bytes, bytearray)) else str(value).encode("utf-8")
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8")
            + value_bytes + b"\r\n"
        )

    for name, fileinfo in (files or {}).items():
        if isinstance(fileinfo, (tuple, list)):
            filename = fileinfo[0]
            content = fileinfo[1]
            content_type = fileinfo[2] if len(fileinfo) > 2 else "application/octet-stream"
        else:
            filename, content, content_type = name, fileinfo, "application/octet-stream"
        if hasattr(content, "read"):
            content = content.read()
        if isinstance(content, str):
            content = content.encode("utf-8")
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            f'Content-Type: {content_type}\r\n\r\n'.encode("utf-8")
            + content + b"\r\n"
        )

    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), boundary


def _build_request(method: str, path: str, host: str, headers: dict, body: bytes):
    """Returns (request_bytes, sent_headers) — sent_headers is the fully
    defaulted dict (User-Agent, Content-Length included) so a caller can
    show/log exactly what went out, not just what it originally passed in."""
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    hdrs = dict(headers or {})
    hdrs.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36")
    # No forced "Connection: close" — HTTP/1.1 already defaults to
    # keep-alive when the header's absent, and Session reuses the
    # connection across calls to the same origin whenever the target
    # allows it (see Session.request's handling of the response's own
    # Connection header). Pass headers={"Connection": "close"} yourself if
    # you specifically want the target to end the connection after one
    # response.
    # Always computed from the body actually being sent on THIS call, never
    # trusted from the caller's own headers dict — a caller can easily be
    # holding a stale Content-Length (e.g. a webservice composer that
    # reloaded a saved/history entry's headers, or a $$QF$$ batch run whose
    # body differs per line) that no longer matches the real body length,
    # which would send a request the target either rejects outright or
    # truncates/hangs reading.
    for stale_key in [k for k in hdrs if k.lower() == "content-length"]:
        del hdrs[stale_key]
    if body:
        hdrs["Content-Length"] = str(len(body))
    for name, value in hdrs.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("utf-8") + (body or b""), hdrs


class Session:
    """Holds tunnel/TLS state per origin (scheme, host, port), so repeat
    requests to the same target reuse the same authorized tunnel and TLS
    connection instead of re-authorizing and re-handshaking every call.
    A different origin transparently opens (and authorizes) its own.

    `timeout` is the default per-read timeout (seconds) applied to every
    request unless overridden per-call. `verify` is True (default OS
    trust store), False (disable certificate validation — only for
    talking to something you already trust out-of-band), or a path to a
    CA bundle. `cert` is a client certificate: a path, or a
    (certfile, keyfile) tuple. `with_timing_defense` turns on the hops'
    own jitter/decoy traffic for every tunnel this Session opens — a
    routing-layer property of the tunnel itself (see RelayClient.
    with_timing_defense), transparent to the actual HTTP bytes, so it's
    safe for a real internet target the same way it is for a ZTR-aware
    one. Deliberately not offering with_encryption() here the same way:
    that end-to-end-encrypts the payload for a ZTR-aware endpoint to
    decrypt on the other end (e.g. ztr_requests.py) — turning it on for
    an arbitrary HTTPS target would hand it an encrypted blob instead of
    a TLS handshake, breaking the request outright. `entry_port` pins
    every tunnel this Session opens to one lane of the entry hop (it has
    to be one of the route's hop_settings.services_ports); None, the
    default, picks the least-used lane per new connection.

    `isf` sends every connection through one of your own ISFs instead of
    having the exit hop connect to the site: a name from your ISF list,
    True for the default one, or an already-built ztr_isf_client.Target.
    `config_file` is then optional — it overrides that ISF's route for this
    Session. `entry_port` is ignored with an ISF (the route's lane is picked
    per connection). See the module docstring.
    """

    def __init__(
        self,
        config_file: str = None,
        ttl: int = 86400,
        timeout: float = 30,
        verify=True,
        cert=None,
        with_timing_defense: bool = False,
        entry_port: int = None,
        isf=None,
    ):
        if config_file is None and not isf:
            raise ValueError("config_file is required unless isf= is given")
        self._isf = isf if isf else None  # a name, True, or a Target; None = the exit hop connects to the site
        self._isf_target = None
        self._config_file = config_file
        self._ttl = ttl
        self._timeout = timeout
        self._verify = verify
        self._cert = cert
        self._with_timing_defense = with_timing_defense
        self._entry_port = entry_port
        self._connections = {}  # (scheme, host, port) -> (io_or_tls, RelayClient)
        self._cookies = {}  # hostname -> {name: value} — exact-host match only, no
                             # Domain=/Path= attribute matching (Set-Cookie carries
                             # those, but nothing here needs cross-subdomain sharing yet)

    def _make_ssl_context(self) -> ssl.SSLContext:
        if self._verify is False:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context = ssl.create_default_context()
            if isinstance(self._verify, str):
                context.load_verify_locations(self._verify)
        if self._cert:
            if isinstance(self._cert, (tuple, list)):
                context.load_cert_chain(*self._cert)
            else:
                context.load_cert_chain(self._cert)
        return context

    def _open_connection(self, scheme: str, domain: str, port: int, fresh: bool = False):
        # fresh=True forces a brand-new authorization, bypassing (and replacing)
        # the saved one in tunnel_cache.db. The recovery path uses it: a tunnel
        # that dies before a single byte comes back is usually a saved session the
        # hops have already expired, so re-reading the same cached session would
        # just reopen the same dead tunnel. See ProxySession.reopen_fresh.
        # domain goes to RelayClient exactly as given, never resolved here
        # — see this module's own docstring for why. The exit hop resolves
        # it itself, over the registry, so no DNS lookup for this target
        # ever happens outside the tunnel.
        # entry_port None = let RelayClient pick the least-used lane
        # itself; a number pins every tunnel this Session opens to that
        # lane of the entry hop (and so to that lane's one cached
        # authorization, instead of one per lane).
        if self._isf is not None:
            return self._open_isf_connection(scheme, domain, port)
        client = RelayClient(target_host=domain, port=self._entry_port, config_file=self._config_file)
        if self._entry_port is not None:
            lanes = client.settings("services_ports")[client.transport_type]
            if self._entry_port not in lanes:
                raise TunnelError(
                    f"entry port {self._entry_port} isn't one of this route's lanes {lanes} — "
                    f"the entry hop isn't listening on it"
                )
        client.set_target_port(port)
        if self._with_timing_defense:
            client.with_timing_defense()

        result = client.set_tunnel(ttl=self._ttl, native=False, reset=fresh)
        if not result or not result.get("status"):
            raise TunnelError(f"tunnel authorization failed for {domain}:{port}: {result}")

        sock = socket.create_connection((client.entry_hop, client.PORT), timeout=15)
        io = _TunnelIO(sock, client)
        if scheme == "https":
            conn = _TLSTunnel(io, server_hostname=domain, ssl_context=self._make_ssl_context())
        else:
            conn = io
        return conn, client

    def _open_isf_connection(self, scheme: str, domain: str, port: int):
        """One connection through the ISF: create a single-use session for domain:port over the ISF's control
        channel, open its encrypted data tunnel, then (https) run TLS with the site over it. The domain is
        handed to the ISF as given and resolved there — never here, never by the exit hop."""
        C = _load_isf_client()
        if self._isf_target is None:
            if isinstance(self._isf, (str, bool)):
                try:
                    self._isf_target = C.target_for(self._isf if isinstance(self._isf, str) else None, route=self._config_file,
                                                    timing_defense=self._with_timing_defense, zdir=_ZTR_CLIENT_DIR)
                except C.IsfError as e:
                    raise TunnelError(f"ISF: {e}") from e
            else:
                self._isf_target = self._isf  # an already-built Target
        t = self._isf_target
        name = getattr(t, "name", None) or t.host
        dest = f"{domain}:{port}"
        try:
            made = t.control().call("create", destination=dest, ttl=60, label="ztr_https")
            tunnel = C.DataTunnel(t.relay_factory(), t.host, t.data_port, bytes.fromhex(made["session_id"]),
                                  C._b64d(made["key"]), ttl=self._ttl, io_timeout=15)
            tunnel.open()
        except C.IsfError as e:
            hint = " (add it to the ISF's allowlist: the dashboard's Allowlist panel, or ztr_isf_client.py ctrl allow-add)" if "allowlist" in str(e) else ""
            raise TunnelError(f"via ISF {name!r} to {dest}: {e}{hint}") from e
        io = _IsfIO(tunnel, C.IsfError)
        relay = tunnel.relay
        relay.isf_info = {"name": getattr(t, "name", None), "host": t.host, "destination": dest, "session_id": made["session_id"]}
        try:
            conn = _TLSTunnel(io, server_hostname=domain, ssl_context=self._make_ssl_context()) if scheme == "https" else io
        except Exception:
            io.close()  # a failed handshake (e.g. an untrusted certificate) must not leave the ISF session open
            raise
        return conn, relay

    def _cookie_header_for(self, hostname):
        jar = self._cookies.get(hostname)
        if not jar:
            return None
        return "; ".join(f"{name}={value}" for name, value in jar.items())

    def _store_cookies(self, hostname, cookies):
        if not cookies:
            return
        self._cookies.setdefault(hostname, {}).update(cookies)

    def _do_request(self, key, method: str, request_bytes: bytes, timeout, want_stream: bool):
        conn, client = self._connections.pop(key, (None, None))
        if conn is None:
            conn, client = self._open_connection(*key)
        conn.set_timeout(timeout if timeout is not None else self._timeout)

        def attempt():
            conn.send(request_bytes)
            reader = _HTTPReader(conn)
            http_version, status_code, reason, resp_headers, cookies, set_cookie_headers = reader.read_headers()
            raw_chunks = reader.iter_raw_body(http_version, status_code, resp_headers, has_body=(method != "HEAD"))
            decoded_chunks = _decode_body_chunks(raw_chunks, resp_headers.get("content-encoding", "").lower())
            if want_stream:
                return status_code, reason, resp_headers, cookies, set_cookie_headers, decoded_chunks, None
            return status_code, reason, resp_headers, cookies, set_cookie_headers, None, b"".join(decoded_chunks)

        try:
            result = attempt()
        except (TunnelError, OSError, ConnectionError, NetworkError):
            # Most likely a stale pooled connection the target already
            # closed on its end (or a one-off read timeout) — drop it and
            # retry once on a fresh connection rather than surfacing pool
            # staleness as a confusing error.
            conn.close()
            conn, client = self._open_connection(*key)
            conn.set_timeout(timeout if timeout is not None else self._timeout)
            result = attempt()

        return conn, client, result

    def _release_after_stream(self, conn, client, key, decoded_chunks, close_after):
        try:
            for chunk in decoded_chunks:
                yield chunk
        finally:
            if close_after:
                conn.close()
            else:
                self._connections[key] = (conn, client)

    def _discard_connection(self, conn, key):
        """Response.abort()'s actual work — close conn for real and make
        sure it isn't sitting in the pool. A plain generator .close() on
        _release_after_stream isn't enough on its own: closing a
        generator that was never iterated (the common abort() case —
        headers looked, body never touched) skips its finally block
        entirely, since the frame never started running, so this pool
        eviction has to happen independently of that generator's own
        cleanup rather than relying on it."""
        try:
            conn.close()
        except (OSError, NetworkError):
            pass
        # Only evict if this exact connection is what's pooled under
        # `key` right now — a stream=True response is never pooled ahead
        # of time, but by the time abort() actually runs, a *different*,
        # unrelated request to the same origin may have already pooled
        # its own healthy connection there, which this must not touch.
        if self._connections.get(key, (None, None))[0] is conn:
            self._connections.pop(key, None)

    def _prepare_body(self, hdrs: dict, data, json, files) -> bytes:
        if files:
            fields = data if isinstance(data, dict) else {}
            body, boundary = _build_multipart(fields, files)
            hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            return body
        if json is not None:
            hdrs.setdefault("Content-Type", "application/json")
            return _json.dumps(json).encode("utf-8")
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        if isinstance(data, dict):
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return urlencode(data, doseq=True).encode("utf-8")
        if isinstance(data, str):
            return data.encode("utf-8")
        return None

    def request(
        self,
        method: str,
        url: str,
        headers: dict = None,
        data=None,
        json=None,
        params: dict = None,
        files: dict = None,
        allow_redirects: bool = True,
        max_redirects: int = 10,
        timeout: float = None,
        stream: bool = False,
        port: int = None,
    ) -> Response:
        """stream=True hands back a Response whose body hasn't been read
        yet — iterate response.iter_content() (or call .content/.text/
        .json(), which drain it for you) to actually pull it over the
        tunnel. The connection stays checked out of this Session's pool
        until that finishes (or response.close() is called), so it isn't
        available for reuse by another request to the same origin in the
        meantime. Only usable with a Session you keep open yourself —
        the module-level one-shot request()/get()/post() helpers close
        their Session before a caller could ever iterate, so they refuse
        stream=True outright.

        `port` overrides the port the URL itself implies (or the 443/80
        default) — for a target that isn't listening on the standard
        port for its scheme, without having to spell that out in the URL
        every time. Only applied to the first hop: a redirect to a
        different host carries its own port in its own Location URL, and
        forcing this override onto that host too would usually be wrong."""
        method = method.upper()
        hdrs = dict(headers or {})
        body = self._prepare_body(hdrs, data, json, files)

        current_url = url
        current_method = method
        current_body = body
        current_params = params
        history = []

        for hop in range(max_redirects + 1):
            parts = urlsplit(current_url)
            if parts.scheme not in ("http", "https"):
                raise ValueError(f"unsupported scheme: {parts.scheme!r} (only http/https)")
            if hop == 0 and port is not None:
                target_port = port
            else:
                target_port = parts.port or (443 if parts.scheme == "https" else 80)
            path = parts.path or "/"
            if current_params:
                path += ("&" if parts.query else "?") + urlencode(current_params, doseq=True)
            elif parts.query:
                path += "?" + parts.query

            req_hdrs = dict(hdrs)
            cookie_header = self._cookie_header_for(parts.hostname)
            if cookie_header:
                req_hdrs.setdefault("Cookie", cookie_header)

            key = (parts.scheme, parts.hostname, target_port)
            request_bytes, sent_headers = _build_request(current_method, path, parts.hostname, req_hdrs, current_body)

            conn, client, (status_code, reason, resp_headers, cookies, set_cookie_headers, decoded_chunks, content) = \
                self._do_request(key, current_method, request_bytes, timeout, want_stream=stream)

            self._store_cookies(parts.hostname, cookies)
            close_after = resp_headers.get("connection", "").lower() == "close"
            is_redirect = (
                allow_redirects
                and status_code in (301, 302, 303, 307, 308)
                and "location" in resp_headers
            )

            if is_redirect:
                if decoded_chunks is not None:
                    content = b"".join(decoded_chunks)  # this hop is being discarded either way
                if close_after:
                    conn.close()
                else:
                    self._connections[key] = (conn, client)

                redirect_resp = Response(status_code, reason, resp_headers, cookies)
                redirect_resp.set_cookie_headers = set_cookie_headers
                redirect_resp._content = content
                redirect_resp.url = current_url
                redirect_resp.request_headers = sent_headers
                redirect_resp.tls_info = getattr(conn, "tls_info", None)
                redirect_resp.route_info = _extract_route_info(client)
                redirect_resp.history = list(history)
                history.append(redirect_resp)

                if hop >= max_redirects:
                    raise HTTPProtocolError(f"exceeded max_redirects ({max_redirects})")

                current_url = urljoin(current_url, resp_headers["location"])
                if status_code == 303 or (status_code in (301, 302) and current_method not in ("GET", "HEAD")):
                    current_method = "GET"
                    current_body = None
                    hdrs.pop("Content-Length", None)
                    hdrs.pop("Content-Type", None)
                current_params = None
                continue

            response = Response(status_code, reason, resp_headers, cookies)
            response.set_cookie_headers = set_cookie_headers
            response.url = current_url
            response.request_headers = sent_headers
            response.tls_info = getattr(conn, "tls_info", None)
            response.route_info = _extract_route_info(client)
            response.history = history
            if stream:
                response._body_chunks = self._release_after_stream(conn, client, key, decoded_chunks, close_after)
                response._discard = lambda conn=conn, key=key: self._discard_connection(conn, key)
            else:
                response._content = content
                if close_after:
                    conn.close()
                else:
                    self._connections[key] = (conn, client)
            return response

        raise HTTPProtocolError(f"exceeded max_redirects ({max_redirects})")

    def get(self, url, **kwargs) -> Response:
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs) -> Response:
        return self.request("POST", url, **kwargs)

    def put(self, url, **kwargs) -> Response:
        return self.request("PUT", url, **kwargs)

    def delete(self, url, **kwargs) -> Response:
        return self.request("DELETE", url, **kwargs)

    def head(self, url, **kwargs) -> Response:
        return self.request("HEAD", url, **kwargs)

    def patch(self, url, **kwargs) -> Response:
        return self.request("PATCH", url, **kwargs)

    def close(self) -> None:
        for conn, _client in self._connections.values():
            conn.close()
        self._connections.clear()

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def request(method: str, url: str, config_file: str = None, verify=True, cert=None, with_timing_defense=False, isf=None, **kwargs) -> Response:
    """One-shot convenience — opens a Session, makes one request, closes
    it. For more than one request to the same target, use Session
    directly so the tunnel/TLS connection gets reused. stream=True isn't
    supported here (see Session.request's docstring) — use Session
    directly for that."""
    if kwargs.get("stream"):
        raise ValueError("stream=True needs a Session kept open by the caller — use ztr_https.Session directly")
    with Session(config_file=config_file, verify=verify, cert=cert, with_timing_defense=with_timing_defense, isf=isf) as session:
        return session.request(method, url, **kwargs)


def get(url: str, config_file: str = None, **kwargs) -> Response:
    return request("GET", url, config_file, **kwargs)


def post(url: str, config_file: str = None, **kwargs) -> Response:
    return request("POST", url, config_file, **kwargs)


def put(url: str, config_file: str = None, **kwargs) -> Response:
    return request("PUT", url, config_file, **kwargs)


def delete(url: str, config_file: str = None, **kwargs) -> Response:
    return request("DELETE", url, config_file, **kwargs)


def head(url: str, config_file: str = None, **kwargs) -> Response:
    return request("HEAD", url, config_file, **kwargs)


def patch(url: str, config_file: str = None, **kwargs) -> Response:
    return request("PATCH", url, config_file, **kwargs)
