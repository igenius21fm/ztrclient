"""
ZTR Requests — a web UI for firing one-off HTTP/HTTPS requests straight
through an authorized ZTRelay tunnel to their own real target, using
ztr_https.py underneath. Point it at a route file, compose a request,
hit Send, see the response.

    python3 plugins/ztr_requests/server.py

Same host-resolution as ztr_dashboard.py: binds to the dedicated dummy
interface (10.10.15.10, see installer-linux.sh --with-local-ip) if this
machine has one, else falls back to 127.0.0.1 — reachable over the ZTR
tunnel/dummy interface rather than the open LAN by default, which matters
here since a request built in this UI can carry a route's real
identifier/secret_key-backed tunnel plus whatever headers/body you type
into it. Pass --host to override either way.
"""
import argparse
import base64
import http.server
import io
import json
import os
import socket
import socketserver
import sys
import time
from urllib.parse import parse_qs, urlsplit

from PIL import ExifTags, Image
from PIL.TiffImagePlugin import IFDRational

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(SCRIPT_DIR, "static")
PLUGINS_DIR = os.path.dirname(SCRIPT_DIR)

# plugins/ztr_requests/server.py -> plugins -> the ztrclient package dir
# itself (ztrClient.py, apps/, routes/, utils/) — same two-hop-up shape
# ztr_ssh/ztr_forward/etc use from one level shallower.
_ZTR_CLIENT_DIR = os.path.dirname(PLUGINS_DIR)
sys.path.insert(0, _ZTR_CLIENT_DIR)
sys.path.insert(0, os.path.join(_ZTR_CLIENT_DIR, "utils"))
# ztr_https.py lives directly in plugins/, alongside this directory.
sys.path.insert(0, PLUGINS_DIR)

import ztr_https  # noqa: E402
from ztrClient import TunnelError, NetworkError  # noqa: E402
from session_manager import SessionManager  # noqa: E402
from history_store import HistoryStore  # noqa: E402
from environment_store import EnvironmentStore  # noqa: E402
from collection_store import CollectionStore  # noqa: E402

DEFAULT_HOST_CANDIDATE = "10.10.15.10"
FALLBACK_HOST = "127.0.0.1"

ROUTES_DIR = os.path.join(_ZTR_CLIENT_DIR, "routes")
_STATIC_CONTENT_TYPES = {
    ".css": "text/css",
    ".js": "application/javascript",
    ".map": "application/json",
    ".html": "text/html; charset=utf-8",
}

sessions = SessionManager()
history = HistoryStore()
environment = EnvironmentStore()
collection = CollectionStore()


def list_route_files():
    if not os.path.isdir(ROUTES_DIR):
        return []
    return sorted(f for f in os.listdir(ROUTES_DIR) if f.endswith(".ztr"))


def _json_safe(value):
    """EXIF values come back as a mix of int/str/bytes/tuple and Pillow's
    own IFDRational — none of which but the first two survive json.dumps
    as-is, so normalize everything to something JSON can actually carry."""
    if isinstance(value, IFDRational):
        return float(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip("\x00").strip()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (int, float, str, bool)) or value is None:
        return value
    return str(value)


def _gps_to_decimal(gps_info):
    """(degrees, minutes, seconds) + a hemisphere ref -> a single signed
    decimal-degrees float — what every map/geocoder actually wants, instead
    of the DMS tuples EXIF stores GPS coordinates as."""
    def to_deg(dms):
        d, m, s = (float(x) for x in dms)
        return d + m / 60 + s / 3600

    lat = lon = None
    if gps_info.get("GPSLatitude") and gps_info.get("GPSLatitudeRef"):
        lat = to_deg(gps_info["GPSLatitude"])
        if str(gps_info["GPSLatitudeRef"]).upper().startswith("S"):
            lat = -lat
    if gps_info.get("GPSLongitude") and gps_info.get("GPSLongitudeRef"):
        lon = to_deg(gps_info["GPSLongitude"])
        if str(gps_info["GPSLongitudeRef"]).upper().startswith("W"):
            lon = -lon
    return lat, lon


_PIL_FORMAT_TO_MIME = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "GIF": "image/gif",
    "WEBP": "image/webp",
    "BMP": "image/bmp",
    "TIFF": "image/tiff",
    "ICO": "image/x-icon",
}


def sniff_image_mime(raw_bytes):
    """Content-Type lies sometimes — a misconfigured server or CDN serving
    real image bytes under text/html, application/octet-stream, or nothing
    at all. Rather than trust the header, actually try to decode the body
    as an image and go by that instead when the header didn't already say
    so. img.verify() is a structural check (bad/truncated data raises)
    without decoding pixel data, so this stays cheap even for a response
    that turns out to be ordinary text — Pillow just fails fast on it."""
    if not raw_bytes:
        return None
    try:
        img = Image.open(io.BytesIO(raw_bytes))
        fmt = img.format
        img.verify()
    except Exception as e:
        print(str(e))
        return None
    return _PIL_FORMAT_TO_MIME.get(fmt, f"image/{fmt.lower()}") if fmt else None


def extract_image_metadata(raw_bytes):
    """Basic image info plus decoded EXIF (camera make/model, timestamp,
    software, GPS) — the actual OSINT payoff of a response being an image
    rather than just something to look at. Never raises: a corrupt/odd file
    just means less metadata, not a broken response."""
    try:
        img = Image.open(io.BytesIO(raw_bytes))
    except Exception:
        return None

    info = {"format": img.format, "mode": img.mode, "width": img.width, "height": img.height}

    try:
        exif = img.getexif()
    except Exception:
        exif = None

    if not exif:
        return info

    # getexif() only walks the main IFD, whose GPSInfo/ExifOffset entries
    # are just pointers (ints) to nested sub-IFDs, not the data itself —
    # both the bulk of "real" EXIF (camera settings, DateTimeOriginal, lens
    # info) and all of GPS live one level down and need their own get_ifd()
    # call to resolve.
    exif_data = {}
    for tag_id, value in exif.items():
        tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
        if tag_name in ("GPSInfo", "ExifOffset"):
            continue
        exif_data[tag_name] = _json_safe(value)

    try:
        for tag_id, value in exif.get_ifd(ExifTags.IFD.Exif).items():
            exif_data[ExifTags.TAGS.get(tag_id, str(tag_id))] = _json_safe(value)
    except (KeyError, AttributeError):
        pass

    gps_info = {}
    try:
        for gps_id, gps_value in exif.get_ifd(ExifTags.IFD.GPSInfo).items():
            gps_info[ExifTags.GPSTAGS.get(gps_id, str(gps_id))] = _json_safe(gps_value)
    except (KeyError, AttributeError):
        pass

    if exif_data:
        info["exif"] = exif_data
    if gps_info:
        info["gps"] = gps_info
        lat, lon = _gps_to_decimal(gps_info)
        if lat is not None and lon is not None:
            info["gps"]["latitude"] = round(lat, 6)
            info["gps"]["longitude"] = round(lon, 6)
            info["gps"]["maps_url"] = f"https://www.google.com/maps?q={lat:.6f},{lon:.6f}"

    return info


def send_request(session, method, url, headers, body, port=None):
    started = time.monotonic()
    resp = session.request(method, url, headers=headers, data=body, port=port)
    elapsed_ms = round((time.monotonic() - started) * 1000, 1)

    # A Set-Cookie can arrive on an intermediate redirect hop rather than
    # the final response (e.g. a "/set-cookie/..." endpoint that 302s
    # straight into showing you the result) — aggregate across the whole
    # chain so one doesn't silently disappear just because a redirect
    # happened along the way.
    all_set_cookies = {}
    all_set_cookie_headers = []
    for hop in list(resp.history) + [resp]:
        all_set_cookies.update(hop.cookies)
        all_set_cookie_headers.extend(hop.set_cookie_headers)

    header_map = resp.headers or {}  # ztr_https.Response.headers is already lowercase-keyed
    declared_content_type = header_map.get("content-type", "")
    content_type = declared_content_type
    is_image = content_type.split(";")[0].strip().lower().startswith("image/")
    sniffed = False

    if not is_image:
        sniffed_mime = sniff_image_mime(resp.content)
        if sniffed_mime:
            is_image = True
            sniffed = True
            content_type = sniffed_mime

    body_text = None
    body_base64 = None
    is_binary = False
    metadata = None

    if is_image:
        body_base64 = base64.b64encode(resp.content).decode("ascii")
        metadata = extract_image_metadata(resp.content)
        if sniffed and metadata is not None:
            # Worth surfacing — a server lying about Content-Type is itself
            # a small data point, not just something to silently paper over.
            metadata["declared_content_type"] = declared_content_type or "(none)"
    else:
        # Decoded strictly here rather than via resp.text, which uses
        # errors="replace" and so would never raise — this app wants a
        # real binary/not-binary distinction, not a body full of U+FFFD.
        charset = "utf-8"
        if "charset=" in declared_content_type:
            charset = declared_content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
        try:
            body_text = resp.content.decode(charset)
        except (UnicodeDecodeError, LookupError, ValueError):
            is_binary = True

    return {
        "ok": resp.ok,
        "status_code": resp.status_code,
        "headers": resp.headers,
        "request_headers": resp.request_headers,
        "set_cookies": all_set_cookies,
        "set_cookie_headers": all_set_cookie_headers,
        "tls_info": resp.tls_info,
        "route_info": resp.route_info,
        "body": body_text,
        "body_base64": body_base64,
        "content_type": content_type,
        "is_image": is_image,
        "metadata": metadata,
        "is_binary": is_binary,
        "error": None,
        "elapsed_ms": elapsed_ms,
    }


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _send(self, status, content_type, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status, data):
        self._send(status, "application/json", json.dumps(data).encode("utf-8"))

    def _path_and_query(self):
        split = urlsplit(self.path)
        return split.path, parse_qs(split.query)

    def do_GET(self):
        path, qs = self._path_and_query()
        if path == "/":
            self._serve_static("index.html")
        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/"):])
        elif path == "/api/routes":
            self._send_json(200, {"routes": list_route_files()})
        elif path == "/api/history":
            limit = int(qs.get("limit", [50])[0])
            self._send_json(200, {"history": history.list(limit)})
        elif path == "/api/sessions":
            self._send_json(200, {"sessions": sessions.stats()})
        elif path == "/api/env":
            self._send_json(200, {"vars": environment.list(), "vars_meta": environment.list_full()})
        elif path == "/api/environments":
            self._send_json(200, {"environments": environment.list_environments()})
        elif path == "/api/collection":
            self._send_json(200, {"items": collection.list()})
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        path, _qs = self._path_and_query()
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            self._send_json(400, {"ok": False, "error": "malformed JSON body"})
            return

        if path == "/api/send":
            self._handle_send(body)
        elif path == "/api/env":
            key = (body.get("key") or "").strip()
            if not key:
                self._send_json(400, {"ok": False, "error": "key is required"})
                return
            environment.set(key, body.get("value") or "", secret=bool(body.get("secret")))
            self._send_json(200, {"ok": True})
        elif path == "/api/environments":
            try:
                env = environment.create_environment(body.get("name") or "")
            except ValueError as e:
                self._send_json(400, {"ok": False, "error": str(e)})
                return
            self._send_json(200, {"ok": True, "environment": env})
        elif path == "/api/environments/activate":
            try:
                environment.set_active_environment(int(body.get("id")))
            except (ValueError, TypeError) as e:
                self._send_json(400, {"ok": False, "error": str(e)})
                return
            self._send_json(200, {"ok": True})
        elif path == "/api/environments/rename":
            try:
                environment.rename_environment(int(body.get("id")), body.get("name") or "")
            except (ValueError, TypeError) as e:
                self._send_json(400, {"ok": False, "error": str(e)})
                return
            self._send_json(200, {"ok": True})
        elif path == "/api/collection":
            entry_id = collection.add(body)
            self._send_json(200, {"ok": True, "id": entry_id})
        elif path == "/api/sessions/drop":
            sessions.drop(
                config_file=(body.get("config_file") or "").strip(),
                with_timing_defense=bool(body.get("with_timing_defense")),
            )
            self._send_json(200, {"ok": True})
        else:
            self._send(404, "text/plain", b"not found")

    def do_DELETE(self):
        path, qs = self._path_and_query()
        if path == "/api/history":
            raw_id = qs.get("id", [""])[0]
            if raw_id:
                try:
                    history.delete(int(raw_id))
                except ValueError:
                    self._send_json(400, {"ok": False, "error": "id must be a number"})
                    return
            else:
                history.clear()
            self._send_json(200, {"ok": True})
        elif path == "/api/env":
            key = qs.get("key", [""])[0]
            if key:
                environment.delete(key)
            self._send_json(200, {"ok": True})
        elif path == "/api/environments":
            try:
                environment.delete_environment(int(qs.get("id", [""])[0]))
            except (ValueError, TypeError) as e:
                self._send_json(400, {"ok": False, "error": str(e)})
                return
            self._send_json(200, {"ok": True})
        elif path == "/api/collection":
            try:
                entry_id = int(qs.get("id", [""])[0])
            except ValueError:
                self._send_json(400, {"ok": False, "error": "id is required"})
                return
            collection.delete(entry_id)
            self._send_json(200, {"ok": True})
        else:
            self._send(404, "text/plain", b"not found")

    def _handle_send(self, body):
        config_file = (body.get("config_file") or "").strip()
        method = (body.get("method") or "GET").strip().upper()
        url = (body.get("url") or "").strip()
        headers = body.get("headers") or {}
        req_body = body.get("body")
        with_timing_defense = bool(body.get("with_timing_defense"))
        raw_port = body.get("port")
        try:
            port = int(raw_port) if raw_port not in (None, "") else None
        except (TypeError, ValueError):
            self._send_json(400, {"ok": False, "error": "port must be a number"})
            return
        if port is not None and not (1 <= port <= 65535):
            self._send_json(400, {"ok": False, "error": "port must be between 1 and 65535"})
            return

        if not config_file or not url:
            self._send_json(400, {"ok": False, "error": "config_file and url are required"})
            return

        session_kwargs = dict(config_file=config_file, with_timing_defense=with_timing_defense)
        session = sessions.get_or_create(**session_kwargs)

        try:
            result = send_request(session, method, url, headers, req_body, port=port)
        except (TunnelError, NetworkError, ztr_https.HTTPProtocolError, ValueError) as e:
            # The session's pooled connections may now be wedged (e.g. a
            # cached tunnel authorization went stale) — drop it so the
            # next Send rebuilds from scratch instead of retrying a dead
            # session forever.
            sessions.drop(**session_kwargs)
            self._send_json(502, {"ok": False, "error": str(e), "elapsed_ms": None})
            return

        history.add({
            "method": method,
            "url": url,
            "config_file": config_file,
            "target_port": port,
            # The exact headers actually sent (includes anything the
            # Session added itself, e.g. a Cookie from its jar) rather
            # than just what the composer had, when that's available.
            "request_headers": result.get("request_headers") or headers,
            "request_body": req_body,
            "ok": result.get("ok"),
            "status_code": result.get("status_code"),
            "response_headers": result.get("headers"),
            "response_body": result.get("body"),
            "error": result.get("error"),
            "elapsed_ms": result.get("elapsed_ms"),
        })
        self._send_json(200, result)

    def _serve_static(self, name):
        # normpath collapses any ../ first; the startswith check afterward
        # is belt-and-suspenders — together they mean this only ever serves
        # a file that resolves to somewhere inside STATIC_DIR.
        path = os.path.abspath(os.path.join(STATIC_DIR, os.path.normpath(name).lstrip(os.sep)))
        if not path.startswith(STATIC_DIR + os.sep) and path != STATIC_DIR:
            self._send(404, "text/plain", b"not found")
            return
        content_type = _STATIC_CONTENT_TYPES.get(os.path.splitext(path)[1])
        if not content_type or not os.path.isfile(path):
            self._send(404, "text/plain", b"not found")
            return
        with open(path, "rb") as f:
            self._send(200, content_type, f.read())


def resolve_host(explicit_host):
    """Same probe ztr_dashboard.py uses: bind a throwaway socket to
    DEFAULT_HOST_CANDIDATE to check whether this machine actually has
    that address (the dummy interface from --with-local-ip) before
    defaulting to it, rather than assuming and failing at real bind
    time with a less obvious error."""
    if explicit_host:
        return explicit_host
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((DEFAULT_HOST_CANDIDATE, 0))
        return DEFAULT_HOST_CANDIDATE
    except OSError:
        return FALLBACK_HOST
    finally:
        probe.close()


def main():
    parser = argparse.ArgumentParser(description="ZTR Requests — a web UI for sending requests through a ZTRelay tunnel.")
    parser.add_argument("--host", default=None, help=f"defaults to {DEFAULT_HOST_CANDIDATE} if this machine has that address, else {FALLBACK_HOST} — see module docstring")
    parser.add_argument("--port", type=int, default=8994, help="this app's own HTTP port (default: 8994)")
    args = parser.parse_args()

    host = resolve_host(args.host)

    # Without this, restarting the server right after stopping it fails
    # with "Address already in use" until the just-closed socket clears
    # TIME_WAIT (up to ~60s) — http.server.HTTPServer sets this same flag
    # by default; plain socketserver.ThreadingTCPServer doesn't.
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    with socketserver.ThreadingTCPServer((host, args.port), Handler) as httpd:
        print(f"Webservice running at http://{host}:{args.port}/")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
