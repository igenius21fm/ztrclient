"""
ZTR Requests — a web UI for firing one-off HTTP/HTTPS requests straight
through an authorized ZTRelay tunnel to their own real target, using
ztr_https.py underneath. Point it at a route file, compose a request,
hit Send, see the response.

    python3 plugins/ztr_requests/server.py

This app's own HTTP port is local-machine-only by default (127.0.0.1) —
unlike ztr_dashboard.py it isn't meant to be reached over the LAN, since a
request built here can carry this route's real identifier/secret_key-backed
tunnel plus whatever headers/body you type into it. Pass --host to widen
that if you really want to.
"""
import argparse
import base64
import http.server
import io
import json
import os
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
from ztrClient import ZTRClientError, TunnelError, NetworkError  # noqa: E402
from session_manager import SessionManager  # noqa: E402
from history_store import HistoryStore  # noqa: E402
from environment_store import EnvironmentStore  # noqa: E402
from collection_store import CollectionStore  # noqa: E402
from batch_store import BatchStore  # noqa: E402

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
batch = BatchStore()


def _compare_qf_op(actual, op, expected):
    if op == "=":
        return actual == expected
    if op == "!=":
        return actual != expected
    if op == ">=":
        return actual >= expected
    if op == "<=":
        return actual <= expected
    if op == ">":
        return actual > expected
    if op == "<":
        return actual < expected
    return False


def _matches_batch_pred(pred, result):
    kind = pred.get("kind")
    if kind == "code":
        return _compare_qf_op(result.get("status_code"), pred.get("op"), pred.get("value"))
    if kind == "body_contains":
        body = str(result.get("body") or "").lower()
        keywords = pred.get("keywords") or []
        return any(str(kw).lower() in body for kw in keywords)
    if kind == "header":
        resp_headers = result.get("headers") or {}
        lower_headers = {str(k).lower(): v for k, v in resp_headers.items()}
        actual = lower_headers.get(str(pred.get("key") or "").lower())
        op = pred.get("op")
        # = / != keep the existing case-insensitive substring behavior
        # (so headers[content-type]="application/json" still matches a
        # real "application/json; charset=utf-8" response header) — != is
        # just its negation, true when the header is absent too. The
        # ordering operators only make sense numerically, so they parse
        # both sides as numbers and fail closed (no match) if either isn't.
        if op == "=":
            return actual is not None and str(pred.get("value") or "").lower() in str(actual).lower()
        if op == "!=":
            return actual is None or str(pred.get("value") or "").lower() not in str(actual).lower()
        if actual is None:
            return False
        try:
            actual_num = float(actual)
            expected_num = float(pred.get("value"))
        except (TypeError, ValueError):
            return False
        return _compare_qf_op(actual_num, op, expected_num)
    return False


def _matches_batch_spec(result, node):
    """Evaluates the AND/OR/PRED expression tree a $$QF::<...>::om$$ token
    parses to against a response. Kept in exact sync with app.js's
    matchesQFSpec()/matchesQFPred() — the CLIENT does all the parsing
    (tokenizing "code=200 AND headers[key]=something", precedence,
    parens) and sends the already-built tree here as plain JSON; this side
    only ever evaluates it. The *decision* of whether a line gets saved
    still has to happen server-side though, since the client already has
    the (already rendered) response by the time it would know the answer
    — too late to un-send the /api/send call that persists it.
    """
    if not node:
        return False
    node_type = node.get("type")
    if node_type == "AND":
        return all(_matches_batch_spec(result, c) for c in node.get("children") or [])
    if node_type == "OR":
        return any(_matches_batch_spec(result, c) for c in node.get("children") or [])
    if node_type == "PRED":
        return _matches_batch_pred(node.get("pred") or {}, result)
    return False


DEFAULT_TIMEOUT = 30.0


def _parse_timeout(raw):
    """Parses a user-supplied timeout (seconds) from a request payload —
    None/"" (not set) defaults to DEFAULT_TIMEOUT rather than falling
    through to ztr_https.Session's own default, so the "defaults to 30" the
    UI advertises is an explicit, testable fact here, not an implicit
    coincidence of two defaults happening to agree. Raises ValueError for
    anything that isn't a positive number, same shape as the port parsing
    right above every caller of this."""
    if raw in (None, ""):
        return DEFAULT_TIMEOUT
    try:
        value = float(raw)
    except TypeError:
        raise ValueError("timeout must be a number")
    if value <= 0:
        raise ValueError("timeout must be positive")
    return value


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


def send_request(session, method, url, headers, body, port=None, timeout=None):
    started = time.monotonic()
    # stream=True so headers (and therefore Content-Type) are available
    # before any body bytes are pulled through the tunnel — a video body
    # never gets touched at all below (resp.abort()), instead of buffering
    # the whole thing here just to find out what /api/stream was going to
    # fetch a second time anyway.
    resp = session.request(method, url, headers=headers, data=body, port=port, timeout=timeout, stream=True)

    header_map = resp.headers or {}  # ztr_https.Response.headers is already lowercase-keyed
    declared_content_type = header_map.get("content-type", "")
    content_type = declared_content_type
    is_image = content_type.split(";")[0].strip().lower().startswith("image/")
    # No Pillow-equivalent sniff for video — a mislabeled video response
    # just won't be detected as one, same as any other non-image binary
    # body. Trusting the header here is the same tradeoff a <video> tag
    # itself makes.
    is_video = content_type.split(";")[0].strip().lower().startswith("video/")
    sniffed = False

    body_text = None
    body_base64 = None
    is_binary = False
    metadata = None

    if is_video:
        # Headers alone are enough to know this — never pull the body
        # through the tunnel here at all. Real playback goes through
        # /api/stream (GET, Range-aware) instead.
        resp.abort()
    else:
        raw = resp.content  # first access here is what actually drains the tunnel
        if not is_image:
            sniffed_mime = sniff_image_mime(raw)
            if sniffed_mime:
                is_image = True
                sniffed = True
                content_type = sniffed_mime

        if is_image:
            body_base64 = base64.b64encode(raw).decode("ascii")
            metadata = extract_image_metadata(raw)
            if sniffed and metadata is not None:
                # Worth surfacing — a server lying about Content-Type is
                # itself a small data point, not just something to
                # silently paper over.
                metadata["declared_content_type"] = declared_content_type or "(none)"
        else:
            # Decoded strictly here rather than via resp.text, which uses
            # errors="replace" and so would never raise — this app wants a
            # real binary/not-binary distinction, not a body full of
            # U+FFFD.
            charset = "utf-8"
            if "charset=" in declared_content_type:
                charset = declared_content_type.split("charset=", 1)[1].split(";", 1)[0].strip()
            try:
                body_text = raw.decode(charset)
            except (UnicodeDecodeError, LookupError, ValueError):
                is_binary = True

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
        "is_video": is_video,
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
        elif path == "/api/stream":
            self._handle_stream(qs)
        elif path == "/api/batch/runs":
            self._send_json(200, {"runs": batch.list_runs()})
        elif path == "/api/batch/requests":
            run_id = qs.get("run_id", [""])[0]
            if not run_id:
                self._send_json(400, {"ok": False, "error": "run_id is required"})
                return
            self._send_json(200, {"requests": batch.list_requests(run_id)})
        elif path == "/api/batch/request":
            run_id = qs.get("run_id", [""])[0]
            raw_line_index = qs.get("line_index", [""])[0]
            if not run_id or raw_line_index == "":
                self._send_json(400, {"ok": False, "error": "run_id and line_index are required"})
                return
            try:
                line_index = int(raw_line_index)
            except ValueError:
                self._send_json(400, {"ok": False, "error": "line_index must be a number"})
                return
            row = batch.get_request(run_id, line_index)
            if row is None:
                self._send(404, "text/plain", b"not found")
                return
            self._send_json(200, row)
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
                verify=body.get("verify", True) if isinstance(body.get("verify", True), bool) else True,
                cert=(body.get("client_cert") or "").strip() or None,
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
        elif path == "/api/batch/runs":
            run_id = qs.get("run_id", [""])[0]
            if not run_id:
                self._send_json(400, {"ok": False, "error": "run_id is required"})
                return
            batch.delete_run(run_id)
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

        try:
            timeout = _parse_timeout(body.get("timeout"))
        except ValueError:
            self._send_json(400, {"ok": False, "error": "timeout must be a positive number"})
            return
        verify = body.get("verify", True)
        if not isinstance(verify, bool):
            verify = True
        client_cert = (body.get("client_cert") or "").strip() or None

        if not config_file or not url:
            self._send_json(400, {"ok": False, "error": "config_file and url are required"})
            return

        batch_run_id = (body.get("batch_run_id") or "").strip()
        raw_line_index = body.get("batch_line_index")
        batch_line_value = body.get("batch_line_value")
        batch_url_template = body.get("batch_url_template")
        batch_omit_spec = body.get("batch_omit_spec")
        batch_line_index = None
        if batch_run_id:
            try:
                batch_line_index = int(raw_line_index)
            except (TypeError, ValueError):
                self._send_json(400, {"ok": False, "error": "batch_line_index must be a number"})
                return

        session_kwargs = dict(
            config_file=config_file,
            with_timing_defense=with_timing_defense,
            verify=verify,
            cert=client_cert,
        )
        session = sessions.get_or_create(**session_kwargs)

        try:
            result = send_request(session, method, url, headers, req_body, port=port, timeout=timeout)
        except (ZTRClientError, ValueError, OSError) as e:
            # The session's pooled connections may now be wedged (e.g. a
            # cached tunnel authorization went stale) — drop it so the
            # next Send rebuilds from scratch instead of retrying a dead
            # session forever.
            sessions.drop(**session_kwargs)
            self._send_json(502, {"ok": False, "error": str(e), "elapsed_ms": None})
            return

        if batch_run_id:
            # ::om mode (batch_omit_spec set): the client already rendered
            # this response before it could know whether it matched — by
            # then it's too late to un-send the save, so the decision has
            # to happen here, on the same request, before batch.add() ever
            # runs. A non-matching line still ran and still shows in the
            # response panel; it just never gets persisted to Batch.
            if not batch_omit_spec or _matches_batch_spec(result, batch_omit_spec):
                batch.add(
                    batch_run_id,
                    batch_line_index,
                    batch_line_value,
                    method,
                    url,
                    batch_url_template,
                    result.get("request_headers") or headers,
                    req_body,
                    result,
                )
        else:
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

    # Headers relayed from the upstream (tunneled) response straight to
    # the browser, unmodified — everything else (Transfer-Encoding,
    # Connection, Content-Encoding once ztr_https has already transparently
    # decoded it) either doesn't apply to how this server frames its own
    # response or would actively lie about it if passed through.
    _STREAM_PASSTHROUGH_HEADERS = (
        "content-type", "content-length", "content-range",
        "accept-ranges", "cache-control", "etag", "last-modified",
    )

    def _handle_stream(self, qs):
        """GET, not POST+JSON like /api/send — a <video> tag's src has to
        be a plain URL. Streams the response straight through instead of
        buffering it (ztr_https.Session.request(..., stream=True)), and
        forwards Range/If-Range/conditional headers from the browser to
        the upstream target and its status/Content-Range/Accept-Ranges
        back unmodified — that round trip is what makes a <video> tag's
        own seeking work, the same way it would against a plain static
        file URL."""
        url = (qs.get("url", [""])[0]).strip()
        config_file = (qs.get("config_file", [""])[0]).strip()
        with_timing_defense = qs.get("with_timing_defense", ["0"])[0] in ("1", "true", "True")
        raw_port = qs.get("port", [""])[0]
        raw_headers = qs.get("headers", [""])[0]
        raw_timeout = qs.get("timeout", [""])[0]
        verify = qs.get("verify", ["1"])[0] not in ("0", "false", "False")
        client_cert = (qs.get("client_cert", [""])[0]).strip() or None

        if not url or not config_file:
            self._send(400, "text/plain", b"url and config_file are required")
            return

        try:
            port = int(raw_port) if raw_port else None
        except ValueError:
            self._send(400, "text/plain", b"port must be a number")
            return

        try:
            timeout = _parse_timeout(raw_timeout or None)
        except ValueError:
            self._send(400, "text/plain", b"timeout must be a positive number")
            return

        extra_headers = {}
        if raw_headers:
            try:
                extra_headers = json.loads(raw_headers)
            except json.JSONDecodeError:
                self._send(400, "text/plain", b"headers must be JSON")
                return

        # Range/If-Range/conditional headers come from the actual browser
        # request to *this* server (a seek is a fresh GET with its own
        # Range) — layered on top of whatever the composer's own Headers
        # tab asked for, not a substitute for it.
        forward_headers = dict(extra_headers)
        for name in ("Range", "If-Range", "If-Modified-Since", "If-None-Match"):
            value = self.headers.get(name)
            if value:
                forward_headers[name] = value

        session_kwargs = dict(
            config_file=config_file,
            with_timing_defense=with_timing_defense,
            verify=verify,
            cert=client_cert,
        )
        session = sessions.get_or_create(**session_kwargs)

        try:
            resp = session.request("GET", url, headers=forward_headers, port=port, timeout=timeout, stream=True)
        except (ZTRClientError, ValueError, OSError) as e:
            sessions.drop(**session_kwargs)
            self._send(502, "text/plain", str(e).encode("utf-8"))
            return

        self.send_response(resp.status_code)
        for name, value in (resp.headers or {}).items():
            if name.lower() in self._STREAM_PASSTHROUGH_HEADERS:
                self.send_header(name, value)
        self.end_headers()

        try:
            for chunk in resp.iter_content():
                self.wfile.write(chunk)
        except (BrokenPipeError, ConnectionResetError):
            # The browser seeked (aborting this request for a new
            # Range one) or navigated away — not a real error, just stop.
            pass
        finally:
            # Drains whatever's left so the connection can be returned to
            # (or evicted from) the session's pool the same way a normal
            # request's does — on an abort above this may mean fully
            # draining a response nothing downstream still wants, which
            # is a real but bounded cost, not worth a bespoke "just close
            # the socket" path for what this app is sized for.
            try:
                resp.close()
            except (TunnelError, OSError, ConnectionError, NetworkError):
                pass

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


def main():
    parser = argparse.ArgumentParser(description="ZTR Requests — a web UI for sending requests through a ZTRelay tunnel.")
    parser.add_argument("--host", default="127.0.0.1", help="defaults to 127.0.0.1 (local-machine-only) — see module docstring")
    parser.add_argument("--port", type=int, default=8089, help="this app's own HTTP port (default: 8089)")
    args = parser.parse_args()

    # Without this, restarting the server right after stopping it fails
    # with "Address already in use" until the just-closed socket clears
    # TIME_WAIT (up to ~60s) — http.server.HTTPServer sets this same flag
    # by default; plain socketserver.ThreadingTCPServer doesn't.
    socketserver.ThreadingTCPServer.allow_reuse_address = True

    with socketserver.ThreadingTCPServer((args.host, args.port), Handler) as httpd:
        print(f"Webservice running at http://{args.host}:{args.port}/")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
