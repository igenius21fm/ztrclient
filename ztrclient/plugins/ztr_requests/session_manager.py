"""
Keeps one ztr_https.Session alive per distinct (route, tunnel-option)
combination instead of opening a fresh tunnel on every request — a
Session already reuses its own TCP/TLS connection per origin, but a
request-composer tool that lets you fire request after request at
different origins under the same route still needs that Session object
itself to persist across calls, not get rebuilt (and its own connection
pool thrown away) every time.

Replaces this app's old pool_manager.py (RCWorkers/rc_task against a
separate ztr_requests.py executor) now that requests go straight to
their own target's real host via ztr_https.py instead of through an
executor's target_host/target_port — there's no separate service to
authorize a worker pool against anymore, just the route itself.
"""
import threading

import ztr_https


class SessionManager:
    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()

    # verify/cert are TLS-handshake-level settings (Session-construction
    # only — ztr_https.Session has no per-call override for them the way
    # it does for timeout), so a different verify/cert combination against
    # the same route genuinely needs its own Session, not a shared one
    # that would silently apply the wrong trust settings to it.
    @staticmethod
    def _key(config_file, with_timing_defense, verify=True, cert=None):
        return (config_file, bool(with_timing_defense), verify, cert)

    def get_or_create(self, config_file, with_timing_defense=False, verify=True, cert=None):
        key = self._key(config_file, with_timing_defense, verify, cert)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                session = ztr_https.Session(
                    config_file=config_file,
                    with_timing_defense=with_timing_defense,
                    verify=verify,
                    cert=cert,
                )
                self._sessions[key] = session
            return session

    def drop(self, config_file, with_timing_defense=False, verify=True, cert=None):
        """Evicts a cached Session (e.g. after a request against it fails)
        so the next request opens fresh tunnels instead of reusing
        connections that may now be wedged."""
        key = self._key(config_file, with_timing_defense, verify, cert)
        with self._lock:
            session = self._sessions.pop(key, None)
        if session is not None:
            session.close()

    def stats(self):
        """One row per live Session, for the connections panel in the UI."""
        with self._lock:
            items = list(self._sessions.items())
        out = []
        for (config_file, with_timing_defense, verify, cert), session in items:
            origins = [f"{scheme}://{host}:{port}" for (scheme, host, port) in session._connections]
            out.append({
                "config_file": config_file,
                "with_timing_defense": with_timing_defense,
                "verify": verify,
                # "client_cert", not "cert" — matches the public field name
                # everywhere else in the app (composerState/sendOne/etc), so
                # the connections panel's disconnect button — which just
                # re-POSTs this exact row back to /api/sessions/drop — hits
                # the same key /api/sessions/drop already reads.
                "client_cert": cert,
                "origins": origins,
            })
        return out


__all__ = ["SessionManager"]
