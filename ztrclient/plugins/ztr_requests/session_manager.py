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

    @staticmethod
    def _key(config_file, with_timing_defense):
        return (config_file, bool(with_timing_defense))

    def get_or_create(self, config_file, with_timing_defense=False):
        key = self._key(config_file, with_timing_defense)
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                session = ztr_https.Session(config_file=config_file, with_timing_defense=with_timing_defense)
                self._sessions[key] = session
            return session

    def drop(self, config_file, with_timing_defense=False):
        """Evicts a cached Session (e.g. after a request against it fails)
        so the next request opens fresh tunnels instead of reusing
        connections that may now be wedged."""
        key = self._key(config_file, with_timing_defense)
        with self._lock:
            session = self._sessions.pop(key, None)
        if session is not None:
            session.close()

    def stats(self):
        """One row per live Session, for the connections panel in the UI."""
        with self._lock:
            items = list(self._sessions.items())
        out = []
        for (config_file, with_timing_defense), session in items:
            origins = [f"{scheme}://{host}:{port}" for (scheme, host, port) in session._connections]
            out.append({
                "config_file": config_file,
                "with_timing_defense": with_timing_defense,
                "origins": origins,
            })
        return out


__all__ = ["SessionManager"]
