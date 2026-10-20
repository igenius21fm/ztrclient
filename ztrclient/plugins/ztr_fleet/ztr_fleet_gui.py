#!/usr/bin/env python3
"""ZTR Fleet — run commands, scripts and file transfers on several servers at once, each through its own ZTRelay route.

A window for what `ztr_fleet` does on the command line: your servers on the
left, what to run on the right, and every server's answer as it arrives. It
runs a command, a local script, or sends and fetches files; rolls a change out
a few servers at a time and stops if one fails; tries failed servers again;
opens a terminal on any one server; keeps saved commands and a history;
compares what the servers answered; and reads and writes the same fleet.conf
the command line uses.

    python3 plugins/ztr_fleet/ztr_fleet_gui.py            # or: ztr_fleet --gui
    python3 plugins/ztr_fleet/ztr_fleet_gui.py --demo     # pretend servers, nothing is contacted

Needs only Python's standard library (tkinter included, Tk 8.6 or newer),
plus the tunnel service (ztr_tunnel_lp.py) running. Linux and macOS.
The work itself is done by ztr_fleet_core.py, next to this file.
"""
import json
import os
import queue
import re
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import ztr_fleet_core as core  # noqa: E402  (its folders and files are patched through `core` for --demo)
from ztr_fleet_core import (  # noqa: E402
    CONTROL_PORT, DEMO_SERVERS, NAME_RE, ROUTES_DIR, VAR_RE, RESERVED, Server, add_history, batches, default_fleet_path,
    demo_work, describe_job, ferry_servers, group_outputs, job_problems, list_routes, load_fleet, load_history,
    load_snippets, make_job, interpreter_for, results_text, risks, run_job, save_fleet, save_snippet, service_up,
    shell_argv, substitute, terminal_argv, Runner, build_argv, load_hooks, save_hooks, hook_command, hook_argv,
    norm_hook, hook_title, hook_wanted, fix_executable, scan_hooks_folder, create_hook, run_hook, HOOK_TEMPLATES,
    run_summary_hook, summary_payload, collect_followups, followup_targets, load_saved_jobs, save_saved_jobs, norm_saved_job,
    saved_job_problems, saved_job_servers, describe_schedule, norm_schedule, install_schedule, remove_schedule, schedule_status,
    schedule_available, DAYS, DEFAULT_OPTS, job_log_path, route_country, route_label)
try:
    from ztr_flags import FLAGS  # noqa: E402  (small flag images by country code; without them the code is shown instead)
except ImportError:
    FLAGS = {}

APP_NAME = "ZTR Fleet"

BG, CARD, FIELD, BORDER = "#1c1c1e", "#262629", "#1a1a1c", "#3a3a3d"
TEXT, DIM = "#f2f2f7", "#8e8e93"
CYAN, PURPLE, GREEN, RED, AMBER = "#0a84ff", "#bf5af2", "#30d158", "#ff453a", "#ffb340"
SEL, ZEBRA, TEAL = "#0a64d6", "#1f1f21", "#64d2ff"

MODES = (("cmd", "Command"), ("script", "Script"), ("put", "Send files"), ("get", "Fetch files"))
TIMEOUTS = {"15 seconds": 15, "30 seconds": 30, "1 minute": 60, "2 minutes": 120, "5 minutes": 300, "15 minutes": 900, "1 hour": 3600}
BATCHES = {"All at once": 0, "1 at a time": 1, "2 at a time": 2, "3 at a time": 3, "5 at a time": 5, "10 at a time": 10}
PAUSES = {"No pause": 0, "10 seconds": 10, "30 seconds": 30, "1 minute": 60, "5 minutes": 300}
RETRIES = {"No retries": 0, "1 more try": 1, "2 more tries": 2, "3 more tries": 3}


def parse_vars(text):
    """'env=prod region=eu' → ({'env': 'prod', 'region': 'eu'}, a message if something is wrong or None)."""
    found = {}
    for word in text.split():
        name, eq, value = word.partition("=")
        if not eq or not value:
            return {}, "'%s' should look like name=value" % word
        if not VAR_RE.match(name):
            return {}, "'%s' can't be a variable name (letters, digits and _, not starting with a digit)" % name
        if name in RESERVED:
            return {}, "'%s' is already taken (name, route, alias, user, port, key, group)" % name
        found[name] = value
    return found, None


def format_vars(values):
    return " ".join("%s=%s" % kv for kv in sorted(values.items()))


def hook_summary(h):
    """A hook's name with what it is limited to: 'save_ips.sh (web only · when it contains DENY · also on failure)'."""
    bits = []
    if h.get("scope") == "all":
        bits.append("once, at the end")
    if h.get("only"):
        bits.append("%s only" % h["only"].replace(",", ", ").replace("  ", " "))
    if h.get("match"):
        bits.append("when it contains %s" % h["match"])
    if h.get("failed"):
        bits.append("also on failure")
    return hook_title(h) + (" (%s)" % " · ".join(bits) if bits else "")


def open_in_system(path):
    """Opens a file or folder with the computer's own program for it."""
    program = "open" if sys.platform == "darwin" else "xdg-open"
    subprocess.Popen([program, path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def exact_lines(chosen, job, opts):
    """The complete command line Fleet runs for each server, as text. A sudo password is never shown: the line says
    where it would go instead."""
    shown = dict(job)
    if opts.get("sudo") and job["kind"] == "cmd":
        shown["sudo_password"] = "<password>"
        shown.pop("sudo_passwords", None)
    lines = ["The exact commands", "",
             "Each server runs one command: ztr_forward opens a tunnel through that server's route, then runs the bash script "
             "that follows — ssh or scp pointed at the tunnel. bash receives, in order: $1 the server's name, $2 the known-hosts "
             "file, $3 the user, $4 what to run on the server (or the remote path), $5 the ssh key file, $6 the local path.", ""]
    for s in chosen:
        argv, stdin = build_argv(s, shown)
        lines.append("# %s" % s.name)
        lines.append(" ".join(shlex.quote(a) for a in argv))
        if stdin is not None:
            if shown["kind"] == "script":
                lines.append("# standard input: the script (%d lines)" % len(job["text"].splitlines()))
            else:
                lines.append("# standard input: your sudo password for this server (never shown, never saved)")
        for h in opts.get("hooks", []):
            if h.get("scope") == "all":
                continue
            only = [w.strip() for w in h.get("only", "").split(",") if w.strip()]
            if only and s.name not in only and s.group not in only:
                continue
            prefix = hook_command(h["path"])[0] or [h["path"]]
            lines.append("# then, on this computer, for %s's answer%s" % (s.name, (" — only if it contains %s" % h["match"]) if h.get("match") else ""))
            lines.append(" ".join(shlex.quote(a) for a in hook_argv(prefix, s, "ok", "<answer-file>", "<error-file>")))
            lines.append("# standard input: the answer; started without a shell, in the script's own folder")
        lines.append("")
    for h in opts.get("hooks", []):
        if h.get("scope") == "all":
            prefix = hook_command(h["path"])[0] or [h["path"]]
            lines.append("# once the whole run is done, on this computer")
            lines.append(" ".join(shlex.quote(a) for a in prefix + ["--all", "--servers", str(len(chosen)), "--ok", "<n>", "--failed", "<n>", "--results-file", "<results-file>"]))
            lines.append("# standard input: every answer as JSON; started without a shell, in the script's own folder")
            lines.append("")
    return lines[:-1]


def plan_lines(chosen, job, opts):
    """What a run would do, as lines of text: the shape of the run, then each server's part, then anything risky."""
    n = len(chosen)
    lines = []
    plan = batches(chosen, opts.get("batch", 0), opts.get("canary", False))
    shape = "%s on %d server%s" % (describe_job(job), n, "" if n == 1 else "s")
    if len(plan) > 1:
        shape += ", %d at a time%s" % (opts["batch"], " after one trial server" if opts.get("canary") else "")
        if opts.get("stop", True):
            shape += ", stopping if one doesn't succeed"
        if opts.get("pause"):
            shape += ", waiting %ds between batches" % opts["pause"]
    else:
        shape += ", up to %d at once" % opts.get("jobs", 4)
    if opts.get("retries"):
        shape += ", trying a failed server up to %d more time%s" % (opts["retries"], "" if opts["retries"] == 1 else "s")
    lines += [shape + "."]
    if opts.get("hooks"):
        lines.append("Then, on this computer, answers go to: %s." % "; ".join(hook_summary(h) for h in opts["hooks"]))
    lines.append("")
    for index, group in enumerate(plan, 1):
        if len(plan) > 1:
            lines.append("Batch %d" % index)
        for s in group:
            where = "%s via %s as %s" % (s.name, route_label(s.route), s.user)
            if job["kind"] == "cmd":
                what = substitute(job["command"], s)[0]
                if job.get("sudo_password") or job.get("sudo_passwords") or opts.get("sudo"):
                    what += "      (with your sudo password)"
            elif job["kind"] == "script":
                what = "%s, run with %s" % (describe_job(job), interpreter_for(job["text"]).split()[0])
            elif job["kind"] == "put":
                what = "%s → %s" % (job["local"], substitute(job.get("remote") or "", s)[0] or "the login folder")
            else:
                what = "%s → %s" % (substitute(job["remote"], s)[0], Path(job["into"]) / s.name)
            lines.append("  %-30s %s" % (where, what))
    text = job.get("command") or job.get("text") or ""
    serious, notices = risks(text)
    if serious or notices:
        lines.append("")
    lines += ["Careful: it %s." % why for why in serious]
    lines += ["Worth knowing: it %s." % why for why in notices]
    return lines


# The modifier a shortcut uses: Command on a Mac, Control elsewhere.
MOD = "Command" if sys.platform == "darwin" else "Control"


def bind_context_menu(widget, handler):
    """Right-click opens the menu — on a Mac that is also a two-finger click (Button-2) or Control-click."""
    widget.bind("<Button-3>", handler)
    if sys.platform == "darwin":
        widget.bind("<Button-2>", handler)
        widget.bind("<Control-Button-1>", handler)


# ── the window's picture ─────────────────────────────────────────────────────


def build_app():
    """Imported lazily so the helpers above work (and are testable) on a machine whose Python has no tkinter."""
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import ttk


    UI = {}  # fonts, filled in by Shell._style
    _corner_cache = {}

    def _rgb(color):
        color = color.lstrip("#")
        return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))

    def _mix(a, b, t):
        return "#%02x%02x%02x" % tuple(int(round(a[i] * (1 - t) + b[i] * t)) for i in range(3))

    def _bg_of(widget):
        """The colour behind a widget, so rounded corners blend into it."""
        try:
            return widget.cget("bg")
        except (tk.TclError, AttributeError):
            pass
        try:
            style = str(widget.cget("style")) or widget.winfo_class()
            return ttk.Style(widget).lookup(style, "background") or BG
        except (tk.TclError, AttributeError):
            return BG

    def _corner(r, fill, border, outside, which, bw):
        key = (r, fill, border, outside, which, bw)
        img = _corner_cache.get(key)
        if img is not None:
            return img
        f, b, o = _rgb(fill), _rgb(border), _rgb(outside)
        samples, rows = 4, []
        for y in range(r):
            row = []
            for x in range(r):
                outer = inner = 0
                for sy in range(samples):
                    for sx in range(samples):
                        px, py = x + (sx + .5) / samples, y + (sy + .5) / samples
                        u = r - px if which in ("tl", "bl") else px
                        v = r - py if which in ("tl", "tr") else py
                        d = (u * u + v * v) ** .5
                        outer += d <= r
                        inner += d <= r - bw
                total = samples * samples
                co, ci = outer / total, inner / total
                colour = tuple(o[i] * (1 - co) + b[i] * (co - ci) + f[i] * ci for i in range(3))
                row.append("#%02x%02x%02x" % tuple(int(round(c)) for c in colour))
            rows.append("{" + " ".join(row) + "}")
        img = tk.PhotoImage(width=r, height=r)
        img.put(" ".join(rows))
        _corner_cache[key] = img
        return img

    def paint_round(cv, x, y, w, h, r, fill, border, outside, tag, bw=1):
        """Draws a filled rounded rectangle (with a 1px border if border differs from fill) on canvas cv."""
        cv.delete(tag)
        if w <= 0 or h <= 0:
            return
        r = int(max(0, min(r, w // 2, h // 2)))
        if not border or border == fill:
            border, bw = fill, 0
        if r < 2:
            cv.create_rectangle(x, y, x + w, y + h, fill=border if bw else fill, outline="", tags=tag)
            if bw:
                cv.create_rectangle(x + bw, y + bw, x + w - bw, y + h - bw, fill=fill, outline="", tags=tag)
            return
        refs = cv.__dict__.setdefault("_corner_refs", {})
        for which, cx, cy in (("tl", x, y), ("tr", x + w - r, y), ("bl", x, y + h - r), ("br", x + w - r, y + h - r)):
            img = _corner(r, fill, border, outside, which, max(1, bw) if bw else 0)
            refs[(which, r, fill, border, outside)] = img
            cv.create_image(cx, cy, anchor="nw", image=img, tags=tag)
        cv.create_rectangle(x + r, y, x + w - r, y + h, fill=fill, outline="", tags=tag)
        cv.create_rectangle(x, y + r, x + w, y + h - r, fill=fill, outline="", tags=tag)
        if bw:
            cv.create_rectangle(x + r, y, x + w - r, y + bw, fill=border, outline="", tags=tag)
            cv.create_rectangle(x + r, y + h - bw, x + w - r, y + h, fill=border, outline="", tags=tag)
            cv.create_rectangle(x, y + r, x + bw, y + h - r, fill=border, outline="", tags=tag)
            cv.create_rectangle(x + w - bw, y + r, x + w, y + h - r, fill=border, outline="", tags=tag)

    class Card(tk.Frame):
        """A rounded panel. Put children in `.body`."""

        def __init__(self, parent, fill=None, border=None, radius=12, pad=(16, 12), bg=None, style="Card.TFrame"):
            super().__init__(parent, bg=bg or _bg_of(parent), bd=0, highlightthickness=0)
            self._fill = fill or CARD
            self._border = BORDER if border is None else border
            self._radius = radius
            self._bg_fixed = bg
            self.cv = tk.Canvas(self, bd=0, highlightthickness=0, bg=self._fill)
            self.cv.place(x=0, y=0, relwidth=1, relheight=1)
            self.body = ttk.Frame(self, style=style)
            self.body.grid(row=0, column=0, sticky="nsew", padx=pad[0], pady=pad[1])
            self.columnconfigure(0, weight=1)
            self.rowconfigure(0, weight=1)
            self.body.columnconfigure(0, weight=1)
            self.cv.bind("<Configure>", lambda e: self.redraw())
            self.cv.bind("<Map>", lambda e: self.after_idle(self.redraw))

        def redraw(self):
            w, h = self.cv.winfo_width(), self.cv.winfo_height()
            outside = self._bg_fixed or _bg_of(self.master)
            self.configure(bg=outside)
            self.cv.configure(bg=outside)
            paint_round(self.cv, 0, 0, w, h, self._radius, self._fill, self._border, outside, "card")

    # button looks: (fill, text, hover fill, pressed fill, disabled fill, disabled text)
    _BTN = {
        "default": ("#3a3a3d", TEXT, "#454548", "#505054", "#2c2c2f", "#6a6a70"),
        "primary": (CYAN, "#ffffff", "#2f95ff", "#0a74e6", "#1f4d80", "#8fb5e2"),
        "go": ("#12335c", "#69b6ff", "#17427a", "#0d2a4d", "#222c38", "#586a7c"),
        "danger": ("#43262a", "#ff6961", "#53302f", "#35201f", "#2e2627", "#70585a"),
        "ghost": (None, DIM, "#3a3a3d", "#454548", None, "#5a5a60"),
    }

    class Btn(tk.Canvas):
        """A rounded button. Same calls as ttk.Button: text, command, state, style, invoke()."""

        def __init__(self, parent, text="", command=None, style="", state="normal", kind=None, selected=False, **kw):
            kw.pop("width", None)
            super().__init__(parent, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._text, self._command, self._state, self._style = text, command, state, style
            self._kind = kind
            self._selected, self._hover, self._down = selected, False, False
            self._fit()
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<Enter>", lambda e: self._set(hover=True))
            self.bind("<Leave>", lambda e: self._set(hover=False, down=False))
            self.bind("<ButtonPress-1>", lambda e: self._set(down=True))
            self.bind("<ButtonRelease-1>", self._release)
            self.bind("<space>", lambda e: self.invoke())
            self.bind("<Return>", lambda e: self.invoke())

        # -- look
        def _kind_name(self):
            if self._kind:
                return self._kind
            for word, kind in (("Primary", "primary"), ("Go", "go"), ("Danger", "danger"), ("Ghost", "ghost")):
                if word in str(self._style):
                    return kind
            return "default"

        def _small(self):
            return "Small" in str(self._style) or self._kind == "tab"

        def _fit(self):
            bold = self._kind_name() == "primary" or (self._kind == "tab" and self._selected)
            font = UI.get("bold" if bold and not self._small() else ("small" if self._small() else "body"))
            if bold and self._small():
                font = UI.get("bold")
            pad = 12 if self._small() else 16
            h = 26 if self._small() else (32 if self._kind_name() == "primary" else 28)
            w = (font.measure(self._text) if font else 8 * len(self._text)) + 2 * pad
            tk.Canvas.configure(self, width=w, height=h)

        def _colors(self):
            kind = self._kind_name()
            if self._kind == "tab":
                kind = "go" if self._selected else "ghost"
            fill, fg, hover, pressed, off_fill, off_fg = _BTN[kind]
            outside = _bg_of(self.master)
            if self._state == "disabled":
                return (off_fill or outside), off_fg, outside
            col = pressed if self._down else (hover if self._hover else fill)
            return (col or outside), fg, outside

        def _draw(self):
            w, h = self.winfo_width(), self.winfo_height()
            fill, fg, outside = self._colors()
            tk.Canvas.configure(self, bg=outside)
            paint_round(self, 0, 0, w, h, 8, fill, fill, outside, "bg", 0)
            self.delete("label")
            font = UI.get("small" if self._small() else "body")
            bold = UI.get("bold") if (self._kind_name() == "primary" or (self._kind == "tab" and self._selected)) else font
            self.create_text(w // 2, h // 2, text=self._text, fill=fg, font=bold or font, tags="label")

        def _set(self, hover=None, down=None):
            if self._state == "disabled":
                return
            if hover is not None:
                self._hover = hover
            if down is not None:
                self._down = down
            self._draw()

        def _release(self, event):
            was_down, self._down = self._down, False
            self._draw()
            if was_down and self._state != "disabled" and 0 <= event.x <= self.winfo_width() and 0 <= event.y <= self.winfo_height():
                self.invoke()

        # -- the ttk.Button calls the app uses
        def invoke(self):
            if self._state != "disabled" and self._command:
                return self._command()

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            changed = False
            for key in ("text", "state", "style", "command", "selected"):
                if key in opts:
                    attr = "_" + key
                    setattr(self, attr, opts.pop(key))
                    changed = True
            if "state" in kw or (cnf and "state" in cnf):
                tk.Canvas.configure(self, cursor="hand2" if self._state != "disabled" else "arrow")
            if opts:
                tk.Canvas.configure(self, **opts)
            if changed:
                self._fit()
                self._draw()

        config = configure

        def cget(self, key):
            return {"text": self._text, "state": self._state, "style": self._style, "command": self._command}.get(key) \
                if key in ("text", "state", "style", "command") else tk.Canvas.cget(self, key)

    class Check(tk.Canvas):
        """A rounded check box with its label (like ttk.Checkbutton)."""

        def __init__(self, parent, text="", variable=None, command=None, state="normal", **kw):
            super().__init__(parent, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._text, self._var, self._command, self._state = text, variable, command, state
            font = UI.get("body")
            tk.Canvas.configure(self, width=24 + (font.measure(text) if font else 8 * len(text)) + 4, height=24)
            self._trace = variable.trace_add("write", lambda *a: self._draw()) if variable is not None else None
            self.bind("<Destroy>", self._forget_trace)  # the variable outlives the widget when a list is rebuilt
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<ButtonRelease-1>", lambda e: self.invoke())
            self.bind("<space>", lambda e: self.invoke())

        def _forget_trace(self, event):
            if event.widget is self and self._trace is not None:
                try:
                    self._var.trace_remove("write", self._trace)
                except (tk.TclError, ValueError):
                    pass
                self._trace = None

        def _on(self):
            return bool(self._var.get()) if self._var is not None else False

        def _draw(self):
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            on, off = self._on(), self._state == "disabled"
            fill = (CYAN if on else FIELD) if not off else "#2f2f31"
            border = CYAN if on else "#6a6a70"
            self.delete("all")
            paint_round(self, 1, 4, 16, 16, 5, fill, border, outside, "box")
            if on:
                self.create_line(5, 12, 8, 15, 13, 8, fill="#ffffff", width=2, capstyle="round", joinstyle="round", tags="box")
            self.create_text(24, 12, text=self._text, anchor="w", fill=TEXT if not off else DIM, font=UI.get("body"), tags="label")

        def invoke(self):
            if self._state == "disabled" or self._var is None:
                return
            self._var.set(not self._var.get())
            if self._command:
                self._command()

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            for key in ("state", "text", "command", "variable"):
                if key in opts:
                    setattr(self, "_" + {"variable": "var"}.get(key, key), opts.pop(key))
            if opts:
                tk.Canvas.configure(self, **opts)
            self._draw()

        config = configure

        def cget(self, key):
            return self._state if key == "state" else tk.Canvas.cget(self, key)

    class Radio(tk.Canvas):
        """A round radio button with its label (like ttk.Radiobutton)."""

        def __init__(self, parent, text="", value=None, variable=None, command=None, state="normal", **kw):
            super().__init__(parent, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._text, self._value, self._var, self._command, self._state = text, value, variable, command, state
            font = UI.get("body")
            tk.Canvas.configure(self, width=24 + (font.measure(text) if font else 8 * len(text)) + 4, height=24)
            variable.trace_add("write", lambda *a: self._draw())
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<ButtonRelease-1>", lambda e: self.invoke())
            self.bind("<space>", lambda e: self.invoke())

        def _draw(self):
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            on, off = self._var.get() == self._value, self._state == "disabled"
            self.delete("all")
            paint_round(self, 1, 4, 16, 16, 8, CYAN if on else FIELD, CYAN if on else "#6a6a70", outside, "box")
            if on:
                paint_round(self, 6, 9, 6, 6, 3, "#ffffff", "#ffffff", CYAN, "dot", 0)
            self.create_text(24, 12, text=self._text, anchor="w", fill=TEXT if not off else DIM, font=UI.get("body"))

        def invoke(self):
            if self._state == "disabled":
                return
            self._var.set(self._value)
            if self._command:
                self._command()

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            for key in ("state", "text", "command"):
                if key in opts:
                    setattr(self, "_" + key, opts.pop(key))
            if opts:
                tk.Canvas.configure(self, **opts)
            self._draw()

        config = configure

        def cget(self, key):
            return self._state if key == "state" else tk.Canvas.cget(self, key)

    class Progress(tk.Canvas):
        """A slim rounded progress bar (like ttk.Progressbar: mode, value, start(), stop())."""

        def __init__(self, parent, mode="determinate", maximum=100, **kw):
            kw.pop("style", None)
            super().__init__(parent, bd=0, highlightthickness=0, height=8)
            self._mode, self._max, self._value, self._phase, self._job = mode, maximum, 0.0, 0.0, None
            self.bind("<Configure>", lambda e: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))

        def _draw(self):
            w, h = self.winfo_width(), self.winfo_height()
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            paint_round(self, 0, 0, w, h, h // 2, "#1d1d1f", "#1d1d1f", outside, "track", 0)
            if self._mode == "indeterminate":
                seg = max(h, int(w * .28))
                x = int((w + seg) * self._phase) - seg
                x0, x1 = max(0, x), min(w, x + seg)
                if x1 - x0 >= 2:
                    paint_round(self, x0, 0, x1 - x0, h, h // 2, CYAN, CYAN, "#1d1d1f", "fill", 0)
                else:
                    self.delete("fill")
            else:
                fw = int(w * max(0.0, min(1.0, self._value / float(self._max or 1))))
                if fw >= 2:
                    paint_round(self, 0, 0, max(fw, h), h, h // 2, CYAN, CYAN, "#1d1d1f", "fill", 0)
                else:
                    self.delete("fill")

        def configure(self, cnf=None, **kw):
            opts = dict(cnf or {}, **kw)
            for key, attr in (("mode", "_mode"), ("value", "_value"), ("maximum", "_max")):
                if key in opts:
                    setattr(self, attr, opts.pop(key))
            opts.pop("style", None)
            if opts:
                tk.Canvas.configure(self, **opts)
            self._draw()

        config = configure

        def cget(self, key):
            return {"mode": self._mode, "value": float(self._value), "maximum": self._max}.get(key) \
                if key in ("mode", "value", "maximum") else tk.Canvas.cget(self, key)

        def start(self, interval=30):
            self.stop()

            def step():
                self._phase = (self._phase + 0.02) % 1.0
                self._draw()
                self._job = self.after(max(15, int(interval)), step)
            self._job = self.after(0, step)

        def stop(self):
            if self._job is not None:
                self.after_cancel(self._job)
                self._job = None

    class Field(tk.Frame):
        """A rounded text field or drop-down. Behaves like the ttk widget inside it (get, insert, bind, state ...)."""

        is_combo = False

        def __init__(self, parent, combo=False, compact=False, placeholder=None, **kw):
            super().__init__(parent, bg=_bg_of(parent), bd=0, highlightthickness=0)
            self.is_combo = combo
            self._focus = False
            self.cv = tk.Canvas(self, bd=0, highlightthickness=0, bg=FIELD)
            self.cv.place(x=0, y=0, relwidth=1, relheight=1)
            kw.setdefault("style", "Flat.TCombobox" if combo else "Flat.TEntry")
            self.inner = (ttk.Combobox if combo else ttk.Entry)(self, **kw)
            self.inner.grid(row=0, column=0, sticky="ew", padx=(10, 4 if combo else 10), pady=3 if compact else 5)
            self.columnconfigure(0, weight=1)
            self.cv.bind("<Configure>", lambda e: self._draw())
            self.cv.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.inner.bind("<FocusIn>", lambda e: self._focused(True), add="+")
            self.inner.bind("<FocusOut>", lambda e: self._focused(False), add="+")
            self._hint = None
            self._var = kw.get("textvariable")
            if placeholder:  # dim hint text shown while the field is empty and unfocused
                self._hint = tk.Label(self, text=placeholder, bg=FIELD, fg=DIM, font=UI.get("body"), bd=0, padx=0, pady=0)
                self._hint.bind("<Button-1>", lambda e: self.inner.focus_set())
                var = kw.get("textvariable")
                if var is not None:
                    var.trace_add("write", lambda *a: self._show_hint())
                self.inner.bind("<KeyRelease>", lambda e: self._show_hint(), add="+")
                self._show_hint()

        def _show_hint(self):
            if self._hint is None:
                return
            # A variable's write callback runs before the entry itself has the new text, so read the variable when there is one.
            text = self._var.get() if self._var is not None else self.inner.get()
            if text or self._focus:
                self._hint.place_forget()
            else:
                self._hint.place(x=11, rely=0.5, anchor="w")

        def _focused(self, on):
            self._focus = on
            self._show_hint()
            self._draw()

        def _draw(self):
            w, h = self.cv.winfo_width(), self.cv.winfo_height()
            outside = _bg_of(self.master)
            tk.Frame.configure(self, bg=outside)
            self.cv.configure(bg=outside)
            state = str(self.inner.cget("state"))
            border = CYAN if self._focus else ("#2c2c2f" if state == "disabled" else BORDER)
            paint_round(self.cv, 0, 0, w, h, 8, FIELD, border, outside, "field", 1)

        # delegate to the real widget
        def configure(self, cnf=None, **kw):
            res = self.inner.configure(cnf or {}, **kw) if (cnf or kw) else self.inner.configure()
            self._draw()
            return res

        config = configure

        def cget(self, key):
            return self.inner.cget(key)

        def bind(self, sequence=None, func=None, add=None):
            return self.inner.bind(sequence, func, add)

        def focus_set(self):
            self.inner.focus_set()

        def __getattr__(self, name):
            if name in ("inner", "cv"):
                raise AttributeError(name)
            return getattr(self.inner, name)

    def Combo(parent, **kw):
        return Field(parent, combo=True, **kw)


    ROW_CHARS = 40   # how much of "route · user@alias" fits on one line of the server list

    _flag_cache = {}

    def flag_image(code):
        """A small flag (24x18) for a two-letter country code, or None when there isn't one."""
        code = (code or "").upper()
        if code not in FLAGS:
            return None
        if code not in _flag_cache:
            try:
                _flag_cache[code] = tk.PhotoImage(data=FLAGS[code])
            except tk.TclError:
                _flag_cache[code] = None
        return _flag_cache[code]

    def _dialog(parent, title):
        """A rounded modal window centred on `parent`. Returns (window, body frame)."""
        top = parent.winfo_toplevel()
        win = tk.Toplevel(top)
        win.withdraw()
        win.title(title)
        win.configure(bg=BG)
        win.transient(top)
        win.resizable(False, False)
        card = Card(win, radius=14, pad=(22, 18), bg=BG)
        card.pack(padx=14, pady=14, fill="both", expand=True)
        return win, card.body

    def _place(win, parent):
        """Shows a window near the top of `parent`, without blocking it."""
        top = parent.winfo_toplevel()
        win.update_idletasks()
        w = win.winfo_reqwidth()
        x = top.winfo_rootx() + top.winfo_width() - w - 40
        y = top.winfo_rooty() + 70
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.deiconify()
        win.focus_set()

    def _show_modal(win, parent, focus=None):
        top = parent.winfo_toplevel()
        win.update_idletasks()
        w, h = win.winfo_reqwidth(), win.winfo_reqheight()
        x = top.winfo_rootx() + (top.winfo_width() - w) // 2
        y = top.winfo_rooty() + max(40, (top.winfo_height() - h) // 3)
        win.geometry(f"+{max(0, x)}+{max(0, y)}")
        win.deiconify()
        try:
            win.wait_visibility()
            win.grab_set()
        except tk.TclError:
            pass
        if focus is not None:
            focus.focus_set()
        win.wait_window()

    # ── small pieces of this window ──────────────────────────────────────────

    class Switch(tk.Canvas):
        """An on/off switch tied to a BooleanVar."""

        def __init__(self, parent, variable, command=None, disabled=False):
            super().__init__(parent, width=42, height=24, bd=0, highlightthickness=0, takefocus=1, cursor="hand2")
            self._var, self._command, self._disabled = variable, command, disabled
            variable.trace_add("write", lambda *a: self._draw())
            self.bind("<Map>", lambda e: self.after_idle(self._draw))
            self.bind("<ButtonRelease-1>", lambda e: self.toggle())
            self.bind("<space>", lambda e: self.toggle())

        def toggle(self):
            if self._disabled:
                return
            self._var.set(not self._var.get())
            if self._command:
                self._command()

        def _draw(self):
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            on = bool(self._var.get())
            if self._disabled:
                fill = "#1f4d80" if on else "#2c2c2f"
            else:
                fill = CYAN if on else "#4a4a4f"
            paint_round(self, 0, 0, 42, 24, 12, fill, fill, outside, "track", 0)
            x = 20 if on else 2
            paint_round(self, x, 2, 20, 20, 10, "#ffffff" if not self._disabled else "#9db4d0", "#ffffff" if not self._disabled else "#9db4d0", fill, "knob", 0)

    class Glyph(tk.Canvas):
        """A 22px status mark: waiting, working (spinning), done, careful or failed."""

        def __init__(self, parent, state="wait", size=22):
            super().__init__(parent, width=size, height=size, bd=0, highlightthickness=0)
            self.size, self.state, self.angle, self._job = size, state, 0, None
            self.bind("<Map>", lambda e: self.after_idle(self.draw))
            self.bind("<Destroy>", lambda e: self._cancel())

        def _cancel(self):
            if self._job:
                try:
                    self.after_cancel(self._job)
                except tk.TclError:
                    pass
                self._job = None

        def set(self, state):
            self.state = state
            self.draw()

        def draw(self):
            self._cancel()
            outside = _bg_of(self.master)
            tk.Canvas.configure(self, bg=outside)
            self.delete("all")
            s = self.size
            m = 2
            d = s - 2 * m
            if self.state == "wait":
                paint_round(self, m, m, d, d, d // 2, "#55555a", "#55555a", outside, "disc", 0)
                paint_round(self, m + 2, m + 2, d - 4, d - 4, (d - 4) // 2, outside, outside, "#55555a", "hole", 0)
            elif self.state == "work":
                paint_round(self, m, m, d, d, d // 2, "#2f3b4d", "#2f3b4d", outside, "disc", 0)
                paint_round(self, m + 2, m + 2, d - 4, d - 4, (d - 4) // 2, outside, outside, "#2f3b4d", "hole", 0)
                self.create_arc(m + 1, m + 1, s - m - 1, s - m - 1, start=self.angle, extent=110, style="arc", outline=CYAN, width=2)
                self.angle = (self.angle - 18) % 360
                self._job = self.after(40, self.draw)
            elif self.state in ("done", "warn", "fail"):
                fill = {"done": GREEN, "warn": AMBER, "fail": RED}[self.state]
                paint_round(self, m, m, d, d, d // 2, fill, fill, outside, "disc", 0)
                ink = "#0d1a10" if self.state == "done" else "#241a05" if self.state == "warn" else "#2a0d0b"
                c = s / 2
                if self.state == "done":
                    self.create_line(c - 4.5, c + 0.5, c - 1.2, c + 3.8, c + 5, c - 3.4, fill=ink, width=2, capstyle="round", joinstyle="round")
                elif self.state == "warn":
                    self.create_line(c, c - 4.5, c, c + 1.5, fill=ink, width=2, capstyle="round")
                    self.create_oval(c - 1.1, c + 3.4, c + 1.1, c + 5.6, fill=ink, outline="")
                else:
                    self.create_line(c - 3.5, c - 3.5, c + 3.5, c + 3.5, fill=ink, width=2, capstyle="round")
                    self.create_line(c - 3.5, c + 3.5, c + 3.5, c - 3.5, fill=ink, width=2, capstyle="round")

    class Badge(tk.Canvas):
        """The big round mark on the last page."""

        def __init__(self, parent, state="done", size=72):
            super().__init__(parent, width=size, height=size, bd=0, highlightthickness=0, bg=BG)
            self.size = size
            self.set(state)

        def set(self, state):
            self.delete("all")
            s = self.size
            color = {"done": GREEN, "warn": AMBER, "fail": RED}[state]
            soft = {"done": "#16301d", "warn": "#3a2c0e", "fail": "#3a1a19"}[state]
            paint_round(self, 2, 2, s - 4, s - 4, (s - 4) // 2, soft, soft, BG, "soft", 0)
            paint_round(self, 10, 10, s - 20, s - 20, (s - 20) // 2, color, color, soft, "disc", 0)
            c, u = s / 2, s / 72
            ink = {"done": "#0d1a10", "warn": "#241a05", "fail": "#2a0d0b"}[state]
            if state == "done":
                self.create_line(c - 12 * u, c + 1 * u, c - 3 * u, c + 10 * u, c + 13 * u, c - 9 * u, fill=ink, width=5 * u, capstyle="round", joinstyle="round")
            elif state == "warn":
                self.create_line(c, c - 13 * u, c, c + 3 * u, fill=ink, width=5 * u, capstyle="round")
                self.create_oval(c - 3 * u, c + 9 * u, c + 3 * u, c + 15 * u, fill=ink, outline="")
            else:
                self.create_line(c - 10 * u, c - 10 * u, c + 10 * u, c + 10 * u, fill=ink, width=5 * u, capstyle="round")
                self.create_line(c - 10 * u, c + 10 * u, c + 10 * u, c - 10 * u, fill=ink, width=5 * u, capstyle="round")

    def autowrap(label, margin=4):
        """Lets a label's text wrap to whatever width its parent has."""
        def fit(event):
            label.configure(wraplength=max(120, event.width - margin))
        label.master.bind("<Configure>", fit, add="+")
        return label

    class ScrollFrame(tk.Frame):
        """A vertically scrolling column. Put widgets in `.inner`."""

        def __init__(self, parent, bg=BG):
            super().__init__(parent, bg=bg, bd=0, highlightthickness=0)
            self.cv = tk.Canvas(self, bg=bg, bd=0, highlightthickness=0)
            self.sb = ttk.Scrollbar(self, orient="vertical", command=self.cv.yview, style="Thin.Vertical.TScrollbar")
            self.cv.configure(yscrollcommand=self._set)
            self.inner = tk.Frame(self.cv, bg=bg)
            self.win = self.cv.create_window(0, 0, window=self.inner, anchor="nw")
            self.cv.grid(row=0, column=0, sticky="nsew")
            self.sb.grid(row=0, column=1, sticky="ns")
            self.columnconfigure(0, weight=1)
            self.rowconfigure(0, weight=1)
            self.inner.bind("<Configure>", lambda e: self.cv.configure(scrollregion=self.cv.bbox("all")))
            self.cv.bind("<Configure>", lambda e: self.cv.itemconfigure(self.win, width=e.width))
            for w in (self.cv, self.inner):
                w.bind("<Enter>", self._bind_wheel)
                w.bind("<Leave>", self._unbind_wheel)

        def _set(self, lo, hi):
            self.sb.set(lo, hi)
            if float(lo) <= 0.0 and float(hi) >= 1.0:
                self.sb.grid_remove()
            else:
                self.sb.grid()

        def _bind_wheel(self, _e=None):
            self.cv.bind_all("<MouseWheel>", self._wheel)
            self.cv.bind_all("<Button-4>", self._wheel)
            self.cv.bind_all("<Button-5>", self._wheel)

        def _unbind_wheel(self, _e=None):
            for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                self.cv.unbind_all(seq)

        def _wheel(self, e):
            if getattr(e, "num", 0) == 4:
                step = -2
            elif getattr(e, "num", 0) == 5:
                step = 2
            else:
                step = -2 if e.delta > 0 else 2
            self.cv.yview_scroll(step, "units")

        def clear(self):
            for w in self.inner.winfo_children():
                w.destroy()
            self.cv.yview_moveto(0)

    STATUS = {  # glyph state, word, colour
        "waiting": ("wait", "Waiting", DIM), "running": ("work", "Running", CYAN), "ok": ("done", "Done", GREEN),
        "failed": ("fail", "Failed", RED), "timeout": ("warn", "Timed out", AMBER), "cancelled": ("warn", "Cancelled", AMBER),
        "retrying": ("work", "Trying again", AMBER), "skipped": ("wait", "Not run", DIM),
    }

    def age_text(ts):
        secs = max(0, int(time.time() - ts))
        for limit, unit, size in ((60, "s", 1), (3600, "m", 60), (86400, "h", 3600)):
            if secs < limit:
                return "%d%s ago" % (secs // size, unit)
        return "%dd ago" % (secs // 86400)

    class App:
        def __init__(self, root, demo=False, fleet_file=None):
            self.root = root
            self.demo = demo
            self.fleet_path = Path(fleet_file) if fleet_file else default_fleet_path()
            self.servers, self.file_problems = load_fleet(self.fleet_path)
            self.sel = {}
            self.events = queue.Queue()
            self.runner = None
            self.run_order, self.results, self.cards = [], {}, {}
            self.command_run, self.kind_run = "", "cmd"
            self.last_job, self.last_opts, self.note, self.tries = None, {}, "", {}
            self.mode = "cmd"
            self.hooks = load_hooks()
            self.hook_last = {}
            self.followups, self.summary_hooks = [], []
            self.saved_jobs = load_saved_jobs()
            self.view = "results"
            self.last = {}
            self.service_ok = None
            self.status = {}
            self.jobs_run, self.timeout_run = 4, 60
            self.run_started = 0.0
            self.toast_label = None
            root.title(APP_NAME)
            root.configure(bg=BG)
            root.minsize(1000, 660)
            root.geometry(f"1220x{min(800, max(660, root.winfo_screenheight() - 80))}")
            self._style()
            self._style_extra()
            self.menu_kw = dict(tearoff=0, bg="#2c2c2f", fg=TEXT, activebackground=SEL, activeforeground="#ffffff", bd=0, relief="flat", activeborderwidth=0)
            self._load_last()
            self._build()
            self.rebuild_servers()
            self.render()
            root.bind(f"<{MOD}-Return>", lambda e: self.run())
            self.root.after(80, self._poll)
            self._watch_service()

        def _load_last(self):
            for entry in reversed(load_history()):
                for r in entry.get("results", []):
                    self.last[r["name"]] = r["status"]

        # ── look ─────────────────────────────────────────────────────────
        def _style(self):
            fams = set(tkfont.families())
            fam = next((f for f in ("SF Pro Text", "SF Pro Display", "Inter", "Helvetica Neue", "Nimbus Sans", "Liberation Sans",
                                    "Arimo", "Noto Sans", "DejaVu Sans") if f in fams), tkfont.nametofont("TkDefaultFont").actual("family"))
            self.family = fam
            for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont", "TkCaptionFont"):
                try:
                    tkfont.nametofont(name).configure(family=fam, size=10)
                except tk.TclError:
                    pass
            mono = next((f for f in ("JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono") if f in fams), "TkFixedFont")
            UI.update(body=tkfont.Font(family=fam, size=10), small=tkfont.Font(family=fam, size=9), tiny=tkfont.Font(family=fam, size=8),
                      bold=tkfont.Font(family=fam, size=10, weight="bold"), h=tkfont.Font(family=fam, size=11, weight="bold"),
                      title=tkfont.Font(family=fam, size=16, weight="bold"), head=tkfont.Font(family=fam, size=9, weight="bold"),
                      big=tkfont.Font(family=fam, size=22, weight="bold"), mono=tkfont.Font(family=mono, size=9))
            s = ttk.Style(self.root)
            s.theme_use("clam")
            s.configure(".", background=BG, foreground=TEXT, fieldbackground=FIELD, bordercolor=BORDER, lightcolor=BORDER,
                        darkcolor=BORDER, troughcolor=FIELD, focuscolor=CYAN, font=UI["body"])
            s.configure("TFrame", background=BG)
            s.configure("Card.TFrame", background=CARD)
            s.configure("Field.TFrame", background=FIELD)
            s.configure("TLabel", background=CARD, foreground=TEXT, font=UI["body"])
            s.configure("Dim.TLabel", background=CARD, foreground=DIM, font=UI["small"])
            s.configure("BgDim.TLabel", background=BG, foreground=DIM, font=UI["small"])
            s.configure("Title.TLabel", background=BG, foreground=TEXT, font=UI["title"])
            s.configure("H.TLabel", background=CARD, foreground=TEXT, font=UI["h"])
            s.configure("Big.TLabel", background=CARD, foreground=TEXT, font=UI["big"])
            s.configure("Mono.TLabel", background=CARD, foreground=TEXT, font=UI["mono"])
            s.configure("Insight.TFrame", background="#1f2c3f")
            s.configure("Insight.TLabel", background="#1f2c3f", foreground=TEXT, font=UI["body"])
            for kind in ("Flat.TEntry", "Flat.TCombobox"):
                s.configure(kind, fieldbackground=FIELD, background=FIELD, foreground=TEXT, insertcolor=TEXT, borderwidth=0,
                            bordercolor=FIELD, lightcolor=FIELD, darkcolor=FIELD, padding=2, arrowcolor=DIM,
                            selectbackground=SEL, selectforeground="#ffffff", font=UI["body"])
                s.map(kind, fieldbackground=[("disabled", FIELD), ("readonly", FIELD)], foreground=[("disabled", DIM), ("readonly", TEXT)],
                      bordercolor=[("focus", FIELD)], lightcolor=[("focus", FIELD)], darkcolor=[("focus", FIELD)],
                      selectbackground=[("readonly", FIELD)], selectforeground=[("readonly", TEXT)], background=[("active", FIELD), ("readonly", FIELD)])
            for opt, val in (("background", FIELD), ("foreground", TEXT), ("selectBackground", SEL), ("selectForeground", "#ffffff"), ("font", UI["body"])):
                self.root.option_add(f"*TCombobox*Listbox.{opt}", val)
            s.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
            s.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT, rowheight=26, borderwidth=0, relief="flat", font=UI["body"])
            s.configure("Treeview.Heading", background="#212124", foreground=DIM, padding=(8, 6), font=UI["head"], relief="flat", borderwidth=0)
            s.map("Treeview", background=[("selected", SEL)], foreground=[("selected", "#ffffff")])
            s.map("Treeview.Heading", background=[("active", "#2c2c30")])
            s.layout("Thin.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
                ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
            s.configure("Thin.Vertical.TScrollbar", background="#4a4a4f", troughcolor=FIELD, bordercolor=FIELD, lightcolor="#4a4a4f",
                        darkcolor="#4a4a4f", arrowsize=9, gripcount=0, borderwidth=0)
            s.map("Thin.Vertical.TScrollbar", background=[("active", "#68686e")], lightcolor=[("active", "#68686e")], darkcolor=[("active", "#68686e")])
            s.layout("Thin.Horizontal.TScrollbar", [("Horizontal.Scrollbar.trough", {"sticky": "ew", "children": [
                ("Horizontal.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
            s.configure("Thin.Horizontal.TScrollbar", background="#4a4a4f", troughcolor=FIELD, bordercolor=FIELD, lightcolor="#4a4a4f",
                        darkcolor="#4a4a4f", arrowsize=9, gripcount=0, borderwidth=0)
            s.map("Thin.Horizontal.TScrollbar", background=[("active", "#68686e")], lightcolor=[("active", "#68686e")], darkcolor=[("active", "#68686e")])


        def _style_extra(self):
            s = ttk.Style(self.root)
            s.configure("Bold.TLabel", background=CARD, foreground=TEXT, font=UI["bold"])
            s.configure("Warn.TLabel", background=CARD, foreground=AMBER, font=UI["small"])

        # ── layout ───────────────────────────────────────────────────────
        def _build(self):
            root = self.root
            root.columnconfigure(0, weight=1)
            root.rowconfigure(0, weight=1)
            page = ttk.Frame(root, padding=(22, 16, 22, 10))
            page.grid(row=0, column=0, sticky="nsew")
            page.columnconfigure(1, weight=1)
            page.rowconfigure(1, weight=1)
            head = ttk.Frame(page)
            head.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 14))
            head.columnconfigure(0, weight=1)
            brand = ttk.Frame(head)
            brand.grid(row=0, column=0, sticky="w")
            word = tk.Frame(brand, bg=BG)
            word.grid(row=0, column=0, sticky="w")
            tk.Label(word, text="ZTR", bg=BG, fg=CYAN, font=UI["title"]).pack(side="left")
            tk.Label(word, text=" Fleet", bg=BG, fg=TEXT, font=UI["title"]).pack(side="left")
            ttk.Label(brand, text="One command, every server, each through its own route", style="BgDim.TLabel").grid(row=1, column=0, sticky="nw")
            pill = Card(head, radius=15, pad=(12, 6), bg=BG)
            pill.grid(row=0, column=1, sticky="e")
            self.pill_dot = tk.Canvas(pill.body, width=12, height=12, bg=CARD, highlightthickness=0)
            self.pill_dot.grid(row=0, column=0, padx=(0, 7))
            self.pill_label = ttk.Label(pill.body, text="Checking the tunnel service…", style="Dim.TLabel")
            self.pill_label.grid(row=0, column=1)
            self.set_pill(DIM, "Checking the tunnel service…")

            # left: the servers
            left = Card(page, radius=14, pad=(14, 12))
            left.grid(row=1, column=0, sticky="ns", padx=(0, 14))
            left.configure(width=350)
            left.grid_propagate(False)
            lb = left.body
            lb.columnconfigure(0, weight=1)
            lb.rowconfigure(3, weight=1)
            top = ttk.Frame(lb, style="Card.TFrame")
            top.grid(row=0, column=0, sticky="ew")
            top.columnconfigure(0, weight=1)
            ttk.Label(top, text="Servers", style="H.TLabel").grid(row=0, column=0, sticky="w")
            self.count_label = ttk.Label(top, text="", style="Dim.TLabel")
            self.count_label.grid(row=0, column=1, sticky="e")
            filt = ttk.Frame(lb, style="Card.TFrame")
            filt.grid(row=1, column=0, sticky="ew", pady=(10, 8))
            filt.columnconfigure(0, weight=1)
            self.filter_var = tk.StringVar()
            Field(filt, compact=True, textvariable=self.filter_var, placeholder="Filter servers").grid(row=0, column=0, sticky="ew")
            self.group_var = tk.StringVar(value="All groups")
            self.group_combo = Combo(filt, compact=True, textvariable=self.group_var, state="readonly", width=12, values=["All groups"])
            self.group_combo.grid(row=0, column=1, padx=(8, 0))
            self.group_combo.inner.bind("<<ComboboxSelected>>", lambda e: self.rebuild_servers())
            self.filter_var.trace_add("write", lambda *a: self.rebuild_servers())
            bar = ttk.Frame(lb, style="Card.TFrame")
            bar.grid(row=2, column=0, sticky="ew", pady=(0, 6))
            Btn(bar, text="All", style="Small.TButton", command=lambda: self.select_shown(True)).grid(row=0, column=0, padx=(0, 6))
            Btn(bar, text="None", style="Small.TButton", command=lambda: self.select_shown(False)).grid(row=0, column=1, padx=(0, 6))
            Btn(bar, text="Failed last time", style="Small.TButton", command=self.select_failed).grid(row=0, column=2)
            self.server_scroll = ScrollFrame(lb, bg=CARD)
            self.server_scroll.grid(row=3, column=0, sticky="nsew")
            foot = ttk.Frame(lb, style="Card.TFrame")
            foot.grid(row=4, column=0, sticky="ew", pady=(10, 0))
            Btn(foot, text="Add server", style="Primary.TButton", command=lambda: self.edit_server(None)).grid(row=0, column=0, padx=(0, 8))
            Btn(foot, text="Import from Ferry", style="Small.TButton", command=self.import_ferry).grid(row=0, column=1, padx=(0, 8))
            Btn(foot, text="Remove ticked servers…", style="Small.Danger.TButton", command=self.remove_selected).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

            # right: the command, then the answers
            right = ttk.Frame(page)
            right.grid(row=1, column=1, sticky="nsew")
            right.columnconfigure(0, weight=1)
            right.rowconfigure(1, weight=1)
            comp = Card(right, radius=14, pad=(16, 12))
            comp.grid(row=0, column=0, sticky="ew", pady=(0, 12))
            cb = comp.body
            cb.columnconfigure(0, weight=1)
            top = ttk.Frame(cb, style="Card.TFrame")
            top.grid(row=0, column=0, sticky="ew")
            top.columnconfigure(4, weight=1)
            self.mode_btns = {}
            for i, (key, title) in enumerate(MODES):
                b = Btn(top, text=title, kind="tab", selected=(key == self.mode), command=lambda k=key: self.set_mode(k))
                b.grid(row=0, column=i, padx=(0, 6))
                self.mode_btns[key] = b
            self.snip_bar = ttk.Frame(top, style="Card.TFrame")
            self.snip_bar.grid(row=0, column=5, sticky="e")
            self.snip_var = tk.StringVar()
            self.snip_combo = Combo(self.snip_bar, compact=True, textvariable=self.snip_var, state="readonly", width=20, values=[])
            self.snip_combo.grid(row=0, column=0, padx=(0, 8))
            self.snip_combo.inner.bind("<<ComboboxSelected>>", lambda e: self.use_snippet())
            Btn(self.snip_bar, text="Save…", style="Small.TButton", command=self.save_snippet_dialog).grid(row=0, column=1)

            # what to run: one panel per mode, only the chosen one is shown
            self.input_area = ttk.Frame(cb, style="Card.TFrame")
            self.input_area.grid(row=1, column=0, sticky="ew", pady=(8, 0))
            self.input_area.columnconfigure(0, weight=1)
            self.panels = {}
            panel = ttk.Frame(self.input_area, style="Card.TFrame")
            panel.columnconfigure(0, weight=1)
            holder = tk.Frame(panel, bg=FIELD, bd=0, highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN)
            holder.grid(row=0, column=0, sticky="ew")
            holder.columnconfigure(0, weight=1)
            self.cmd_text = tk.Text(holder, height=3, bg=FIELD, fg=TEXT, insertbackground=TEXT, bd=0, highlightthickness=0, wrap="word",
                                    font=UI["mono"], padx=10, pady=8, selectbackground=SEL, undo=True)
            self.cmd_text.grid(row=0, column=0, sticky="ew")
            self.cmd_text.insert("1.0", "uptime")
            self.cmd_text.bind("<KeyRelease>", lambda e: self.update_hint())
            self.panels["cmd"] = panel

            self.script_var, self.put_var, self.put_to_var = tk.StringVar(), tk.StringVar(), tk.StringVar()
            self.get_var, self.into_var = tk.StringVar(), tk.StringVar(value=str(Path.home() / "fleet-files"))
            for var in (self.script_var, self.put_var, self.put_to_var, self.get_var, self.into_var):
                var.trace_add("write", lambda *a: self.update_hint())

            def path_panel(key, rows):
                pn = ttk.Frame(self.input_area, style="Card.TFrame")
                pn.columnconfigure(0, weight=1)
                for r, (var, hint, buttons) in enumerate(rows):
                    Field(pn, compact=True, textvariable=var, placeholder=hint).grid(row=r, column=0, sticky="ew", pady=(0, 6 if r < len(rows) - 1 else 0))
                    for c, (label, cmd) in enumerate(buttons):
                        Btn(pn, text=label, style="Small.TButton", command=cmd).grid(row=r, column=1 + c, padx=(8, 0), pady=(0, 6 if r < len(rows) - 1 else 0))
                self.panels[key] = pn
            path_panel("script", [(self.script_var, "A script on this computer (.sh, .py …) — it is sent to each server and run there", [("Choose…", self.pick_script)])])
            path_panel("put", [(self.put_var, "The file or folder on this computer to send", [("File…", self.pick_put_file), ("Folder…", self.pick_put_folder)]),
                               (self.put_to_var, "Where on the server (blank = the login folder), for example /tmp/", [])])
            path_panel("get", [(self.get_var, "The file or folder on each server to fetch, for example /var/log/syslog", []),
                               (self.into_var, "Save into this folder on this computer — each server gets its own folder inside", [("Choose…", self.pick_into)])])

            self.hint = tk.Label(cb, text="", bg=CARD, fg=DIM, font=UI["small"], justify="left", anchor="w")
            self.hint.grid(row=2, column=0, sticky="ew", pady=(6, 0))
            autowrap(self.hint)

            opts = ttk.Frame(cb, style="Card.TFrame")
            opts.grid(row=3, column=0, sticky="ew", pady=(8, 0))
            opts.columnconfigure(5, weight=1)
            ttk.Label(opts, text="At once", style="Dim.TLabel").grid(row=0, column=0, padx=(0, 8))
            self.jobs_var = tk.StringVar(value="4")
            Combo(opts, compact=True, textvariable=self.jobs_var, state="readonly", width=4, values=["1", "2", "3", "4", "6", "8", "12", "16"]).grid(row=0, column=1, padx=(0, 18))
            ttk.Label(opts, text="Give up after", style="Dim.TLabel").grid(row=0, column=2, padx=(0, 8))
            self.timeout_var = tk.StringVar(value="1 minute")
            Combo(opts, compact=True, textvariable=self.timeout_var, state="readonly", width=10, values=list(TIMEOUTS)).grid(row=0, column=3, padx=(0, 14))
            self.more_btn = Btn(opts, text="More options ▾", style="Small.TButton", command=self.toggle_more)
            self.more_btn.grid(row=0, column=4)
            self.schedule_btn = Btn(opts, text="Schedule…", style="Small.TButton", command=lambda: self.schedule_dialog(None))
            self.schedule_btn.grid(row=0, column=6, sticky="e", padx=(0, 8))
            self.preview_btn = Btn(opts, text="Preview", style="Small.TButton", command=self.preview)
            self.preview_btn.grid(row=0, column=7, sticky="e", padx=(0, 8))
            self.run_btn = Btn(opts, text="Run", style="Primary.TButton", command=self.run)
            self.run_btn.grid(row=0, column=8, sticky="e")
            self.cancel_btn = Btn(opts, text="Cancel", style="Danger.TButton", command=self.cancel)
            self.cancel_btn.grid(row=0, column=9, sticky="e", padx=(8, 0))
            self.cancel_btn.grid_remove()

            # rolling, retrying and sudo — tucked away until asked for
            self.more = ttk.Frame(cb, style="Card.TFrame")
            self.more.grid(row=4, column=0, sticky="ew", pady=(10, 0))
            self.more.grid_remove()
            self.batch_var, self.pause_var = tk.StringVar(value="All at once"), tk.StringVar(value="No pause")
            self.retry_var = tk.StringVar(value="No retries")
            self.canary_var, self.stop_var, self.sudo_var = tk.BooleanVar(value=False), tk.BooleanVar(value=True), tk.BooleanVar(value=False)
            ttk.Label(self.more, text="Roll out", style="Dim.TLabel").grid(row=0, column=0, padx=(0, 8), sticky="w")
            bc = Combo(self.more, compact=True, textvariable=self.batch_var, state="readonly", width=12, values=list(BATCHES))
            bc.grid(row=0, column=1, padx=(0, 14))
            bc.inner.bind("<<ComboboxSelected>>", lambda e: self.update_rolling())
            self.canary_check = Check(self.more, text="Try one server first", variable=self.canary_var)
            self.canary_check.grid(row=0, column=2, padx=(0, 10))
            self.stop_check = Check(self.more, text="Stop if one fails", variable=self.stop_var)
            self.stop_check.grid(row=0, column=3, padx=(0, 14))
            ttk.Label(self.more, text="Wait between", style="Dim.TLabel").grid(row=0, column=4, padx=(0, 8))
            self.pause_combo = Combo(self.more, compact=True, textvariable=self.pause_var, state="readonly", width=10, values=list(PAUSES))
            self.pause_combo.grid(row=0, column=5)
            ttk.Label(self.more, text="If a server fails", style="Dim.TLabel").grid(row=1, column=0, padx=(0, 8), pady=(8, 0), sticky="w")
            Combo(self.more, compact=True, textvariable=self.retry_var, state="readonly", width=12, values=list(RETRIES)).grid(row=1, column=1, padx=(0, 14), pady=(8, 0))
            self.sudo_check = Check(self.more, text="Send my sudo password", variable=self.sudo_var)
            self.sudo_check.grid(row=1, column=2, columnspan=3, sticky="w", pady=(8, 0))
            ttk.Label(self.more, text="After each answer", style="Dim.TLabel").grid(row=2, column=0, padx=(0, 8), pady=(8, 0), sticky="w")
            self.hooks_btn = Btn(self.more, text="", style="Small.TButton", command=self.edit_hooks)
            self.hooks_btn.grid(row=2, column=1, columnspan=2, padx=(0, 14), pady=(8, 0), sticky="w")
            self.update_rolling()
            self.update_hooks_label()

            res = Card(right, radius=14, pad=(16, 12))
            res.grid(row=1, column=0, sticky="nsew")
            rb = res.body
            rb.columnconfigure(0, weight=1)
            rb.rowconfigure(2, weight=1)
            tabs = ttk.Frame(rb, style="Card.TFrame")
            tabs.grid(row=0, column=0, sticky="ew")
            tabs.columnconfigure(5, weight=1)
            self.tab_btns = {}
            for i, (key, title) in enumerate((("results", "Answers"), ("compare", "Compare"), ("history", "History"), ("schedules", "Schedules"))):
                b = Btn(tabs, text=title, kind="tab", selected=(key == self.view), command=lambda k=key: self.show_view(k))
                b.grid(row=0, column=i, padx=(0, 6))
                self.tab_btns[key] = b
            self.ignore_var = tk.BooleanVar(value=False)
            self.ignore_check = Check(tabs, text="Ignore numbers", variable=self.ignore_var, command=self.render)
            self.ignore_check.grid(row=0, column=6, padx=(0, 10))
            self.copy_btn = Btn(tabs, text="Copy", style="Small.TButton", command=self.copy_results)
            self.copy_btn.grid(row=0, column=7, padx=(0, 6))
            self.save_btn = Btn(tabs, text="Save…", style="Small.TButton", command=self.save_results)
            self.save_btn.grid(row=0, column=8)
            sumrow = ttk.Frame(rb, style="Card.TFrame")
            sumrow.grid(row=1, column=0, sticky="ew", pady=(10, 8))
            sumrow.columnconfigure(0, weight=1)
            self.summary_label = ttk.Label(sumrow, text="", style="Dim.TLabel")
            self.summary_label.grid(row=0, column=0, sticky="w")
            self.retry_btn = Btn(sumrow, text="Retry the ones that failed", style="Small.TButton", command=self.retry_failed)
            self.retry_btn.grid(row=0, column=1, sticky="e")
            self.retry_btn.grid_remove()
            self.retry_wanted = False
            sumrow.bind("<Configure>", lambda e: self._wrap_summary())
            self.progress = Progress(sumrow, mode="determinate")
            self.progress.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
            self.result_scroll = ScrollFrame(rb, bg=CARD)
            self.result_scroll.grid(row=2, column=0, sticky="nsew")
            self.refresh_snippets()
            self.snip_var.set("Saved commands")
            # Every mode's panel gets the same height, so switching modes never moves what is below it.
            root.update_idletasks()
            self.input_area.grid_propagate(False)
            self.input_area.configure(height=max(p.winfo_reqheight() for p in self.panels.values()))
            self.set_mode("cmd")

        # ── small helpers ────────────────────────────────────────────────
        def set_pill(self, color, text):
            self.pill_dot.delete("all")
            self.pill_dot.create_oval(1, 1, 11, 11, fill=color, outline="")
            self.pill_label.configure(text=text)

        def _wrap_summary(self):
            room = self.summary_label.master.winfo_width() - (self.retry_btn.winfo_reqwidth() + 24 if self.retry_btn.winfo_ismapped() else 8)
            self.summary_label.configure(wraplength=max(200, room))

        def _show_retry(self, wanted=None):
            """The Retry button belongs to the Answers tab and only shows after a run that left servers unfinished."""
            if wanted is not None:
                self.retry_wanted = wanted
            if self.retry_wanted and self.view == "results":
                self.retry_btn.grid()
            else:
                self.retry_btn.grid_remove()
            self.root.after_idle(self._wrap_summary)

        def toast(self, text, kind="ok"):
            if self.toast_label is not None:
                self.toast_label.destroy()
            color = {"ok": GREEN, "warn": AMBER, "error": RED}.get(kind, TEXT)
            self.toast_label = tk.Label(self.root, text=text, bg="#2c2c2f", fg=color, font=UI["body"], padx=16, pady=8, bd=0)
            self.toast_label.place(relx=0.5, rely=0.95, anchor="center")
            self.root.after(2800, lambda: self.toast_label and self.toast_label.destroy())

        def copy(self, text, note="Copied"):
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.toast(note)

        def confirm(self, title, message, ok="OK", danger=False):
            win, body = _dialog(self.root, title)
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text=title, style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text=message, style="Dim.TLabel", wraplength=380, justify="left").grid(row=1, column=0, sticky="w", pady=(6, 14))
            out = {"yes": False}
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=2, column=0, sticky="e")

            def done(v):
                out["yes"] = v
                win.destroy()
            Btn(row, text="Cancel", style="Ghost.TButton", command=lambda: done(False)).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text=ok, style="Danger.TButton" if danger else "Primary.TButton", command=lambda: done(True)).grid(row=0, column=1)
            _show_modal(win, self.root)
            return out["yes"]

        def _watch_service(self):
            if self.demo:
                self.set_pill(AMBER, "Demo — no server is contacted")
                return

            # The check runs off the screen's thread; only the screen's own thread may schedule the next one.
            threading.Thread(target=lambda: self.events.put(("service", service_up(CONTROL_PORT))), daemon=True).start()

        # ── the server list ──────────────────────────────────────────────
        def groups(self):
            return sorted({s.group for s in self.servers if s.group})

        def shown(self):
            text = self.filter_var.get().strip().lower()
            group = self.group_var.get()
            out = []
            for s in self.servers:
                if group != "All groups" and s.group != group:
                    continue
                if text and text not in (s.name + " " + s.alias + " " + s.route + " " + route_country(s.route) + " " + s.group).lower():
                    continue
                out.append(s)
            return out

        def rebuild_servers(self):
            groups = ["All groups"] + self.groups()
            self.group_combo.inner.configure(values=groups)
            if self.group_var.get() not in groups:
                self.group_var.set("All groups")
            for s in self.servers:
                self.sel.setdefault(s.name, tk.BooleanVar(value=True))
            self.server_scroll.clear()
            inner = self.server_scroll.inner
            inner.columnconfigure(0, weight=1)
            shown = self.shown()
            if not self.servers:
                tk.Label(inner, text="No servers yet.\nAdd one, or import the sites you saved in Ferry.", bg=CARD, fg=DIM, font=UI["body"], justify="left", pady=20).grid(row=0, column=0, sticky="w")
            for i, s in enumerate(shown):
                row = tk.Frame(inner, bg=CARD, bd=0, highlightthickness=0)
                row.grid(row=i, column=0, sticky="ew", pady=(0, 1))
                row.columnconfigure(1, weight=1)
                state = {"ok": "done", "failed": "fail", "timeout": "warn", "cancelled": "warn"}.get(self.last.get(s.name), "wait")
                Check(row, text=s.name, variable=self.sel[s.name], command=self.update_count).grid(row=0, column=0, sticky="w")
                if s.group:
                    tk.Label(row, text=s.group, bg=CARD, fg=TEAL, font=UI["small"]).grid(row=0, column=1, sticky="w", padx=(8, 0))
                g = Glyph(row, state, size=16)
                g.grid(row=0, column=2, sticky="e", padx=(6, 4))
                flag = flag_image(route_country(s.route))
                # one line that always fits the list: "route · user@alias", the alias shortened in the middle when it is long
                # (a line wider than the list would be cut off at both ends, and a flag at its left end with it)
                head = s.route if flag else route_label(s.route)
                tail = "%s@%s" % (s.user, s.alias)
                room = max(16, ROW_CHARS - len(head) - 5)
                if len(tail) > room:
                    alias_room = room - len(s.user) - 1      # keep the user whole and shorten the alias from its middle
                    if alias_room >= 6:
                        keep = alias_room - 1
                        tail = "%s@%s" % (s.user, s.alias[:keep // 2 + keep % 2] + "…" + s.alias[len(s.alias) - keep // 2:])
                    else:
                        keep = room - 1
                        tail = tail[:keep // 2 + keep % 2] + "…" + tail[len(tail) - keep // 2:]
                sub = "%s  ·  %s" % (head, tail)
                if s.vars:
                    extra = format_vars(s.vars)
                    if len(sub) + 5 + len(extra) <= ROW_CHARS:
                        sub += "  ·  " + extra
                tk.Label(row, text=(" " + sub) if flag else sub, image=flag or "", compound="left", anchor="w", bg=CARD, fg=DIM, font=UI["tiny"]).grid(
                    row=1, column=0, columnspan=3, sticky="w", padx=(26, 0), pady=(0, 4))
                for w in (row,) + tuple(row.winfo_children()):
                    if w.winfo_class() != "Canvas":
                        w.bind("<Double-Button-1>", lambda e, srv=s: self.edit_server(srv))
                    bind_context_menu(w, lambda e, srv=s: self.server_menu(e, srv))
            self.update_count()

        def update_count(self):
            n = sum(1 for s in self.servers if s.name in self.sel and self.sel[s.name].get())
            self.count_label.configure(text="%d of %d selected" % (n, len(self.servers)))
            verb = {"put": "Send to", "get": "Fetch from"}.get(self.mode, "Run on")
            self.run_btn.configure(text=("%s %d" % (verb, n)) if n else verb.split()[0])

        def select_shown(self, on):
            for s in self.shown():
                self.sel[s.name].set(on)
            self.update_count()

        def select_failed(self):
            bad = {s.name for s in self.servers if self.last.get(s.name) in ("failed", "timeout")}
            if not bad:
                self.toast("Nothing failed last time.", "ok")
                return
            for s in self.servers:
                self.sel[s.name].set(s.name in bad)
            self.update_count()

        def server_menu(self, event, server):
            menu = tk.Menu(self.root, **self.menu_kw)
            menu.add_command(label="Open a shell", command=lambda: self.open_shell(server))
            menu.add_command(label="Run on this one only", command=lambda: self.only(server))
            menu.add_separator()
            menu.add_command(label="Edit…", command=lambda: self.edit_server(server))
            menu.add_command(label="Copy alias", command=lambda: self.copy(server.alias, "Alias copied"))
            menu.add_separator()
            menu.add_command(label="Remove", command=lambda: self.remove_server(server))
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        def only(self, server):
            for s in self.servers:
                self.sel[s.name].set(s.name == server.name)
            self.update_count()

        def persist(self):
            if self.demo:
                return
            try:
                save_fleet(self.fleet_path, self.servers)
            except OSError as e:
                self.toast("Couldn't save %s: %s" % (self.fleet_path.name, e), "error")

        def remove_server(self, server):
            if self.confirm("Remove %s?" % server.name, "It is taken out of %s. The server itself is not touched." % self.fleet_path.name, "Remove", danger=True):
                self.servers = [s for s in self.servers if s.name != server.name]
                self.sel.pop(server.name, None)
                self.persist()
                self.rebuild_servers()

        def remove_selected(self):
            """Removes every server whose box is ticked, after listing them."""
            names = [s.name for s in self.servers if self.sel[s.name].get()]
            if not names:
                self.toast("Tick the servers you want to remove first.", "warn")
                return
            shown = ", ".join(names[:8]) + (" and %d more" % (len(names) - 8) if len(names) > 8 else "")
            if self.confirm("Remove %d server%s?" % (len(names), "" if len(names) == 1 else "s"),
                            "%s — taken out of %s. The servers themselves are not touched." % (shown, self.fleet_path.name), "Remove", danger=True):
                gone = set(names)
                self.servers = [s for s in self.servers if s.name not in gone]
                for n in gone:
                    self.sel.pop(n, None)
                self.persist()
                self.rebuild_servers()
                self.toast("Removed %d server%s" % (len(names), "" if len(names) == 1 else "s"))

        def edit_server(self, server):
            new = server is None
            win, body = _dialog(self.root, "Add a server" if new else "Edit " + server.name)
            body.columnconfigure(1, weight=1)
            ttk.Label(body, text="Add a server" if new else "Edit " + server.name, style="H.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
            v = {k: tk.StringVar(value=getattr(server, k, d) if server else d)
                 for k, d in (("name", ""), ("alias", ""), ("user", "root"), ("port", "22"), ("route", ""), ("group", ""), ("key", ""))}
            routes = list_routes()
            if new and routes and not v["route"].get():
                v["route"].set(routes[0])
            # the dropdown shows 'US  ·  route.ztr'; v["route"] keeps the plain file name (also when one is typed in)
            route_names = {route_label(n): n for n in routes}
            route_shown = tk.StringVar(value=route_label(v["route"].get()))
            route_shown.trace_add("write", lambda *a: v["route"].set(route_names.get(route_shown.get(), route_shown.get())))

            def line(r, label, key, widget=None, hint=None):
                ttk.Label(body, text=label).grid(row=r, column=0, sticky="w", padx=(0, 14), pady=4)
                w = widget or Field(body, compact=True, textvariable=v[key], width=34)
                w.grid(row=r, column=1, sticky="ew", pady=4)
                return w
            line(1, "Name", "name")
            line(2, "Alias or address", "alias")
            line(3, "Route", "route", Combo(body, compact=True, textvariable=route_shown, width=32, values=list(route_names)))
            line(4, "User", "user")
            line(5, "SSH port", "port")
            line(6, "Group (optional)", "group")
            keyfield = line(7, "SSH key file (optional)", "key")
            vars_var = tk.StringVar(value=format_vars(server.vars) if server else "")
            line(8, "Variables (optional)", None, Field(body, compact=True, textvariable=vars_var, width=34, placeholder="env=prod region=eu"))

            def browse():
                from tkinter import filedialog
                path = filedialog.askopenfilename(parent=win, title="Choose an ssh key", initialdir=str(Path.home() / ".ssh"))
                if path:
                    v["key"].set(path)
            Btn(body, text="Browse…", style="Small.TButton", command=browse).grid(row=7, column=2, padx=(8, 0))
            ttk.Label(body, text="Commands can use {name}, {env}, … — each server fills in its own. A script gets them as $ZTR_NAME, $ZTR_ENV.",
                      style="Dim.TLabel", wraplength=420, justify="left").grid(row=9, column=0, columnspan=3, sticky="w", pady=(2, 0))
            note = ttk.Label(body, text="", style="Warn.TLabel", wraplength=420, justify="left")
            note.grid(row=10, column=0, columnspan=3, sticky="w", pady=(8, 0))
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=11, column=0, columnspan=3, sticky="e", pady=(14, 0))

            def save():
                values, why = parse_vars(vars_var.get())
                if why:
                    note.configure(text=why)
                    return
                candidate = Server(v["name"].get().strip(), v["route"].get().strip(), v["alias"].get().strip(), v["user"].get().strip() or "root",
                                   v["port"].get().strip() or "22", v["key"].get().strip(), v["group"].get().strip(), values)
                problems = candidate.problems(None if self.demo else ROUTES_DIR)
                if any(s.name == candidate.name and s is not server for s in self.servers):
                    problems.insert(0, "Another server already has that name")
                if problems:
                    note.configure(text=problems[0])
                    return
                if new:
                    self.servers.append(candidate)
                    self.sel[candidate.name] = tk.BooleanVar(value=True)
                else:
                    old = server.name
                    idx = self.servers.index(server)
                    self.servers[idx] = candidate
                    if old != candidate.name:
                        self.sel[candidate.name] = self.sel.pop(old, tk.BooleanVar(value=True))
                        if old in self.last:
                            self.last[candidate.name] = self.last.pop(old)
                self.persist()
                win.destroy()
                self.rebuild_servers()
                self.toast("Saved %s" % candidate.name)
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Save", style="Primary.TButton", command=save).grid(row=0, column=1)
            if not new:
                Btn(body, text="Remove server", style="Danger.TButton", command=lambda: (win.destroy(), self.remove_server(server))).grid(
                    row=11, column=0, sticky="w", pady=(14, 0))
            _show_modal(win, self.root)

        def import_ferry(self):
            found = [s for s in ferry_servers() if not any(x.name == s.name or x.alias == s.alias for x in self.servers)]
            if not found:
                self.toast("Nothing new in Ferry's saved sites.", "warn")
                return
            win, body = _dialog(self.root, "Import from Ferry")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Saved sites in Ferry", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="Pick the ones to add to this fleet.", style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 10))
            picks = []
            for i, s in enumerate(found):
                var = tk.BooleanVar(value=True)
                picks.append((s, var))
                Check(body, text="%s   (%s, %s@%s)" % (s.name, route_label(s.route), s.user, s.alias if len(s.alias) < 30 else s.alias[:14] + "…"), variable=var).grid(row=2 + i, column=0, sticky="w", pady=2)
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=3 + len(found), column=0, sticky="e", pady=(14, 0))

            def add():
                chosen = [s for s, var in picks if var.get()]
                for s in chosen:
                    self.servers.append(s)
                    self.sel[s.name] = tk.BooleanVar(value=True)
                self.persist()
                win.destroy()
                self.rebuild_servers()
                self.toast("Added %d server%s" % (len(chosen), "" if len(chosen) == 1 else "s"))
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Add", style="Primary.TButton", command=add).grid(row=0, column=1)
            _show_modal(win, self.root)

        # ── commands ─────────────────────────────────────────────────────
        def refresh_snippets(self):
            self.snippets = load_snippets()
            self.snip_combo.inner.configure(values=[a for a, _b in self.snippets])

        def use_snippet(self):
            for name, command in self.snippets:
                if name == self.snip_var.get():
                    self.cmd_text.delete("1.0", "end")
                    self.cmd_text.insert("1.0", command)
                    break

        def save_snippet_dialog(self):
            command = self.cmd_text.get("1.0", "end").strip()
            if not command:
                self.toast("Type a command first.", "warn")
                return
            win, body = _dialog(self.root, "Save command")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Save this command", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text=command[:80] + ("…" if len(command) > 80 else ""), style="Mono.TLabel").grid(row=1, column=0, sticky="w", pady=(4, 10))
            name = tk.StringVar()
            field = Field(body, textvariable=name, placeholder="A name for it", width=36)
            field.grid(row=2, column=0, sticky="ew")
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=3, column=0, sticky="e", pady=(14, 0))

            def save():
                label = name.get().strip()
                if not label:
                    return
                try:
                    if not self.demo:
                        save_snippet(label, command)
                    else:
                        self.snippets.insert(0, (label, command))
                except OSError as e:
                    self.toast("Couldn't save: %s" % e, "error")
                    return
                if not self.demo:
                    self.refresh_snippets()
                else:
                    self.snip_combo.inner.configure(values=[a for a, _b in self.snippets])
                win.destroy()
                self.snip_var.set(label)
                self.toast("Saved “%s”" % label)
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Save", style="Primary.TButton", command=save).grid(row=0, column=1)
            win.bind("<Return>", lambda e: save())
            _show_modal(win, self.root, focus=field.inner)

        # ── what to run ──────────────────────────────────────────────────
        def set_mode(self, mode):
            self.mode = mode
            for k, b in self.mode_btns.items():
                b.configure(selected=(k == mode))
            for k, pn in self.panels.items():
                if k == mode:
                    pn.grid(row=0, column=0, sticky="ew")
                else:
                    pn.grid_remove()
            if mode == "cmd":
                self.snip_bar.grid()
            else:
                self.snip_bar.grid_remove()
            if mode != "cmd":
                self.sudo_var.set(False)
            self.sudo_check.configure(state="normal" if mode == "cmd" else "disabled")
            self.update_hint()
            if hasattr(self, "servers"):
                self.update_count()

        def toggle_more(self):
            if self.more.winfo_ismapped():
                self.more.grid_remove()
                self.more_btn.configure(text="More options ▾")
            else:
                self.more.grid()
                self.more_btn.configure(text="Fewer options ▴")

        def update_rolling(self):
            rolling = BATCHES.get(self.batch_var.get(), 0) > 0
            for w in (self.canary_check, self.stop_check):
                w.configure(state="normal" if rolling else "disabled")
            self.pause_combo.configure(state="readonly" if rolling else "disabled")

        def set_hint(self, text, color=DIM):
            self.hint.configure(text=text, fg=color)

        def update_hint(self):
            if not hasattr(self, "hint"):
                return
            mode = self.mode
            if mode == "put":
                self.set_hint("A folder is sent whole. With the second box left empty the file goes to the login folder.")
                return
            if mode == "get":
                self.set_hint("Each server's copy is saved in its own folder inside the one you choose, so nothing is overwritten.")
                return
            if mode == "script":
                text = self.read_script_quiet()
                note = "Sent to each server over ssh and run there — nothing is left behind. Each server's values are in $ZTR_NAME, $ZTR_ENV …"
            else:
                text = self.cmd_text.get("1.0", "end")
                note = "{name}, {env} and your other variables fill in each server's own value. Write {{name}} to keep the braces."
            serious, notices = risks(text)
            if serious:
                self.set_hint("Careful: this %s. You will be asked to confirm." % "; and it ".join(serious), AMBER)
            elif notices:
                self.set_hint("This %s." % "; and it ".join(notices), DIM)
            else:
                self.set_hint(note, DIM)

        def update_hooks_label(self):
            on = sum(1 for h in self.hooks if h["on"])
            text = "No hooks" if not self.hooks else ("%d hook%s on" % (on, "" if on == 1 else "s")) if on else "All off"
            self.hooks_btn.configure(text=text + "  ·  Choose…")

        def edit_hooks(self):
            """The hook manager: every local script that can get an answer — add, make from a template, set what each one
            runs for, try it on a real answer, switch on and off."""
            win, body = _dialog(self.root, "Hooks")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Hooks — scripts that get each answer", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="After a server answers, every hook that is switched on and wants that answer runs on this computer, "
                                 "once per server, with the answer on its standard input and: --server NAME --status ok "
                                 "--answer-file PATH --error-file PATH. The answer comes from the server, so treat it as untrusted text.",
                      style="Dim.TLabel", wraplength=640, justify="left").grid(row=1, column=0, sticky="w", pady=(4, 8))
            state = [dict(h) for h in self.hooks]
            known = {h["path"] for h in state}
            fresh = [f for f in scan_hooks_folder() if f not in known]
            for f in fresh:
                state.append(norm_hook(dict(path=f, on=False)))
            info = ttk.Label(body, text=("Found %d new script%s in your hooks folder — switched off until you turn %s on." %
                                         (len(fresh), "" if len(fresh) == 1 else "s", "it" if len(fresh) == 1 else "them")) if fresh else "",
                             style="Dim.TLabel", foreground=TEAL)
            info.grid(row=2, column=0, sticky="w", pady=(0, 6))
            box = ScrollFrame(body, bg=CARD)
            box.grid(row=3, column=0, sticky="ew")
            box.inner.columnconfigure(1, weight=1)
            note = ttk.Label(body, text="", style="Warn.TLabel", wraplength=640, justify="left")
            note.grid(row=4, column=0, sticky="w", pady=(8, 0))

            def status_of(h):
                prefix, why = hook_command(h["path"])
                if prefix is None:
                    return ("missing" if not os.path.isfile(os.path.expanduser(h["path"])) else "not executable"), RED if not os.path.isfile(os.path.expanduser(h["path"])) else AMBER
                last = self.hook_last.get(h["path"])
                if last is None:
                    return "ready", DIM
                return ("last run: ok", GREEN) if last == 0 else ("last run: failed (exit %s)" % last, AMBER)

            def draw():
                for w in box.inner.winfo_children():
                    w.destroy()
                height = min(320, max(60, 66 * len(state)))
                box.cv.configure(height=height)
                if not state:
                    ttk.Label(box.inner, text="No hooks yet. Start from a template, or add a script you already have.", style="Dim.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=14)
                for i, h in enumerate(state):
                    var = tk.BooleanVar(value=h["on"])
                    var.trace_add("write", lambda *a, h=h, v=var: h.__setitem__("on", bool(v.get())))
                    Check(box.inner, text="", variable=var).grid(row=i, column=0, sticky="nw", pady=(8, 0))
                    mid = ttk.Frame(box.inner, style="Card.TFrame")
                    mid.grid(row=i, column=1, sticky="ew", padx=(2, 10), pady=4)
                    head = ttk.Frame(mid, style="Card.TFrame")
                    head.grid(row=0, column=0, sticky="w")
                    ttk.Label(head, text=hook_title(h), style="Bold.TLabel").pack(side="left")
                    word, color = status_of(h)
                    ttk.Label(head, text="   " + word, style="Dim.TLabel", foreground=color).pack(side="left")
                    path = h["path"]
                    ttk.Label(mid, text=path if len(path) < 62 else "…" + path[-60:], style="Dim.TLabel").grid(row=1, column=0, sticky="w")
                    limits = hook_summary(h)[len(hook_title(h)):].strip(" ()")
                    if limits:
                        ttk.Label(mid, text=limits, style="Dim.TLabel", foreground=TEAL).grid(row=2, column=0, sticky="w")
                    btns = ttk.Frame(box.inner, style="Card.TFrame")
                    btns.grid(row=i, column=2, sticky="ne", pady=(6, 0))
                    if word == "not executable":
                        Btn(btns, text="Make runnable", style="Small.TButton", command=lambda h=h: (fix_executable(h["path"]), draw())).grid(row=0, column=0, padx=(0, 6))
                    Btn(btns, text="Try", style="Small.TButton", command=lambda h=h: self.try_hook(h, win)).grid(row=0, column=1, padx=(0, 6))
                    Btn(btns, text="Edit", style="Small.TButton", command=lambda h=h: edit(h)).grid(row=0, column=2, padx=(0, 6))
                    Btn(btns, text="Remove", style="Small.TButton", command=lambda h=h: (state.remove(h), draw())).grid(row=0, column=3)

            def edit(h):
                changed = self.hook_editor(win, h)
                if changed:
                    h.update(changed)
                    note.configure(text="")
                    draw()

            def add():
                changed = self.hook_editor(win, None)
                if changed:
                    if any(x["path"] == changed["path"] for x in state):
                        note.configure(text="That script is already in the list.")
                        return
                    state.append(changed)
                    note.configure(text="")
                    draw()

            def new():
                path = self.new_hook_dialog(win)
                if path:
                    state.append(norm_hook(dict(path=path, on=True)))
                    note.configure(text="Created %s — it is switched on. Edit it to do what you want with the answer." % path)
                    draw()
            draw()
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=5, column=0, sticky="ew", pady=(12, 0))
            row.columnconfigure(3, weight=1)
            Btn(row, text="New from a template…", style="Small.TButton", command=new).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Add a script…", style="Small.TButton", command=add).grid(row=0, column=1, padx=(0, 8))

            def open_folder():
                try:
                    core.HOOKS_DIR.mkdir(parents=True, exist_ok=True)
                    open_in_system(str(core.HOOKS_DIR))
                except OSError as e:
                    note.configure(text="Couldn't open it: %s" % e)
            Btn(row, text="Open the hooks folder", style="Small.TButton", command=open_folder).grid(row=0, column=2)

            def save():
                self.hooks = state
                try:
                    save_hooks(state)
                except OSError as e:
                    self.toast("Couldn't save the list: %s" % e, "error")
                self.update_hooks_label()
                win.destroy()
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=4, padx=(0, 8))
            Btn(row, text="Save", style="Primary.TButton", command=save).grid(row=0, column=5)
            _show_modal(win, self.root)

        def hook_editor(self, parent, h):
            """Add or change one hook. Returns the hook as a dict, or None if cancelled."""
            from tkinter import filedialog
            win, body = _dialog(parent, "Add a hook" if h is None else "Edit " + hook_title(h))
            body.columnconfigure(1, weight=1)
            ttk.Label(body, text="Add a script" if h is None else "Edit " + hook_title(h), style="H.TLabel").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))
            h = h or norm_hook(dict(path=""))
            v = dict(path=tk.StringVar(value=h["path"]), name=tk.StringVar(value=h["name"]), only=tk.StringVar(value=h["only"]),
                     match=tk.StringVar(value=h["match"]))
            failed = tk.BooleanVar(value=h["failed"])
            scope = tk.StringVar(value=h["scope"])
            rows = (("Script", "path", "The script on this computer"), ("Name (optional)", "name", "Shown in the results — default is the file name"),
                    ("Only for", "only", "Servers or groups, comma-separated — empty means all"),
                    ("Only when the answer contains", "match", "A word or pattern, for example DENY — empty means always"))
            fields = {}
            for i, (label, key, hint) in enumerate(rows, 1):
                ttk.Label(body, text=label).grid(row=i, column=0, sticky="w", padx=(0, 14), pady=4)
                fields[key] = Field(body, compact=True, textvariable=v[key], width=46, placeholder=hint)
                fields[key].grid(row=i, column=1, sticky="ew", pady=4)

            def browse():
                path = filedialog.askopenfilename(parent=win, title="Choose a script", initialdir=str(core.HOOKS_DIR if core.HOOKS_DIR.is_dir() else Path.home()))
                if path:
                    v["path"].set(path)
            Btn(body, text="Choose…", style="Small.TButton", command=browse).grid(row=1, column=2, padx=(8, 0))
            ttk.Label(body, text="Runs").grid(row=5, column=0, sticky="nw", padx=(0, 14), pady=(8, 0))
            kinds = ttk.Frame(body, style="Card.TFrame")
            kinds.grid(row=5, column=1, columnspan=2, sticky="w", pady=(6, 0))
            fail_check = Check(body, text="Also run it when a server fails (the answer is then empty; the error is in --error-file)", variable=failed)
            fail_check.grid(row=6, column=0, columnspan=3, sticky="w", pady=(6, 0))

            def sync():
                each = scope.get() == "each"
                fail_check.configure(state="normal" if each else "disabled")
                fields["match"].configure(state="normal" if each else "disabled")
            Radio(kinds, text="Once for each server, with its answer", value="each", variable=scope, command=sync).grid(row=0, column=0, sticky="w")
            Radio(kinds, text="Once at the end, with every answer (a report)", value="all", variable=scope, command=sync).grid(row=1, column=0, sticky="w")
            sync()
            groups = self.groups()
            ttk.Label(body, text=("Groups in this fleet: " + ", ".join(groups)) if groups else "", style="Dim.TLabel").grid(row=7, column=0, columnspan=3, sticky="w", pady=(6, 0))
            msg = ttk.Label(body, text="", style="Warn.TLabel", wraplength=520, justify="left")
            msg.grid(row=8, column=0, columnspan=3, sticky="w", pady=(6, 0))
            out = {"hook": None}
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=9, column=0, columnspan=3, sticky="e", pady=(12, 0))

            def ok():
                path = v["path"].get().strip()
                if not path:
                    msg.configure(text="Choose the script first.")
                    return
                if not os.path.isfile(os.path.expanduser(path)):
                    msg.configure(text="There's no file at %s." % path)
                    return
                if hook_command(path)[0] is None:
                    if self.confirm("Make it runnable?", "%s isn't marked as a program, so Fleet can't start it. Make it executable (chmod u+x)?" % os.path.basename(path), "Make it runnable"):
                        if not fix_executable(path):
                            msg.configure(text="Couldn't change its permissions.")
                            return
                    else:
                        return
                pattern = v["match"].get().strip()
                if pattern:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        msg.configure(text="That isn't a valid pattern (%s). A plain word works too." % e)
                        return
                out["hook"] = norm_hook(dict(path=os.path.expanduser(path), on=h["on"] if h["path"] else True, name=v["name"].get().strip(),
                                             only=v["only"].get().strip(), match=pattern if scope.get() == "each" else "",
                                             failed=bool(failed.get()) and scope.get() == "each", scope=scope.get()))
                win.destroy()
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Save", style="Primary.TButton", command=ok).grid(row=0, column=1)
            _show_modal(win, self.root, focus=fields["path"].inner)
            return out["hook"]

        def new_hook_dialog(self, parent):
            """Pick a starter script; it is written to the hooks folder. Returns its path or None."""
            win, body = _dialog(parent, "New hook")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Start from a template", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="Fleet writes the script into your hooks folder, ready to run. Open it afterwards to change what it does.",
                      style="Dim.TLabel", wraplength=480, justify="left").grid(row=1, column=0, sticky="w", pady=(4, 10))
            choice = tk.StringVar(value="ips")
            fname = tk.StringVar(value=HOOK_TEMPLATES["ips"][1])

            def picked():
                fname.set(HOOK_TEMPLATES[choice.get()][1])
            for i, (key, (title, filename, _body)) in enumerate(HOOK_TEMPLATES.items()):
                Radio(body, text="%s  (%s)" % (title, filename), value=key, variable=choice, command=picked).grid(row=2 + i, column=0, sticky="w", pady=2)
            r = 2 + len(HOOK_TEMPLATES)
            ttk.Label(body, text="File name", style="Dim.TLabel").grid(row=r, column=0, sticky="w", pady=(10, 2))
            Field(body, compact=True, textvariable=fname, width=40).grid(row=r + 1, column=0, sticky="ew")
            edit_after = tk.BooleanVar(value=True)
            Check(body, text="Open it in my editor afterwards", variable=edit_after).grid(row=r + 2, column=0, sticky="w", pady=(8, 0))
            msg = ttk.Label(body, text="", style="Warn.TLabel")
            msg.grid(row=r + 3, column=0, sticky="w", pady=(6, 0))
            out = {"path": None}
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=r + 4, column=0, sticky="e", pady=(10, 0))

            def make():
                try:
                    path = create_hook(choice.get(), fname.get().strip() or None)
                except OSError as e:
                    msg.configure(text="Couldn't create it: %s" % e)
                    return
                out["path"] = path
                win.destroy()
                if edit_after.get():
                    try:
                        open_in_system(path)
                    except OSError:
                        pass
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Create", style="Primary.TButton", command=make).grid(row=0, column=1)
            _show_modal(win, self.root)
            return out["path"]

        def try_hook(self, h, parent):
            """Runs one hook for real, once, on an answer you choose (or edit) — to see what it does before a real run."""
            win, body = _dialog(parent, "Try " + hook_title(h))
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Try “%s”" % hook_title(h), style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="This really runs the script, once, on this computer — with the answer below.", style="Warn.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 8))
            names = [n for n in self.run_order if n in self.results and self.results[n]["status"] == "ok"]
            sample = "ALLOW IN 10.0.0.5\nDENY IN 203.0.113.7\nDENY IN 198.51.100.9"
            wide = h.get("scope") == "all"
            pick = tk.StringVar(value=names[0] if names else "A sample answer")
            top = ttk.Frame(body, style="Card.TFrame")
            top.grid(row=2, column=0, sticky="ew")
            ttk.Label(top, text="Answer from", style="Dim.TLabel").grid(row=0, column=0, padx=(0, 8))
            combo = Combo(top, compact=True, textvariable=pick, state="readonly", width=24, values=names + ["A sample answer"])
            if wide:
                ttk.Label(top, text="This hook gets every answer at once, as JSON — the last run's, or a sample. Edit it if you like.", style="Dim.TLabel").grid(row=0, column=1)
            else:
                combo.grid(row=0, column=1)
            holder = tk.Frame(body, bg=FIELD, bd=0, highlightthickness=1, highlightbackground=BORDER, highlightcolor=CYAN)
            holder.grid(row=3, column=0, sticky="ew", pady=(8, 0))
            holder.columnconfigure(0, weight=1)
            answer = tk.Text(holder, width=84, height=7, bg=FIELD, fg=TEXT, insertbackground=TEXT, bd=0, highlightthickness=0, wrap="none",
                             font=UI["mono"], padx=10, pady=8, selectbackground=SEL)
            answer.grid(row=0, column=0, sticky="ew")

            def sample_payload():
                rows = [self.results[n] for n in self.run_order if n in self.results] or [
                    dict(name="web1", status="ok", rc=0, secs=2, out=sample, err="", route="web.ztr"),
                    dict(name="db1", status="failed", rc=255, secs=3, out="", err="connection refused", route="data.ztr")]
                return json.dumps(summary_payload(make_job("cmd", command=self.last_job["command"] if self.last_job and self.last_job["kind"] == "cmd" else "(a trial run)"),
                                                  self.servers, rows), indent=1)

            def load(*_):
                answer.delete("1.0", "end")
                answer.insert("1.0", sample_payload() if wide else (self.results[pick.get()]["out"] if pick.get() in self.results else sample))
            combo.inner.bind("<<ComboboxSelected>>", load)
            load()
            ttk.Label(body, text="What the script did", style="Dim.TLabel").grid(row=4, column=0, sticky="w", pady=(10, 2))
            holder2 = tk.Frame(body, bg=FIELD, bd=0, highlightthickness=1, highlightbackground=BORDER)
            holder2.grid(row=5, column=0, sticky="ew")
            holder2.columnconfigure(0, weight=1)
            result = tk.Text(holder2, width=84, height=6, bg=FIELD, fg="#d7d7dc", bd=0, highlightthickness=0, wrap="word", font=UI["mono"], padx=10, pady=8)
            result.insert("1.0", "(not run yet)")
            result.configure(state="disabled")
            result.grid(row=0, column=0, sticky="ew")
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=6, column=0, sticky="e", pady=(12, 0))
            q = queue.Queue()
            busy = {"on": False}

            def show(text, color="#d7d7dc"):
                result.configure(state="normal", fg=color)
                result.delete("1.0", "end")
                result.insert("1.0", text)
                result.configure(state="disabled")

            def poll():
                if not win.winfo_exists():
                    return
                try:
                    r = q.get_nowait()
                except queue.Empty:
                    win.after(100, poll)
                    return
                busy["on"] = False
                go.configure(state="normal", text="Run it")
                body_text = r["out"] if r["rc"] == 0 else "\n".join(t for t in (r["err"], r["out"]) if t)
                show("%s  ·  %ds\n%s" % ("Ran fine" if r["rc"] == 0 else "Failed (exit %s)" % r["rc"], r["secs"], body_text or "(it printed nothing)"),
                     GREEN if r["rc"] == 0 else AMBER)

            def run_it():
                if busy["on"]:
                    return
                text = answer.get("1.0", "end").rstrip("\n")
                if wide:
                    try:
                        payload = json.loads(text)
                        payload["summary"]["servers"]
                    except (ValueError, KeyError, TypeError):
                        show("That isn't valid JSON in the shape Fleet sends. Put the original back by choosing the hook again.", AMBER)
                        return
                    work = lambda: q.put(run_summary_hook(h["path"], payload, name=hook_title(h)))
                else:
                    server = next((s for s in self.servers if s.name == pick.get()), Server("sample", "route.ztr", "sample._ztr", "root"))
                    res = dict(name=server.name, status="ok", rc=0, out=text, err="", secs=0)
                    work = lambda: q.put(run_hook(h["path"], server, res, make_job("cmd", command="(a trial run)"), name=hook_title(h)))
                busy["on"] = True
                go.configure(state="disabled", text="Running…")
                show("Running…", DIM)
                threading.Thread(target=work, daemon=True).start()
                win.after(100, poll)
            go = Btn(row, text="Run it", style="Primary.TButton", command=run_it)
            Btn(row, text="Close", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            go.grid(row=0, column=1)
            _show_modal(win, self.root)

        def read_script_quiet(self):
            path = os.path.expanduser(self.script_var.get().strip())
            try:
                if path and os.path.isfile(path) and os.path.getsize(path) < 1000000:
                    return Path(path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            return ""

        def pick_script(self):
            from tkinter import filedialog
            path = filedialog.askopenfilename(parent=self.root, title="Choose a script to run on every server")
            if path:
                self.script_var.set(path)

        def pick_put_file(self):
            from tkinter import filedialog
            path = filedialog.askopenfilename(parent=self.root, title="Choose a file to send")
            if path:
                self.put_var.set(path)

        def pick_put_folder(self):
            from tkinter import filedialog
            path = filedialog.askdirectory(parent=self.root, title="Choose a folder to send")
            if path:
                self.put_var.set(path)

        def pick_into(self):
            from tkinter import filedialog
            path = filedialog.askdirectory(parent=self.root, title="Where should the fetched files go?", mustexist=False)
            if path:
                self.into_var.set(path)

        def build_job(self):
            """The job the window describes, or None (after saying what is missing)."""
            mode = self.mode
            if mode == "cmd":
                command = self.cmd_text.get("1.0", "end").strip()
                if not command:
                    self.toast("Type the command to run.", "warn")
                    return None
                return make_job("cmd", command=command)
            if mode == "script":
                path = os.path.expanduser(self.script_var.get().strip())
                if not path:
                    self.toast("Choose the script to run.", "warn")
                    return None
                if not os.path.isfile(path):
                    self.toast("There's no file at %s." % path, "error")
                    return None
                try:
                    if os.path.getsize(path) > 1000000:
                        self.toast("That script is over 1 MB — send it as a file and run it with a command instead.", "error")
                        return None
                    job = make_job("script", script=path)
                except (OSError, UnicodeDecodeError) as e:
                    self.toast("Couldn't read the script: %s" % e, "error")
                    return None
                if not job["text"].strip():
                    self.toast("That script is empty.", "warn")
                    return None
                return job
            if mode == "put":
                local = os.path.expanduser(self.put_var.get().strip())
                if not local:
                    self.toast("Choose the file or folder to send.", "warn")
                    return None
                if not os.path.exists(local):
                    self.toast("%s doesn't exist." % local, "error")
                    return None
                return make_job("put", local=local, remote=self.put_to_var.get().strip())
            remote = self.get_var.get().strip()
            into = os.path.expanduser(self.into_var.get().strip())
            if not remote:
                self.toast("Type the path of the file to fetch.", "warn")
                return None
            if not into:
                self.toast("Choose a folder to save into.", "warn")
                return None
            return make_job("get", remote=remote, into=into)

        def build_opts(self):
            batch = BATCHES.get(self.batch_var.get(), 0)
            return dict(jobs=int(self.jobs_var.get() or 4), timeout=TIMEOUTS.get(self.timeout_var.get(), 60), batch=batch,
                        canary=bool(batch and self.canary_var.get()), stop=bool(batch and self.stop_var.get()),
                        pause=PAUSES.get(self.pause_var.get(), 0) if batch else 0, retries=RETRIES.get(self.retry_var.get(), 0),
                        sudo=bool(self.mode == "cmd" and self.sudo_var.get()),
                        hooks=[dict(h) for h in self.hooks if h["on"]] if self.mode in ("cmd", "script") else [])

        def chosen_servers(self):
            return [s for s in self.servers if self.sel[s.name].get()]

        def prepare(self, job=None, opts=None, check_service=True):
            """(servers, job, options) ready to run, or None after telling the user what's wrong."""
            job = job or self.build_job()
            if job is None:
                return None
            chosen = self.chosen_servers()
            if not chosen:
                self.toast("Pick at least one server.", "warn")
                return None
            if not self.demo:
                if check_service and self.service_ok is False:
                    self.toast("The tunnel service isn't answering — start ztr_tunnel_lp.py first.", "error")
                    return None
                for srv in chosen:
                    problems = srv.problems(ROUTES_DIR)
                    if problems:
                        self.toast("%s: %s" % (srv.name, problems[0]), "error")
                        return None
            bad = job_problems(chosen, job)
            if bad:
                self.toast("%s: %s" % bad[0], "error")
                return None
            opts = opts or self.build_opts()
            for h in opts.get("hooks", []):
                prefix, why = hook_command(h["path"])
                if prefix is None:
                    self.toast(why, "error")
                    return None
            return chosen, job, opts

        def preview(self):
            ready = self.prepare(check_service=False)
            if not ready:
                return
            chosen, job, opts = ready
            win, body = _dialog(self.root, "Preview")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="What would happen", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="Nothing has been contacted yet.", style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 8))
            lines = plan_lines(chosen, job, opts) + ["", "-" * 60, ""] + exact_lines(chosen, job, opts)
            holder = tk.Frame(body, bg=FIELD, bd=0, highlightthickness=1, highlightbackground=BORDER)
            holder.grid(row=2, column=0, sticky="ew")
            holder.columnconfigure(0, weight=1)
            box = tk.Text(holder, width=100, height=22, bg=FIELD, fg=TEXT, bd=0, highlightthickness=0, wrap="word",
                          font=UI["mono"], padx=10, pady=8, selectbackground=SEL)
            sb = ttk.Scrollbar(holder, orient="vertical", command=box.yview, style="Thin.Vertical.TScrollbar")
            box.configure(yscrollcommand=sb.set)
            box.insert("1.0", "\n".join(lines))
            box.configure(state="disabled")
            box.grid(row=0, column=0, sticky="ew")
            sb.grid(row=0, column=1, sticky="ns")
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=3, column=0, sticky="e", pady=(14, 0))
            out = {"run": False}

            def go():
                out["run"] = True
                win.destroy()
            Btn(row, text="Copy all", style="Small.TButton", command=lambda: self.copy("\n".join(lines), "Copied")).grid(row=0, column=0, padx=(0, 14))
            Btn(row, text="Close", style="Ghost.TButton", command=win.destroy).grid(row=0, column=1, padx=(0, 8))
            Btn(row, text="Run it", style="Primary.TButton", command=go).grid(row=0, column=2)
            _show_modal(win, self.root)
            if out["run"]:
                self.run()

        def ask_passwords(self, chosen):
            """The sudo passwords to use: (one for all servers, {server name: its own}), or None if cancelled."""
            win, body = _dialog(self.root, "Sudo passwords")
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="Sudo passwords", style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text="Each is sent over ssh to sudo on that server — never saved, never written to a file. "
                                 "A server that has passwordless sudo never uses its password.",
                      style="Dim.TLabel", wraplength=460, justify="left").grid(row=1, column=0, sticky="w", pady=(4, 10))
            ttk.Label(body, text="Same password for every server", style="Dim.TLabel").grid(row=2, column=0, sticky="w")
            shared = tk.StringVar()
            first = Field(body, textvariable=shared, show="•", width=40)
            first.grid(row=3, column=0, sticky="ew", pady=(4, 12))
            ttk.Label(body, text="Or a different one for particular servers" if len(chosen) > 1 else "This server's own password",
                      style="Dim.TLabel").grid(row=4, column=0, sticky="w")
            box = ScrollFrame(body, bg=CARD)
            box.grid(row=5, column=0, sticky="ew", pady=(4, 0))
            box.configure(height=min(190, 38 * len(chosen)))
            box.cv.configure(height=min(190, 38 * len(chosen)))
            box.inner.columnconfigure(1, weight=1)
            own = {}
            for i, srv in enumerate(chosen):
                own[srv.name] = tk.StringVar()
                ttk.Label(box.inner, text=srv.name, style="Bold.TLabel").grid(row=i, column=0, sticky="w", padx=(0, 12), pady=3)
                Field(box.inner, compact=True, textvariable=own[srv.name], show="•", width=30, placeholder="same as above").grid(row=i, column=1, sticky="ew", pady=3)
            out = {"pw": None}
            note = ttk.Label(body, text="", style="Warn.TLabel")
            note.grid(row=6, column=0, sticky="w", pady=(8, 0))
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=7, column=0, sticky="e", pady=(10, 0))

            def done(ok):
                if ok:
                    mine = {n: v.get() for n, v in own.items() if v.get()}
                    if not shared.get() and not mine:
                        note.configure(text="Type a password first, or untick “Send my sudo password”.")
                        return
                    out["pw"] = (shared.get(), mine)
                win.destroy()
            Btn(row, text="Cancel", style="Ghost.TButton", command=lambda: done(False)).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Use them", style="Primary.TButton", command=lambda: done(True)).grid(row=0, column=1)
            win.bind("<Return>", lambda e: done(True))
            _show_modal(win, self.root, focus=first.inner)
            return out["pw"]

        def run(self, job=None, opts=None):
            if self.runner is not None:
                return
            retry = job is not None
            ready = self.prepare(job, opts)
            if not ready:
                return
            chosen, job, opts = ready
            job = dict(job)
            text = job.get("command") or job.get("text") or ""
            serious, _notices = risks(text)
            if serious and not retry:
                if not self.confirm("This looks destructive", "It %s.\n\nIt would run on %s." % ("; and it ".join(serious), ", ".join(s.name for s in chosen)),
                                    "Run it anyway", danger=True):
                    return
            if opts.get("sudo"):
                pws = self.ask_passwords(chosen)
                if not pws:
                    return
                job["sudo_password"], job["sudo_passwords"] = pws
            self.command_run, self.kind_run = describe_job(job), job["kind"]
            self.results = {}
            self.run_order = [s.name for s in chosen]
            self.run_started = time.time()
            self.note, self.tries = "", {}
            self.followups, self.summary_hooks = [], []
            self.view = "results"
            for k, b in self.tab_btns.items():
                b.configure(selected=(k == "results"))
            self.cancel_btn.grid()
            self._show_retry(False)
            self.run_btn.configure(state="disabled", text="Running…")
            self.status = {n: "waiting" for n in self.run_order}
            self.progress.configure(value=0)
            self.render()
            self.last_job, self.last_opts = {k: v for k, v in job.items() if k not in ("sudo_password", "sudo_passwords")}, dict(opts)
            self.runner = Runner(chosen, job, opts["jobs"], opts["timeout"], self.events.put, work=demo_work if self.demo else run_job,
                                 batch=opts["batch"], canary=opts["canary"], pause=opts["pause"], stop_on_failure=opts["stop"],
                                 retries=opts["retries"], retry_wait=1.5 if self.demo else 5, hooks=opts.get("hooks", []))
            self.jobs_run, self.timeout_run = opts["jobs"], opts["timeout"]
            self.runner.start()

        def retry_failed(self):
            if self.runner is not None or not self.last_job:
                return
            bad = {n for n in self.run_order if self.results.get(n, {}).get("status") != "ok"}
            if not bad:
                return
            for srv in self.servers:
                self.sel[srv.name].set(srv.name in bad)
            self.update_count()
            self.run(job=self.last_job, opts=self.last_opts)

        # ── a shell on one server ────────────────────────────────────────
        def open_shell(self, server):
            if self.demo:
                self.toast("Demo: a terminal would open on %s." % server.name, "warn")
                return
            problems = server.problems(ROUTES_DIR)
            if problems:
                self.toast("%s: %s" % (server.name, problems[0]), "error")
                return
            if self.service_ok is False:
                self.toast("The tunnel service isn't answering — start ztr_tunnel_lp.py first.", "error")
                return
            if not core.SSH_WRAPPER.is_file():
                self.toast("ztr_ssh wasn't found next to ztr_fleet.", "error")
                return
            argv = terminal_argv(shell_argv(server), title="ZTR Fleet — " + server.name)
            if not argv:
                self.toast("No terminal program found. Set FLEET_TERMINAL, for example: xterm -e", "error")
                return
            try:
                core.KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
                subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            except OSError as e:
                self.toast("Couldn't open a terminal: %s" % e, "error")
                return
            self.toast("Opened a terminal on %s" % server.name)

        def cancel(self):
            if self.runner:
                self.runner.cancel()
                self.toast("Cancelling…", "warn")

        def _poll(self):
            try:
                while True:
                    kind, *rest = self.events.get_nowait()
                    payload = rest[0] if rest else None
                    if kind == "service":
                        self.service_ok = payload
                        self.root.after(5000, self._watch_service)
                        if payload:
                            self.set_pill(GREEN, "Tunnel service ready")
                        else:
                            self.set_pill(RED, "Tunnel service not answering")
                    elif kind == "start":
                        self.status[payload] = "running"
                        self.update_card(payload)
                    elif kind == "retry":
                        self.status[payload] = "retrying"
                        self.tries[payload] = (rest[1], rest[2])
                        self.update_card(payload)
                    elif kind == "note":
                        self.note = payload
                        self.update_summary()
                    elif kind == "summary":
                        self.summary_hooks = payload
                        for h in payload:
                            self.hook_last[h["path"]] = h["rc"]
                    elif kind == "done":
                        self.results[payload["name"]] = payload
                        for h in payload.get("hooks", []):
                            self.hook_last[h["path"]] = h["rc"]
                        self.status[payload["name"]] = payload["status"]
                        self.update_card(payload["name"])
                        self.update_summary()
                    elif kind == "finished":
                        self.finish_run()
            except queue.Empty:
                pass
            self.root.after(80, self._poll)

        def finish_run(self):
            self.runner = None
            ordered = [self.results[n] for n in self.run_order if n in self.results]
            self.run_btn.configure(state="normal")
            self.update_count()
            self.cancel_btn.grid_remove()
            for r in ordered:
                if r["status"] != "skipped":
                    self.last[r["name"]] = r["status"]
            try:
                add_history(self.command_run, ordered, self.jobs_run, self.timeout_run, kind=self.kind_run)
            except OSError:
                pass
            if not self.note.startswith("Stopping"):
                self.note = ""
            self.followups = collect_followups(ordered + [dict(hooks=self.summary_hooks)])
            self.rebuild_servers()
            if self.view == "results" and (self.followups or self.summary_hooks):
                self.render()
            self.update_summary(final=True)
            if self.view == "results":
                self.draw_bars()
            bad = sum(1 for r in ordered if r["status"] != "ok")
            if bad and self.last_job:
                self._show_retry(True)
            skipped = sum(1 for r in ordered if r["status"] == "skipped")
            self.toast("Done: %d ok%s%s" % (len(ordered) - bad, (", %d did not succeed" % (bad - skipped)) if bad - skipped else "",
                                             (", %d not run" % skipped) if skipped else ""), "ok" if not bad else "warn")

        def update_summary(self, final=False):
            total = len(self.run_order)
            done = len(self.results)
            ok = sum(1 for r in self.results.values() if r["status"] == "ok")
            skipped = sum(1 for r in self.results.values() if r["status"] == "skipped")
            bad = done - ok - skipped
            elapsed = int(time.time() - self.run_started)
            parts = ["%d of %d done" % (done, total)] if not final else ["%d server%s" % (total, "" if total == 1 else "s")]
            parts.append("%d ok" % ok)
            if bad:
                parts.append("%d did not succeed" % bad)
            if skipped:
                parts.append("%d not run" % skipped)
            parts.append("%ds" % elapsed)
            if self.note and not final or self.note.startswith("Stopping"):
                parts.append(self.note)
            what = ("$ " if self.kind_run == "cmd" else "") + (self.command_run.splitlines()[0][:60] if self.command_run else "")
            self.summary_label.configure(text="  ·  ".join(parts) + (("   —   " + what) if self.command_run else ""))
            self.progress.configure(value=100.0 * done / max(1, total))

        # ── what is shown ────────────────────────────────────────────────
        def show_view(self, key):
            self.view = key
            for k, b in self.tab_btns.items():
                b.configure(selected=(k == key))
            self.render()

        def render(self):
            self.result_scroll.clear()
            inner = self.result_scroll.inner
            inner.columnconfigure(0, weight=1)
            self.cards = {}
            if self.view == "ignore":
                return
            if self.view == "results":
                self.render_answers(inner)
            elif self.view == "compare":
                self.render_compare(inner)
            elif self.view == "schedules":
                self.render_schedules(inner)
            else:
                self.render_history(inner)
            if self.view == "compare":
                self.ignore_check.grid()
            else:
                self.ignore_check.grid_remove()
            for b in (self.copy_btn, self.save_btn):
                if self.view == "schedules":
                    b.grid_remove()
                else:
                    b.grid()
            self._show_retry()

        def empty(self, inner, title, text):
            box = tk.Frame(inner, bg=CARD)
            box.grid(row=0, column=0, sticky="ew", pady=40)
            tk.Label(box, text=title, bg=CARD, fg=TEXT, font=UI["h"]).pack()
            tk.Label(box, text=text, bg=CARD, fg=DIM, font=UI["body"], justify="center").pack(pady=(4, 0))

        def render_answers(self, inner):
            if not self.run_order:
                self.summary_label.configure(text="")
                self.progress.configure(value=0)
                self.empty(inner, "Nothing run yet", "Choose what to run, pick your servers, and press Run.\nEvery server's answer shows up here as soon as it arrives.")
                return
            offset = 0
            if self.followups:
                self.make_followups(inner, 0)
                offset = 1
            for i, name in enumerate(self.run_order):
                self.cards[name] = self.make_card(inner, i + offset, name)
                self.update_card(name)
            if self.summary_hooks:
                self.make_summary_card(inner, len(self.run_order) + offset)
            self.update_summary(final=self.runner is None)
            if self.runner is None:
                self.draw_bars()

        def make_followups(self, inner, row):
            """Next steps that hooks proposed. Nothing here runs by itself: Review fills the composer and opens the preview."""
            card = Card(inner, radius=12, pad=(14, 10), border="#7a6226")
            card.grid(row=row, column=0, sticky="ew", pady=(0, 8))
            b = card.body
            b.columnconfigure(0, weight=1)
            ttk.Label(b, text="Suggested next step%s" % ("" if len(self.followups) == 1 else "s"), style="Bold.TLabel", foreground=AMBER).grid(row=0, column=0, sticky="w")
            ttk.Label(b, text="Proposed by your hooks from what the servers answered. Nothing runs until you review it and press Run.", style="Dim.TLabel",
                      wraplength=520, justify="left").grid(row=1, column=0, sticky="w", pady=(0, 6))
            for i, n in enumerate(self.followups):
                box = ttk.Frame(b, style="Card.TFrame")
                box.grid(row=2 + i, column=0, sticky="ew", pady=(4, 0))
                box.columnconfigure(0, weight=1)
                ttk.Label(box, text=n["title"], style="Bold.TLabel").grid(row=0, column=0, sticky="w")
                targets, missing = followup_targets(n, self.servers)
                where = "every server" if n["all"] else ", ".join(t.name for t in targets) or "no server in the fleet"
                tk.Label(box, text=n["command"][:200], bg=CARD, fg="#d7d7dc", font=UI["mono"], anchor="w", justify="left").grid(row=1, column=0, sticky="w")
                ttk.Label(box, text="on %s  ·  from %s%s" % (where, n["source"] or "a hook", ("  ·  not in the fleet: " + ", ".join(missing)) if missing else ""),
                          style="Dim.TLabel").grid(row=2, column=0, sticky="w")
                btns = ttk.Frame(box, style="Card.TFrame")
                btns.grid(row=0, column=1, rowspan=3, sticky="e")
                Btn(btns, text="Review…", style="Small.TButton", command=lambda n=n: self.review_followup(n)).grid(row=0, column=0, padx=(0, 6))
                Btn(btns, text="Dismiss", style="Small.TButton", command=lambda n=n: self.dismiss_followup(n)).grid(row=0, column=1)

        def dismiss_followup(self, proposal):
            self.followups = [n for n in self.followups if n is not proposal]
            self.render()

        def review_followup(self, proposal):
            if self.runner is not None:
                self.toast("Wait for the current run to finish.", "warn")
                return
            targets, missing = followup_targets(proposal, self.servers)
            if not targets:
                self.toast("None of its servers are in the fleet file.", "error")
                return
            for srv in self.servers:
                self.sel[srv.name].set(any(srv is t for t in targets))
            self.set_mode("cmd")
            self.cmd_text.delete("1.0", "end")
            self.cmd_text.insert("1.0", proposal["command"])
            self.update_hint()
            self.update_count()
            if missing:
                self.toast("Not in the fleet file, left out: %s" % ", ".join(missing), "warn")
            self.preview()

        def make_summary_card(self, inner, row):
            card = Card(inner, radius=12, pad=(14, 10))
            card.grid(row=row, column=0, sticky="ew", pady=(0, 8))
            b = card.body
            b.columnconfigure(0, weight=1)
            ttk.Label(b, text="Whole-run scripts", style="Bold.TLabel").grid(row=0, column=0, sticky="w")
            for i, h in enumerate(self.summary_hooks):
                ok = h["rc"] == 0
                ttk.Label(b, text="%s  ·  %s  ·  %ds" % (h["name"], "ran" if ok else "failed (exit %s)" % h["rc"], h["secs"]), style="Dim.TLabel",
                          foreground=GREEN if ok else AMBER).grid(row=1 + 2 * i, column=0, sticky="w", pady=(6, 0))
                text = (h["out"] if ok else "\n".join(t for t in (h["err"], h["out"]) if t)) or "(it printed nothing)"
                lines = text.splitlines()
                tk.Label(b, text="\n".join(lines[:10]) + ("\n… %d more" % (len(lines) - 10) if len(lines) > 10 else ""), bg=CARD, fg="#d7d7dc" if ok else AMBER,
                         font=UI["mono"], justify="left", anchor="w", wraplength=560).grid(row=2 + 2 * i, column=0, sticky="w")

        def make_card(self, inner, row, name):
            card = Card(inner, radius=12, pad=(14, 10))
            card.grid(row=row, column=0, sticky="ew", pady=(0, 8))
            b = card.body
            b.columnconfigure(0, weight=0)
            b.columnconfigure(1, weight=1)
            glyph = Glyph(b, "wait", size=20)
            glyph.grid(row=0, column=0, padx=(0, 10), sticky="n")
            srv = next((x for x in self.servers if x.name == name), None)
            flag = flag_image(route_country(srv.route)) if srv else None
            title = ttk.Label(b, text=(" " + name) if flag else name, image=flag or "", compound="left", style="Bold.TLabel")
            title.grid(row=0, column=1, sticky="w")
            status = ttk.Label(b, text="", style="Dim.TLabel")
            status.grid(row=0, column=2, sticky="e")
            Btn(b, text="Shell", style="Small.TButton", command=lambda n=name: self.open_shell(next(s for s in self.servers if s.name == n))).grid(
                row=0, column=3, sticky="e", padx=(10, 0))
            sub = ttk.Label(b, text="", style="Dim.TLabel")
            sub.grid(row=1, column=1, sticky="w")
            view = Btn(b, text="Full answer", style="Small.TButton", command=lambda n=name: self.show_full(n))
            view.grid(row=1, column=2, columnspan=2, sticky="e", pady=(4, 0))
            view.grid_remove()
            out = tk.Label(b, text="", bg=CARD, fg="#d7d7dc", font=UI["mono"], justify="left", anchor="w", wraplength=520)
            out.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(6, 0))
            autowrap(out)
            bar = tk.Canvas(b, height=4, bg=CARD, highlightthickness=0)
            bar.grid(row=3, column=1, columnspan=3, sticky="ew", pady=(8, 0))
            card.configure()
            for w in (b,) + tuple(b.winfo_children()):
                bind_context_menu(w, lambda e, n=name: self.card_menu(e, n))
            out.bind("<Double-Button-1>", lambda e, n=name: self.show_full(n))
            return dict(card=card, glyph=glyph, status=status, sub=sub, out=out, bar=bar, view=view, expanded=False)

        def card_menu(self, event, name):
            r = self.results.get(name)
            menu = tk.Menu(self.root, **self.menu_kw)
            menu.add_command(label="Show the full answer", command=lambda: self.show_full(name), state="normal" if r else "disabled")
            menu.add_command(label="Copy answer", command=lambda: self.copy((r or {}).get("out", ""), "Answer copied"), state="normal" if r else "disabled")
            menu.add_command(label="Open a shell", command=lambda: self.open_shell(next(s for s in self.servers if s.name == name)))
            menu.add_command(label="Run again on this one", command=lambda: self.rerun_one(name), state="normal" if self.last_job and self.runner is None else "disabled")
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        def show_full(self, name):
            """A window with one server's complete answer (or its error), to read, copy or save."""
            r = self.results.get(name)
            if not r:
                return
            ok = r["status"] == "ok"
            text = r["out"] if ok else "\n".join(t for t in (r.get("err"), r["out"]) if t)
            win, body = _dialog(self.root, "Answer from " + name)
            body.columnconfigure(0, weight=1)
            word = STATUS.get(r["status"], ("", r["status"], DIM))[1]
            ttk.Label(body, text="%s  ·  %s  ·  %ds" % (name, word, r["secs"]), style="H.TLabel").grid(row=0, column=0, sticky="w")
            lines = text.count("\n") + 1 if text else 0
            note = "%d line%s, %d characters" % (lines, "" if lines == 1 else "s", len(text))
            if not r.get("ended") and len(r["out"]) >= core.OUTPUT_KEEP:
                note += " — the history keeps only the first %d characters of each answer" % core.OUTPUT_KEEP
            ttk.Label(body, text=note, style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 8))
            holder = tk.Frame(body, bg=FIELD, bd=0, highlightthickness=1, highlightbackground=BORDER)
            holder.grid(row=2, column=0, sticky="ew")
            holder.columnconfigure(0, weight=1)
            box = tk.Text(holder, width=100, height=26, bg=FIELD, fg="#d7d7dc" if ok else AMBER, bd=0, highlightthickness=0, wrap="none",
                          font=UI["mono"], padx=10, pady=8, selectbackground=SEL)
            ys = ttk.Scrollbar(holder, orient="vertical", command=box.yview, style="Thin.Vertical.TScrollbar")
            xs = ttk.Scrollbar(holder, orient="horizontal", command=box.xview, style="Thin.Horizontal.TScrollbar")
            box.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
            shown_text = text if text else "(no output)"
            for h in r.get("hooks", []):
                shown_text += "\n\n── %s: %s ──\n%s" % (h["name"], "ran" if h["rc"] == 0 else "exit %s" % h["rc"],
                                                     (h["out"] if h["rc"] == 0 else "\n".join(t for t in (h["err"], h["out"]) if t)) or "(no output)")
            box.insert("1.0", shown_text)
            box.configure(state="disabled")
            box.grid(row=0, column=0, sticky="ew")
            ys.grid(row=0, column=1, sticky="ns")
            xs.grid(row=1, column=0, sticky="ew")
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=3, column=0, sticky="e", pady=(14, 0))

            def save():
                from tkinter import filedialog
                path = filedialog.asksaveasfilename(parent=win, title="Save this answer", defaultextension=".txt", initialfile="%s.txt" % name)
                if path:
                    try:
                        Path(path).write_text(text + "\n", encoding="utf-8")
                        self.toast("Saved %s" % Path(path).name)
                    except OSError as e:
                        self.toast("Couldn't save: %s" % e, "error")
            Btn(row, text="Copy", style="Small.TButton", command=lambda: self.copy(text, "Answer copied")).grid(row=0, column=0, padx=(0, 6))
            Btn(row, text="Save…", style="Small.TButton", command=save).grid(row=0, column=1, padx=(0, 14))
            Btn(row, text="Close", style="Primary.TButton", command=win.destroy).grid(row=0, column=2)
            win.bind("<Escape>", lambda e: win.destroy())
            _show_modal(win, self.root)

        def rerun_one(self, name):
            if self.runner is not None or not self.last_job:
                return
            for srv in self.servers:
                self.sel[srv.name].set(srv.name == name)
            self.update_count()
            self.run(job=self.last_job, opts=self.last_opts)

        def update_card(self, name):
            c = self.cards.get(name)
            if not c:
                return
            state = self.status.get(name, "waiting")
            glyph, word, color = STATUS[state]
            c["glyph"].set(glyph)
            r = self.results.get(name)
            route = next((s.route for s in self.servers if s.name == name), "")
            sub = route
            if state == "retrying" and name in self.tries:
                sub += "  ·  try %d of %d" % self.tries[name]
            elif r and r.get("attempts", 1) > 1:
                sub += "  ·  tried %d times" % r["attempts"]
            if r and r.get("hooks"):
                bad = [h["name"] for h in r["hooks"] if h["rc"] != 0]
                sub += ("  ·  %s failed" % ", ".join(bad)) if bad else ("  ·  %d script%s ran" % (len(r["hooks"]), "" if len(r["hooks"]) == 1 else "s"))
            c["sub"].configure(text=sub)
            if r:
                word = "%s  ·  %ds" % (word if state != "failed" else "Failed (exit %s)" % r["rc"], r["secs"])
                text = r["out"] if state == "ok" else (r.get("err") or r["out"] or "")
                lines = text.splitlines()
                shown = "\n".join(lines[:8]) + (("\n… %d more line%s" % (len(lines) - 8, "" if len(lines) - 8 == 1 else "s")) if len(lines) > 8 else "")
                if state == "ok" and not text:
                    shown = "(no output)"
                c["out"].configure(text=shown, fg="#d7d7dc" if state == "ok" else (RED if state == "failed" else DIM if state == "skipped" else AMBER))
                if text.strip() and state != "skipped":
                    c["view"].grid()
            else:
                c["out"].configure(text="")
                c["view"].grid_remove()
            c["status"].configure(text=word, foreground=color)

        def draw_bars(self):
            if not self.results:
                return
            peak = max(1, max(r["secs"] for r in self.results.values()))
            for name, c in self.cards.items():
                r = self.results.get(name)
                bar = c["bar"]
                bar.delete("all")
                if not r:
                    continue
                w = max(bar.winfo_width(), 100)
                color = {"ok": GREEN, "failed": RED, "skipped": "#55555a"}.get(r["status"], AMBER)
                bar.create_rectangle(0, 0, w, 4, fill="#343438", outline="")
                bar.create_rectangle(0, 0, max(6, int(w * r["secs"] / peak)), 4, fill=color, outline="")

        def render_compare(self, inner):
            done = [self.results[n] for n in self.run_order if n in self.results]
            if not done:
                self.empty(inner, "Nothing to compare yet", "Run a command, then see which servers answered the same way\nand which are the odd ones out.")
                return
            groups = group_outputs(done, self.ignore_var.get())
            self.summary_label.configure(text="%d server%s, %d different answer%s" % (len(done), "" if len(done) == 1 else "s", len(groups), "" if len(groups) == 1 else "s"))
            for i, g in enumerate(groups):
                odd = i > 0 or not g["ok"]
                card = Card(inner, radius=12, pad=(14, 10), border="#7a6226" if (odd and g["ok"]) else (BORDER if g["ok"] else "#6a2f2c"))
                card.grid(row=i, column=0, sticky="ew", pady=(0, 8))
                b = card.body
                b.columnconfigure(0, weight=0)
                b.columnconfigure(1, weight=1)
                n = len(g["members"])
                if not g["ok"]:
                    head, color, glyph = "%d did not succeed" % n if n > 1 else "Did not succeed", RED, "fail"
                elif i == 0:
                    head, color, glyph = ("All %d answered the same" % n) if n == len(done) else ("%d answered the same — the most common answer" % n), GREEN, "done"
                else:
                    head, color, glyph = ("%d answered differently" % n) if n > 1 else "1 answered differently", AMBER, "warn"
                Glyph(b, glyph, size=20).grid(row=0, column=0, padx=(0, 10), sticky="n")
                ttk.Label(b, text=head, style="Bold.TLabel", foreground=color).grid(row=0, column=1, sticky="w")
                ttk.Label(b, text=",  ".join(g["members"]), style="Dim.TLabel", wraplength=480, justify="left").grid(row=1, column=1, sticky="w")
                for hrow, htext, hcolor in self.hook_lines(g["members"]):
                    tk.Label(b, text=htext, bg=CARD, fg=hcolor, font=UI["small"], justify="left", anchor="w", wraplength=520).grid(row=10 + hrow, column=1, sticky="w", pady=(4 if hrow == 0 else 0, 0))
                text = g["text"] if g["text"].strip() else ("(no output)" if g["ok"] else "")
                lines = text.splitlines()
                shown = "\n".join(lines[:8]) + ("\n…" if len(lines) > 8 else "")
                if shown:
                    out = tk.Label(b, text=shown, bg=CARD, fg="#d7d7dc" if g["ok"] else AMBER, font=UI["mono"], justify="left", anchor="w", wraplength=520)
                    out.grid(row=2, column=1, sticky="ew", pady=(6, 0))
                    autowrap(out)

        # ── scheduled jobs ───────────────────────────────────────────────
        def last_scheduled_run(self, name):
            """(when, 'all ok' / 'N did not succeed') of the newest history entry a schedule made for this job, or None."""
            for entry in load_history():
                if entry.get("source") == "scheduled: %s" % name:
                    res = entry.get("results", [])
                    bad = sum(1 for r in res if r["status"] != "ok")
                    return age_text(entry.get("ts", 0)), ("all ok" if not bad else "%d did not succeed" % bad), not bad
            return None

        def render_schedules(self, inner):
            self.summary_label.configure(text="%d saved job%s" % (len(self.saved_jobs), "" if len(self.saved_jobs) == 1 else "s"))
            self.progress.configure(value=0)
            why = None if self.demo else schedule_available()
            row = 0
            if why:
                tk.Label(inner, text="Schedules can't be switched on here: %s" % why, bg=CARD, fg=AMBER, font=UI["small"], justify="left", anchor="w", wraplength=560).grid(row=row, column=0, sticky="w", pady=(0, 8))
                row += 1
            if not self.saved_jobs:
                box = tk.Frame(inner, bg=CARD)
                box.grid(row=row, column=0, sticky="ew", pady=40)
                tk.Label(box, text="No schedules yet", bg=CARD, fg=TEXT, font=UI["h"]).pack()
                tk.Label(box, text="Set up a run in the composer — command or script, the servers, any options —\nthen press Schedule… to repeat it automatically. Each run lands in History,\nand your hooks get its answers like any other run.",
                         bg=CARD, fg=DIM, font=UI["body"], justify="center").pack(pady=(4, 0))
                return
            for j in self.saved_jobs:
                st = {"active": j["on"], "next": "", "last": ""} if self.demo else schedule_status(j["name"])
                card = Card(inner, radius=12, pad=(14, 10))
                card.grid(row=row, column=0, sticky="ew", pady=(0, 8))
                row += 1
                b = card.body
                b.columnconfigure(0, weight=1)
                head = ttk.Frame(b, style="Card.TFrame")
                head.grid(row=0, column=0, sticky="w")
                ttk.Label(head, text=j["name"], style="Bold.TLabel").pack(side="left")
                ttk.Label(head, text="   " + ("Active" if st["active"] else "Paused"), style="Dim.TLabel", foreground=GREEN if st["active"] else AMBER).pack(side="left")
                when = describe_schedule(j["sched"]) + (("  ·  next run %s" % st["next"]) if st["active"] and st["next"] else "")
                ttk.Label(b, text=when, style="Dim.TLabel").grid(row=1, column=0, sticky="w")
                what = j["command"] if j["mode"] == "cmd" else "script " + os.path.basename(j["script"])
                tk.Label(b, text=what[:110] + ("…" if len(what) > 110 else ""), bg=CARD, fg="#d7d7dc", font=UI["mono"], anchor="w").grid(row=2, column=0, sticky="w", pady=(4, 0))
                where = "every server" if j["all"] else ", ".join(j["servers"] + (["group " + j["group"]] if j["group"] else []))
                ttk.Label(b, text="on %s%s" % (where, "  ·  hands answers to your switched-on hooks" if j["hooks"] == "saved" else ""), style="Dim.TLabel").grid(row=3, column=0, sticky="w")
                last = self.last_scheduled_run(j["name"])
                problem = st.get("problem") or ""
                if problem:  # switched on, but the system can't start it: say so instead of "hasn't run yet"
                    tk.Label(b, text=problem, bg=CARD, fg=AMBER, font=UI["small"], justify="left", anchor="w", wraplength=520).grid(row=4, column=0, sticky="w", pady=(6, 0))
                if last:
                    ttk.Label(b, text="Last run %s  ·  %s" % last[:2], style="Dim.TLabel", foreground=GREEN if last[2] else AMBER).grid(row=5, column=0, sticky="w")
                elif st.get("runs"):
                    ttk.Label(b, text="Started %d time%s, but no run has finished yet%s" % (st["runs"], "" if st["runs"] == 1 else "s", " — see the Log" if st.get("log") else ""),
                              style="Dim.TLabel", foreground=AMBER if problem or st.get("log") else DIM).grid(row=5, column=0, sticky="w")
                elif not problem:
                    ttk.Label(b, text="Hasn't run yet", style="Dim.TLabel", foreground=DIM).grid(row=5, column=0, sticky="w")
                btns = ttk.Frame(b, style="Card.TFrame")
                btns.grid(row=0, column=1, rowspan=6, sticky="ne")
                Btn(btns, text="Run now", style="Small.TButton", command=lambda j=j: self.run_saved_now(j)).grid(row=0, column=0, padx=(0, 6), pady=(0, 6))
                Btn(btns, text="Edit…", style="Small.TButton", command=lambda j=j: self.schedule_dialog(j)).grid(row=0, column=1, padx=(0, 6), pady=(0, 6))
                Btn(btns, text="Resume" if not st["active"] else "Pause", style="Small.TButton", command=lambda j=j, a=st["active"]: self.toggle_job(j, not a)).grid(row=1, column=0, padx=(0, 6))
                Btn(btns, text="Load in composer", style="Small.TButton", command=lambda j=j: self.load_job_into_composer(j)).grid(row=1, column=1, padx=(0, 6))
                Btn(btns, text="Delete", style="Small.TButton", command=lambda j=j: self.delete_job(j)).grid(row=1, column=2)
                if st.get("log"):
                    Btn(btns, text="Log", style="Small.TButton", command=lambda j=j: self.show_job_log(j)).grid(row=0, column=2, pady=(0, 6))
            if sys.platform != "darwin" and not self.demo:
                tk.Label(inner, text="On Linux a schedule runs while you are logged in. To keep it running after you log out: loginctl enable-linger $USER",
                         bg=CARD, fg=DIM, font=UI["small"], justify="left", anchor="w", wraplength=560).grid(row=row, column=0, sticky="w", pady=(4, 0))

        def show_job_log(self, j):
            """A window with the end of a scheduled job's log (macOS keeps one per job; launchd keeps nothing itself)."""
            path = job_log_path(j["name"])
            try:
                lines = path.read_text(errors="replace").splitlines()[-300:]
            except OSError:
                lines = []
            text = "\n".join(lines) or "(nothing has been written yet)"
            win, body = _dialog(self.root, "Log of " + j["name"])
            body.columnconfigure(0, weight=1)
            ttk.Label(body, text="%s  ·  the newest %d line%s" % (j["name"], len(lines), "" if len(lines) == 1 else "s"), style="H.TLabel").grid(row=0, column=0, sticky="w")
            ttk.Label(body, text=str(path), style="Dim.TLabel").grid(row=1, column=0, sticky="w", pady=(2, 8))
            holder = tk.Frame(body, bg=FIELD, bd=0, highlightthickness=1, highlightbackground=BORDER)
            holder.grid(row=2, column=0, sticky="ew")
            holder.columnconfigure(0, weight=1)
            box = tk.Text(holder, width=100, height=18, bg=FIELD, fg="#d7d7dc", bd=0, highlightthickness=0, wrap="none", font=UI["mono"], padx=10, pady=8, selectbackground=SEL)
            ys = ttk.Scrollbar(holder, orient="vertical", command=box.yview, style="Thin.Vertical.TScrollbar")
            box.configure(yscrollcommand=ys.set)
            box.insert("1.0", text)
            box.see("end")
            box.configure(state="disabled")
            box.grid(row=0, column=0, sticky="ew")
            ys.grid(row=0, column=1, sticky="ns")
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=3, column=0, sticky="e", pady=(14, 0))
            Btn(row, text="Copy", style="Small.TButton", command=lambda: self.copy(text, "Log copied")).grid(row=0, column=0, padx=(0, 6))
            Btn(row, text="Close", style="Primary.TButton", command=win.destroy).grid(row=0, column=1)
            win.bind("<Escape>", lambda e: win.destroy())
            _show_modal(win, self.root)

        def persist_jobs(self):
            try:
                save_saved_jobs(self.saved_jobs)
            except OSError as e:
                self.toast("Couldn't save the jobs: %s" % e, "error")

        def apply_schedule(self, j):
            """Switches a saved job's timer on or off to match j['on']. Returns a message when it didn't work."""
            if self.demo:
                return None
            if not j["on"]:
                remove_schedule(j["name"])
                return None
            why = schedule_available()
            if why:
                j["on"] = False
                return why
            ok, text = install_schedule(j)
            if not ok:
                j["on"] = False
                return text
            return None

        def toggle_job(self, j, on):
            j["on"] = on
            problem = self.apply_schedule(j)
            self.persist_jobs()
            self.toast(problem if problem else ("Resumed %s" % j["name"] if on else "Paused %s" % j["name"]), "error" if problem else "ok")
            self.render()

        def delete_job(self, j):
            if self.confirm("Delete %s?" % j["name"], "Its schedule is switched off and it is removed from the list. Past runs stay in History.", "Delete", danger=True):
                if not self.demo:
                    remove_schedule(j["name"])
                self.saved_jobs = [x for x in self.saved_jobs if x["name"] != j["name"]]
                self.persist_jobs()
                self.render()

        def load_job_into_composer(self, j):
            """Puts a saved job's command, servers and options back in the composer, to change and save again under the same name."""
            if self.runner is not None:
                return
            self.set_mode(j["mode"])
            if j["mode"] == "cmd":
                self.cmd_text.delete("1.0", "end")
                self.cmd_text.insert("1.0", j["command"])
            else:
                self.script_var.set(j["script"])
            names = {s.name for s in self.servers if j["all"] or s.name in j["servers"] or (j["group"] and s.group == j["group"])}
            for srv in self.servers:
                self.sel[srv.name].set(srv.name in names)
            o = j["opts"]
            back = lambda table, value: next((k for k, v in table.items() if v == value), next(iter(table)))
            self.jobs_var.set(str(o["jobs"]))
            self.timeout_var.set(back(TIMEOUTS, o["timeout"]))
            self.batch_var.set(back(BATCHES, o["batch"]))
            self.canary_var.set(bool(o["canary"]))
            self.stop_var.set(bool(o["stop"]))
            self.pause_var.set(back(PAUSES, o["pause"]))
            self.retry_var.set(back(RETRIES, o["retries"]))
            self.update_rolling()
            self.update_hint()
            self.update_count()
            self.toast("Loaded %s — change it, then press Schedule… and keep the name to replace it." % j["name"])

        def run_saved_now(self, j):
            if self.runner is not None:
                return
            problems = saved_job_problems(j)
            if problems:
                self.toast(problems[0], "error")
                return
            chosen, gone = saved_job_servers(j, self.servers)
            if not chosen:
                self.toast("None of its servers are in the fleet file any more.", "error")
                return
            for srv in self.servers:
                self.sel[srv.name].set(any(srv is c for c in chosen))
            try:
                job = make_job("cmd", command=j["command"]) if j["mode"] == "cmd" else make_job("script", script=j["script"])
            except OSError as e:
                self.toast("Couldn't read the script: %s" % e, "error")
                return
            o = j["opts"]
            opts = dict(jobs=o["jobs"], timeout=o["timeout"], batch=o["batch"], canary=bool(o["batch"] and o["canary"]), stop=bool(o["batch"] and o["stop"]),
                        pause=o["pause"] if o["batch"] else 0, retries=o["retries"], sudo=False,
                        hooks=[dict(h) for h in self.hooks if h["on"]] if j["hooks"] == "saved" else [])
            self.update_count()
            self.run(job=job, opts=opts)

        def schedule_dialog(self, existing):
            """Save the composer's run as a job with a schedule — or change an existing job's name, schedule and hooks."""
            new = existing is None
            if new:
                if self.mode not in ("cmd", "script"):
                    self.toast("Only commands and scripts can be scheduled.", "warn")
                    return
                if self.sudo_var.get():
                    self.toast("A scheduled run can't ask for a sudo password. Use passwordless sudo for it, and untick the box.", "error")
                    return
                ready = self.prepare(check_service=False)
                if not ready:
                    return
                chosen, job, opts = ready
                spec = dict(mode=job["kind"], command=job.get("command", ""), script=job.get("script", ""), servers=[c.name for c in chosen],
                            opts={k: opts[k] for k in DEFAULT_OPTS if k in opts})
                shown = describe_job(job)
            else:
                spec = dict(existing)
                shown = existing["command"] if existing["mode"] == "cmd" else "script " + os.path.basename(existing["script"])
                chosen = None
            win, body = _dialog(self.root, "Schedule" if new else "Edit " + existing["name"])
            body.columnconfigure(1, weight=1)
            ttk.Label(body, text="Run this on a schedule" if new else "Edit " + existing["name"], style="H.TLabel").grid(row=0, column=0, columnspan=3, sticky="w")
            tk.Label(body, text=shown[:90] + ("…" if len(shown) > 90 else ""), bg=CARD, fg="#d7d7dc", font=UI["mono"], anchor="w").grid(row=1, column=0, columnspan=3, sticky="w", pady=(4, 0))
            n = len(spec["servers"]) if new else len(existing["servers"])
            ttk.Label(body, text=("on %d server%s, the way the composer has it set up" % (n, "" if n == 1 else "s")) if new else
                      "Change what it runs with “Load in composer”, then Schedule… again with the same name.", style="Dim.TLabel").grid(row=2, column=0, columnspan=3, sticky="w", pady=(0, 10))
            name = tk.StringVar(value="" if new else existing["name"])
            ttk.Label(body, text="Name").grid(row=3, column=0, sticky="w", padx=(0, 14), pady=4)
            Field(body, compact=True, textvariable=name, width=30, placeholder="for example firewall-audit").grid(row=3, column=1, columnspan=2, sticky="ew", pady=4)
            sc = norm_schedule(None if new else existing["sched"])
            kind = tk.StringVar(value=sc["kind"])
            every_n = tk.StringVar(value=str(sc["minutes"] // 60 if sc["kind"] == "every" and sc["minutes"] % 60 == 0 else sc.get("minutes", 1) if sc["kind"] == "every" else 1))
            every_unit = tk.StringVar(value="hours" if sc["kind"] != "every" or sc["minutes"] % 60 == 0 else "minutes")
            at = tk.StringVar(value=sc.get("at", "03:00"))
            day = tk.StringVar(value=sc.get("day", "mon").capitalize())
            ttk.Label(body, text="When").grid(row=4, column=0, sticky="nw", padx=(0, 14), pady=(10, 0))
            pick = ttk.Frame(body, style="Card.TFrame")
            pick.grid(row=4, column=1, columnspan=2, sticky="w", pady=(8, 0))
            Radio(pick, text="Every", value="every", variable=kind).grid(row=0, column=0, sticky="w")
            Field(pick, compact=True, textvariable=every_n, width=4).grid(row=0, column=1, padx=(0, 6))
            Combo(pick, compact=True, textvariable=every_unit, state="readonly", width=8, values=["minutes", "hours"]).grid(row=0, column=2)
            Radio(pick, text="Every day at", value="daily", variable=kind).grid(row=1, column=0, sticky="w", pady=(6, 0))
            Field(pick, compact=True, textvariable=at, width=6, placeholder="03:00").grid(row=1, column=1, pady=(6, 0))
            Radio(pick, text="Every week on", value="weekly", variable=kind).grid(row=2, column=0, sticky="w", pady=(6, 0))
            Combo(pick, compact=True, textvariable=day, state="readonly", width=6, values=[d.capitalize() for d in DAYS]).grid(row=2, column=1, pady=(6, 0))
            hooks_on = tk.BooleanVar(value=(any(h["on"] for h in self.hooks) if new else existing["hooks"] == "saved"))
            Check(body, text="Give each answer to my switched-on hooks", variable=hooks_on).grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 0))
            why = None if self.demo else schedule_available()
            msg = ttk.Label(body, text=("It will be saved but not switched on: %s" % why) if why else "", style="Warn.TLabel", wraplength=480, justify="left")
            msg.grid(row=6, column=0, columnspan=3, sticky="w", pady=(8, 0))
            row = ttk.Frame(body, style="Card.TFrame")
            row.grid(row=7, column=0, columnspan=3, sticky="e", pady=(12, 0))

            def save():
                label = name.get().strip()
                if not NAME_RE.match(label):
                    msg.configure(text="Give it a name using letters, digits, . _ -")
                    return
                if kind.get() == "every":
                    try:
                        count = int(every_n.get())
                        assert count >= 1
                    except (ValueError, AssertionError):
                        msg.configure(text="“Every” needs a whole number, 1 or more.")
                        return
                    schedule = dict(kind="every", minutes=count * (60 if every_unit.get() == "hours" else 1))
                else:
                    if not re.match(r"^\d{1,2}:\d{2}$", at.get().strip()) or int(at.get().split(":")[0]) > 23 or int(at.get().split(":")[1]) > 59:
                        msg.configure(text="Type the time as HH:MM, for example 03:00.")
                        return
                    schedule = dict(kind=kind.get(), at=at.get().strip(), day=day.get().lower())
                clash = any(x["name"] == label and (new or x["name"] != existing["name"]) for x in self.saved_jobs)
                if clash and not self.confirm("Replace %s?" % label, "A job with that name exists. It is replaced, and its schedule updated." , "Replace"):
                    return
                if new:
                    serious, _notes = risks(spec["command"] or (Path(spec["script"]).read_text(encoding="utf-8", errors="replace") if spec["script"] else ""))
                    if serious and not self.confirm("This looks destructive", "It %s. A schedule would repeat it on %s without asking again." % (
                            "; and it ".join(serious), "%d servers" % len(spec["servers"])), "Schedule it anyway", danger=True):
                        return
                    job_spec = norm_saved_job(dict(spec, name=label, sched=schedule, hooks="saved" if hooks_on.get() else "none", on=True,
                                                   file="" if self.demo else str(self.fleet_path)))
                else:
                    job_spec = norm_saved_job(dict(existing, name=label, sched=schedule, hooks="saved" if hooks_on.get() else "none"))
                    if label != existing["name"] and not self.demo:
                        remove_schedule(existing["name"])
                problem = self.apply_schedule(job_spec)
                self.saved_jobs = [x for x in self.saved_jobs if x["name"] not in (label, None if new else existing["name"])] + [job_spec]
                self.persist_jobs()
                win.destroy()
                self.toast(("Saved %s — %s" % (label, problem)) if problem else "Scheduled %s: %s" % (label, describe_schedule(schedule)), "warn" if problem else "ok")
                self.show_view("schedules")
            Btn(row, text="Cancel", style="Ghost.TButton", command=win.destroy).grid(row=0, column=0, padx=(0, 8))
            Btn(row, text="Save", style="Primary.TButton", command=save).grid(row=0, column=1)
            _show_modal(win, self.root)

        def hook_lines(self, members):
            """What each hook printed for these servers: one line when they all got the same thing, else one line per server."""
            per_hook = {}
            for name in members:
                for h in self.results.get(name, {}).get("hooks", []):
                    per_hook.setdefault(h["name"], []).append((name, h))
            lines = []
            for hook, items in per_hook.items():
                outs = {(h["rc"], h["out"] if h["rc"] == 0 else h["err"] or h["out"]) for _n, h in items}
                if len(outs) == 1:
                    rc, text = next(iter(outs))
                    first = (text.splitlines() or ["(no output)"])[0]
                    lines.append(("↳ %s: %s%s" % (hook, first[:100], "" if rc == 0 else "  (failed, exit %s)" % rc), TEAL if rc == 0 else AMBER))
                else:
                    for n, h in items:
                        first = ((h["out"] if h["rc"] == 0 else h["err"] or h["out"]).splitlines() or ["(no output)"])[0]
                        lines.append(("↳ %s on %s: %s%s" % (hook, n, first[:90], "" if h["rc"] == 0 else "  (failed)"), TEAL if h["rc"] == 0 else AMBER))
            return [(i, t, c) for i, (t, c) in enumerate(lines[:12])]

        def render_history(self, inner):
            data = load_history()
            self.summary_label.configure(text="%d run%s kept" % (len(data), "" if len(data) == 1 else "s"))
            self.progress.configure(value=0)
            if not data:
                self.empty(inner, "No history yet", "Every run is kept here, so you can look back or run it again.")
                return
            for i, entry in enumerate(data):
                card = Card(inner, radius=12, pad=(14, 10))
                card.grid(row=i, column=0, sticky="ew", pady=(0, 8))
                b = card.body
                b.columnconfigure(0, weight=1)
                res = entry.get("results", [])
                bad = sum(1 for r in res if r["status"] != "ok")
                first = (entry.get("command") or "").splitlines()[0] if entry.get("command") else ""
                tk.Label(b, text=first[:90] + ("…" if len(first) > 90 else ""), bg=CARD, fg=TEXT, font=UI["mono"], anchor="w").grid(row=0, column=0, sticky="w")
                ttk.Label(b, text="%s%s  ·  %d server%s  ·  %s" % (age_text(entry.get("ts", 0)), ("  ·  " + entry["source"]) if entry.get("source") else "",
                                                                   len(res), "" if len(res) == 1 else "s", "all ok" if not bad else "%d did not succeed" % bad),
                          style="Dim.TLabel", foreground=GREEN if not bad else AMBER).grid(row=1, column=0, sticky="w")
                btns = ttk.Frame(b, style="Card.TFrame")
                btns.grid(row=0, column=1, rowspan=2, sticky="e")
                Btn(btns, text="Open", style="Small.TButton", command=lambda e=entry: self.open_history(e)).grid(row=0, column=0, padx=(0, 6))
                if entry.get("kind", "cmd") == "cmd":
                    Btn(btns, text="Use command", style="Small.TButton", command=lambda e=entry: self.use_history(e)).grid(row=0, column=1)

        def open_history(self, entry):
            self.command_run, self.kind_run = entry.get("command", ""), entry.get("kind", "cmd")
            self.last_job, self.note, self.tries = None, "", {}
            self._show_retry(False)
            self.results = {r["name"]: dict(r, ended=0) for r in entry.get("results", [])}
            self.run_order = [r["name"] for r in entry.get("results", [])]
            self.status = {n: r["status"] for n, r in self.results.items()}
            self.run_started = entry.get("ts", time.time()) - max([r["secs"] for r in entry.get("results", [])] or [0])
            self.show_view("results")

        def use_history(self, entry):
            self.set_mode("cmd")
            self.cmd_text.delete("1.0", "end")
            self.cmd_text.insert("1.0", entry.get("command", ""))
            self.update_hint()
            self.toast("Command loaded")

        # ── export ───────────────────────────────────────────────────────
        def ordered_results(self):
            return [self.results[n] for n in self.run_order if n in self.results]

        def copy_results(self):
            rs = self.ordered_results()
            if not rs:
                self.toast("Nothing to copy yet.", "warn")
                return
            self.copy(results_text(self.command_run, rs), "Answers copied")

        def save_results(self):
            rs = self.ordered_results()
            if not rs:
                self.toast("Nothing to save yet.", "warn")
                return
            from tkinter import filedialog
            path = filedialog.asksaveasfilename(parent=self.root, title="Save the answers", defaultextension=".json",
                                                initialfile="fleet-%s.json" % time.strftime("%Y%m%d-%H%M%S"),
                                                filetypes=[("JSON", "*.json"), ("Text", "*.txt")])
            if not path:
                return
            try:
                if path.endswith(".txt"):
                    Path(path).write_text(results_text(self.command_run, rs), encoding="utf-8")
                else:
                    Path(path).write_text(json.dumps(dict(command=self.command_run, results=rs), indent=1), encoding="utf-8")
                self.toast("Saved %s" % Path(path).name)
            except OSError as e:
                self.toast("Couldn't save: %s" % e, "error")

    return App, tk


def seed_demo_history():
    """A few earlier runs, so the History view and the red/green dots have something to show in --demo."""
    base = time.time()
    ok = lambda n, out, s: dict(name=n, status="ok", rc=0, secs=s, route="web.ztr", out=out, err="", ended=0)
    add_history("uptime", [ok("web1", " 09:14:02 up 11 days, 2 users, load average: 0.10, 0.12, 0.09", 3), ok("web2", " 09:14:03 up 11 days, 1 user, load average: 0.31, 0.22, 0.18", 4),
                           dict(ok("edge-us", "", 6), status="failed", rc=255, err="ssh: connect to host 10.10.15.10 port 41022: Connection refused")], 4, 60)
    add_history("df -h / | tail -n 1", [ok("web1", "/dev/vda1  80G  41G  39G  52% /", 3), ok("db1", "/dev/vda1  80G  61G  19G  77% /", 4)], 4, 60)
    entries = load_history()
    for i, e in enumerate(entries):
        e["ts"] = base - (3600 * (i + 1) * 3)
    core.HISTORY_PATH.write_text(json.dumps(entries), encoding="utf-8")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="A window for running one command on several servers, each through its own ZTRelay route.")
    parser.add_argument("--file", help="the fleet file (default: ./fleet.conf, else ~/.config/ztr_fleet/fleet.conf)")
    parser.add_argument("--demo", action="store_true", help="pretend servers; nothing is contacted and nothing of yours is touched")
    args = parser.parse_args()
    try:
        import tkinter  # noqa: F401
    except ImportError:
        if sys.platform == "darwin":
            print("This needs Python's tkinter. With Homebrew: brew install python-tk@%d.%d (or use the python.org installer)." % sys.version_info[:2])
        else:
            print("This needs Python's tkinter. On Debian/Raspberry Pi OS: sudo apt install python3-tk")
        return 1
    if args.demo:
        core.CONFIG_DIR = Path(tempfile.mkdtemp(prefix="ztr-fleet-demo-"))
        core.SNIPPETS_PATH, core.HISTORY_PATH = core.CONFIG_DIR / "snippets.json", core.CONFIG_DIR / "history.json"
        core.KNOWN_HOSTS = core.CONFIG_DIR / "known_hosts"
        seed_demo_history()
    App, tk = build_app()
    try:
        root = tk.Tk()
    except tk.TclError as e:
        print("The window couldn't open (%s)." % e)
        print("Run this from a terminal on your desktop, or use the command line: ztr_fleet --help")
        return 1
    app = App(root, demo=args.demo, fleet_file=(core.CONFIG_DIR / "fleet.conf") if args.demo else args.file)
    if args.demo:
        app.servers = [Server(**dict(s.__dict__, vars=dict(s.vars))) for s in DEMO_SERVERS]
        app.sel = {}
        app.last = {"web1": "ok", "web2": "ok", "edge-us": "failed", "db1": "ok"}
        app.rebuild_servers()
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
