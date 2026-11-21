(function () {
  "use strict";
  var TOKEN = document.querySelector('meta[name="dash-token"]').content;
  var $ = function (id) { return document.getElementById(id); };
  var data = null;          // last /api/state payload
  var selected = "";        // name of the ISF being viewed
  var manageOpen = false;
  var editing = null;       // name being edited, or null when adding
  var routeSig = "";

  var hideIps = true;       // addresses of the hops and of the ISF are masked unless the user asks to see them
  try { selected = window.localStorage.getItem("isf-selected") || ""; } catch (e) { /* storage unavailable */ }
  try { if (window.localStorage.getItem("isf-hide-ips") === "0") hideIps = false; } catch (e) { /* storage unavailable */ }
  function remember() { try { window.localStorage.setItem("isf-selected", selected); } catch (e) { /* ignore */ } }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function show(node, on) { node.classList.toggle("hidden", !on); }

  // Same masking rule as the isf_ssh path log: 138.197.149.249 -> 138.197.x.x, mor-tra.com -> mo***.com
  function maskHost(h) {
    h = String(h == null ? "" : h);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) { var a = h.split("."); return a[0] + "." + a[1] + ".x.x"; }
    if (/\._ztr$/.test(h)) return "***._ztr";
    if (/^[A-Za-z0-9.-]+$/.test(h) && h.indexOf(".") > 0) return h.slice(0, 2) + "***." + h.split(".").pop();
    return "***";
  }
  function maskH(h) { return hideIps ? maskHost(h) : (h == null ? "—" : h); }

  function fmtBytes(n) {
    if (n == null) return "—";
    var u = ["B", "KB", "MB", "GB", "TB"], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n >= 100 ? 0 : 1)) + " " + u[i];
  }
  function fmtDur(s) {
    s = Math.max(0, Math.floor(s));
    var d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60), x = s % 60;
    if (d) return d + "d " + h + "h";
    if (h) return h + "h " + m + "m";
    if (m) return m + "m " + (x < 10 ? "0" : "") + x + "s";
    return x + "s";
  }
  function fmtClock(t) { return new Date(t * 1000).toLocaleTimeString(); }
  function fmtDateTime(t) { return new Date(t * 1000).toLocaleString(); }

  function api(path, body) {
    body = body || {};
    if (body.isf === undefined && selected) body.isf = selected;
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Dashboard-Token": TOKEN },
      body: JSON.stringify(body)
    }).then(function (r) {
      if (!r.ok) throw new Error("request refused (" + r.status + ")");
      return r.json();
    });
  }

  function setCard(id, text, cls) {
    var e = $(id);
    e.textContent = text;
    e.className = "value" + (cls ? " " + cls : "");
  }
  function sel() { return data && data.selected; }
  function policy() { var s = sel(); return s && s.overview && s.overview.policy; }

  // ------------------------------------------------------------------ ISF tabs
  function renderTabs() {
    var box = $("isf-tabs");
    clear(box);
    (data.isfs || []).forEach(function (i) {
      var b = el("button", "tab" + (i.name === selected ? " selected" : ""));
      b.type = "button";
      b.appendChild(el("span", "dot " + i.status));
      var t = el("span");
      var nm = el("span", "tname", i.name);
      if (i.default) nm.appendChild(el("span", "star", " ★"));
      t.appendChild(nm);
      t.appendChild(el("span", "tsub", maskH(i.host) + " · " + i.route));
      b.appendChild(t);
      b.addEventListener("click", function () {
        if (selected !== i.name) { $("ticket").value = ""; $("command").value = ""; show($("ticket-box"), false); showError($("create-error"), ""); show($("allow-it-wrap"), false); }
        selected = i.name; remember(); load();
      });
      box.appendChild(b);
    });
  }

  // ------------------------------------------------------------------ selected ISF view
  function renderStatus(s) {
    var pill = $("status");
    var st = s ? s.status : "checking";
    pill.textContent = s ? st.toUpperCase() : "NO ISF";
    pill.className = "pill " + (s ? st : "checking");
    var upd = $("updated"), stale = $("stale");
    if (!s) { upd.textContent = ""; show(stale, false); return; }
    if (s.last_ok) upd.textContent = "last answer " + fmtDur(s.now - s.last_ok) + " ago";
    else upd.textContent = st === "checking" ? "contacting the ISF through your route…" : "no answer yet";
    if (st === "offline") {
      stale.textContent = (s.last_ok ? "showing the last known data — " : "") + (s.error || "ISF unreachable");
      show(stale, true);
    } else show(stale, false);
  }

  function renderCards(s) {
    var ov = s.overview;
    if (s.rtt_ms != null) {
      setCard("m-rtt", Math.round(s.rtt_ms) + " ms", s.status === "offline" ? "bad" : (s.rtt_ms > 8000 ? "amber" : "ok"));
    } else setCard("m-rtt", "—");
    if (!ov) {
      setCard("m-uptime", "—"); setCard("m-live", "—"); setCard("m-skew", "—");
      $("m-live-hint").textContent = ""; $("m-skew-hint").textContent = "";
      return;
    }
    setCard("m-uptime", fmtDur(ov.uptime + (s.now - s.last_ok)));
    setCard("m-live", ov.capacity.live_mine + " / " + ov.capacity.live_total, "ok");
    $("m-live-hint").textContent = "yours / all clients · max " + ov.limits.max_per_client + " each, " + ov.limits.max_sessions + " total";
    var skew = s.clock_skew, bad = Math.abs(skew) > 60;
    setCard("m-skew", (skew >= 0 ? "+" : "") + skew.toFixed(1) + " s", Math.abs(skew) > 100 ? "bad" : (bad ? "amber" : "ok"));
    $("m-skew-hint").textContent = bad ? "ISF rejects requests more than 120 s off" : "ISF clock vs this machine";
  }

  // The sessions list can get long (every ztr_https / proxy connection is one), so it is filtered, searchable,
  // capped and scrolls inside its own box with the header kept in view.
  var SESS_MAX_ROWS = 300;
  var sessView = { filter: null, q: "" };       // filter: "open" | "closed" | "all"; null = pick one on first sight
  var lastSessState = null;
  var STATE_RANK = { active: 0, pending: 1, closed: 2 };

  function sessionRows(ov) {
    var rows = ov ? ov.sessions.slice() : [];
    rows.sort(function (a, b) {
      var ra = STATE_RANK[a.state], rb = STATE_RANK[b.state];
      if (ra !== rb) return ra - rb;
      return (b.created_at || 0) - (a.created_at || 0);
    });
    return rows;
  }

  function renderSessions(s) {
    lastSessState = s;
    var ov = s.overview, tbl = $("sessions"), empty = $("sessions-empty");
    var all = sessionRows(ov);
    var nActive = 0, nPending = 0, nClosed = 0;
    all.forEach(function (r) { if (r.state === "active") nActive++; else if (r.state === "pending") nPending++; else nClosed++; });
    var nOpen = nActive + nPending;
    $("sf-open").textContent = nOpen; $("sf-closed").textContent = nClosed; $("sf-all").textContent = all.length;
    $("sess-summary").textContent = all.length ? nActive + " active · " + nPending + " pending · " + nClosed + " closed" : "";
    if (sessView.filter === null) sessView.filter = nOpen ? "open" : "all";
    Array.prototype.forEach.call($("sess-filter").querySelectorAll(".segbtn"), function (b) {
      b.classList.toggle("on", b.getAttribute("data-f") === sessView.filter);
    });
    var q = sessView.q.trim().toLowerCase();
    var rows = all.filter(function (r) {
      if (sessView.filter === "open" && r.state === "closed") return false;
      if (sessView.filter === "closed" && r.state !== "closed") return false;
      if (!q) return true;
      return (r.destination + " " + (r.label || "") + " " + r.session_id + " " + r.state).toLowerCase().indexOf(q) >= 0;
    });
    var tb = tbl.querySelector("tbody");
    clear(tb);
    show($("sess-tools"), all.length > 0);
    if (!all.length) { show(tbl, false); show(empty, true); empty.textContent = "No sessions yet."; show($("sess-more"), false); return; }
    if (!rows.length) {
      show(tbl, false); show(empty, true); show($("sess-more"), false);
      empty.textContent = q ? "No session matches “" + sessView.q.trim() + "”." : (sessView.filter === "open" ? "No open sessions right now." : "No closed sessions.");
      return;
    }
    show(tbl, true); show(empty, false);
    var shown = rows.length > SESS_MAX_ROWS ? rows.slice(0, SESS_MAX_ROWS) : rows;
    var more = $("sess-more");
    if (shown.length < rows.length) { more.textContent = "Showing the first " + shown.length + " of " + rows.length + " — use the filter or the search to narrow it down."; show(more, true); }
    else show(more, false);
    var serverNow = s.now + (s.clock_skew || 0);
    shown.forEach(function (r) {
      var tr = el("tr");
      var st = el("td", "nw"); st.appendChild(el("span", "badge " + r.state, r.state)); tr.appendChild(st);
      if (r.proto === "udp") st.appendChild(el("span", "badge udp", "UDP"));
      var d = el("td"); d.appendChild(el("span", "mono", r.destination));
      if (r.alias) { var al = el("div", "muted mono", "via alias " + r.alias.slice(0, 8) + "…"); al.title = r.alias; d.appendChild(al); }
      d.appendChild(el("div", "muted mono", r.session_id.slice(0, 8))); tr.appendChild(d);
      var lab = el("td", "lab", r.label || "—"); if (r.label) lab.title = r.label; tr.appendChild(lab);
      var when;
      if (r.state === "pending") when = serverNow < r.expires_at ? "expires in " + fmtDur(r.expires_at - serverNow) : "expired";
      else if (r.state === "active") when = "active " + fmtDur(serverNow - r.active_at);
      else when = "closed " + fmtDur(serverNow - (r.closed_at || r.created_at)) + " ago";
      tr.appendChild(el("td", "muted nw", when));
      tr.appendChild(el("td", "num", fmtBytes(r.bytes_up)));
      tr.appendChild(el("td", "num", fmtBytes(r.bytes_down)));
      var act = el("td", "num");
      if (r.state !== "closed") {
        var b = el("button", "btn danger small", r.state === "active" ? "End" : "Cancel");
        b.addEventListener("click", function () {
          if (!window.confirm((r.state === "active" ? "End this live session?" : "Cancel this session?") + "\n" + r.destination)) return;
          b.disabled = true;
          api("/api/session/delete", { session_id: r.session_id }).then(function (res) {
            if (!res.ok) window.alert(res.error || "could not end the session");
            return refreshSoon();
          }).catch(function (e) { window.alert(e.message); b.disabled = false; });
        });
        act.appendChild(b);
      }
      tr.appendChild(act);
      tb.appendChild(tr);
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll("#sess-filter .segbtn"), function (b) {
    b.addEventListener("click", function () {
      sessView.filter = b.getAttribute("data-f");
      $("sess-scroll").scrollTop = 0;
      if (lastSessState) renderSessions(lastSessState);
    });
  });
  $("sess-q").addEventListener("input", function () {
    sessView.q = this.value;
    $("sess-scroll").scrollTop = 0;
    if (lastSessState) renderSessions(lastSessState);
  });

  function kv(dl, pairs) {
    clear(dl);
    pairs.forEach(function (p) {
      dl.appendChild(el("dt", null, p[0]));
      var dd = el("dd");
      if (Array.isArray(p[1])) {
        if (!p[1].length) dd.textContent = "—";
        p[1].forEach(function (x) { dd.appendChild(el("div", "mono", x)); });
      } else dd.appendChild(el("span", p[2] ? "mono" : null, p[1] == null ? "—" : String(p[1])));
      dl.appendChild(dd);
    });
  }

  function renderDetails(s) {
    var ov = s.overview, fp = s.fingerprints || {};
    var mine = data.client && data.client.fingerprint;
    var pr = s.profile || {};
    kv($("isf-details"), [
      ["Name", s.name],
      ["Address", maskH(s.isf_host) + (pr.ctrl_port ? "  (ports " + pr.ctrl_port + " / " + pr.data_port + " / " + (pr.udp_port || 7782) + " udp)" : ""), true],
      ["Version", ov ? ov.version : null],
      ["Running since", ov ? fmtDateTime(ov.started_at) : null],
      ["Authorised clients", ov ? ov.authorised_clients : null],
      ["Your key", mine, true],
      ["ISF key", fp.isf, true],
      ["Key seen by ISF", ov ? ov.client_fingerprint : null, true]
    ]);
    if (!ov) { kv($("policy-details"), [["Policy", null]]); return; }
    var L = ov.limits;
    kv($("policy-details"), [
      ["Mode", ov.policy.description],
      ["Ticket lifetime", "default " + fmtDur(L.default_ttl) + ", max " + fmtDur(L.max_ttl)],
      ["Idle timeout", fmtDur(L.idle_timeout)],
      ["Dial timeout", fmtDur(L.connect_timeout)],
      ["UDP", ov.udp && ov.udp.enabled ? "on · port " + ov.udp.port + " · max " + ov.udp.max_payload + " B · idle " + fmtDur(ov.udp.idle) + (ov.udp.rate_pps ? " · " + ov.udp.rate_pps + " pps" : "")
                                       : "off (the ISF wasn't started with --udp-bind)"]
    ]);
  }

  // ------------------------------------------------------------------ aliases (<name>.isf -> a real host, known only to the ISF)
  function renderAliases(s) {
    var ov = s.overview, tbl = $("alias-table"), note = $("alias-note"), tb = tbl.querySelector("tbody");
    clear(tb);
    var list = ov && ov.aliases ? ov.aliases : [], editable = !!(ov && ov.alias_editable);
    $("alias-count").textContent = list.length ? "(" + list.length + ")" : "";
    ["alias-target", "alias-name", "alias-note-in", "alias-add", "alias-generate"].forEach(function (id) { $(id).disabled = !editable; });
    if (!ov) { note.textContent = "Waiting for the ISF…"; show(tbl, false); return; }
    if (!editable) note.textContent = "This ISF was started without --alias-file, so it can't keep aliases. Start it with --alias-file FILE to create them here.";
    else if (!list.length) note.textContent = "No aliases yet. An alias is a name like <64 characters>.isf that only this ISF understands; it hides the real host name from your commands, files and scripts.";
    else note.textContent = "Use an alias wherever you would write the host. The ISF turns it back into the real host when the session starts, and its allowlist still applies to that real host.";
    show(tbl, list.length > 0);
    list.forEach(function (a) {
      var tr = el("tr");
      var nm = el("td");
      var short = a.name.length > 30 ? a.name.slice(0, 14) + "…" + a.name.slice(-12) : a.name;
      var sp = el("span", "mono", short); sp.title = a.name; nm.appendChild(sp);
      var cp = el("button", "btn small", "Copy"); cp.style.marginLeft = "8px";
      cp.addEventListener("click", function () { copy(a.name, cp); });
      nm.appendChild(cp);
      if (a.note) nm.appendChild(el("div", "muted", a.note));
      tr.appendChild(nm);
      var tg = el("td"); tg.appendChild(el("span", "mono", a.target));
      if (a.created_at) tg.appendChild(el("div", "muted", fmtDateTime(a.created_at)));
      tr.appendChild(tg);
      var act = el("td", "num");
      if (editable) {
        var ed = el("button", "btn small", "Change"); ed.style.marginRight = "6px";
        ed.addEventListener("click", function () {
          var t2 = window.prompt("Point " + short + " at which host?", a.target);
          if (t2 === null || !t2.trim() || t2.trim() === a.target) return;
          api("/api/alias/retarget", { name: a.name, target: t2.trim() }).then(function (r) {
            showError($("alias-error"), r.ok ? "" : r.error); return load();
          }).catch(function (er) { showError($("alias-error"), er.message); });
        });
        var rm = el("button", "btn danger small", "Remove");
        rm.addEventListener("click", function () {
          if (!window.confirm("Remove " + short + "?\nAnything still using it will stop working.")) return;
          rm.disabled = true;
          api("/api/alias/remove", { name: a.name }).then(function (r) {
            showError($("alias-error"), r.ok ? "" : r.error); return load();
          }).catch(function (er) { showError($("alias-error"), er.message); rm.disabled = false; });
        });
        act.appendChild(ed); act.appendChild(rm);
      }
      tr.appendChild(act);
      tb.appendChild(tr);
    });
  }
  $("alias-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = $("alias-add");
    btn.disabled = true;
    api("/api/alias/add", { target: $("alias-target").value, name: $("alias-name").value, note: $("alias-note-in").value }).then(function (r) {
      if (!r.ok) { showError($("alias-error"), r.error || "could not create the alias"); return; }
      showError($("alias-error"), "");
      $("alias-made-text").value = r.alias; show($("alias-made"), true);
      $("alias-target").value = ""; $("alias-name").value = ""; $("alias-note-in").value = ""; previewAlias();
      return load();
    }).catch(function (e) { showError($("alias-error"), e.message); }).then(function () { btn.disabled = false; });
  });
  // A random 64-character name (256 bits), made here so it can be seen — and copied — before it is created.
  function randomAliasName() {
    var b = new Uint8Array(32), out = "";
    (window.crypto || window.msCrypto).getRandomValues(b);
    for (var i = 0; i < b.length; i++) out += (b[i] < 16 ? "0" : "") + b[i].toString(16);
    return out;
  }
  function previewAlias() {
    var n = $("alias-name").value.trim().toLowerCase().replace(/\.isf$/, "");
    $("alias-preview").textContent = n ? "Will be created as: " + n + ".isf" : "Leave the name empty and the ISF picks 64 random characters.";
  }
  $("alias-generate").addEventListener("click", function () { $("alias-name").value = randomAliasName(); previewAlias(); $("alias-name").focus(); });
  $("alias-name").addEventListener("input", previewAlias);
  previewAlias();
  $("alias-copy").addEventListener("click", function () { copy($("alias-made-text").value, $("alias-copy")); });
  $("alias-hide").addEventListener("click", function () { $("alias-made-text").value = ""; show($("alias-made"), false); });

  // ------------------------------------------------------------------ allowlist
  function renderAllow() {
    var pol = policy(), note = $("allow-note"), tbl = $("allow-table"), form = $("allow-form");
    var tb = tbl.querySelector("tbody");
    clear(tb);
    var editable = !!(pol && pol.remote_editable);
    $("allow-entry").disabled = !editable;
    $("allow-add").disabled = !editable;
    if (!pol) { note.textContent = "Waiting for the ISF…"; show(tbl, false); return; }
    if (!pol.remote_editable) note.textContent = "Read-only here: this ISF was started without --policy-file, so its allowlist can only be changed on the ISF itself. " + pol.description + ".";
    else if (!pol.restrict) note.textContent = "No allowlist: this ISF currently accepts any public destination. Adding an entry switches it to allowlist-only.";
    else if (!pol.entries.length) note.textContent = "The allowlist is empty: nothing can be dialed. Add the destinations you need.";
    else note.textContent = "Only these destinations can be dialed. Entries added here are saved on the ISF; entries from its own configuration can't be removed here.";
    show(tbl, pol.entries.length > 0);
    pol.entries.forEach(function (e) {
      var tr = el("tr");
      tr.appendChild(el("td", "mono", e.entry));
      var from = el("td");
      from.appendChild(el("span", "badge " + e.origin, e.origin === "config" ? "ISF config" : "added here"));
      if (e.added_at) from.appendChild(el("div", "muted", fmtDateTime(e.added_at)));
      tr.appendChild(from);
      var act = el("td", "num");
      if (e.origin === "remote" && editable) {
        var b = el("button", "btn danger small", "Remove");
        b.addEventListener("click", function () {
          if (!window.confirm("Stop allowing " + e.entry + "?")) return;
          b.disabled = true;
          api("/api/policy/remove", { entry: e.entry }).then(function (r) {
            showError($("allow-error"), r.ok ? "" : r.error);
            return load();
          }).catch(function (er) { showError($("allow-error"), er.message); b.disabled = false; });
        });
        act.appendChild(b);
      }
      tr.appendChild(act);
      tb.appendChild(tr);
    });
  }

  function showError(node, msg) {
    node.textContent = msg || "";
    show(node, !!msg);
  }

  function addAllow(entry) {
    var pol = policy();
    if (pol && !pol.restrict && !window.confirm("This ISF now accepts any public destination. Adding \"" + entry + "\" switches it to allowlist-only — everything not listed will be refused. Continue?")) {
      return Promise.resolve({ ok: false, error: "" });
    }
    return api("/api/policy/add", { entry: entry });
  }

  $("allow-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var input = $("allow-entry"), btn = $("allow-add");
    var entry = input.value.trim();
    if (!entry) return;
    btn.disabled = true;
    addAllow(entry).then(function (r) {
      showError($("allow-error"), r.ok ? "" : r.error);
      if (r.ok) input.value = "";
      return load();
    }).catch(function (e) { showError($("allow-error"), e.message); }).then(function () { btn.disabled = false; });
  });

  // ------------------------------------------------------------------ route
  function routeOptions(select, current) {
    var routes = data.routes || [];
    clear(select);
    var seen = false;
    routes.forEach(function (r) {
      var o = el("option", null, r.file + "  (" + (r.exit_country || "-") + ", " + (r.status || "-") + ")");
      o.value = r.file;
      if (r.file === current) { o.selected = true; seen = true; }
      select.appendChild(o);
    });
    if (current && !seen) { var o2 = el("option", null, current + "  (not in routes/)"); o2.value = current; o2.selected = true; select.appendChild(o2); }
  }

  function renderRoute(s) {
    var box = $("route");
    clear(box);
    var r = s.route;
    if (!r) { box.className = "pad muted"; box.textContent = "Route details unavailable."; }
    else {
      box.className = "";
      var ch = el("div", "chain");
      (r.chain || []).forEach(function (h) {
        var row = el("div", "hop");
        row.appendChild(el("span", "role", h.role || "hop"));
        row.appendChild(el("span", "mono", maskH(h.address)));
        ch.appendChild(row);
      });
      var isf = el("div", "hop");
      isf.appendChild(el("span", "role", "ISF"));
      isf.appendChild(el("span", "mono", maskH(s.isf_host)));
      ch.appendChild(isf);
      box.appendChild(ch);
      box.appendChild(el("div", "muted pad", r.file + (r.exit_country ? " · exit " + r.exit_country : "")));
    }
    var current = (s.profile && s.profile.route) || (r && r.file) || "";
    var sig = JSON.stringify([s.name, current, (data.routes || []).map(function (x) { return x.file; })]);
    if (sig !== routeSig) {
      routeSig = sig;
      routeOptions($("route-select"), current);
    }
    $("route-save").disabled = $("route-select").value === current;
  }

  $("route-select").addEventListener("change", function () {
    var s = sel();
    $("route-save").disabled = !s || $("route-select").value === (s.profile && s.profile.route);
  });
  $("route-save").addEventListener("click", function () {
    var b = $("route-save"), route = $("route-select").value;
    b.disabled = true; b.textContent = "Saving…";
    api("/api/isf/save", { name: selected, route: route }).then(function (r) {
      if (!r.ok) window.alert(r.error || "could not change the route");
      routeSig = "";
      return refreshSoon();
    }).catch(function (e) { window.alert(e.message); }).then(function () { b.textContent = "Use this route"; });
  });

  // ------------------------------------------------------------------ network diagram
  function node(cls, title, sub, note, caption) {
    var n = el("div", "node " + cls);
    n.appendChild(el("div", "nt", title));
    if (sub) n.appendChild(el("div", "ns", sub));
    if (note) n.appendChild(el("div", "nn", note));
    n.appendChild(el("div", "nc", caption));
    return n;
  }
  function edge(lines) {
    var e = el("div", "edge");
    lines.forEach(function (l) {
      e.appendChild(el("div", "ln " + (l.cls || "")));
      if (l.label) e.appendChild(el("div", "el", l.label));
    });
    return e;
  }

  function renderNet(s) {
    var box = $("net"), foot = $("net-foot");
    clear(box); clear(foot);
    var r = s.route, chain = (r && r.chain) || [], roles = {};
    chain.forEach(function (h) { roles[h.role] = h; });
    var ov = s.overview, st = s.status, ok = st === "online";
    var isDefault = (data.isfs || []).some(function (i) { return i.name === s.name && i.default; });

    box.appendChild(node("mine", "You", "this machine", "", "talks only to the entry hop"));
    box.appendChild(edge([{}]));
    box.appendChild(node("relay", "Entry hop", roles.entry ? maskH(roles.entry.address) : "—", "", "sees opaque frames"));
    if (!r || roles.middle || !chain.length) {
      box.appendChild(edge([{}]));
      box.appendChild(node("relay", "Middle hop", "address not shown", "", "sees opaque frames"));
    }
    box.appendChild(edge([{}]));
    box.appendChild(node("relay", "Exit hop", roles.exit ? maskH(roles.exit.address) : "—", r && r.exit_country ? "exit country " + r.exit_country : "",
      "sees only \"connect to the ISF\": ciphertext, timing, volume"));
    box.appendChild(edge([{ cls: ok ? "ctrl" : "bad", label: "7700" }, { cls: ok ? "data" : "bad", label: "7781" }]));
    var live = ov ? ov.capacity.live_mine : null;
    box.appendChild(node("isf " + st, "Your ISF" + (isDefault ? " ★" : ""), maskH(s.isf_host),
      ok && ov ? "v" + ov.version + " · " + live + " live" : (st === "offline" ? "not answering" : "checking…"),
      "decrypts; sees the destination and the stream"));
    box.appendChild(edge([{ cls: ok ? "data" : "bad", label: live ? live + " live" : "" }]));

    var dest = el("div", "node dest");
    dest.appendChild(el("div", "nt", "Destinations"));
    var open = ov ? ov.sessions.filter(function (x) { return x.state !== "closed"; }) : [];
    if (open.length) {
      open.slice(0, 3).forEach(function (x) { dest.appendChild(el("div", "dl", x.destination)); });
      if (open.length > 3) dest.appendChild(el("div", "nn", "+ " + (open.length - 3) + " more"));
    } else if (ov && ov.policy.restrict) {
      dest.appendChild(el("div", "ns", ov.policy.entries.length + " allowed"));
      dest.appendChild(el("div", "nn", "none open right now"));
    } else if (ov) {
      dest.appendChild(el("div", "ns", "any public address"));
      dest.appendChild(el("div", "nn", "none open right now"));
    } else dest.appendChild(el("div", "ns", "—"));
    dest.appendChild(el("div", "nc", "sees the ISF's IP, not yours"));
    box.appendChild(dest);

    var k1 = el("span", "k"); k1.appendChild(el("span", "sw ctrl")); k1.appendChild(document.createTextNode("control :7700 — signed, encrypted requests"));
    var k2 = el("span", "k"); k2.appendChild(el("span", "sw data")); k2.appendChild(document.createTextNode("data :7781 — encrypted frames"));
    foot.appendChild(k1); foot.appendChild(k2);
    var bits = [];
    if (s.rtt_ms != null) bits.push(["round trip", Math.round(s.rtt_ms) + " ms"]);
    if (r) bits.push(["route", r.file]);
    bits.push(["addresses", hideIps ? "hidden" : "shown"]);
    bits.forEach(function (b) {
      var sp = el("span"); sp.appendChild(document.createTextNode(b[0] + " ")); sp.appendChild(el("b", null, b[1])); foot.appendChild(sp);
    });
  }

  // ------------------------------------------------------------------ history, events
  function renderSpark(s) {
    var box = $("spark"), pts = s.history;
    clear(box);
    if (!pts.length) { box.appendChild(el("span", "muted", "No checks yet.")); return; }
    var ns = "http://www.w3.org/2000/svg", W = 300, H = 70, pad = 6;
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", "0 0 " + W + " " + H);
    svg.setAttribute("preserveAspectRatio", "none");
    var vals = pts.filter(function (p) { return p.ok; }).map(function (p) { return p.rtt; });
    var max = Math.max.apply(null, vals.concat([1000]));
    var step = pts.length > 1 ? (W - 2 * pad) / (pts.length - 1) : 0;
    var path = "", last = false;
    pts.forEach(function (p, i) {
      var x = pad + i * step;
      if (p.ok) {
        var y = H - pad - (p.rtt / max) * (H - 2 * pad);
        path += (last ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1) + " ";
        last = true;
      } else {
        last = false;
        var line = document.createElementNS(ns, "line");
        line.setAttribute("x1", x); line.setAttribute("x2", x); line.setAttribute("y1", pad); line.setAttribute("y2", H - pad);
        line.setAttribute("stroke", "#f16a63"); line.setAttribute("stroke-width", "2");
        svg.appendChild(line);
      }
    });
    if (path) {
      var p = document.createElementNS(ns, "path");
      p.setAttribute("d", path); p.setAttribute("fill", "none"); p.setAttribute("stroke", "#34c3b5");
      p.setAttribute("stroke-width", "2"); p.setAttribute("vector-effect", "non-scaling-stroke");
      svg.appendChild(p);
    }
    box.appendChild(svg);
    box.appendChild(el("div", "muted", "last " + pts.length + " checks · scale up to " + Math.round(max) + " ms · red = no answer"));
  }

  function renderEvents(s) {
    var ul = $("events");
    clear(ul);
    if (!s.events.length) { ul.appendChild(el("li", "muted", "Nothing yet.")); return; }
    s.events.forEach(function (ev) {
      var li = el("li", ev.kind);
      li.appendChild(el("span", "t", fmtClock(ev.t)));
      li.appendChild(document.createTextNode(ev.msg));
      ul.appendChild(li);
    });
  }

  // ------------------------------------------------------------------ managing ISFs
  function renderManage() {
    show($("manage"), manageOpen);
    $("manage-btn").textContent = manageOpen ? "Hide ISF list" : "Manage ISFs";
    if (!manageOpen) return;
    if (!$("i-route").options.length && (data.routes || []).length) routeOptions($("i-route"), data.routes[0].file);   // the form is usable before Add/Edit is clicked
    var isfs = data.isfs || [], tbl = $("isf-table"), tb = tbl.querySelector("tbody");
    clear(tb);
    show($("isf-empty"), !isfs.length);
    show(tbl, isfs.length > 0);
    isfs.forEach(function (i) {
      var tr = el("tr");
      tr.appendChild(el("td", "dot-cell", i.default ? "★" : ""));
      var n = el("td"); n.appendChild(el("div", null, i.name)); if (i.note) n.appendChild(el("div", "muted", i.note)); tr.appendChild(n);
      tr.appendChild(el("td", "mono", maskH(i.host) + ":" + i.ctrl_port + "/" + i.data_port + "/" + (i.udp_port || 7782) + "u"));
      tr.appendChild(el("td", "mono", i.route));
      var st = el("td", "dot-cell"); st.appendChild(el("span", "dot " + i.status)); st.appendChild(document.createTextNode(" " + i.status + (i.rtt_ms != null ? " · " + Math.round(i.rtt_ms) + " ms" : ""))); tr.appendChild(st);
      var k = el("td"); k.appendChild(el("span", "badge " + (i.key_installed ? "active" : "pending"), i.key_installed ? "installed" : "missing")); tr.appendChild(k);
      var acts = el("td"); var row = el("div", "acts");
      var eb = el("button", "btn small", "Edit"); eb.addEventListener("click", function () { openForm(i); }); row.appendChild(eb);
      if (!i.default) {
        var db = el("button", "btn small", "Make default");
        db.addEventListener("click", function () { api("/api/isf/default", { name: i.name }).then(load); });
        row.appendChild(db);
      }
      var xb = el("button", "btn danger small", "Delete");
      xb.addEventListener("click", function () {
        if (!window.confirm("Remove the ISF \"" + i.name + "\" from this machine?\n(The ISF itself is not touched; its key file stays on disk.)")) return;
        api("/api/isf/delete", { name: i.name }).then(function (r) {
          if (!r.ok) { window.alert(r.error); return; }
          if (selected === i.name) { selected = ""; remember(); }
          return load();
        });
      });
      row.appendChild(xb); acts.appendChild(row); tr.appendChild(acts);
      tb.appendChild(tr);
    });
    if (data.client) { $("key-fp").textContent = data.client.fingerprint || "—"; $("key-pem").value = data.client.public_key || "(no client key yet — run: ztr_isf_client.py gen-keys)"; }
  }

  function openForm(isf) {
    manageOpen = true;
    editing = isf ? isf.name : null;
    $("isf-form-title").textContent = isf ? "Change \"" + isf.name + "\"" : "Add an ISF";
    $("i-name").value = isf ? isf.name : ""; $("i-name").disabled = !!isf;
    // with addresses hidden the real one is not put on screen; an empty address means "keep the current one"
    $("i-host").value = isf && !hideIps ? isf.host : "";
    $("i-host").placeholder = isf && hideIps ? maskH(isf.host) + " — hidden; leave empty to keep it" : "public IPv4 of the ISF";
    $("i-host").required = !isf;
    $("i-ctrl").value = isf ? isf.ctrl_port : 7700; $("i-data").value = isf ? isf.data_port : 7781; $("i-udp").value = isf ? (isf.udp_port || 7782) : 7782;
    $("i-note").value = isf ? isf.note : "";
    $("i-timing").checked = !!(isf && isf.timing_defense);
    $("i-default").checked = !isf && !(data.isfs || []).length;
    $("i-pem").value = ""; $("i-pem").placeholder = isf && isf.key_installed ? "leave empty to keep the installed key" : "-----BEGIN PUBLIC KEY-----";
    $("i-replace").checked = false; show($("i-replace-wrap"), !!(isf && isf.key_installed));
    routeOptions($("i-route"), isf ? isf.route : ((data.routes || [])[0] || {}).file);
    showError($("isf-error"), "");
    show($("isf-form"), true);
    renderManage();
    $("i-" + (isf ? "host" : "name")).focus();
  }

  $("isf-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var btn = $("i-save");
    btn.disabled = true; btn.textContent = "Saving…";
    var name = $("i-name").value.trim();
    api("/api/isf/save", {
      name: name, host: $("i-host").value, route: $("i-route").value, ctrl_port: parseInt($("i-ctrl").value, 10), data_port: parseInt($("i-data").value, 10), udp_port: parseInt($("i-udp").value, 10),
      note: $("i-note").value, timing_defense: $("i-timing").checked, isf_pub_pem: $("i-pem").value, replace_key: $("i-replace").checked,
      make_default: $("i-default").checked, isf: name
    }).then(function (r) {
      if (!r.ok) { showError($("isf-error"), r.error || "could not save"); return; }
      selected = name; remember();
      editing = null; show($("isf-form"), false); $("i-pem").value = "";
      return load();
    }).catch(function (e) { showError($("isf-error"), e.message); }).then(function () { btn.disabled = false; btn.textContent = "Save ISF"; });
  });
  $("i-cancel").addEventListener("click", function () { editing = null; show($("isf-form"), false); });
  $("add-isf-btn").addEventListener("click", function () { openForm(null); window.scrollTo(0, 0); });
  $("manage-btn").addEventListener("click", function () { manageOpen = !manageOpen; if (!manageOpen) show($("isf-form"), false); renderManage(); });

  // ------------------------------------------------------------------ render everything
  function render() {
    renderTabs();
    var s = sel(), none = !(data.isfs || []).length;
    show($("isf-view"), !none && !!s);
    show($("no-isf"), none);
    if (none && !manageOpen) { manageOpen = true; openForm(null); }
    if (!none && data.problem) { selected = (data.isfs[0] || {}).name || ""; }
    renderStatus(s);
    if (s) {
      renderCards(s); renderSessions(s); renderDetails(s); renderAllow(); renderAliases(s);
      renderRoute(s); renderSpark(s); renderEvents(s); renderNet(s);
    }
    $("addr-toggle").textContent = hideIps ? "Addresses hidden" : "Addresses shown";
    renderManage();
  }

  function load() {
    var url = "/api/state" + (selected ? "?isf=" + encodeURIComponent(selected) : "");
    return fetch(url, { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (d) {
      data = d;
      if (d.selected) { selected = d.selected.name; remember(); }
      render();
    }).catch(function () {
      $("status").textContent = "DASHBOARD DOWN"; $("status").className = "pill offline";
    });
  }
  function refreshSoon() { return api("/api/refresh").then(function () { return new Promise(function (r) { setTimeout(r, 400); }); }).then(load); }

  $("addr-toggle").addEventListener("click", function () {
    hideIps = !hideIps;
    try { window.localStorage.setItem("isf-hide-ips", hideIps ? "1" : "0"); } catch (e) { /* ignore */ }
    if (data) render();
  });

  $("refresh-btn").addEventListener("click", function () {
    var b = $("refresh-btn"), s0 = sel(), before = s0 && s0.last_attempt, tries = 0;
    b.disabled = true; b.textContent = "Checking…";
    var finish = function () { b.disabled = false; b.textContent = "Refresh now"; };
    api("/api/refresh").then(function () {
      (function wait() {
        load().then(function () {
          var s = sel();
          if (!s || (!s.polling && s.last_attempt !== before) || ++tries > 60) finish();
          else setTimeout(wait, 1000);
        });
      })();
    }).catch(finish);
  });

  // ------------------------------------------------------------------ new session, tickets
  function copy(text, btn) {
    var done = function () { var t = btn.textContent; btn.textContent = "Copied"; setTimeout(function () { btn.textContent = t; }, 1200); };
    if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(text).then(done); return; }
    var ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
    try { document.execCommand("copy"); done(); } catch (e) { /* user can select the text by hand */ }
    document.body.removeChild(ta);
  }

  function createSession() {
    var btn = $("create-btn"), err = $("create-error"), dest = $("f-dest").value.trim();
    showError(err, ""); show($("allow-it-wrap"), false);
    btn.disabled = true; btn.textContent = "Creating…";
    return api("/api/session/create", { destination: dest, ttl: parseInt($("f-ttl").value, 10) || 300, label: $("f-label").value, proto: $("f-proto").value })
      .then(function (r) {
        if (!r.ok) {
          showError(err, r.error || "could not create the session");
          var pol = policy();
          if (/allowlist/i.test(r.error || "") && pol && pol.remote_editable) {
            var ab = $("allow-it");
            ab.textContent = "Allow " + dest + " and retry";
            ab.onclick = function () {
              ab.disabled = true;
              addAllow(dest).then(function (a) {
                if (!a.ok) { if (a.error) showError(err, a.error); ab.disabled = false; return; }
                return load().then(createSession).then(function () { ab.disabled = false; });
              });
            };
            show($("allow-it-wrap"), true);
          }
          return;
        }
        var udp = r.proto === "udp";
        $("ticket").value = udp ? "" : r.ticket; $("command").value = r.command;
        show($("ticket"), !udp); show($("ticket-lead"), true); show($("copy-ticket"), !udp);
        $("ticket-lead").textContent = udp ? "The ISF accepts " + r.destination + " over UDP. A UDP session is opened by the client that uses it, so there is no ticket." : "Ticket (shown once — it holds the session key; treat it like a password)";
        $("command-lead").textContent = udp ? "Start a local UDP port that goes through the ISF:" : "Open it on this machine:";
        show($("ticket-box"), true);
        $("f-dest").value = ""; $("f-label").value = "";
        return refreshSoon();
      })
      .catch(function (e) { showError(err, e.message); })
      .then(function () { btn.disabled = false; btn.textContent = $("f-proto").value === "udp" ? "Check and show command" : "Create session"; });
  }
  $("f-proto").addEventListener("change", function () {
    var udp = this.value === "udp";
    $("create-btn").textContent = udp ? "Check and show command" : "Create session";
    $("f-dest").placeholder = udp ? "host:port, e.g. 1.1.1.1:53" : "host:port, e.g. 10.0.0.5:22";
  });
  $("create-form").addEventListener("submit", function (ev) { ev.preventDefault(); createSession(); });
  $("copy-ticket").addEventListener("click", function () { copy($("ticket").value, $("copy-ticket")); });
  $("copy-command").addEventListener("click", function () { copy($("command").value, $("copy-command")); });
  $("copy-key").addEventListener("click", function () { copy($("key-pem").value, $("copy-key")); });
  $("hide-ticket").addEventListener("click", function () { $("ticket").value = ""; $("command").value = ""; show($("ticket-box"), false); });

  load();
  setInterval(load, 2000);
})();
