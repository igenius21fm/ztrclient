$(function () {
  let lastPacketKey = null;
  let flowingUntil = 0;
  let lastData = null;
  let paused = false;
  let selectedPort = null;
  let errorFilter = "";
  let pollTimer = null;
  let startedAt = Date.now();
  const revealed = { identifier: false, secret_key: false };

  let hopModal = null;
  if (window.bootstrap) {
    hopModal = new bootstrap.Modal(document.getElementById("hop-modal"));
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  function emptyRow(cols, text) {
    return `<tr><td class="empty" colspan="${cols}">${text}</td></tr>`;
  }

  // Every captured packet has the entry hop on one side — the other side
  // is this machine itself, under whatever local port the tunnel used.
  // Naming it [YOU] instead of a bare loopback/local IP is just easier to
  // scan than remembering which address is "us" in a feed of addresses.
  function labelEndpoint(hostport, entryAddress) {
    if (!entryAddress) return hostport;
    const i = hostport.lastIndexOf(":");
    const host = hostport.slice(0, i);
    const port = hostport.slice(i + 1);
    return host === entryAddress ? hostport : `[YOU]:${port}`;
  }

  function mask(value) {
    if (!value) return "&mdash;";
    return "&bull;".repeat(Math.min(18, Math.max(8, value.length)));
  }

  function renderCreds(data) {
    const route = data.route;
    if (!route || (!route.identifier && !route.secret_key)) {
      $("#creds-section").hide();
      return;
    }
    $("#creds-section").show();
    ["identifier", "secret_key"].forEach(field => {
      const val = route[field];
      const $el = $(`#creds-${field}`);
      if (!val) { $el.html("&mdash;").removeClass("masked"); return; }
      if (revealed[field]) {
        $el.text(val).removeClass("masked");
      } else {
        $el.html(mask(val)).addClass("masked");
      }
    });
  }

  $(".reveal-btn").on("click", function () {
    const field = $(this).data("field");
    revealed[field] = !revealed[field];
    $(this).find(".icon-eye").toggle(!revealed[field]);
    $(this).find(".icon-eye-off").toggle(revealed[field]);
    if (lastData) renderCreds(lastData);
  });

  function routeStatus(chain) {
    if (!chain || !chain.length) return { text: "NO ROUTE", cls: "unknown" };
    const allUp = chain.every(h => h.status === "up");
    return allUp ? { text: "OPERATIONAL", cls: "operational" } : { text: "DEGRADED", cls: "degraded" };
  }

  function render(data) {
    $("#total-tunnels").text(data.tunnels.total);

    const traffic = data.traffic;
    const $statusEl = $("#traffic-status");
    const $liveDot = $("#term-live-dot");
    if (traffic.enabled) {
      $statusEl.text("Live").attr("class", "value ok");
      $liveDot.addClass("live");
    } else {
      $statusEl.text(traffic.reason || "off").attr("class", "value off");
      $liveDot.removeClass("live");
    }

    const st = routeStatus(data.chain);
    $("#route-status").text(st.text).attr("class", `route-status ${st.cls}`);

    const ports = Object.entries(data.tunnels.by_port);
    const $portsBody = $("#ports-table tbody");
    $portsBody.html(ports.length
      ? ports.map(([p, c]) => {
          const selected = p === selectedPort ? " selected" : "";
          return `<tr class="port-row${selected}" data-port="${p}"><td class="mono">${p}</td><td>${c} active</td></tr>`;
        }).join("")
      : emptyRow(2, "No active tunnels right now."));

    $portsBody.find("tr.port-row").on("click", function () {
      const p = $(this).data("port").toString();
      selectedPort = selectedPort === p ? null : p;
      render(lastData);
    });

    const filterLower = errorFilter.trim().toLowerCase();
    const filteredErrors = filterLower
      ? data.ra_errors.filter(e => `${e.error_code} ${e.error}`.toLowerCase().includes(filterLower))
      : data.ra_errors;
    $("#errors-table tbody").html(filteredErrors.length
      ? filteredErrors.map(e => `<tr><td class="mono">${e.time}</td><td class="error-code">${e.error_code}</td><td>${escapeHtml(e.error)}</td></tr>`).join("")
      : emptyRow(3, data.ra_errors.length ? "No errors match your filter." : "No hop rejections logged."));

    const $trafficSection = $("#traffic-section");
    if (traffic.enabled || traffic.recent.length) {
      $trafficSection.show();
      const shown = selectedPort
        ? traffic.recent.filter(p => p.src.endsWith(`:${selectedPort}`) || p.dst.endsWith(`:${selectedPort}`))
        : traffic.recent;
      $("#traffic-hint").text(selectedPort ? `filtered to :${selectedPort}` : "");

      const entryAddress = data.chain && data.chain[0] ? data.chain[0].address : null;
      const $term = $("#term-body");
      if (!shown.length) {
        $term.html(`<div class="term-empty">$ waiting for traffic${traffic.enabled ? "" : " — capture is off"}...<span class="term-cursor"></span></div>`);
      } else {
        const lines = shown.slice().reverse().map(p => {
          const direction = p.src.includes(entryAddress || "\0") ? "arrow-in" : "arrow-out";
          const src = labelEndpoint(p.src, entryAddress);
          const dst = labelEndpoint(p.dst, entryAddress);
          return `<div class="term-line"><span class="t">[${p.time}]</span> <span class="${direction}">${src}</span> &rarr; ${dst} <span class="t">(${p.length}B)</span></div>`;
        });
        lines.push('<div class="term-line">$<span class="term-cursor"></span></div>');
        $term.html(lines.join(""));
        $term.scrollTop($term[0].scrollHeight);
      }
    } else {
      $trafficSection.hide();
    }

    const $chainSection = $("#chain-section");
    if (data.chain && data.chain.length) {
      $chainSection.show();
      const roles = data.chain.map((h, i) => i === 0 ? "entry" : i === data.chain.length - 1 ? "exit" : "middle");

      if (traffic.recent.length) {
        const top = traffic.recent[0];
        const key = `${top.time}|${top.src}|${top.dst}|${top.length}`;
        if (key !== lastPacketKey) {
          lastPacketKey = key;
          flowingUntil = Date.now() + 4000;
        }
      }
      const arrowClass = Date.now() < flowingUntil ? "arrow flowing" : "arrow";

      $("#chain").html(data.chain.map((h, i) => {
        const statusClass = h.status === "up" ? "up" : (h.status ? "down" : "");
        return (i > 0 ? `<span class="${arrowClass}">&rarr;</span>` : '') +
          `<div class="hop" data-index="${i}"><span class="role">${roles[i]}<span class="hop-status ${statusClass}"></span></span>${h.address}</div>`;
      }).join(""));

      $("#chain .hop").on("click", function () {
        showHopDetail(data.chain[$(this).data("index")], roles[$(this).data("index")]);
      });
    } else {
      $chainSection.hide();
    }

    renderCreds(data);
  }

  function showHopDetail(hop, role) {
    $("#hop-modal-role").text(role.toUpperCase());
    $("#hop-modal-address").text(hop.address || "—");
    $("#hop-modal-status").text(hop.status || "unknown").attr("class", hop.status === "up" ? "text-body" : "error-code");
    $("#hop-modal-pubkey").text(hop.pubkey || "(not available)");
    if (hopModal) hopModal.show();
  }

  function tickClock() {
    const secs = Math.floor((Date.now() - startedAt) / 1000);
    const h = String(Math.floor(secs / 3600)).padStart(2, "0");
    const m = String(Math.floor((secs % 3600) / 60)).padStart(2, "0");
    const s = String(secs % 60).padStart(2, "0");
    $("#session-clock").text(`T+${h}:${m}:${s}`);
  }

  function setLastUpdated() {
    $("#last-updated").text(`Updated ${new Date().toLocaleTimeString()}`);
  }

  function poll() {
    $.getJSON("/api/data").done(data => {
      lastData = data;
      render(data);
      setLastUpdated();
    }).fail(() => {});
  }

  function setPaused(next) {
    paused = next;
    const $btn = $("#pause-btn");
    $btn.text(paused ? "Resume" : "Pause").toggleClass("active", paused);
    if (paused) {
      clearInterval(pollTimer);
    } else {
      pollTimer = setInterval(poll, 3000);
      poll();
    }
  }

  $("#pause-btn").on("click", () => setPaused(!paused));
  $("#refresh-btn").on("click", () => poll());
  $("#error-filter").on("input", function () {
    errorFilter = $(this).val();
    if (lastData) render(lastData);
  });

  // Tactical hotkeys — skip when typing in the filter box.
  $(document).on("keydown", (e) => {
    if ($(e.target).is("input, textarea")) return;
    if (e.key === "p" || e.key === "P") setPaused(!paused);
    if (e.key === "r" || e.key === "R") poll();
  });

  poll();
  pollTimer = setInterval(poll, 3000);
  setInterval(tickClock, 1000);
  // Redraws with the last known data more often than we re-fetch, purely so
  // the chain's flow animation fades out on time instead of jumping every 3s.
  setInterval(() => { if (lastData && !paused) render(lastData); }, 500);
});
