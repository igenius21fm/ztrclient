let lastPacketKey = null;
let flowingUntil = 0;
let lastData = null;
let paused = false;
let selectedPort = null;
let errorFilter = "";
let pollTimer = null;

function emptyRow(cols, text) {
  return `<tr><td class="empty" colspan="${cols}">${text}</td></tr>`;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function render(data) {
  document.getElementById("total-tunnels").textContent = data.tunnels.total;

  const traffic = data.traffic;
  const statusEl = document.getElementById("traffic-status");
  if (traffic.enabled) {
    statusEl.textContent = "Live";
    statusEl.className = "value ok";
  } else {
    statusEl.textContent = traffic.reason || "off";
    statusEl.className = "value off";
  }

  const ports = Object.entries(data.tunnels.by_port);
  const portsBody = document.querySelector("#ports-table tbody");
  portsBody.innerHTML = ports.length
    ? ports.map(([p, c]) => {
        const selected = p === selectedPort ? " selected" : "";
        return `<tr class="port-row${selected}" data-port="${p}"><td class="mono">${p}</td><td>${c} active</td></tr>`;
      }).join("")
    : emptyRow(2, "No active tunnels right now.");

  portsBody.querySelectorAll("tr.port-row").forEach(row => {
    row.onclick = () => {
      const p = row.dataset.port;
      selectedPort = selectedPort === p ? null : p;
      render(lastData);
    };
  });

  const filterLower = errorFilter.trim().toLowerCase();
  const filteredErrors = filterLower
    ? data.ra_errors.filter(e => `${e.error_code} ${e.error}`.toLowerCase().includes(filterLower))
    : data.ra_errors;
  const errorsBody = document.querySelector("#errors-table tbody");
  errorsBody.innerHTML = filteredErrors.length
    ? filteredErrors.map(e => `<tr><td class="mono">${e.time}</td><td class="error-code">${e.error_code}</td><td>${escapeHtml(e.error)}</td></tr>`).join("")
    : emptyRow(3, data.ra_errors.length ? "No errors match your filter." : "No hop rejections logged.");

  const trafficSection = document.getElementById("traffic-section");
  if (traffic.enabled || traffic.recent.length) {
    trafficSection.style.display = "";
    const shown = selectedPort
      ? traffic.recent.filter(p => p.src.endsWith(`:${selectedPort}`) || p.dst.endsWith(`:${selectedPort}`))
      : traffic.recent;
    const hint = document.getElementById("traffic-hint");
    hint.textContent = selectedPort ? `filtered to port ${selectedPort} — click it again to clear` : "";
    const trafficBody = document.querySelector("#traffic-table tbody");
    trafficBody.innerHTML = shown.length
      ? shown.map(p => `<tr><td class="mono">${p.time}</td><td class="mono">${p.src}</td><td class="mono">${p.dst}</td><td>${p.length} bytes</td></tr>`).join("")
      : emptyRow(4, "Waiting for traffic...");
  } else {
    trafficSection.style.display = "none";
  }

  const chainSection = document.getElementById("chain-section");
  if (data.chain && data.chain.length) {
    chainSection.style.display = "";
    const chainEl = document.getElementById("chain");
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

    chainEl.innerHTML = data.chain.map((h, i) =>
      (i > 0 ? `<span class="${arrowClass}">&rarr;</span>` : '') +
      `<div class="hop"><span class="role">${roles[i]}</span>${h.address}</div>`
    ).join("");
  } else {
    chainSection.style.display = "none";
  }
}

function setLastUpdated() {
  document.getElementById("last-updated").textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

function poll() {
  fetch("/api/data").then(r => r.json()).then(data => {
    lastData = data;
    render(data);
    setLastUpdated();
  }).catch(() => {});
}

function setPaused(next) {
  paused = next;
  const btn = document.getElementById("pause-btn");
  btn.textContent = paused ? "Resume" : "Pause";
  btn.classList.toggle("active", paused);
  if (paused) {
    clearInterval(pollTimer);
  } else {
    pollTimer = setInterval(poll, 3000);
    poll();
  }
}

document.getElementById("pause-btn").onclick = () => setPaused(!paused);
document.getElementById("refresh-btn").onclick = () => poll();
document.getElementById("error-filter").oninput = (e) => {
  errorFilter = e.target.value;
  if (lastData) render(lastData);
};

poll();
pollTimer = setInterval(poll, 3000);
// Redraws with the last known data more often than we re-fetch, purely so
// the chain's flow animation fades out on time instead of jumping every 3s.
setInterval(() => { if (lastData && !paused) render(lastData); }, 500);
