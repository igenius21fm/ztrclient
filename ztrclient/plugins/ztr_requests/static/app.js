$(function () {
  // Sent automatically when the request doesn't set its own User-Agent, so
  // a plain request doesn't announce itself as a script — a normal-looking
  // browser UA blends in better for OSINT-style lookups than no UA at all
  // (or an obviously custom one).
  const DEFAULT_USER_AGENT =
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

  function escapeHtml(str) {
    return $('<div>').text(str == null ? '' : str).html();
  }

  function statusPillClass(result) {
    if (!result) return 'idle';
    if (!result.ok && !result.status_code) return 'errnet';
    const code = result.status_code || 0;
    if (code >= 500) return 'err5xx';
    if (code >= 400) return 'warn4xx';
    if (code >= 300) return 'ok3xx';
    if (code >= 200) return 'ok2xx';
    return 'errnet';
  }

  function statusPillText(result) {
    if (!result) return 'Ready';
    if (!result.status_code) return result.error ? 'Network error' : 'No response';
    return String(result.status_code);
  }

  function prettyBody(text) {
    if (text == null) return '';
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch (e) {
      return text;
    }
  }

  // ---------------- Generic key/value row editor (headers, params) ----------------

  function addKVRow($container, key, value, keyPlaceholder, valuePlaceholder, onChange, keyListId) {
    const listAttr = keyListId ? `list="${keyListId}"` : '';
    const $row = $(`
      <div class="header-row">
        <input class="header-key" ${listAttr} placeholder="${escapeHtml(keyPlaceholder)}" value="${escapeHtml(key || '')}">
        <input class="header-value" placeholder="${escapeHtml(valuePlaceholder)}" value="${escapeHtml(value || '')}">
        <button type="button" class="header-remove" title="Remove">&times;</button>
      </div>
    `);
    $row.find('.header-remove').on('click', () => { $row.remove(); if (onChange) onChange(); });
    if (onChange) $row.find('input').on('change', onChange);
    $container.append($row);
    return $row;
  }

  function collectKVRows($container) {
    const out = {};
    $container.find('.header-row').each(function () {
      const key = $(this).find('.header-key').val().trim();
      const value = $(this).find('.header-value').val();
      if (key) out[key] = value;
    });
    return out;
  }

  // ---------------- Headers ----------------

  function addHeaderRow(key, value) {
    const $row = addKVRow($('#headerRows'), key, value, 'Header', 'Value', updateHeaderCount, 'headerNameOptions');
    updateHeaderCount();
    return $row;
  }
  function updateHeaderCount() {
    const n = $('#headerRows .header-row').length;
    $('#headerCount').text(n ? `(${n})` : '');
  }
  $(document).on('click', '#headerRows .header-remove', updateHeaderCount);
  $('#addHeaderBtn').on('click', () => addHeaderRow('', ''));

  // ---------------- Params (synced with the URL's query string) ----------------

  let syncingParams = false;

  function addParamRow(key, value) {
    addKVRow($('#paramRows'), key, value, 'Param', 'Value', syncUrlFromParams);
    updateParamCount();
  }
  function updateParamCount() {
    const n = $('#paramRows .header-row').length;
    $('#paramCount').text(n ? `(${n})` : '');
  }
  $(document).on('click', '#paramRows .header-remove', () => { updateParamCount(); syncUrlFromParams(); });
  $('#addParamBtn').on('click', () => addParamRow('', ''));

  function syncUrlFromParams() {
    if (syncingParams) return;
    const params = collectKVRows($('#paramRows'));
    const [base] = $('#urlInput').val().split('?');
    const qs = new URLSearchParams(params).toString();
    syncingParams = true;
    $('#urlInput').val(qs ? `${base}?${qs}` : base);
    syncingParams = false;
  }

  function syncParamsFromUrl() {
    if (syncingParams) return;
    const url = $('#urlInput').val();
    const qIndex = url.indexOf('?');
    syncingParams = true;
    $('#paramRows').empty();
    if (qIndex !== -1) {
      const params = new URLSearchParams(url.slice(qIndex + 1));
      params.forEach((value, key) => addKVRow($('#paramRows'), key, value, 'Param', 'Value', syncUrlFromParams));
    }
    updateParamCount();
    syncingParams = false;
  }

  $('#urlInput').on('change', syncParamsFromUrl);

  // ---------------- Auth ----------------

  $('#authType').on('change', function () {
    const type = $(this).val();
    $('#authBearerFields').toggle(type === 'bearer');
    $('#authBasicFields').toggle(type === 'basic');
    $('#authBadge').text(type === 'none' ? '' : 'on');
  });

  function computeAuthHeader() {
    const type = $('#authType').val();
    if (type === 'bearer') {
      const token = $('#authBearerToken').val().trim();
      return token ? { Authorization: `Bearer ${token}` } : {};
    }
    if (type === 'basic') {
      const user = $('#authBasicUser').val();
      const pass = $('#authBasicPass').val();
      if (!user) return {};
      try {
        return { Authorization: `Basic ${btoa(unescape(encodeURIComponent(`${user}:${pass}`)))}` };
      } catch (e) {
        return {};
      }
    }
    return {};
  }

  // ---------------- Variables ({{key}} substitution) ----------------

  let envVars = {};

  function substituteVars(str) {
    if (str == null) return str;
    return String(str).replace(/\{\{\s*([\w.-]+)\s*\}\}/g, (m, key) => (key in envVars ? envVars[key] : m));
  }

  function loadVars() {
    $.get('/api/env').done((res) => {
      envVars = res.vars || {};
      renderVarRows(res.vars_meta || []);
    });
  }

  function renderVarRows(varsMeta) {
    const $rows = $('#varRows');
    $rows.empty();
    varsMeta.forEach((v) => addVarRow(v.key, v.value, v.secret));
  }

  // A dedicated row (not the generic addKVRow) — variables get a secret
  // toggle headers/params rows don't need. Marking one secret masks its
  // value here (type=password) and in the sidebar; the real value is
  // still sent to the browser for {{var}} substitution to work, so this
  // is a display convenience against shoulder-surfing/screenshots, not a
  // server-side secret store.
  function addVarRow(key, value, secret) {
    const $row = $(`
      <div class="header-row">
        <input class="header-key" placeholder="name" value="${escapeHtml(key || '')}">
        <input class="header-value" type="${secret ? 'password' : 'text'}" placeholder="value" value="${escapeHtml(value || '')}">
        <button type="button" class="icon-btn var-secret-btn${secret ? ' is-secret' : ''}" title="${secret ? 'Secret — click to show' : 'Click to mark as secret'}" aria-label="Toggle secret">
          <svg class="icon"><use href="#icon-lock"></use></svg>
        </button>
        <button type="button" class="header-remove" title="Remove">&times;</button>
      </div>
    `);
    $row.data('secret', !!secret);

    function persist() {
      const k = $row.find('.header-key').val().trim();
      const v = $row.find('.header-value').val();
      if (!k) return;
      envVars[k] = v;
      $.ajax({
        url: '/api/env',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ key: k, value: v, secret: $row.data('secret') }),
      });
    }

    $row.find('.header-key, .header-value').on('change', persist);

    $row.find('.var-secret-btn').on('click', function () {
      const nowSecret = !$row.data('secret');
      $row.data('secret', nowSecret);
      $(this).toggleClass('is-secret', nowSecret)
        .attr('title', nowSecret ? 'Secret — click to show' : 'Click to mark as secret');
      $row.find('.header-value').attr('type', nowSecret ? 'password' : 'text');
      persist();
    });

    $row.find('.header-remove').on('click', function () {
      const k = $row.find('.header-key').val().trim();
      if (k) {
        delete envVars[k];
        $.ajax({ url: '/api/env?key=' + encodeURIComponent(k), method: 'DELETE' });
      }
      $row.remove();
    });

    $('#varRows').append($row);
    return $row;
  }
  $('#addVarBtn').on('click', () => addVarRow('', '', false));

  // ---------------- Environments (named var profiles) ----------------

  function loadEnvironments() {
    $.get('/api/environments').done((res) => {
      renderEnvSelect(res.environments || []);
    });
  }

  function renderEnvSelect(envs) {
    const $sel = $('#envSelect');
    $sel.empty();
    envs.forEach((e) => {
      $sel.append(`<option value="${e.id}"${e.active ? ' selected' : ''}>${escapeHtml(e.name)}</option>`);
    });
    $('#deleteEnvBtn').prop('disabled', envs.length <= 1);
  }

  $('#envSelect').on('change', function () {
    const id = parseInt($(this).val(), 10);
    $.ajax({ url: '/api/environments/activate', method: 'POST', contentType: 'application/json', data: JSON.stringify({ id }) })
      .done(loadVars);
  });

  $('#addEnvBtn').on('click', function () {
    const name = prompt('New environment name:');
    if (!name) return;
    $.ajax({ url: '/api/environments', method: 'POST', contentType: 'application/json', data: JSON.stringify({ name }) })
      .done((res) => {
        $.ajax({
          url: '/api/environments/activate',
          method: 'POST',
          contentType: 'application/json',
          data: JSON.stringify({ id: res.environment.id }),
        }).done(() => { loadEnvironments(); loadVars(); });
      })
      .fail((xhr) => alert((xhr.responseJSON && xhr.responseJSON.error) || 'could not create environment'));
  });

  $('#renameEnvBtn').on('click', function () {
    const $opt = $('#envSelect option:selected');
    if (!$opt.length) return;
    const name = prompt('Rename environment:', $opt.text());
    if (!name || name === $opt.text()) return;
    $.ajax({
      url: '/api/environments/rename',
      method: 'POST',
      contentType: 'application/json',
      data: JSON.stringify({ id: parseInt($opt.val(), 10), name }),
    })
      .done(loadEnvironments)
      .fail((xhr) => alert((xhr.responseJSON && xhr.responseJSON.error) || 'could not rename environment'));
  });

  $('#deleteEnvBtn').on('click', function () {
    const $opt = $('#envSelect option:selected');
    if (!$opt.length) return;
    if (!confirm(`Delete environment "${$opt.text()}" and all its variables?`)) return;
    $.ajax({ url: '/api/environments?id=' + encodeURIComponent($opt.val()), method: 'DELETE' })
      .done(() => { loadEnvironments(); loadVars(); })
      .fail((xhr) => alert((xhr.responseJSON && xhr.responseJSON.error) || 'could not delete environment'));
  });

  // ---------------- Request/response tabs ----------------

  $('#requestTabs .tab').on('click', function () {
    const tab = $(this).data('tab');
    $('#requestTabs .tab').removeClass('active');
    $(this).addClass('active');
    $('#tab-params, #tab-auth, #tab-headers, #tab-body').removeClass('active');
    $('#tab-' + tab).addClass('active');
  });

  $('#responseTabs .tab').on('click', function () {
    const tab = $(this).data('rtab');
    $('#responseTabs .tab').removeClass('active');
    $(this).addClass('active');
    $('#rtab-body, #rtab-headers, #rtab-security, #rtab-metadata').removeClass('active');
    $('#rtab-' + tab).addClass('active');
  });

  // ---------------- Sidebar tabs (History / Saved / Conns) ----------------

  $('#sidebarTabs .side-tab').on('click', function () {
    const side = $(this).data('side');
    $('#sidebarTabs .side-tab').removeClass('active');
    $(this).addClass('active');
    $('#side-history, #side-saved, #side-conns').removeClass('active');
    $('#side-' + side).addClass('active');
    if (side === 'saved') loadSaved();
    if (side === 'conns') loadPools();
  });

  // ---------------- Method select coloring ----------------

  $('#methodSelect').on('change', function () {
    $(this).removeClass('method-GET method-POST method-PUT method-PATCH method-DELETE');
    $(this).addClass('method-' + $(this).val());
  });

  // ---------------- Format JSON ----------------

  $('#formatJsonBtn').on('click', function () {
    const text = $('#bodyInput').val();
    if (!text.trim()) return;
    try {
      $('#bodyInput').val(JSON.stringify(JSON.parse(text), null, 2));
    } catch (e) {
      alert("That doesn't look like valid JSON.");
    }
  });

  // ---------------- Load routes ----------------

  $.get('/api/routes').done((res) => {
    const $sel = $('#routeSelect');
    $sel.empty();
    if (!res.routes || !res.routes.length) {
      $sel.append('<option value="">No .ztr files in routes/</option>');
      return;
    }
    res.routes.forEach((r) => $sel.append(`<option value="${escapeHtml(r)}">${escapeHtml(r)}</option>`));
  });

  loadEnvironments();
  loadVars();

  // ---------------- History ----------------

  function renderList($list, items, emptyText, onClick, onRemove, showStatus) {
    $list.empty();
    if (!items || !items.length) {
      $list.append(`<div class="history-empty">${emptyText}</div>`);
      return;
    }
    items.forEach((item) => {
      const cls = statusPillClass(item);
      const label = item.name ? escapeHtml(item.name) : escapeHtml(item.url);
      const statusHtml = showStatus
        ? `<span class="history-status status-pill ${cls}">${escapeHtml(statusPillText(item))}</span>`
        : '';
      const removeHtml = onRemove
        ? '<button type="button" class="list-item-remove" title="Delete"><svg class="icon"><use href="#icon-x"></use></svg></button>'
        : '';
      const $row = $(`
        <div class="history-item" title="${escapeHtml(item.url)}">
          <span class="history-method method-${escapeHtml(item.method)}">${escapeHtml(item.method)}</span>
          <span class="history-url">${label}</span>
          ${statusHtml}
          ${removeHtml}
        </div>
      `);
      $row.on('click', (e) => { if (!$(e.target).closest('.list-item-remove').length) onClick(item); });
      if (onRemove) $row.find('.list-item-remove').on('click', (e) => { e.stopPropagation(); onRemove(item); });
      $list.append($row);
    });
  }

  function loadHistory() {
    $.get('/api/history?limit=50').done((res) => {
      renderList($('#historyList'), res.history, 'No requests yet.', loadEntryIntoComposer, (item) => {
        $.ajax({ url: '/api/history?id=' + item.id, method: 'DELETE' }).done(loadHistory);
      }, true);
    });
  }

  function loadSaved() {
    $.get('/api/collection').done((res) => {
      renderList($('#savedList'), res.items, 'Nothing saved yet.', loadEntryIntoComposer, (item) => {
        if (!confirm(`Delete saved request "${item.name}"?`)) return;
        $.ajax({ url: '/api/collection?id=' + item.id, method: 'DELETE' }).done(loadSaved);
      });
    });
  }

  function loadEntryIntoComposer(item) {
    $('#methodSelect').val(item.method).trigger('change');
    $('#urlInput').val(item.url);
    syncParamsFromUrl();
    if (item.config_file) $('#routeSelect').val(item.config_file);
    $('#targetPort').val(item.target_port || '');
    $('#withTimingDefense').prop('checked', !!item.with_timing_defense);

    // Auth isn't part of a saved/history entry (it's folded into headers at
    // send time) — reset it so a Bearer/Basic setup from a previous request
    // can't silently carry over onto this one.
    $('#authType').val('none').trigger('change');
    $('#authBearerToken').val('');
    $('#authBasicUser').val('');
    $('#authBasicPass').val('');

    const headers = item.request_headers || item.headers || {};
    $('#headerRows').empty();
    const keys = Object.keys(headers);
    if (keys.length) keys.forEach((k) => addHeaderRow(k, headers[k]));
    else addHeaderRow('Content-Type', 'application/json');

    $('#bodyInput').val(item.request_body || item.body || '');
  }

  // Clears the request being composed — method, URL, params, auth, headers,
  // body, and the response panel — but leaves Connection settings (route,
  // target, worker/tunnel options) alone, since those describe where you're
  // working, not what you're about to send.
  function resetComposer() {
    $('#methodSelect').val('GET').trigger('change');
    $('#urlInput').val('');
    $('#paramRows').empty();
    updateParamCount();

    $('#authType').val('none').trigger('change');
    $('#authBearerToken').val('');
    $('#authBasicUser').val('');
    $('#authBasicPass').val('');

    $('#headerRows').empty();
    addHeaderRow('Content-Type', 'application/json');

    $('#bodyInput').val('');

    $('#statusPill').attr('class', 'status-pill idle').text('Ready');
    $('#timingStat').text('');
    $('#sizeStat').text('');
    showTextResponse();
    $('#metadataTab').hide();
    if ($('#metadataTab').hasClass('active')) {
      $('#responseTabs .tab[data-rtab="body"]').trigger('click');
    }
    $('#responseBody').text('Send a request to see the response here.');
    $('#requestHeaders').text('');
    $('#responseHeaders').text('');
    $('#cookieBar').empty();
    $('#routeInfoCard').hide().empty();
    $('#tlsCertCard').hide().empty();
    $('#responseSecurity').text('Send a request to see its headers analyzed here.');
    $('#securityCount').text('');
    lastResponseHeaders = {};
    lastSetCookies = {};
  }

  $('#newRequestBtn').on('click', resetComposer);

  $('#clearHistoryBtn').on('click', function () {
    if (!confirm('Clear all request history?')) return;
    $.ajax({ url: '/api/history', method: 'DELETE' }).done(loadHistory);
  });

  loadHistory();
  addHeaderRow('Content-Type', 'application/json');

  // ---------------- Connections ----------------

  function loadPools() {
    $.get('/api/sessions').done((res) => {
      const $list = $('#poolsList');
      $list.empty();
      if (!res.sessions || !res.sessions.length) {
        $list.append('<div class="history-empty">No active tunnels yet — send a request to open one.</div>');
        return;
      }
      res.sessions.forEach((p) => {
        const flags = p.with_timing_defense ? 'timing-defense' : 'plain';
        const origins = p.origins && p.origins.length ? p.origins.join(', ') : 'no open connections yet';
        const $row = $(`
          <div class="pool-row">
            <div class="pool-row-head">
              <span class="pool-target">${escapeHtml(p.config_file)}</span>
              <button type="button" class="list-item-remove" title="Disconnect"><svg class="icon"><use href="#icon-x"></use></svg></button>
            </div>
            <div class="pool-flags">${escapeHtml(flags)}</div>
            <div class="pool-workers">
              <span class="free">${escapeHtml(origins)}</span>
            </div>
          </div>
        `);
        $row.find('.list-item-remove').on('click', () => {
          $.ajax({
            url: '/api/sessions/drop',
            method: 'POST',
            contentType: 'application/json',
            data: JSON.stringify(p),
          }).done(loadPools);
        });
        $list.append($row);
      });
    });
  }
  $('#refreshPoolsBtn').on('click', loadPools);

  // ---------------- Save to collection ----------------

  function composerState() {
    return {
      method: $('#methodSelect').val(),
      url: $('#urlInput').val().trim(),
      headers: collectKVRows($('#headerRows')),
      body: $('#bodyInput').val() || undefined,
      config_file: $('#routeSelect').val(),
      target_port: parseInt($('#targetPort').val(), 10) || undefined,
      with_timing_defense: $('#withTimingDefense').is(':checked'),
    };
  }

  $('#saveBtn').on('click', function () {
    const url = $('#urlInput').val().trim();
    if (!url) return alert('URL is required.');
    const name = prompt('Name this request:', url);
    if (!name) return;
    const entry = Object.assign({ name }, composerState());
    $.ajax({ url: '/api/collection', method: 'POST', contentType: 'application/json', data: JSON.stringify(entry) })
      .done(() => { if ($('#side-saved').hasClass('active')) loadSaved(); });
  });

  // ---------------- Set-Cookie -> reuse in next request ----------------

  let lastResponseHeaders = {};
  let lastSetCookies = {};

  function cookieEntries(cookies) {
    return Object.entries(cookies || {}).map(([name, value]) => ({ name, value }));
  }

  function addCookieToComposer(name, value, skipFocus) {
    let $cookieRow = null;
    $('#headerRows .header-row').each(function () {
      if ($(this).find('.header-key').val().trim().toLowerCase() === 'cookie') {
        $cookieRow = $(this);
      }
    });
    if (!$cookieRow) {
      $cookieRow = addHeaderRow('Cookie', '');
    }

    const $valInput = $cookieRow.find('.header-value');
    const map = {};
    $valInput.val().split(';').forEach((pair) => {
      const idx = pair.indexOf('=');
      if (idx === -1) return;
      const k = pair.slice(0, idx).trim();
      if (k) map[k] = pair.slice(idx + 1).trim();
    });
    map[name] = value;
    $valInput.val(Object.entries(map).map(([k, v]) => `${k}=${v}`).join('; '));

    if (!skipFocus) {
      $('#requestTabs .tab[data-tab="headers"]').trigger('click');
      $valInput.css('outline', '2px solid var(--accent)');
      setTimeout(() => $valInput.css('outline', ''), 900);
    }
  }

  function renderCookieBar(cookies) {
    const entries = cookieEntries(cookies);
    if (!entries.length) return $();
    const $bar = $('<div class="cookie-bar"></div>');
    $bar.append('<div class="side-eyebrow">Set-Cookie <span class="hint">click Use to carry it into your next request</span></div>');
    entries.forEach((c) => {
      const $row = $(`
        <div class="cookie-row">
          <span class="cookie-name"></span>
          <span class="cookie-value"></span>
          <button type="button" class="ghost-btn small use-cookie-btn" title="Use in next request">
            <svg class="icon"><use href="#icon-plus"></use></svg> Use
          </button>
        </div>
      `);
      $row.find('.cookie-name').text(c.name);
      $row.find('.cookie-value').text(c.value);
      $row.find('.use-cookie-btn').data('name', c.name).data('value', c.value);
      $bar.append($row);
    });
    if (entries.length > 1) {
      $bar.append('<button type="button" class="ghost-btn small" id="useAllCookiesBtn"><svg class="icon"><use href="#icon-plus"></use></svg> Use all</button>');
    }
    return $bar;
  }

  $(document).on('click', '.use-cookie-btn', function () {
    addCookieToComposer($(this).data('name'), $(this).data('value'));
  });

  $(document).on('click', '#useAllCookiesBtn', function () {
    const entries = cookieEntries(lastSetCookies);
    entries.forEach((c, i) => addCookieToComposer(c.name, c.value, i < entries.length - 1));
  });

  // ---------------- Relay path (exit-hop identity) ----------------

  function renderRouteInfoCard(routeInfo) {
    const $card = $('#routeInfoCard');
    if (!routeInfo || !routeInfo.hops || !routeInfo.hops.length) {
      $card.hide().empty();
      return;
    }
    const $dl = $('<dl class="tls-cert-grid"></dl>');
    routeInfo.hops.forEach((h) => {
      const label = h.role ? h.role.charAt(0).toUpperCase() + h.role.slice(1) : `Hop ${h.hop}`;
      const value = h.status && h.status !== 'online' ? `${h.address} (${h.status})` : (h.address || '?');
      $dl.append(`<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`);
    });
    $card.empty()
      .append('<div class="side-eyebrow">Relay Path</div>')
      .append($dl)
      .show();
  }

  // ---------------- TLS certificate ----------------

  function daysUntil(dateStr) {
    if (!dateStr) return null;
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return null;
    return Math.floor((d.getTime() - Date.now()) / 86400000);
  }

  function renderTlsCertCard(tlsInfo) {
    const $card = $('#tlsCertCard');
    if (!tlsInfo || (!tlsInfo.certificate && !tlsInfo.protocol)) {
      $card.hide().empty();
      return;
    }
    const cert = tlsInfo.certificate;
    const rows = [];
    if (tlsInfo.protocol) {
      rows.push(['Protocol', tlsInfo.protocol + (tlsInfo.cipher ? ` · ${tlsInfo.cipher.name}` : '')]);
    }
    if (cert) {
      rows.push(['Subject', cert.subject_cn || '(none)']);
      rows.push(['Issuer', [cert.issuer_cn, cert.issuer_o].filter(Boolean).join(' · ') || '(unknown)']);
      const days = daysUntil(cert.not_after);
      let validity = `${cert.not_before || '?'} → ${cert.not_after || '?'}`;
      if (days != null) validity += days < 0 ? ` (expired ${Math.abs(days)}d ago)` : ` (${days}d left)`;
      rows.push(['Valid', validity]);
      if (cert.subject_alt_names && cert.subject_alt_names.length) {
        rows.push(['SANs', cert.subject_alt_names.join(', ')]);
      }
      if (cert.serial_number) rows.push(['Serial', cert.serial_number]);
    } else {
      rows.push(['Certificate', 'not available (certificate verification is disabled for this request)']);
    }

    const $dl = $('<dl class="tls-cert-grid"></dl>');
    rows.forEach(([label, value]) => {
      $dl.append(`<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`);
    });

    $card.empty()
      .append('<div class="side-eyebrow">TLS Certificate</div>')
      .append($dl)
      .show();
  }

  function analyzeTls(tlsInfo, isHttps) {
    const findings = [];
    if (!isHttps || !tlsInfo) return findings;

    if (tlsInfo.protocol) {
      const modern = /TLSv1\.[23]/i.test(tlsInfo.protocol);
      if (modern) {
        findings.push({ sev: 'ok', title: `${tlsInfo.protocol} negotiated`, detail: tlsInfo.cipher ? tlsInfo.cipher.name : '' });
      } else {
        findings.push({ sev: 'warn', title: `Outdated TLS protocol (${tlsInfo.protocol})`, detail: 'TLS 1.2 or 1.3 is expected; older protocols have known weaknesses.' });
      }
    }

    const cert = tlsInfo.certificate;
    if (cert) {
      const days = daysUntil(cert.not_after);
      if (days != null) {
        if (days < 0) {
          findings.push({ sev: 'high', title: 'Certificate expired', detail: `Expired ${Math.abs(days)} day(s) ago (${cert.not_after}).` });
        } else if (days <= 14) {
          findings.push({ sev: 'warn', title: `Certificate expires in ${days} day(s)`, detail: cert.not_after });
        }
      }
      if (cert.subject_cn && cert.issuer_cn && cert.subject_cn === cert.issuer_cn) {
        findings.push({ sev: 'warn', title: 'Certificate appears self-signed', detail: `Subject and issuer both "${cert.subject_cn}".` });
      }
    } else {
      findings.push({ sev: 'info', title: 'No certificate details available', detail: 'Certificate verification was disabled for this request (verify=False).' });
    }

    return findings;
  }

  // ---------------- Security header analysis ----------------

  function analyzeSecurityHeaders(headers, url, setCookieHeaders, tlsInfo) {
    const h = {};
    Object.entries(headers || {}).forEach(([k, v]) => { h[k.toLowerCase()] = v; });
    const has = (name) => Object.prototype.hasOwnProperty.call(h, name);
    const isHttps = /^https:\/\//i.test(url || '');
    const findings = analyzeTls(tlsInfo, isHttps);

    if (has('strict-transport-security')) {
      findings.push({ sev: 'ok', title: 'Strict-Transport-Security present', detail: h['strict-transport-security'] });
    } else if (isHttps) {
      findings.push({ sev: 'warn', title: 'Missing Strict-Transport-Security', detail: 'No HSTS on an HTTPS response — browsers aren\'t told to force HTTPS on future visits, leaving room for a downgrade/SSL-stripping attack.' });
    }

    const csp = h['content-security-policy'] || '';
    if (has('x-frame-options') || /frame-ancestors/i.test(csp)) {
      findings.push({ sev: 'ok', title: 'Clickjacking protection present', detail: has('x-frame-options') ? `X-Frame-Options: ${h['x-frame-options']}` : 'CSP frame-ancestors directive' });
    } else {
      findings.push({ sev: 'warn', title: 'No clickjacking protection', detail: 'Neither X-Frame-Options nor a CSP frame-ancestors directive is set — this response could be framed by another site.' });
    }

    if ((h['x-content-type-options'] || '').toLowerCase() === 'nosniff') {
      findings.push({ sev: 'ok', title: 'X-Content-Type-Options: nosniff present' });
    } else {
      findings.push({ sev: 'warn', title: 'Missing X-Content-Type-Options: nosniff', detail: 'Browsers may MIME-sniff the body into a different, possibly executable content type.' });
    }

    if (csp) {
      findings.push({ sev: 'ok', title: 'Content-Security-Policy present', detail: csp.length > 140 ? csp.slice(0, 140) + '…' : csp });
    } else {
      findings.push({ sev: 'info', title: 'No Content-Security-Policy', detail: 'A CSP adds defense-in-depth against XSS/injection even when input handling is otherwise correct.' });
    }

    if (has('referrer-policy')) {
      findings.push({ sev: 'ok', title: 'Referrer-Policy present', detail: h['referrer-policy'] });
    } else {
      findings.push({ sev: 'info', title: 'No Referrer-Policy', detail: 'Full URLs — including sensitive query parameters — may leak to third parties via the Referer header on outbound links.' });
    }

    if (has('permissions-policy')) {
      findings.push({ sev: 'ok', title: 'Permissions-Policy present', detail: h['permissions-policy'] });
    } else {
      findings.push({ sev: 'info', title: 'No Permissions-Policy', detail: 'Browser features (camera, geolocation, etc.) aren\'t explicitly restricted for this response.' });
    }

    const acao = h['access-control-allow-origin'];
    const acac = (h['access-control-allow-credentials'] || '').toLowerCase() === 'true';
    if (acao === '*' && acac) {
      findings.push({ sev: 'high', title: 'Wildcard CORS origin with credentials allowed', detail: 'Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true is a serious CORS misconfiguration.' });
    } else if (acao === '*') {
      findings.push({ sev: 'info', title: 'Wildcard CORS origin', detail: 'Access-Control-Allow-Origin: * — any website can read this response via fetch/XHR.' });
    }

    ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'].forEach((name) => {
      if (has(name)) {
        findings.push({ sev: 'info', title: `${name} discloses server software`, detail: `${name}: ${h[name]}` });
      }
    });

    (setCookieHeaders || []).forEach((raw) => {
      const name = raw.split('=')[0].trim();
      const lower = raw.toLowerCase();
      const issues = [];
      if (!lower.includes('httponly')) issues.push('missing HttpOnly (readable by JavaScript)');
      if (isHttps && !lower.includes('secure')) issues.push('missing Secure (sendable over plain HTTP)');
      if (!/samesite=/i.test(raw)) issues.push('missing SameSite (CSRF exposure)');
      else if (/samesite=none/i.test(raw) && !lower.includes('secure')) issues.push('SameSite=None without Secure');
      if (issues.length) {
        findings.push({ sev: 'warn', title: `Cookie "${name}": ${issues.join(', ')}`, detail: raw });
      } else {
        findings.push({ sev: 'ok', title: `Cookie "${name}" flags look fine`, detail: raw });
      }
    });

    const order = { high: 0, warn: 1, info: 2, ok: 3 };
    findings.sort((a, b) => order[a.sev] - order[b.sev]);
    return findings;
  }

  const SEV_PILL_CLASS = { high: 'err5xx', warn: 'warn4xx', info: 'ok3xx', ok: 'ok2xx' };
  const SEV_LABEL = { high: 'HIGH', warn: 'WARN', info: 'INFO', ok: 'OK' };

  function renderSecurityView(headers, url, setCookieHeaders, tlsInfo) {
    const findings = analyzeSecurityHeaders(headers, url, setCookieHeaders, tlsInfo);
    if (!findings.length) {
      return { html: '<div class="history-empty">No response headers to analyze.</div>', issueCount: 0 };
    }
    const html = findings.map((f) => `
      <div class="sec-row">
        <span class="status-pill ${SEV_PILL_CLASS[f.sev]}">${SEV_LABEL[f.sev]}</span>
        <div class="sec-body">
          <div class="sec-title">${escapeHtml(f.title)}</div>
          ${f.detail ? `<div class="sec-detail">${escapeHtml(f.detail)}</div>` : ''}
        </div>
      </div>
    `).join('');
    const issueCount = findings.filter((f) => f.sev === 'high' || f.sev === 'warn').length;
    return { html, issueCount };
  }

  // ---------------- Send ----------------

  function setPending(pending) {
    $('#sendBtn').prop('disabled', pending);
    if (pending) {
      $('#statusPill').attr('class', 'status-pill pending').text('Sending…');
    }
  }

  function showTextResponse() {
    $('#responseImageWrap').hide();
    $('#responseBody').show();
    $('#responseBodyToolbar').show();
  }

  function showImageResponse(contentType, base64) {
    $('#responseBody').hide();
    $('#responseBodyToolbar').hide();
    $('#responseImage').attr('src', `data:${contentType};base64,${base64}`);
    $('#responseImageWrap').css('display', 'flex');
  }

  function metaRows(obj, exclude) {
    return Object.entries(obj)
      .filter(([k]) => !(exclude || []).includes(k))
      .map(([k, v]) => {
        const text = typeof v === 'object' && v !== null ? JSON.stringify(v) : v;
        return `<div class="meta-row"><span class="meta-key">${escapeHtml(k)}</span><span class="meta-val">${escapeHtml(text)}</span></div>`;
      })
      .join('');
  }

  function renderMetadataView(metadata) {
    if (!metadata) {
      return '<div class="history-empty">Couldn\'t read this image — it may be corrupt or an unsupported format.</div>';
    }

    const declaredRow = metadata.declared_content_type
      ? `<div class="meta-row meta-warn"><span class="meta-key">Declared Content-Type</span><span class="meta-val">${escapeHtml(metadata.declared_content_type)} <span class="hint">(detected as an image anyway)</span></span></div>`
      : '';

    let html = `
      <div class="meta-group">
        <div class="meta-group-title">Image</div>
        <div class="meta-row"><span class="meta-key">Format</span><span class="meta-val">${escapeHtml(metadata.format || '—')}</span></div>
        <div class="meta-row"><span class="meta-key">Dimensions</span><span class="meta-val">${metadata.width} &times; ${metadata.height}</span></div>
        <div class="meta-row"><span class="meta-key">Mode</span><span class="meta-val">${escapeHtml(metadata.mode || '—')}</span></div>
        ${declaredRow}
      </div>
    `;

    if (metadata.gps) {
      const gps = metadata.gps;
      html += '<div class="meta-group"><div class="meta-group-title">GPS</div>';
      if (gps.latitude != null && gps.longitude != null) {
        html += `<div class="meta-row"><span class="meta-key">Coordinates</span><span class="meta-val">${gps.latitude}, ${gps.longitude} &nbsp;<a href="${escapeHtml(gps.maps_url)}" target="_blank" rel="noopener" class="meta-link">View on map</a></span></div>`;
      }
      html += metaRows(gps, ['latitude', 'longitude', 'maps_url']);
      html += '</div>';
    }

    if (metadata.exif) {
      html += `<div class="meta-group"><div class="meta-group-title">EXIF</div>${metaRows(metadata.exif)}</div>`;
    }

    if (!metadata.exif && !metadata.gps) {
      html += '<p class="hint" style="margin-top:14px">No EXIF data found in this image.</p>';
    }

    return html;
  }

  function renderResponse(result, requestHeaders) {
    const cls = statusPillClass(result);
    $('#statusPill').attr('class', 'status-pill ' + cls).text(statusPillText(result));
    $('#timingStat').text(result.elapsed_ms != null ? `${result.elapsed_ms} ms` : '');

    // result.request_headers, when present, is the exact headers the
    // server actually sent (including a Cookie header the Session's own
    // jar may have added that the composer never knew about) — prefer
    // that over the composer's own pre-send guess.
    const actualRequestHeaders = (result.request_headers && Object.keys(result.request_headers).length)
      ? result.request_headers
      : requestHeaders;
    const requestHeaderLines = Object.entries(actualRequestHeaders || {}).map(([k, v]) => `${k}: ${v}`);
    $('#requestHeaders').text(requestHeaderLines.join('\n') || '(no headers)');

    if (result.error && !result.status_code) {
      showTextResponse();
      $('#responseBody').text(result.error);
      $('#responseHeaders').text('');
      $('#sizeStat').text('');
      $('#metadataTab').hide();
      $('#cookieBar').empty();
      $('#routeInfoCard').hide().empty();
      $('#tlsCertCard').hide().empty();
      $('#responseSecurity').html('<div class="history-empty">No response — nothing to analyze.</div>');
      $('#securityCount').text('');
      lastResponseHeaders = {};
      lastSetCookies = {};
      return;
    }

    if (result.is_image && result.body_base64) {
      showImageResponse(result.content_type, result.body_base64);
      let byteLength = 0;
      try { byteLength = atob(result.body_base64).length; } catch (e) { /* ignore */ }
      $('#sizeStat').text(`${byteLength} B`);
      $('#metadataTab').show();
      $('#responseMetadata').html(renderMetadataView(result.metadata));
    } else {
      showTextResponse();
      const bodyText = result.is_binary ? '(binary response body — not shown)' : (result.body || '');
      $('#responseBody').text(prettyBody(bodyText));
      $('#sizeStat').text(bodyText ? `${new Blob([bodyText]).size} B` : '');
      $('#metadataTab').hide();
      if ($('#metadataTab').hasClass('active')) {
        $('#responseTabs .tab[data-rtab="body"]').trigger('click');
      }
    }

    lastResponseHeaders = result.headers || {};
    lastSetCookies = result.set_cookies || {};
    const headerLines = Object.entries(lastResponseHeaders).map(([k, v]) => `${k}: ${v}`);
    $('#responseHeaders').text(headerLines.join('\n') || '(no headers)');
    $('#cookieBar').empty().append(renderCookieBar(lastSetCookies));

    renderRouteInfoCard(result.route_info);
    renderTlsCertCard(result.tls_info);
    const security = renderSecurityView(lastResponseHeaders, $('#urlInput').val(), result.set_cookie_headers, result.tls_info);
    $('#responseSecurity').html(security.html);
    $('#securityCount').text(security.issueCount ? `(${security.issueCount})` : '');
  }

  function send() {
    const configFile = $('#routeSelect').val();
    const url = substituteVars($('#urlInput').val().trim());

    if (!configFile) return alert('Pick a route config first.');
    if (!url) return alert('URL is required.');

    const headers = {};
    const rawHeaders = collectKVRows($('#headerRows'));
    Object.entries(Object.assign({}, computeAuthHeader(), rawHeaders)).forEach(([k, v]) => {
      headers[k] = substituteVars(v);
    });
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'user-agent')) {
      headers['User-Agent'] = DEFAULT_USER_AGENT;
    }

    const payload = {
      config_file: configFile,
      port: parseInt($('#targetPort').val(), 10) || undefined,
      with_timing_defense: $('#withTimingDefense').is(':checked'),
      method: $('#methodSelect').val(),
      url,
      headers,
      body: substituteVars($('#bodyInput').val()) || undefined,
    };

    setPending(true);
    $.ajax({
      url: '/api/send',
      method: 'POST',
      contentType: 'application/json',
      data: JSON.stringify(payload),
    })
      .done((result) => {
        renderResponse(result, headers);
        loadHistory();
      })
      .fail((xhr) => {
        renderResponse(xhr.responseJSON || { ok: false, error: 'request failed' }, headers);
      })
      .always(() => setPending(false));
  }

  $('#sendBtn').on('click', send);
  $('#urlInput, #bodyInput').on('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') send();
  });

  // ---------------- Copy response body ----------------

  $('#copyBodyBtn').on('click', function () {
    const text = $('#responseBody').text();
    const $btn = $(this);
    const original = $btn.html();
    const flash = () => {
      $btn.html('<svg class="icon"><use href="#icon-check"></use></svg> Copied');
      setTimeout(() => $btn.html(original), 1200);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(flash);
      return;
    }
    const $tmp = $('<textarea readonly></textarea>').val(text).css({ position: 'fixed', left: '-9999px' });
    $('body').append($tmp);
    $tmp[0].select();
    try { document.execCommand('copy'); flash(); } catch (e) { /* no-op */ }
    $tmp.remove();
  });
});
