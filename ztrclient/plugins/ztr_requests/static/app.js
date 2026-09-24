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

  function formatBytes(n) {
    n = Number(n);
    if (!isFinite(n) || n < 0) return '';
    if (n < 1024) return `${n} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let value = n;
    let unit = -1;
    do {
      value /= 1024;
      unit++;
    } while (value >= 1024 && unit < units.length - 1);
    return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[unit]}`;
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

  // URLSearchParams.toString() percent-encodes characters — $ { } < > [ ]
  // ' " : , = — that are perfectly legal, unambiguous in a URL query
  // string. Left alone, that silently breaks a $$QF$$/$$QF::<...>$$/
  // {{var}} token the moment its param round-trips through this tab (type
  // $$QF$$ into a param value, tab out, and it becomes %24%24QF%24%24 —
  // containsQF() then can't find it anymore; the stop spec's own
  // "code=500" syntax needs literal "=" for the same reason). None of
  // these are top-level query-string delimiters (& and, for parsing, the
  // FIRST = in each pair) — URLSearchParams itself only splits each pair
  // on its first "=", so a later literal "=" in the value round-trips
  // unambiguously. Space stays encoded (as "+"): unlike these, a literal
  // space is actually invalid in the real outgoing request line.
  const QUERY_SAFE_RESTORE = {
    '%24': '$', '%7B': '{', '%7D': '}', '%3C': '<', '%3E': '>',
    '%5B': '[', '%5D': ']', '%27': "'", '%22': '"', '%3A': ':', '%2C': ',', '%3D': '=',
  };
  function restoreQuerySafeChars(qs) {
    return qs.replace(/%24|%7B|%7D|%3C|%3E|%5B|%5D|%27|%22|%3A|%2C|%3D/g, (seq) => QUERY_SAFE_RESTORE[seq]);
  }

  function syncUrlFromParams() {
    if (syncingParams) return;
    const params = collectKVRows($('#paramRows'));
    const [base] = $('#urlInput').val().split('?');
    const qs = restoreQuerySafeChars(new URLSearchParams(params).toString());
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

  // ---------------- Sidebar tabs (History / Batch / Saved / Conns) ----------------

  $('#sidebarTabs .side-tab').on('click', function () {
    const side = $(this).data('side');
    $('#sidebarTabs .side-tab').removeClass('active');
    $(this).addClass('active');
    $('#side-history, #side-batch, #side-saved, #side-conns').removeClass('active');
    $('#side-' + side).addClass('active');
    if (side === 'saved') loadSaved();
    if (side === 'conns') loadPools();
    if (side === 'batch') loadBatchRuns();
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

  // ---------------- Batch (full detail for $$QF$$ runs) ----------------
  //
  // History only ever kept a thin summary row per request, so once a batch
  // run finished, every line but the last had its full response (headers,
  // cookies, TLS info, relay path, metadata) gone for good. Each line here
  // is loaded on demand from BatchStore's own row, which keeps everything
  // /api/send returns — so any past line can be reopened in full, not just
  // the most recent one.

  function loadBatchRuns() {
    $.get('/api/batch/runs').done((res) => {
      const $list = $('#batchRunsList');
      $list.empty();
      if (!res.runs || !res.runs.length) {
        $list.append('<div class="history-empty">No batch runs yet — attach a query file and send a $$QF$$ request.</div>');
        return;
      }
      res.runs.forEach((run) => {
        const cls = run.ok_count === run.total ? 'ok2xx' : (run.ok_count === 0 ? 'err5xx' : 'warn4xx');
        const label = run.url_template ? escapeHtml(run.url_template) : '(no url)';
        const $row = $(`
          <div class="history-item batch-run-item" title="${label}">
            <span class="history-method method-${escapeHtml(run.method || 'GET')}">${escapeHtml(run.method || 'GET')}</span>
            <span class="history-url">${label}</span>
            <span class="history-status status-pill ${cls}">${run.ok_count}/${run.total}</span>
            <button type="button" class="list-item-remove" title="Delete run"><svg class="icon"><use href="#icon-x"></use></svg></button>
          </div>
        `);
        const $lines = $(`<div class="batch-run-lines" style="display:none"></div>`);

        $row.on('click', (e) => {
          if ($(e.target).closest('.list-item-remove').length) return;
          if ($lines.is(':visible')) { $lines.hide(); return; }
          $lines.show();
          if ($lines.data('loaded')) return;
          $lines.data('loaded', true);
          $lines.html('<div class="history-empty">Loading…</div>');
          $.get('/api/batch/requests', { run_id: run.run_id }).done((lres) => {
            $lines.empty();
            (lres.requests || []).forEach((line) => {
              const lcls = statusPillClass(line);
              const $lrow = $(`
                <div class="history-item batch-line-item" title="${escapeHtml(line.url)}">
                  <span class="history-status status-pill ${lcls}">${escapeHtml(statusPillText(line))}</span>
                  <span class="history-url">${escapeHtml(line.line_value != null ? line.line_value : line.url)}</span>
                </div>
              `);
              $lrow.on('click', () => {
                $.get('/api/batch/request', { run_id: run.run_id, line_index: line.line_index }).done((row) => {
                  renderBatchRow(row);
                });
              });
              $lines.append($lrow);
            });
          });
        });

        $row.find('.list-item-remove').on('click', (e) => {
          e.stopPropagation();
          if (!confirm('Delete this batch run?')) return;
          $.ajax({ url: '/api/batch/runs?run_id=' + encodeURIComponent(run.run_id), method: 'DELETE' }).done(loadBatchRuns);
        });

        $list.append($row).append($lines);
      });
    });
  }

  // Batch rows never keep the video bytes themselves (a video response is
  // aborted right after its headers, same as a live request) and, unlike
  // History, don't retain a config_file to re-open a live /api/stream with
  // — so a stored video line shows what's known about it instead of trying
  // to play a stream it structurally can't reconstruct.
  function renderBatchRow(row) {
    if (row.is_video) {
      const note = `(video response — ${escapeHtml(row.content_type || 'unknown type')}, not replayable from Batch)`;
      renderResponse(Object.assign({}, row, { is_video: false, body: note }), row.request_headers);
      return;
    }
    renderResponse(row, row.request_headers);
  }

  $('#refreshBatchBtn').on('click', loadBatchRuns);

  function loadEntryIntoComposer(item) {
    $('#methodSelect').val(item.method).trigger('change');
    $('#urlInput').val(item.url);
    syncParamsFromUrl();
    if (item.config_file) $('#routeSelect').val(item.config_file);
    $('#targetPort').val(item.target_port || '');
    $('#withTimingDefense').prop('checked', !!item.with_timing_defense);
    $('#timeoutInput').val(item.timeout || '');
    // verify defaults to true — an entry saved before this option existed
    // (item.verify undefined) must NOT silently reload as "unverified".
    $('#verifyTls').prop('checked', item.verify !== false);
    $('#clientCertPath').val(item.client_cert || '');

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
    $('#batchProgress').hide();

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
        const flagParts = [p.with_timing_defense ? 'timing-defense' : 'plain'];
        if (p.verify === false) flagParts.push('TLS unverified');
        if (p.client_cert) flagParts.push('client cert');
        const flags = flagParts.join(' · ');
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
      timeout: parseFloat($('#timeoutInput').val()) || undefined,
      verify: $('#verifyTls').is(':checked'),
      client_cert: $('#clientCertPath').val().trim() || undefined,
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

  function truncateMiddle(str, max) {
    if (!str) return '';
    if (str.length <= max) return str;
    const half = Math.floor((max - 1) / 2);
    return str.slice(0, half) + '…' + str.slice(str.length - half);
  }

  function currentTargetHost() {
    try {
      return new URL(substituteVars($('#urlInput').val().trim())).hostname;
    } catch (e) {
      return '';
    }
  }

  // A horizontal node-and-arrow diagram (You -> each configured hop ->
  // Target) instead of a plain key/value list — the hop chain is a path,
  // and a path reads more clearly as one than as rows in a table. Built
  // as one inline SVG so it can pull icons straight from this page's own
  // sprite (<use href="#icon-...">) and pick up the same CSS custom
  // properties (light/dark, accent) the rest of the app already uses,
  // rather than a separate image asset that would need its own theming.
  function renderRouteInfoCard(routeInfo) {
    const $card = $('#routeInfoCard');
    if (!routeInfo || !routeInfo.hops || !routeInfo.hops.length) {
      $card.hide().empty();
      return;
    }

    const nodes = [
      { title: 'You', sub: '', icon: 'icon-user', kind: 'endpoint' },
      ...routeInfo.hops.map((h) => ({
        title: h.role ? h.role.charAt(0).toUpperCase() + h.role.slice(1) : `Hop ${h.hop}`,
        sub: h.address || '?',
        full: h.address || '',
        icon: 'icon-lock',
        kind: h.status && h.status !== 'online' ? 'warn' : 'hop',
      })),
      { title: 'Target', sub: currentTargetHost(), icon: 'icon-globe', kind: 'endpoint' },
    ];

    const BOX_W = 128;
    const BOX_H = 60;
    const GAP = 40;
    const PAD_X = 18;
    const PAD_Y = 14;
    const totalW = nodes.length * BOX_W + (nodes.length - 1) * GAP + PAD_X * 2;
    const totalH = BOX_H + PAD_Y * 2;
    const cy = PAD_Y + BOX_H / 2;

    let svg = `<svg viewBox="0 0 ${totalW} ${totalH}" class="route-diagram" xmlns="http://www.w3.org/2000/svg">`;
    svg += '<defs><marker id="routeArrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 Z" class="route-arrow-head"/></marker></defs>';

    nodes.forEach((n, i) => {
      const x = PAD_X + i * (BOX_W + GAP);
      if (i > 0) {
        const prevRight = PAD_X + (i - 1) * (BOX_W + GAP) + BOX_W;
        svg += `<line x1="${prevRight}" y1="${cy}" x2="${x}" y2="${cy}" class="route-edge" marker-end="url(#routeArrow)" />`;
      }
      const cls = `route-node route-node-${n.kind}`;
      const subText = escapeHtml(truncateMiddle(n.sub, 17));
      const titleAttr = n.full && n.full !== n.sub ? `<title>${escapeHtml(n.full)}</title>` : '';
      svg += `
        <g class="${cls}">
          ${titleAttr}
          <rect x="${x}" y="${PAD_Y}" width="${BOX_W}" height="${BOX_H}" rx="9" />
          <use href="#${n.icon}" class="route-node-icon" x="${x + BOX_W / 2 - 8}" y="${PAD_Y + 8}" width="16" height="16" />
          <text x="${x + BOX_W / 2}" y="${PAD_Y + 42}" text-anchor="middle" class="route-node-title">${escapeHtml(n.title)}</text>
          ${n.sub ? `<text x="${x + BOX_W / 2}" y="${PAD_Y + 54}" text-anchor="middle" class="route-node-sub">${subText}</text>` : ''}
        </g>`;
    });
    svg += '</svg>';

    $card.empty()
      .append('<div class="side-eyebrow">Relay Path</div>')
      .append(`<div class="route-diagram-scroll">${svg}</div>`)
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
    const $video = $('#responseVideo');
    if ($video.length) $video.get(0).pause();
    $('#responseVideoWrap').hide();
    $('#responseBody').show();
    $('#responseBodyToolbar').show();
  }

  function showImageResponse(contentType, base64) {
    $('#responseBody').hide();
    $('#responseBodyToolbar').hide();
    $('#responseVideoWrap').hide();
    $('#responseImage').attr('src', `data:${contentType};base64,${base64}`);
    $('#responseImageWrap').css('display', 'flex');
  }

  function showVideoResponse(streamUrl) {
    $('#responseBody').hide();
    $('#responseBodyToolbar').hide();
    $('#responseImageWrap').hide();
    $('#responseVideo').attr('src', streamUrl);
    $('#responseVideoWrap').css('display', 'flex');
  }

  // Points a <video> tag straight at /api/stream instead of the buffered
  // data: URI an image gets — real Range-request seeking only works
  // against a plain URL, never a data: URI (the whole thing has to be one
  // in-memory string either way, so there's nothing to seek "into").
  // Reads straight from the composer's current fields, same as
  // renderSecurityView already does for the URL — not threaded through as
  // a parameter, since nothing else needs it.
  function buildStreamUrl(requestHeaders) {
    const configFile = $('#routeSelect').val();
    const url = substituteVars($('#urlInput').val().trim());
    const port = parseInt($('#targetPort').val(), 10) || undefined;
    const withTimingDefense = $('#withTimingDefense').is(':checked');
    const timeout = parseFloat($('#timeoutInput').val()) || undefined;
    const verify = $('#verifyTls').is(':checked');
    const clientCert = $('#clientCertPath').val().trim();

    const params = new URLSearchParams();
    params.set('url', url);
    params.set('config_file', configFile);
    if (port) params.set('port', String(port));
    if (withTimingDefense) params.set('with_timing_defense', '1');
    if (timeout) params.set('timeout', String(timeout));
    if (!verify) params.set('verify', '0');
    if (clientCert) params.set('client_cert', clientCert);
    if (requestHeaders && Object.keys(requestHeaders).length) {
      params.set('headers', JSON.stringify(requestHeaders));
    }
    return '/api/stream?' + params.toString();
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
      $('#sizeStat').text(formatBytes(byteLength));
      $('#metadataTab').show();
      $('#responseMetadata').html(renderMetadataView(result.metadata));
    } else if (result.is_video) {
      showVideoResponse(buildStreamUrl(actualRequestHeaders));
      const contentLength = (result.headers || {})['content-length'];
      $('#sizeStat').text(contentLength ? formatBytes(contentLength) : '');
      $('#metadataTab').hide();
      if ($('#metadataTab').hasClass('active')) {
        $('#responseTabs .tab[data-rtab="body"]').trigger('click');
      }
    } else {
      showTextResponse();
      const bodyText = result.is_binary ? '(binary response body — not shown)' : (result.body || '');
      $('#responseBody').text(prettyBody(bodyText));
      $('#sizeStat').text(bodyText ? formatBytes(new Blob([bodyText]).size) : '');
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

  // ---------------- Query file ($$QF$$ batch runs) ----------------
  //
  // A $$QF$$ (or $$QF::<status_code>$$) token anywhere in the URL, a
  // header value, or the body means "run this once per line in the
  // attached file, substituting that line in for the token each time" —
  // a lightweight fuzzer/wordlist runner built on the exact same
  // /api/send + {{var}} machinery a single request already uses, not a
  // separate code path. The ::<code> variant additionally stops the run
  // the moment a response's status code matches, instead of always
  // running every line.

  let queryFileLines = [];
  let batchAbort = false;

  // Both $$QF$$ and $$QF::<...>$$[::om] are per-line substitution points —
  // each is replaced with the current line's value wherever it appears,
  // exactly like plain $$QF$$. $$QF::<...>$$ ALSO declares a condition,
  // parsed once up front from the raw (pre-substitution) fields,
  // independently of the substitution pass — and the trailing ::om switch
  // decides what that condition means for the run:
  //   $$QF::<...>$$       stop the whole run the moment a response matches.
  //   $$QF::<...>::om$$   keep running every line, but only SAVE to Batch
  //                        the lines whose response matches — everything
  //                        else still runs and still renders, it's just
  //                        never persisted.
  const QF_TOKEN_RE = /\$\$QF(?:::<[\s\S]*?>(?:::om)?)?\$\$/g;
  const QF_STOP_RE = /\$\$QF::<([\s\S]*?)>(::om)?\$\$/;
  const QF_ANY_RE = /\$\$QF(?:::<[\s\S]*?>(?:::om)?)?\$\$/;

  function substituteQF(str, value) {
    if (str == null) return str;
    return String(str).replace(QF_TOKEN_RE, () => value);
  }

  function containsQF(strings) {
    return strings.some((s) => s != null && QF_ANY_RE.test(String(s)));
  }

  // code and headers[...] both accept any of these comparison operators.
  // Order matters here: a 2-char operator must be tried before the 1-char
  // operators that are its own prefix (>= before >, <= before <, != has no
  // 1-char prefix collision but stays grouped with the others for
  // clarity), or ">=value" would tokenize as ">" leaving a stray "=".
  const QF_OP_RE = '(!=|>=|<=|=|>|<)';

  // Tokenizes the inside of $$QF::<...>$$ into predicates —
  // code<op><number>, body_contains=['kw1','kw2'], headers[Name]<op>value
  // (value quoted with ' or ", or a bareword up to the next space/paren;
  // <op> is one of != = >= <= > <) — plus AND / OR (case-insensitive) and
  // parens for grouping. A predicate is recognized as one indivisible unit
  // (its own regex anchored at the tokenizer's current position) BEFORE
  // the generic AND/OR check ever runs at that position, so e.g. a
  // bareword header value like "Android" is consumed whole and never
  // mistaken for the "AND" keyword.
  function tokenizeQFExpr(text) {
    const tokens = [];
    const isWordChar = (c) => /[A-Za-z0-9_]/.test(c || '');
    let i = 0;
    const n = text.length;
    while (i < n) {
      const c = text[i];
      if (/\s/.test(c)) { i++; continue; }
      if (c === '(') { tokens.push({ type: 'LPAREN' }); i++; continue; }
      if (c === ')') { tokens.push({ type: 'RPAREN' }); i++; continue; }

      const rest = text.slice(i);
      const upper = rest.toUpperCase();
      if (upper.startsWith('AND') && !isWordChar(text[i + 3])) { tokens.push({ type: 'AND' }); i += 3; continue; }
      if (upper.startsWith('OR') && !isWordChar(text[i + 2])) { tokens.push({ type: 'OR' }); i += 2; continue; }

      let m;
      if ((m = new RegExp(`^code\\s*${QF_OP_RE}\\s*(\\d+)`, 'i').exec(rest))) {
        tokens.push({ type: 'PRED', pred: { kind: 'code', op: m[1], value: parseInt(m[2], 10) } });
        i += m[0].length;
        continue;
      }
      if ((m = /^body_contains\s*=\s*\[([^\]]*)\]/i.exec(rest))) {
        const keywords = m[1].split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter((s) => s.length);
        tokens.push({ type: 'PRED', pred: { kind: 'body_contains', keywords } });
        i += m[0].length;
        continue;
      }
      if ((m = new RegExp(`^headers\\[([^\\]]+)\\]\\s*${QF_OP_RE}\\s*`, 'i').exec(rest))) {
        const key = m[1].trim();
        const op = m[2];
        let j = i + m[0].length;
        let value;
        if (text[j] === '"' || text[j] === "'") {
          const quote = text[j];
          const end = text.indexOf(quote, j + 1);
          if (end === -1) { value = text.slice(j + 1); j = n; } else { value = text.slice(j + 1, end); j = end + 1; }
        } else {
          const start = j;
          while (j < n && !/[\s)]/.test(text[j])) j++;
          value = text.slice(start, j);
        }
        tokens.push({ type: 'PRED', pred: { kind: 'header', key, op, value } });
        i = j;
        continue;
      }

      // Unrecognized character (stray punctuation, typo) — skip it rather
      // than throwing, so a slightly malformed expression degrades to
      // "ignore the noise" instead of breaking the whole composer.
      i++;
    }
    return tokens;
  }

  // Recursive-descent parse of the token stream into a boolean-expression
  // tree: AND binds tighter than OR (standard precedence), and parens
  // override both. AND/OR nodes flatten same-operator siblings into one
  // { type, children:[...] } array rather than nesting binary pairs, so
  // evaluation is a plain every()/some() over children.
  function parseQFExprTokens(tokens) {
    let pos = 0;
    function peek() { return tokens[pos]; }
    function parsePrimary() {
      const t = peek();
      if (!t) return null;
      if (t.type === 'LPAREN') {
        pos++;
        const inner = parseOr();
        if (peek() && peek().type === 'RPAREN') pos++;
        return inner;
      }
      if (t.type === 'PRED') { pos++; return { type: 'PRED', pred: t.pred }; }
      // A stray AND/OR/RPAREN where a predicate was expected — skip it and
      // keep going, same tolerant-of-noise stance as the tokenizer.
      pos++;
      return parsePrimary();
    }
    function parseAnd() {
      let node = parsePrimary();
      while (peek() && peek().type === 'AND') {
        pos++;
        const right = parsePrimary();
        if (!right) break;
        node = { type: 'AND', children: (node && node.type === 'AND' ? node.children : [node]).concat([right]) };
      }
      return node;
    }
    function parseOr() {
      let node = parseAnd();
      while (peek() && peek().type === 'OR') {
        pos++;
        const right = parseAnd();
        if (!right) break;
        node = { type: 'OR', children: (node && node.type === 'OR' ? node.children : [node]).concat([right]) };
      }
      return node;
    }
    return parseOr();
  }

  // Parses the inside of $$QF::<...>$$ into a boolean-expression tree, or
  // null if it's empty/has no recognized predicates (never matches).
  function parseQFStopSpec(specText) {
    const tokens = tokenizeQFExpr(specText);
    if (!tokens.some((t) => t.type === 'PRED')) return null;
    return parseQFExprTokens(tokens);
  }

  // Scans the raw fields for the (single) $$QF::<...>$$ token and returns
  // both its parsed expression tree and which of the two modes below it
  // declared. omit and stopSpec are mutually exclusive by construction: a
  // run either stops early on match, or filters what gets saved — never
  // both.
  //   $$QF::<...>$$       stop the whole run the moment a response matches.
  //   $$QF::<...>::om$$   keep running every line, but only SAVE to Batch
  //                        the lines whose response matches — everything
  //                        else still runs and still renders, it's just
  //                        never persisted.
  function findQFMode(strings) {
    for (const s of strings) {
      if (s == null) continue;
      const m = String(s).match(QF_STOP_RE);
      if (m) {
        const spec = parseQFStopSpec(m[1]);
        const omit = !!m[2];
        return { stopSpec: omit ? null : spec, omitSpec: omit ? spec : null };
      }
    }
    return { stopSpec: null, omitSpec: null };
  }

  // Applies one of != = >= <= > < to two already-comparable values (both
  // numbers, or both strings for = / !=).
  function compareQFOp(actual, op, expected) {
    switch (op) {
      case '=': return actual === expected;
      case '!=': return actual !== expected;
      case '>=': return actual >= expected;
      case '<=': return actual <= expected;
      case '>': return actual > expected;
      case '<': return actual < expected;
      default: return false;
    }
  }

  function matchesQFPred(pred, result) {
    if (pred.kind === 'code') {
      return compareQFOp(result.status_code, pred.op, pred.value);
    }
    if (pred.kind === 'body_contains') {
      const body = String(result.body || '').toLowerCase();
      return pred.keywords.some((kw) => body.includes(String(kw).toLowerCase()));
    }
    if (pred.kind === 'header') {
      const respHeaders = result.headers || {};
      const lowerHeaders = {};
      Object.keys(respHeaders).forEach((k) => { lowerHeaders[k.toLowerCase()] = respHeaders[k]; });
      const actual = lowerHeaders[pred.key.toLowerCase()];
      // = / != keep the existing case-insensitive substring behavior (so
      // headers[content-type]="application/json" still matches a real
      // "application/json; charset=utf-8" response header) — != is just
      // its negation, true when the header is absent too. The ordering
      // operators only make sense numerically, so they parse both sides
      // as numbers and fail closed (no match) if either isn't one.
      if (pred.op === '=') {
        return actual != null && String(actual).toLowerCase().includes(String(pred.value).toLowerCase());
      }
      if (pred.op === '!=') {
        return actual == null || !String(actual).toLowerCase().includes(String(pred.value).toLowerCase());
      }
      if (actual == null) return false;
      const actualNum = parseFloat(actual);
      const expectedNum = parseFloat(pred.value);
      if (Number.isNaN(actualNum) || Number.isNaN(expectedNum)) return false;
      return compareQFOp(actualNum, pred.op, expectedNum);
    }
    return false;
  }

  // Evaluates the expression tree from parseQFStopSpec against a
  // response. AND nodes require every child to match, OR nodes require
  // any one child to match — exactly the boolean logic the AND/OR/parens
  // in the token spell out. body_contains keeps its own "any keyword"
  // semantics as a single predicate. All text matching is a
  // case-insensitive substring check, not exact equality, so e.g.
  // headers[content-type]="application/json" still matches a real
  // "application/json; charset=utf-8" response header.
  function matchesQFSpec(result, node) {
    if (!node) return false;
    if (node.type === 'AND') return node.children.every((c) => matchesQFSpec(result, c));
    if (node.type === 'OR') return node.children.some((c) => matchesQFSpec(result, c));
    if (node.type === 'PRED') return matchesQFPred(node.pred, result);
    return false;
  }

  $('#queryFileInput').on('change', function () {
    const file = this.files && this.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      queryFileLines = String(reader.result)
        .split(/\r\n|\r|\n/)
        .map((l) => l.trim())
        .filter(Boolean);
      const count = queryFileLines.length;
      $('#batchFileChip').text(`${file.name} · ${count} line${count === 1 ? '' : 's'}`);
      $('#clearQueryFileBtn').show();
    };
    reader.onerror = () => alert("Couldn't read that file.");
    reader.readAsText(file);
  });

  $('#clearQueryFileBtn').on('click', function () {
    queryFileLines = [];
    $('#queryFileInput').val('');
    $('#batchFileChip').text('');
    $(this).hide();
  });

  $('#batchStopBtn').on('click', () => { batchAbort = true; });

  // ---------------- $$QF$$ syntax help ----------------

  function openQFHelp() { $('#qfHelpOverlay').css('display', 'flex'); }
  function closeQFHelp() { $('#qfHelpOverlay').hide(); }

  $('#qfHelpBtn').on('click', openQFHelp);
  $('#qfHelpCloseBtn').on('click', closeQFHelp);
  $('#qfHelpOverlay').on('click', function (e) {
    if (e.target === this) closeQFHelp();
  });
  $(document).on('keydown', function (e) {
    if (e.key === 'Escape' && $('#qfHelpOverlay').is(':visible')) closeQFHelp();
  });

  // ---------------- Send ----------------

  function buildHeaders(rawHeaders, authHeader) {
    const headers = {};
    Object.entries(Object.assign({}, authHeader, rawHeaders)).forEach(([k, v]) => {
      headers[k] = substituteVars(v);
    });
    if (!Object.keys(headers).some((k) => k.toLowerCase() === 'user-agent')) {
      headers['User-Agent'] = DEFAULT_USER_AGENT;
    }
    return headers;
  }

  // Sends exactly one request from already-resolved (any $$QF$$ already
  // substituted) raw field values, applying {{var}} substitution the same
  // way a single manual Send always has. Resolves with the result either
  // way (success or failure) instead of using done()/fail() separately,
  // so a batch run can await one thing per line without duplicating the
  // render/history/pending bookkeeping below.
  function sendOne({ configFile, rawUrl, rawHeaders, authHeader, rawBody, batch }) {
    const url = substituteVars(rawUrl);
    const headers = buildHeaders(rawHeaders, authHeader);
    const payload = {
      config_file: configFile,
      port: parseInt($('#targetPort').val(), 10) || undefined,
      with_timing_defense: $('#withTimingDefense').is(':checked'),
      timeout: parseFloat($('#timeoutInput').val()) || undefined,
      verify: $('#verifyTls').is(':checked'),
      client_cert: $('#clientCertPath').val().trim() || undefined,
      method: $('#methodSelect').val(),
      url,
      headers,
      body: substituteVars(rawBody) || undefined,
    };
    if (batch) {
      payload.batch_run_id = batch.runId;
      payload.batch_line_index = batch.lineIndex;
      payload.batch_line_value = batch.lineValue;
      payload.batch_url_template = batch.urlTemplate;
      // Sent as the plain expression tree (AND/OR/PRED nodes) — evaluated
      // server-side, since that's the one that decides whether to persist
      // this line at all; the client already has the response by the time
      // it could evaluate this, but by then it's too late to un-send the
      // POST that saved it.
      if (batch.omitSpec) {
        payload.batch_omit_spec = batch.omitSpec;
      }
    }

    setPending(true);
    return new Promise((resolve) => {
      $.ajax({
        url: '/api/send',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(payload),
      })
        .done((result) => {
          renderResponse(result, headers);
          if (batch) {
            loadBatchRuns();
          } else {
            loadHistory();
          }
          resolve(result);
        })
        .fail((xhr) => {
          const result = xhr.responseJSON || { ok: false, error: 'request failed' };
          renderResponse(result, headers);
          resolve(result);
        })
        .always(() => setPending(false));
    });
  }

  function runBatch({ configFile, rawUrl, rawHeaders, authHeader, rawBody, stopSpec, omitSpec }) {
    batchAbort = false;
    const total = queryFileLines.length;
    const runId = 'run_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    $('#batchProgress').css('display', 'flex');
    $('#sendBtn').prop('disabled', true);

    let i = 0;
    const next = () => {
      if (batchAbort) {
        $('#batchProgressText').text(`Stopped — sent ${i}/${total}.`);
        $('#sendBtn').prop('disabled', false);
        return;
      }
      if (i >= total) {
        $('#batchProgressText').text(`Done — sent ${total}/${total}.`);
        $('#sendBtn').prop('disabled', false);
        return;
      }
      const lineIndex = i;
      const line = queryFileLines[i];
      i += 1;
      $('#batchProgressText').text(`Sending ${i}/${total}…`);

      sendOne({
        configFile,
        rawUrl: substituteQF(rawUrl, line),
        rawHeaders: Object.fromEntries(Object.entries(rawHeaders).map(([k, v]) => [k, substituteQF(v, line)])),
        authHeader: Object.fromEntries(Object.entries(authHeader).map(([k, v]) => [k, substituteQF(v, line)])),
        rawBody: substituteQF(rawBody, line),
        batch: { runId, lineIndex, lineValue: line, urlTemplate: rawUrl, omitSpec },
      }).then((result) => {
        if (matchesQFSpec(result, stopSpec)) {
          $('#batchProgressText').text(`Stopped — matched stop condition on line ${i}/${total}.`);
          $('#sendBtn').prop('disabled', false);
          return;
        }
        next();
      });
    };
    next();
  }

  function send() {
    const configFile = $('#routeSelect').val();
    const rawUrl = $('#urlInput').val().trim();
    if (!configFile) return alert('Pick a route config first.');
    if (!rawUrl) return alert('URL is required.');

    const rawHeaders = collectKVRows($('#headerRows'));
    const authHeader = computeAuthHeader();
    const rawBody = $('#bodyInput').val();

    const allRaw = [rawUrl, rawBody, ...Object.values(rawHeaders), ...Object.values(authHeader)];

    if (containsQF(allRaw)) {
      if (!queryFileLines.length) {
        return alert('Found $$QF$$ in the request, but no query file is attached — click "Query file…" first.');
      }
      const { stopSpec, omitSpec } = findQFMode(allRaw);
      runBatch({ configFile, rawUrl, rawHeaders, authHeader, rawBody, stopSpec, omitSpec });
      return;
    }

    sendOne({ configFile, rawUrl, rawHeaders, authHeader, rawBody });
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
