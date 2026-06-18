/* ===========================================================================
   WarSniffer UI controller
   =========================================================================== */
'use strict';
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const api = (p, opt) => fetch(p, opt).then(r => r.json().catch(() => ({})));
const post = (p, body) => api(p, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: body ? JSON.stringify(body) : undefined
});

const MAX_ROWS = 500;
let paused = false;
let capturing = true;
let alertCursor = 0;
let credCursor = 0;
let lastCredCount = 0;
let selectedId = null;

/* ---- tabs ---------------------------------------------------------------- */
function showTab(name) {
  $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  $$('.panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  if (name === 'devices') loadDevices();
  if (name === 'alerts')  loadAlerts(true);
  if (name === 'creds')   loadCreds(true);
  if (name === 'filters') loadFilters();
  if (name === 'pcap')    loadPcap();
  if (name === 'settings')loadSettings();
}
$('#tabs').addEventListener('click', e => {
  const b = e.target.closest('.tab'); if (b) showTab(b.dataset.tab);
});
document.addEventListener('click', e => {
  const l = e.target.closest('.navlink'); if (l) { e.preventDefault(); showTab(l.dataset.tab); }
});

/* ---- helpers ------------------------------------------------------------- */
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;');
const fmt = n => (n || 0).toLocaleString();
const rssiClass = r => r > -65 ? 'rssi-strong' : (r < -80 ? 'rssi-weak' : '');
const typeClass = t => ({ Mgmt: 't-mgmt', Ctrl: 't-ctrl', Data: 't-data' }[t] || '');

/* ---- live frame table ---------------------------------------------------- */
const rows = $('#frame-rows');
function addFrame(f) {
  if (paused) return;
  const q = $('#live-search').value.trim().toLowerCase();
  const hay = `${f.src||''} ${f.dst||''} ${f.bssid||''} ${f.proto||''} ${f.sub||''} ${f.info||''}`.toLowerCase();
  if (q && !hay.includes(q)) return;

  const tr = document.createElement('tr');
  tr.dataset.id = f.id;
  if (f.id === selectedId) tr.classList.add('sel');
  tr.innerHTML =
    `<td>${f.id}</td><td>${(f.ts % 1000).toFixed(2)}</td><td>${f.ch}</td>` +
    `<td class="${rssiClass(f.rssi)}">${f.rssi}</td>` +
    `<td class="${typeClass(f.type)}">${esc(f.type)}</td>` +
    `<td>${esc(f.sub)}</td>` +
    `<td>${f.proto ? `<span class="tag">${esc(f.proto)}</span>` : ''}</td>` +
    `<td>${esc(f.src || '')}</td><td>${esc(f.dst || '')}</td><td>${esc(f.info || '')}</td>`;
  rows.insertBefore(tr, rows.firstChild);
  while (rows.childElementCount > MAX_ROWS) rows.removeChild(rows.lastChild);
}
rows.addEventListener('click', e => {
  const tr = e.target.closest('tr'); if (!tr) return;
  $$('.frames tbody tr.sel').forEach(x => x.classList.remove('sel'));
  tr.classList.add('sel');
  selectedId = Number(tr.dataset.id);
  showDetail(selectedId);
});
function showDetail(id) {
  api('/api/frame?id=' + id).then(d => {
    if (!d.meta) { $('#detail').innerHTML = `<div class="detail-empty">${esc(d.message||'unavailable')}</div>`; return; }
    const m = d.meta;
    const kv = (k, v) => `<div class="kv"><span>${k}</span><span>${esc(v)}</span></div>`;
    let html = `<h4>frame #${m.id}</h4>` +
      kv('time', m.ts.toFixed(6) + 's') + kv('channel', m.ch) + kv('rssi', m.rssi + ' dBm') +
      kv('length', m.len + ' B') + kv('type', m.type + ' / ' + m.sub) +
      kv('proto', m.proto || '—') + kv('encrypted', m.enc ? 'yes' : 'no') +
      (m.src ? kv('source', m.src) : '') + kv('dest', m.dst) +
      (m.bssid ? kv('bssid', m.bssid) : '') + (m.info ? kv('info', m.info) : '');
    // hex dump formatting
    let dump = '';
    const h = d.hex || '';
    for (let i = 0; i < h.length; i += 32) {
      const slice = h.slice(i, i + 32).match(/.{1,2}/g) || [];
      dump += (i / 2).toString(16).padStart(4, '0') + '  ' + slice.join(' ') + '\n';
    }
    html += `<div class="hex">${esc(dump)}</div>`;
    $('#detail').innerHTML = html;
  });
}
$('#live-pause').addEventListener('change', e => paused = e.target.checked);
$('#live-clear').addEventListener('click', () => { rows.innerHTML = ''; });
$('#buf-clear').addEventListener('click', () => post('/api/capture/clear').then(() => rows.innerHTML = ''));

/* ---- capture toggle ------------------------------------------------------ */
$('#btn-capture').addEventListener('click', () => {
  post(capturing ? '/api/capture/stop' : '/api/capture/start').then(() => refreshStatus());
});
function setCaptureBtn(on) {
  capturing = on;
  const b = $('#btn-capture');
  b.textContent = on ? '◼ STOP' : '▶ START';
  b.classList.toggle('go', !on);
}

/* ---- status -------------------------------------------------------------- */
function refreshStatus() {
  api('/api/status').then(s => {
    $('#st-ch').textContent = 'CH ' + s.channel;
    $('#st-frames').textContent = fmt(s.frames_total) + ' frames';
    $('#st-dev').textContent = `${s.ap_count} AP / ${s.sta_count} STA`;
    const ab = $('#st-alerts');
    ab.textContent = fmt(s.alert_count) + ' alerts';
    ab.classList.toggle('hot', s.alert_count > 0);
    const cb = $('#st-creds');
    cb.textContent = fmt(s.cred_count) + ' creds';
    cb.classList.toggle('hot', s.cred_count > 0);
    lastCredCount = s.cred_count;
    setCaptureBtn(s.capturing);
    $('#pw-warning').classList.toggle('hidden', !s.default_password);
    $('#fwinfo').textContent =
      `WarSniffer v${s.version} · built ${s.build} · heap ${fmt(s.heap_free)}B · psram ${fmt(s.psram_free)}B · up ${s.uptime_s}s`;
  });
}

/* ---- dashboard ----------------------------------------------------------- */
function bar(label, val, max) {
  const pct = max ? Math.round(val / max * 100) : 0;
  return `<div class="bar-row"><span class="bar-label">${esc(label)}</span>` +
    `<span class="bar-track"><span class="bar-fill" style="width:${pct}%"></span></span>` +
    `<span class="bar-val">${fmt(val)}</span></div>`;
}
function loadStats() {
  api('/api/stats').then(g => {
    $('#d-frames').textContent = fmt(g.frames);
    $('#d-drop').textContent = fmt(g.dropped);
    $('#d-bytes').textContent = fmt(g.bytes);
    $('#d-enc').textContent = fmt(g.encrypted);
    drawSpark($('#pps-canvas'), g.pps || [], '#00ff9c');
    drawBars($('#chan-canvas'), g.per_channel || []);
    const tmax = Math.max(g.mgmt, g.ctrl, g.data, 1);
    $('#type-bars').innerHTML = bar('mgmt', g.mgmt, tmax) + bar('ctrl', g.ctrl, tmax) + bar('data', g.data, tmax);
    const pv = { ARP: g.arp, DNS: g.dns, DHCP: g.dhcp, HTTP: g.http, TLS: g.https, EAPOL: g.eapol, IPv4: g.ipv4, IPv6: g.ipv6 };
    const pmax = Math.max(...Object.values(pv), 1);
    $('#proto-bars').innerHTML = Object.entries(pv).map(([k, v]) => bar(k, v, pmax)).join('');
  });
}
function drawSpark(c, data, color) {
  const ctx = c.getContext('2d'); const w = c.width = c.clientWidth, h = c.height;
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(...data, 1), n = data.length;
  ctx.strokeStyle = color; ctx.lineWidth = 1.5; ctx.beginPath();
  data.forEach((v, i) => {
    const x = i / (n - 1) * w, y = h - (v / max) * (h - 6) - 3;
    i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
  });
  ctx.stroke();
  ctx.fillStyle = 'rgba(0,255,156,.12)';
  ctx.lineTo(w, h); ctx.lineTo(0, h); ctx.closePath(); ctx.fill();
}
function drawBars(c, data) {
  const ctx = c.getContext('2d'); const w = c.width = c.clientWidth, h = c.height;
  ctx.clearRect(0, 0, w, h);
  const vals = data.slice(); const max = Math.max(...vals, 1); const n = vals.length;
  const bw = w / n;
  vals.forEach((v, i) => {
    const bh = (v / max) * (h - 16);
    ctx.fillStyle = '#0a8f5e'; ctx.fillRect(i * bw + 2, h - bh - 12, bw - 4, bh);
    ctx.fillStyle = '#5f9d83'; ctx.font = '9px monospace'; ctx.textAlign = 'center';
    ctx.fillText(i + 1, i * bw + bw / 2, h - 2);
  });
}

/* ---- devices ------------------------------------------------------------- */
function loadDevices() {
  api('/api/devices').then(d => {
    $('#ap-n').textContent = (d.aps || []).length;
    $('#sta-n').textContent = (d.stas || []).length;
    $('#ap-rows').innerHTML = (d.aps || []).sort((a, b) => b.rssi - a.rssi).map(a =>
      `<tr><td>${esc(a.bssid)}</td><td>${esc(a.ssid || '—')}</td><td>${a.channel}</td>` +
      `<td class="${rssiClass(a.rssi)}">${a.rssi}</td><td>${a.privacy ? '🔒' : '○'}</td>` +
      `<td>${fmt(a.beacons)}</td><td>${esc(a.vendor || '')}</td><td>${a.age_s}s</td></tr>`).join('');
    $('#sta-rows').innerHTML = (d.stas || []).sort((a, b) => b.rssi - a.rssi).map(s =>
      `<tr><td>${esc(s.mac)}</td><td class="${rssiClass(s.rssi)}">${s.rssi}</td>` +
      `<td>${fmt(s.frames)}</td><td>${s.randomized ? '~' : ''}</td>` +
      `<td>${esc(s.bssid || '')}</td><td>${esc(s.last_probe || '')}</td>` +
      `<td>${esc(s.vendor || '')}</td><td>${s.age_s}s</td></tr>`).join('');
  });
}

/* ---- alerts -------------------------------------------------------------- */
function alertHtml(a) {
  return `<div class="alert ${esc(a.severity)}"><div class="a-head">` +
    `<span class="a-type">${esc(a.type)}</span>` +
    `<span class="a-meta">ch${a.channel} · ${new Date(a.ts * 1000).toLocaleTimeString()}</span></div>` +
    `<div>${esc(a.detail)}</div>` +
    `<div class="a-meta">${a.bssid ? 'bssid ' + esc(a.bssid) + ' ' : ''}${a.station ? 'sta ' + esc(a.station) : ''}</div></div>`;
}
function loadAlerts(reset) {
  if (reset) { alertCursor = 0; $('#alert-list').innerHTML = ''; }
  api('/api/alerts?since=' + alertCursor).then(d => {
    (d.alerts || []).forEach(a => {
      alertCursor = Math.max(alertCursor, a.id);
      $('#alert-list').insertAdjacentHTML('afterbegin', alertHtml(a));
    });
  });
}
$('#alerts-clear').addEventListener('click', () =>
  post('/api/alerts/clear').then(() => { alertCursor = 0; $('#alert-list').innerHTML = ''; }));

/* ---- credentials --------------------------------------------------------- */
function credRow(c) {
  const masked = $('#cred-mask').checked;
  const pw = masked
    ? `<span class="pw" data-pw="${esc(c.password)}">${'•'.repeat(Math.min(c.password.length, 12)) || '—'}</span>`
    : `<span class="pw-shown">${esc(c.password) || '—'}</span>`;
  return `<tr><td>${new Date(c.ts * 1000).toLocaleTimeString()}</td>` +
    `<td><span class="tag">${esc(c.proto)}</span></td>` +
    `<td>${esc(c.dst)}:${c.port}</td>` +
    `<td class="cred-user">${esc(c.username) || '—'}</td>` +
    `<td class="cred-pass">${pw}</td>` +
    `<td>${esc(c.context) || ''}</td><td>${esc(c.src)}</td><td>${c.channel}</td></tr>`;
}
function loadCreds(reset) {
  if (reset) { credCursor = 0; $('#cred-rows').innerHTML = ''; }
  api('/api/creds?since=' + credCursor).then(d => {
    (d.creds || []).forEach(c => {
      credCursor = Math.max(credCursor, c.id);
      $('#cred-rows').insertAdjacentHTML('afterbegin', credRow(c));
    });
    if (!$('#cred-rows').childElementCount)
      $('#cred-rows').innerHTML = '<tr><td colspan="8" class="muted">no cleartext credentials captured yet</td></tr>';
  });
}
$('#creds-clear').addEventListener('click', () =>
  post('/api/creds/clear').then(() => { credCursor = 0; lastCredCount = 0; loadCreds(true); }));
// toggle reveal/mask: re-render current view
$('#cred-mask').addEventListener('change', () => { credCursor = 0; loadCreds(true); });
// click a masked password to reveal just that one
$('#cred-rows').addEventListener('click', e => {
  const s = e.target.closest('.pw'); if (s) s.outerHTML = `<span class="pw-shown">${esc(s.dataset.pw)}</span>`;
});

/* ---- filters ------------------------------------------------------------- */
function loadFilters() {
  api('/api/filters').then(d => {
    $('#bpf-input').value = d.bpf || '';
    $('#mac-list').innerHTML = (d.macs || []).map(m =>
      `<li>${esc(m.mac)}${m.note ? ' · ' + esc(m.note) : ''}<span class="x" data-mac="${esc(m.mac)}">✕</span></li>`).join('');
    $('#ssid-list').innerHTML = (d.ssids || []).map(s =>
      `<li class="${s.exclude ? 'excl' : ''}">${esc(s.ssid)} ${s.exclude ? '(excl)' : '(incl)'}<span class="x" data-ssid="${esc(s.ssid)}">✕</span></li>`).join('');
  });
  api('/api/settings').then(s => {
    $('#filter-enabled').checked = s.filter_enabled;
    $('#mac-whitelist').checked = s.mac_filter_is_whitelist;
    $('#mac-mode').textContent = s.mac_filter_is_whitelist ? '(whitelist)' : '(blacklist)';
    $('#cap_mgmt').checked = s.cap_mgmt; $('#cap_ctrl').checked = s.cap_ctrl; $('#cap_data').checked = s.cap_data;
  });
}
$('#bpf-apply').addEventListener('click', () => {
  post('/api/filters/bpf', { bpf: $('#bpf-input').value }).then(r => {
    $('#bpf-status').textContent = r.ok ? '✓ compiled' : '✗ ' + (r.error || r.message);
    $('#bpf-status').style.color = r.ok ? 'var(--accent)' : 'var(--crit)';
  });
});
$('#mac-add').addEventListener('click', () => {
  post('/api/filters/mac', { mac: $('#mac-input').value.trim(), note: $('#mac-note').value.trim() })
    .then(() => { $('#mac-input').value = ''; $('#mac-note').value = ''; loadFilters(); });
});
$('#mac-list').addEventListener('click', e => {
  const x = e.target.closest('.x'); if (x) post('/api/filters/mac', { mac: x.dataset.mac, remove: true }).then(loadFilters);
});
$('#ssid-add').addEventListener('click', () => {
  post('/api/filters/ssid', { ssid: $('#ssid-input').value.trim(), exclude: $('#ssid-mode').value === 'exclude' })
    .then(() => { $('#ssid-input').value = ''; loadFilters(); });
});
$('#ssid-list').addEventListener('click', e => {
  const x = e.target.closest('.x'); if (x) post('/api/filters/ssid', { ssid: x.dataset.ssid, remove: true }).then(loadFilters);
});
['filter-enabled', 'mac-whitelist', 'cap_mgmt', 'cap_ctrl', 'cap_data'].forEach(id => {
  $('#' + id).addEventListener('change', () => post('/api/settings', {
    filter_enabled: $('#filter-enabled').checked,
    mac_filter_is_whitelist: $('#mac-whitelist').checked,
    cap_mgmt: $('#cap_mgmt').checked, cap_ctrl: $('#cap_ctrl').checked, cap_data: $('#cap_data').checked
  }).then(() => { $('#mac-mode').textContent = $('#mac-whitelist').checked ? '(whitelist)' : '(blacklist)'; }));
});

/* ---- pcap ---------------------------------------------------------------- */
function loadPcap() {
  api('/api/settings').then(s => { $('#pcap_enabled').checked = s.pcap_enabled; $('#pcap_radiotap').checked = s.pcap_radiotap; });
  api('/api/pcap/list').then(d => {
    $('#pcap-rows').innerHTML = (d.files || []).map(f => {
      const name = f.name.split('/').pop();
      return `<tr><td>${esc(name)}</td><td>${fmt(f.size)} B</td>` +
        `<td><a class="btn" href="/api/pcap/download?file=${encodeURIComponent(name)}">download</a> ` +
        `<button class="btn danger pcap-del" data-f="${esc(name)}">del</button></td></tr>`;
    }).join('') || '<tr><td colspan="3" class="muted">no captures yet</td></tr>';
  });
}
['pcap_enabled', 'pcap_radiotap'].forEach(id => $('#' + id).addEventListener('change', () =>
  post('/api/settings', { pcap_enabled: $('#pcap_enabled').checked, pcap_radiotap: $('#pcap_radiotap').checked })));
$('#pcap-rows').addEventListener('click', e => {
  const b = e.target.closest('.pcap-del');
  if (b && confirm('Delete ' + b.dataset.f + '?')) post('/api/pcap/delete', { file: b.dataset.f }).then(loadPcap);
});

/* ---- settings ------------------------------------------------------------ */
const SET_FIELDS = ['ap_ssid', 'ap_channel', 'ap_hidden', 'channel_hop', 'hop_pause_on_client',
  'hop_interval_ms', 'fixed_channel', 'snap_len', 'ws_max_pps', 'det_deauth', 'det_beacon_flood',
  'det_evil_twin', 'det_pmkid', 'det_arp_spoof', 'det_dns_anomaly', 'det_deauth_threshold',
  'det_beacon_threshold', 'cred_harvest', 'geo_enabled', 'geo_label', 'geo_lat', 'geo_lon'];
function loadSettings() {
  api('/api/settings').then(s => {
    SET_FIELDS.forEach(k => {
      const el = $('#' + k); if (!el) return;
      if (el.type === 'checkbox') el.checked = !!s[k]; else el.value = s[k];
    });
    const grid = $('#chan-grid'); grid.innerHTML = '';
    (s.channel_enabled || []).forEach((on, i) => {
      const ch = i + 1;
      grid.insertAdjacentHTML('beforeend',
        `<label><input type="checkbox" class="chsel" data-ch="${ch}" ${on ? 'checked' : ''}>${ch}</label>`);
    });
  });
}
function gatherSettings() {
  const out = {};
  SET_FIELDS.forEach(k => {
    const el = $('#' + k); if (!el) return;
    if (el.type === 'checkbox') out[k] = el.checked;
    else if (el.type === 'number') out[k] = parseFloat(el.value);
    else out[k] = el.value;
  });
  const pw = $('#ap_password').value;
  if (pw) out.ap_password = pw;
  out.channel_enabled = $$('.chsel').map(c => c.checked);
  return out;
}
$('#settings-save').addEventListener('click', () => {
  post('/api/settings', gatherSettings()).then(r => {
    $('#settings-status').textContent = r.message || 'saved';
    $('#ap_password').value = '';
    setTimeout(refreshStatus, 200);
  });
});
$('#geo-here').addEventListener('click', () => {
  if (!navigator.geolocation) return;
  navigator.geolocation.getCurrentPosition(p => {
    $('#geo_lat').value = p.coords.latitude.toFixed(6);
    $('#geo_lon').value = p.coords.longitude.toFixed(6);
    $('#geo_enabled').checked = true;
  });
});
$('#btn-reboot').addEventListener('click', () => { if (confirm('Reboot device?')) post('/api/reboot'); });
$('#btn-factory').addEventListener('click', () => { if (confirm('Erase all settings and reboot?')) post('/api/factory-reset'); });

/* ---- websocket ----------------------------------------------------------- */
let ws;
function connectWs() {
  ws = new WebSocket('ws://' + location.host + '/ws');
  ws.onopen = () => $('#st-link').classList.add('ok');
  ws.onclose = () => { $('#st-link').classList.remove('ok'); setTimeout(connectWs, 1500); };
  ws.onerror = () => ws.close();
  ws.onmessage = ev => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.t === 'frames') { (m.f || []).forEach(addFrame); }
    else if (m.t === 'stat') {
      $('#st-ch').textContent = 'CH ' + m.ch;
      $('#st-pps').textContent = m.pps + ' pps';
      $('#st-frames').textContent = fmt(m.frames) + ' frames';
      $('#st-dev').textContent = `${m.ap} AP / ${m.sta} STA`;
      const ab = $('#st-alerts'); ab.textContent = fmt(m.alerts) + ' alerts';
      ab.classList.toggle('hot', m.alerts > 0);
      if (typeof m.creds === 'number') {
        const cb = $('#st-creds'); cb.textContent = fmt(m.creds) + ' creds';
        cb.classList.toggle('hot', m.creds > 0);
        if (m.creds > lastCredCount) {
          lastCredCount = m.creds;
          if ($('#tab-creds').classList.contains('active')) loadCreds(false);
        }
      }
      if ($('#tab-dash').classList.contains('active')) loadStats();
      if (m.alert) {
        if ($('#tab-alerts').classList.contains('active')) loadAlerts(false);
      }
    }
  };
}

/* ---- boot ---------------------------------------------------------------- */
function boot() {
  post('/api/time', { epoch: Math.floor(Date.now() / 1000) });  // sync clock for PCAP
  refreshStatus();
  loadStats();
  connectWs();
  setInterval(refreshStatus, 5000);
  setInterval(() => { if ($('#tab-devices').classList.contains('active')) loadDevices(); }, 3000);
}
boot();
