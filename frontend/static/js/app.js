/**
 * NIDS SOC Dashboard — Main Application JS
 * Single-page application: JS handles all section rendering and API calls.
 * No frameworks — vanilla JS only for simplicity and readability.
 */

'use strict';

// ── State ──────────────────────────────────────────────────────────────────────
const state = {
  currentSection: 'dashboard',
  charts: {},            // keyed by chart canvas id
  alertsPage: 1,
  alertsPerPage: 25,
  alertsTotal: 0,
  alertsSortBy: 'timestamp',
  alertsSortOrder: 'desc',
  alertsFilters: { search: '', severity: '', category: '', protocol: '', src_ip: '', dest_ip: '' },
  rulesSearch: '',
  dataMode: 'demo',
  pollTimer: null,
  lastTotalAlerts: null,
  isPolling: false,
};

// ── API Helper ─────────────────────────────────────────────────────────────────
async function apiFetch(path) {
  const res = await fetch(path);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || res.statusText);
  }
  return res.json();
}

// ── Navigation ─────────────────────────────────────────────────────────────────
function navigate(sectionId) {
  state.currentSection = sectionId;

  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  const target = document.getElementById(`section-${sectionId}`);
  if (target) target.classList.add('active');

  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.section === sectionId);
  });

  const titles = {
    dashboard: 'Main Dashboard',
    alerts: 'Alert Investigation',
    traffic: 'Traffic Analysis',
    pcap: 'PCAP Analysis',
    rules: 'Detection Rules',
    status: 'System Status',
    about: 'Project / About',
  };
  document.getElementById('page-title').textContent = titles[sectionId] || sectionId;

  // Lazy-load section data
  loaders[sectionId]?.();
}

// ── Section Loaders ────────────────────────────────────────────────────────────
const loaders = {
  dashboard: loadDashboard,
  alerts: loadAlerts,
  traffic: loadTraffic,
  pcap: loadPcap,
  rules: loadRules,
  status: loadStatus,
  about: () => { },   // static content
};

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const stats = await apiFetch('/api/stats');
    state.lastTotalAlerts = stats.total_alerts;

    renderStatCards(stats);
    await refreshDashboardCharts();
    loadRecentAlerts(true);
  } catch (e) {
    showError('dash-error', e.message);
  }
}

async function refreshDashboardCharts() {
  try {
    const [timeline, topSrc, topDst, protocols, categories, destPorts] = await Promise.all([
      apiFetch('/api/timeline?bucket=hour'),
      apiFetch('/api/top-sources?limit=8'),
      apiFetch('/api/top-destinations?limit=8'),
      apiFetch('/api/protocols'),
      apiFetch('/api/categories'),
      apiFetch('/api/top-dest-ports?limit=8'),
    ]);

    renderTimeline(timeline);
    renderProtocolChart(protocols);
    renderCategoryChart(categories);
    renderTopIPs('top-src-list', topSrc, 'ip', 'count');
    renderTopIPs('top-dst-list', topDst, 'ip', 'count');
    renderDestPortsChart(destPorts);
  } catch (e) {
    console.debug('Dashboard charts refresh error:', e);
  }
}

function renderStatCards(stats) {
  const animateValue = (el, target) => {
    if (typeof target !== 'number' || isNaN(target)) { el.textContent = target ?? '—'; return; }
    const currentVal = parseInt(el.textContent, 10);
    if (!isNaN(currentVal) && currentVal === target) return;
    const startVal = isNaN(currentVal) ? 0 : currentVal;
    const duration = 600;
    const start = performance.now();
    const step = (now) => {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      el.textContent = Math.round(startVal + eased * (target - startVal));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  };
  const set = (id, val) => {
    const el = document.getElementById(id);
    if (el) animateValue(el, val);
  };
  set('stat-total', stats.total_alerts);
  set('stat-critical', stats.critical);
  set('stat-high', stats.high);
  set('stat-medium', stats.medium);
  set('stat-low', stats.low);
  set('stat-today', stats.events_today);
  set('stat-src-ips', stats.unique_src_ips);
  set('stat-dst-ips', stats.unique_dest_ips);

  // Store data mode for badge
  state.dataMode = stats.data_mode || 'demo';
  updateModeBadge(stats.is_demo);
}

function updateModeBadge(isDemo) {
  const badge = document.getElementById('mode-badge');
  if (!badge) return;
  if (isDemo) {
    badge.className = 'demo-badge';
    badge.innerHTML = '<span class="pulse-dot"></span><span>DEMO DATA</span>';
  } else {
    badge.className = 'demo-badge real';
    badge.innerHTML = '<span class="pulse-dot"></span><span>LIVE DATA</span>';
  }
}

function renderTimeline(data) {
  const ctx = document.getElementById('chart-timeline');
  if (!ctx) return;
  destroyChart('chart-timeline');

  if (!data || !data.length) {
    ctx.parentElement.innerHTML = emptyHtml('No timeline data available');
    return;
  }

  const labels = data.map(d => {
    const t = d.time.replace('T', ' ');
    return t.length > 13 ? t.substring(5, 16) : t.substring(5);
  });

  state.charts['chart-timeline'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Alerts',
        data: data.map(d => d.count),
        backgroundColor: 'rgba(139,92,246,0.45)',
        borderColor: 'rgba(139,92,246,0.9)',
        borderWidth: 1,
        borderRadius: 4,
        borderSkipped: false,
      }],
    },
    options: chartDefaults({ yTitle: 'Alert Count' }),
  });
}

function renderProtocolChart(data) {
  const ctx = document.getElementById('chart-protocols');
  if (!ctx) return;
  destroyChart('chart-protocols');

  if (!data || !data.length) {
    ctx.parentElement.innerHTML = emptyHtml('No protocol data');
    return;
  }

  const colors = ['rgba(139,92,246,0.8)', 'rgba(167,139,250,0.8)', 'rgba(124,58,237,0.8)',
    'rgba(196,181,253,0.8)', 'rgba(109,40,217,0.7)', 'rgba(91,83,128,0.7)'];

  state.charts['chart-protocols'] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: data.map(d => d.protocol),
      datasets: [{
        data: data.map(d => d.count),
        backgroundColor: colors.slice(0, data.length),
        borderWidth: 2,
        borderColor: 'rgba(10,6,18,0.9)',
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#a5a0c2', boxWidth: 14, padding: 12, font: { size: 12 } } },
        tooltip: tooltipStyle(),
      },
      cutout: '65%',
    },
  });
}

function renderCategoryChart(data) {
  const ctx = document.getElementById('chart-categories');
  if (!ctx) return;
  destroyChart('chart-categories');

  if (!data || !data.length) {
    ctx.parentElement.innerHTML = emptyHtml('No category data');
    return;
  }

  const top = data.slice(0, 7);

  state.charts['chart-categories'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: top.map(d => truncate(d.category, 28)),
      datasets: [{
        label: 'Count',
        data: top.map(d => d.count),
        backgroundColor: [
          'rgba(239,68,68,0.7)', 'rgba(249,115,22,0.7)', 'rgba(245,158,11,0.7)',
          'rgba(139,92,246,0.7)', 'rgba(167,139,250,0.7)', 'rgba(124,58,237,0.7)', 'rgba(6,182,212,0.7)',
        ],
        borderRadius: 4,
      }],
    },
    options: {
      ...chartDefaults({ yTitle: 'Count' }),
      indexAxis: 'y',
      plugins: {
        ...chartDefaults({}).plugins,
        legend: { display: false },
      },
    },
  });
}

function renderDestPortsChart(data) {
  const ctx = document.getElementById('chart-dest-ports');
  if (!ctx) return;
  destroyChart('chart-dest-ports');

  if (!data || !data.length) {
    ctx.parentElement.innerHTML = emptyHtml('No port data');
    return;
  }

  state.charts['chart-dest-ports'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => `Port ${d.port}`),
      datasets: [{
        label: 'Alerts',
        data: data.map(d => d.count),
        backgroundColor: 'rgba(167,139,250,0.5)',
        borderColor: 'rgba(167,139,250,0.9)',
        borderWidth: 1,
        borderRadius: 4,
      }],
    },
    options: chartDefaults({ yTitle: 'Alert Count' }),
  });
}

function renderTopIPs(listId, data, ipKey, countKey) {
  const el = document.getElementById(listId);
  if (!el) return;

  if (!data || !data.length) {
    el.innerHTML = `<li style="color:var(--text-muted);font-size:0.8rem;padding:10px 0">No data available</li>`;
    return;
  }

  const max = data[0]?.[countKey] || 1;
  el.innerHTML = data.map(d => `
    <li>
      <span class="ip-addr">${esc(d[ipKey])}</span>
      <div class="ip-bar-wrap"><div class="ip-bar" style="width:${Math.round(d[countKey] / max * 100)}%"></div></div>
      <span class="ip-count">${d[countKey]}</span>
    </li>
  `).join('');
}

async function loadRecentAlerts(showSpinner = true) {
  const tbody = document.getElementById('recent-alerts-tbody');
  if (!tbody) return;
  if (showSpinner || !tbody.children.length) {
    tbody.innerHTML = loadingRow(7);
  }

  try {
    const data = await apiFetch('/api/alerts?per_page=10&sort_by=timestamp&sort_order=desc');
    if (!data.alerts?.length) {
      tbody.innerHTML = `<tr><td colspan="7">${emptyHtml('No recent alerts')}</td></tr>`;
      return;
    }
    tbody.innerHTML = data.alerts.map(a => alertRow(a, true)).join('');
    tbody.querySelectorAll('tr[data-id]').forEach(row => {
      row.addEventListener('click', () => openAlertDetail(+row.dataset.id));
    });
  } catch (e) {
    if (showSpinner || !tbody.children.length) {
      tbody.innerHTML = errorRow(7, e.message);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ALERTS
// ─────────────────────────────────────────────────────────────────────────────
async function loadAlerts() {
  // Populate filter dropdowns once
  if (!document.getElementById('filter-category').options.length > 1) return;
  await populateFilterDropdowns();
  await fetchAndRenderAlerts(true);
}

async function populateFilterDropdowns() {
  try {
    const opts = await apiFetch('/api/filter-options');
    const catSel = document.getElementById('filter-category');
    const protoSel = document.getElementById('filter-protocol');
    if (catSel && catSel.options.length === 1) {
      opts.categories?.forEach(c => {
        catSel.add(new Option(c, c));
      });
    }
    if (protoSel && protoSel.options.length === 1) {
      opts.protocols?.forEach(p => {
        protoSel.add(new Option(p, p));
      });
    }
  } catch (_) { /* non-fatal */ }
}

async function fetchAndRenderAlerts(showSpinner = true) {
  const tbody = document.getElementById('alerts-tbody');
  if (!tbody) return;
  if (showSpinner || !tbody.children.length) {
    tbody.innerHTML = loadingRow(9);
  }

  const f = state.alertsFilters;
  const params = new URLSearchParams({
    page: state.alertsPage,
    per_page: state.alertsPerPage,
    sort_by: state.alertsSortBy,
    sort_order: state.alertsSortOrder,
  });
  if (f.search) params.set('search', f.search);
  if (f.severity) params.set('severity', f.severity);
  if (f.category) params.set('category', f.category);
  if (f.protocol) params.set('protocol', f.protocol);
  if (f.src_ip) params.set('src_ip', f.src_ip);
  if (f.dest_ip) params.set('dest_ip', f.dest_ip);

  try {
    const data = await apiFetch(`/api/alerts?${params}`);
    state.alertsTotal = data.total;

    if (!data.alerts?.length) {
      tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state" style="padding:30px">${svgIcon('shield-off')}<p>No alerts match the current filters</p></div></td></tr>`;
    } else {
      tbody.innerHTML = data.alerts.map(a => alertRow(a, false)).join('');
      tbody.querySelectorAll('tr[data-id]').forEach(row => {
        row.addEventListener('click', () => openAlertDetail(+row.dataset.id));
      });
    }

    renderPagination(data);
    updateSortHeaders();
  } catch (e) {
    if (showSpinner || !tbody.children.length) {
      tbody.innerHTML = errorRow(9, e.message);
    }
  }
}

function alertRow(a, compact) {
  const sev = sevBadge(a.severity_label);
  if (compact) {
    return `<tr data-id="${a.id}" title="Click to view details">
      <td><span class="text-muted text-mono" style="font-size:0.75rem">${shortTs(a.timestamp)}</span></td>
      <td class="sig-cell" style="max-width:200px">${esc(truncate(a.signature, 45))}</td>
      <td>${sev}</td>
      <td><code>${esc(a.src_ip)}${a.src_port ? ':' + a.src_port : ''}</code></td>
      <td><code>${esc(a.dest_ip)}${a.dest_port ? ':' + a.dest_port : ''}</code></td>
      <td><span class="badge badge-info">${esc(a.proto || '—')}</span></td>
      <td><code>${a.sid}</code></td>
    </tr>`;
  }
  return `<tr data-id="${a.id}" title="Click to view details">
    <td><span class="text-mono" style="font-size:0.75rem;color:var(--text-muted)">${shortTs(a.timestamp)}</span></td>
    <td class="sig-cell" style="max-width:260px" title="${esc(a.signature)}">${esc(truncate(a.signature, 50))}</td>
    <td>${sev}</td>
    <td style="max-width:180px" title="${esc(a.category)}">${esc(truncate(a.category, 30))}</td>
    <td><code>${esc(a.src_ip)}${a.src_port ? ':' + a.src_port : ''}</code></td>
    <td><code>${esc(a.dest_ip)}${a.dest_port ? ':' + a.dest_port : ''}</code></td>
    <td><span class="badge badge-info">${esc(a.proto || '—')}</span></td>
    <td><code>${a.sid}</code></td>
    <td><code>${a.flow_id || '—'}</code></td>
  </tr>`;
}

function renderPagination(data) {
  const info = document.getElementById('page-info');
  const controls = document.getElementById('page-controls');
  if (!info || !controls) return;

  const { page, per_page, total, total_pages } = data;
  const start = Math.min((page - 1) * per_page + 1, total);
  const end = Math.min(page * per_page, total);
  info.textContent = total ? `Showing ${start}–${end} of ${total} alerts` : 'No alerts';

  const pages = [];
  if (total_pages <= 1) { controls.innerHTML = ''; return; }

  const addBtn = (label, pg, disabled, current) => {
    const cls = ['page-btn', current ? 'current' : ''].filter(Boolean).join(' ');
    pages.push(`<button class="${cls}" data-page="${pg}" ${disabled ? 'disabled' : ''}>${label}</button>`);
  };

  addBtn('‹', page - 1, page === 1);
  const range = pageRange(page, total_pages);
  range.forEach(p => {
    if (p === '…') pages.push(`<span style="color:var(--text-muted);padding:0 4px">…</span>`);
    else addBtn(p, p, false, p === page);
  });
  addBtn('›', page + 1, page === total_pages);

  controls.innerHTML = pages.join('');
  controls.querySelectorAll('.page-btn:not([disabled])').forEach(btn => {
    btn.addEventListener('click', () => {
      state.alertsPage = +btn.dataset.page;
      fetchAndRenderAlerts();
    });
  });
}

function pageRange(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages = [1];
  if (current > 3) pages.push('…');
  for (let p = Math.max(2, current - 1); p <= Math.min(total - 1, current + 1); p++) pages.push(p);
  if (current < total - 2) pages.push('…');
  pages.push(total);
  return pages;
}

function updateSortHeaders() {
  document.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.classList.toggle('sorted', th.dataset.sort === state.alertsSortBy);
    const arrow = th.dataset.sort === state.alertsSortBy
      ? (state.alertsSortOrder === 'desc' ? ' ↓' : ' ↑')
      : '';
    const base = th.dataset.label || th.textContent.replace(/[ ↓↑]+$/, '');
    th.dataset.label = base;
    th.textContent = base + arrow;
  });
}

// ── Alert Detail Modal ──────────────────────────────────────────────────────────
async function openAlertDetail(id) {
  const backdrop = document.getElementById('alert-modal');
  backdrop.classList.add('open');
  document.getElementById('modal-content').innerHTML = `<div class="loading-spinner"><div class="spinner"></div> Loading alert…</div>`;

  try {
    const a = await apiFetch(`/api/alerts/${id}`);
    document.getElementById('modal-title').textContent = a.signature || 'Alert Detail';

    document.getElementById('modal-content').innerHTML = `
      <div class="detail-grid">
        <div class="detail-field">
          <div class="field-label">Timestamp</div>
          <div class="field-value mono">${esc(a.timestamp || '—')}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Severity</div>
          <div class="field-value">${sevBadge(a.severity_label)}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Category</div>
          <div class="field-value">${esc(a.category || '—')}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Protocol</div>
          <div class="field-value"><span class="badge badge-info">${esc(a.proto || '—')}</span></div>
        </div>
        <div class="detail-field">
          <div class="field-label">Source IP : Port</div>
          <div class="field-value mono">${esc(a.src_ip || '—')}${a.src_port ? ':' + a.src_port : ''}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Destination IP : Port</div>
          <div class="field-value mono">${esc(a.dest_ip || '—')}${a.dest_port ? ':' + a.dest_port : ''}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Signature ID (SID)</div>
          <div class="field-value mono">${a.sid || '—'}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Generator ID (GID)</div>
          <div class="field-value mono">${a.gid || '—'}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Flow ID</div>
          <div class="field-value mono">${esc(String(a.flow_id || '—'))}</div>
        </div>
        <div class="detail-field">
          <div class="field-label">Action</div>
          <div class="field-value">${esc(a.action || '—')}</div>
        </div>
        <div class="detail-field span-2">
          <div class="field-label">Signature</div>
          <div class="field-value">${esc(a.signature || '—')}</div>
        </div>
      </div>
      <div class="mb-8" style="font-size:0.72rem;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px">Raw Suricata JSON</div>
      <pre class="raw-json">${esc(a.raw || '—')}</pre>
    `;
  } catch (e) {
    document.getElementById('modal-content').innerHTML = `<div class="error-state">Failed to load alert: ${esc(e.message)}</div>`;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TRAFFIC ANALYSIS
// ─────────────────────────────────────────────────────────────────────────────
async function loadTraffic() {
  try {
    const [flowPairs, protocols, topSrc, topDst, srcPorts, destPorts] = await Promise.all([
      apiFetch('/api/flow-pairs?limit=15'),
      apiFetch('/api/protocols'),
      apiFetch('/api/top-sources?limit=10'),
      apiFetch('/api/top-destinations?limit=10'),
      apiFetch('/api/top-src-ports?limit=8'),
      apiFetch('/api/top-dest-ports?limit=8'),
    ]);

    renderFlowPairs(flowPairs);
    renderTrafficProtocols(protocols);
    renderTopIPs('traffic-src-list', topSrc, 'ip', 'count');
    renderTopIPs('traffic-dst-list', topDst, 'ip', 'count');
    renderPortChart('chart-src-ports', srcPorts, 'Source Ports', 'rgba(139,92,246,0.6)', 'rgba(139,92,246,1)');
    renderPortChart('chart-dst-ports-traffic', destPorts, 'Dest Ports', 'rgba(6,182,212,0.6)', 'rgba(6,182,212,1)');
  } catch (e) {
    showError('traffic-error', e.message);
  }
}

function renderFlowPairs(pairs) {
  const el = document.getElementById('flow-pairs-list');
  if (!el) return;
  if (!pairs?.length) {
    el.innerHTML = `<li style="color:var(--text-muted);font-size:0.8rem;padding:10px 0">No flow data available</li>`;
    return;
  }
  el.innerHTML = pairs.map(p => `
    <li>
      <span class="flow-src">${esc(p.src)}</span>
      <span class="flow-arrow">&#8594;</span>
      <span class="flow-dst">${esc(p.dest)}</span>
      <span class="flow-count">${p.count}</span>
    </li>
  `).join('');
}

function renderTrafficProtocols(data) {
  const el = document.getElementById('traffic-proto-list');
  if (!el) return;
  if (!data?.length) {
    el.innerHTML = `<p style="color:var(--text-muted);font-size:0.8rem">No protocol data</p>`;
    return;
  }
  el.innerHTML = data.map(d => `
    <div class="mb-12">
      <div class="flex items-center justify-between mb-4">
        <span style="font-size:0.85rem;font-weight:600;color:var(--text-primary)">${esc(d.protocol)}</span>
        <span style="font-size:0.78rem;color:var(--text-muted)">${d.count} alerts (${d.percent}%)</span>
      </div>
      <div style="height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden">
        <div style="width:${d.percent}%;height:100%;background:linear-gradient(90deg,var(--accent-blue),var(--accent-cyan));border-radius:3px;transition:width 0.6s ease"></div>
      </div>
    </div>
  `).join('');
}

function renderPortChart(canvasId, data, label, bg, border) {
  const ctx = document.getElementById(canvasId);
  if (!ctx) return;
  destroyChart(canvasId);
  if (!data?.length) { ctx.parentElement.innerHTML = emptyHtml('No port data'); return; }

  state.charts[canvasId] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.map(d => `${d.port}`),
      datasets: [{ label, data: data.map(d => d.count), backgroundColor: bg, borderColor: border, borderWidth: 1, borderRadius: 4 }],
    },
    options: chartDefaults({ yTitle: 'Alerts' }),
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP
// ─────────────────────────────────────────────────────────────────────────────
async function loadPcap() {
  const fileList = document.getElementById('pcap-file-list');
  if (!fileList) return;
  fileList.innerHTML = `<div class="loading-spinner"><div class="spinner"></div> Loading…</div>`;

  try {
    const data = await apiFetch('/api/pcap/list');
    renderPcapList(data.files || []);
  } catch (e) {
    fileList.innerHTML = `<div class="error-state">Failed to load PCAP list: ${esc(e.message)}</div>`;
  }
}

function renderPcapList(files) {
  const el = document.getElementById('pcap-file-list');
  if (!el) return;
  if (!files.length) {
    el.innerHTML = `<div class="empty-state"><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg><h3>No PCAP files uploaded</h3><p>Upload a .pcap or .pcapng file using the form above</p></div>`;
    return;
  }
  el.innerHTML = files.map(f => `
    <div class="file-item">
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
      <span class="file-name">${esc(f.filename)}</span>
      <span class="file-size text-muted">${formatBytes(f.size_bytes)}</span>
      <span class="file-status"><span class="badge badge-unknown">Pending Offline Analysis</span></span>
    </div>
  `).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// RULES
// ─────────────────────────────────────────────────────────────────────────────
async function loadRules() {
  const tbody = document.getElementById('rules-tbody');
  if (!tbody) return;
  tbody.innerHTML = loadingRow(6);

  try {
    const data = await apiFetch('/api/rules');
    renderRules(data.rules || [], data.is_demo);
  } catch (e) {
    tbody.innerHTML = errorRow(6, e.message);
  }
}

function renderRules(rules, isDemo) {
  const tbody = document.getElementById('rules-tbody');
  const countEl = document.getElementById('rules-count');
  const demoNote = document.getElementById('rules-demo-note');

  if (demoNote) demoNote.style.display = isDemo ? 'flex' : 'none';

  const search = state.rulesSearch.toLowerCase();
  const filtered = search
    ? rules.filter(r => r.signature.toLowerCase().includes(search) || String(r.sid).includes(search))
    : rules;

  if (countEl) countEl.textContent = `${filtered.length} rules`;

  if (!filtered.length) {
    tbody.innerHTML = `<tr><td colspan="6"><div class="empty-state" style="padding:30px"><p>No rules match the current filter</p></div></td></tr>`;
    return;
  }

  const sevLbl = { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low' };
  tbody.innerHTML = filtered.map(r => `
    <tr>
      <td><code>${r.sid}</code></td>
      <td style="max-width:280px" title="${esc(r.signature)}">${esc(truncate(r.signature, 55))}</td>
      <td>${esc(r.category || '—')}</td>
      <td>${sevBadge(sevLbl[r.severity] || 'Low')}</td>
      <td><span class="badge badge-info">${esc(r.protocol || '—')}</span></td>
      <td>${r.enabled
      ? '<span class="badge badge-low">Enabled</span>'
      : '<span class="badge badge-unknown">Disabled</span>'}</td>
    </tr>
  `).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// SYSTEM STATUS
// ─────────────────────────────────────────────────────────────────────────────
async function loadStatus() {
  const grid = document.getElementById('status-grid');
  if (!grid) return;
  grid.innerHTML = `<div class="loading-spinner"><div class="spinner"></div> Checking components…</div>`;

  try {
    const data = await apiFetch('/api/system-status');
    renderStatus(data.components || []);
  } catch (e) {
    grid.innerHTML = `<div class="error-state">Failed to load system status: ${esc(e.message)}</div>`;
  }
}

function renderStatus(components) {
  const grid = document.getElementById('status-grid');
  if (!grid) return;

  const statusMeta = (s) => {
    const k = (s || '').toLowerCase();
    if (k === 'online' || k.startsWith('online')) return { cls: 'online', labelCls: 'text-low' };
    if (k === 'offline' || k === 'error') return { cls: 'offline', labelCls: 'text-critical' };
    if (k.includes('simulation') || k.includes('demo')) return { cls: 'simulation', labelCls: 'text-medium' };
    if (k.includes('not configured') || k.includes('not connect')) return { cls: 'offline', labelCls: 'text-high' };
    if (k.includes('offline workflow')) return { cls: 'warning', labelCls: 'text-high' };
    return { cls: 'unknown', labelCls: 'text-muted' };
  };

  grid.innerHTML = components.map(c => {
    const { cls, labelCls } = statusMeta(c.status);
    return `
      <div class="status-card">
        <div class="status-indicator ${cls}"></div>
        <div class="status-info">
          <div class="status-name">${esc(c.name)}</div>
          <div class="status-role">${esc(c.role)}</div>
          <div class="status-label ${labelCls}">${esc(c.status)}</div>
          <div class="status-detail">${esc(c.detail || '')}</div>
        </div>
      </div>
    `;
  }).join('');
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP UPLOAD
// ─────────────────────────────────────────────────────────────────────────────
function initPcapUpload() {
  const zone = document.getElementById('upload-zone');
  const input = document.getElementById('pcap-file-input');
  const btn = document.getElementById('upload-btn');
  const progress = document.getElementById('upload-progress');

  if (!zone || !input) return;

  zone.addEventListener('click', () => input.click());
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) { input.files = e.dataTransfer.files; updateUploadLabel(file.name); }
  });

  input.addEventListener('change', () => {
    if (input.files[0]) updateUploadLabel(input.files[0].name);
  });

  btn?.addEventListener('click', async () => {
    if (!input.files[0]) { toast('Please select a file first.', 'error'); return; }
    if (progress) progress.textContent = 'Uploading…';

    const form = new FormData();
    form.append('pcap', input.files[0]);

    try {
      const res = await fetch('/api/pcap/upload', { method: 'POST', body: form });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Upload failed');
      toast(`Uploaded: ${data.filename}`, 'success');
      if (progress) progress.textContent = '';
      input.value = '';
      updateUploadLabel('');
      loadPcap();
    } catch (e) {
      toast(`Upload failed: ${e.message}`, 'error');
      if (progress) progress.textContent = '';
    }
  });
}

function updateUploadLabel(name) {
  const label = document.getElementById('upload-filename');
  if (label) label.textContent = name || 'No file selected';
}

// ─────────────────────────────────────────────────────────────────────────────
// SHARED UTILITIES
// ─────────────────────────────────────────────────────────────────────────────
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function truncate(str, len) {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '…' : str;
}

function shortTs(ts) {
  if (!ts) return '—';
  try { return ts.replace('T', ' ').substring(0, 19); }
  catch (_) { return ts; }
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function sevBadge(label) {
  const map = { Critical: 'badge-critical', High: 'badge-high', Medium: 'badge-medium', Low: 'badge-low' };
  const cls = map[label] || 'badge-unknown';
  return `<span class="badge ${cls}">${esc(label || 'Unknown')}</span>`;
}

function loadingRow(cols) {
  return `<tr><td colspan="${cols}"><div class="loading-spinner"><div class="spinner"></div> Loading…</div></td></tr>`;
}

function errorRow(cols, msg) {
  return `<tr><td colspan="${cols}"><div class="error-state">Error: ${esc(msg)}</div></td></tr>`;
}

function emptyHtml(msg) {
  return `<div style="text-align:center;padding:30px;color:var(--text-muted);font-size:0.85rem">${msg}</div>`;
}

function showError(id, msg) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="error-state">Error: ${esc(msg)}</div>`;
}

function svgIcon(name) {
  const icons = {
    'shield-off': `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016zM12 9v2m0 4h.01"/></svg>`,
  };
  return icons[name] || '';
}

function destroyChart(id) {
  if (state.charts[id]) {
    state.charts[id].destroy();
    delete state.charts[id];
  }
}

function chartDefaults({ yTitle = '' } = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: tooltipStyle(),
    },
    scales: {
      x: {
        ticks: { color: '#a5a0c2', font: { size: 11 }, maxRotation: 35 },
        grid: { color: 'rgba(139,92,246,0.06)' },
      },
      y: {
        ticks: { color: '#a5a0c2', font: { size: 11 } },
        grid: { color: 'rgba(139,92,246,0.08)' },
        title: yTitle ? { display: true, text: yTitle, color: '#a5a0c2', font: { size: 11 } } : { display: false },
      },
    },
  };
}

function tooltipStyle() {
  return {
    backgroundColor: 'rgba(15,10,30,0.92)',
    borderColor: 'rgba(139,92,246,0.25)',
    borderWidth: 1,
    titleColor: '#ede9fe',
    bodyColor: '#a5a0c2',
    padding: 10,
    cornerRadius: 10,
  };
}

function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const div = document.createElement('div');
  div.className = `toast ${type}`;
  div.innerHTML = `<span>${esc(msg)}</span>`;
  container.appendChild(div);
  setTimeout(() => div.remove(), 4000);
}

// ─────────────────────────────────────────────────────────────────────────────
// CLOCK
// ─────────────────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('topbar-time');
  if (!el) return;
  const update = () => {
    const now = new Date();
    el.textContent = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  };
  update();
  setInterval(update, 1000);
}

// ─────────────────────────────────────────────────────────────────────────────
// INITIALISE
// ─────────────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  startClock();
  initPcapUpload();
  initCursorGlow();

  // Nav clicks
  document.querySelectorAll('.nav-item[data-section]').forEach(item => {
    item.addEventListener('click', () => navigate(item.dataset.section));
  });

  // Alerts filters
  const applyFilters = () => {
    state.alertsPage = 1;
    state.alertsFilters = {
      search: document.getElementById('search-input')?.value || '',
      severity: document.getElementById('filter-severity')?.value || '',
      category: document.getElementById('filter-category')?.value || '',
      protocol: document.getElementById('filter-protocol')?.value || '',
      src_ip: document.getElementById('filter-src-ip')?.value || '',
      dest_ip: document.getElementById('filter-dest-ip')?.value || '',
    };
    fetchAndRenderAlerts();
  };

  document.getElementById('search-input')?.addEventListener('input', debounce(applyFilters, 350));
  document.getElementById('filter-severity')?.addEventListener('change', applyFilters);
  document.getElementById('filter-category')?.addEventListener('change', applyFilters);
  document.getElementById('filter-protocol')?.addEventListener('change', applyFilters);
  document.getElementById('filter-src-ip')?.addEventListener('input', debounce(applyFilters, 350));
  document.getElementById('filter-dest-ip')?.addEventListener('input', debounce(applyFilters, 350));

  document.getElementById('clear-filters-btn')?.addEventListener('click', () => {
    ['search-input', 'filter-severity', 'filter-category', 'filter-protocol', 'filter-src-ip', 'filter-dest-ip'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    applyFilters();
  });

  // Sort headers
  document.querySelectorAll('thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      if (th.dataset.sort === state.alertsSortBy) {
        state.alertsSortOrder = state.alertsSortOrder === 'desc' ? 'asc' : 'desc';
      } else {
        state.alertsSortBy = th.dataset.sort;
        state.alertsSortOrder = 'desc';
      }
      state.alertsPage = 1;
      fetchAndRenderAlerts();
    });
  });

  // Per-page selector
  document.getElementById('per-page-select')?.addEventListener('change', e => {
    state.alertsPerPage = +e.target.value;
    state.alertsPage = 1;
    fetchAndRenderAlerts();
  });

  // Rules search
  document.getElementById('rules-search-input')?.addEventListener('input', debounce(async e => {
    state.rulesSearch = e.target.value;
    const data = await apiFetch('/api/rules').catch(() => ({ rules: [], is_demo: true }));
    renderRules(data.rules || [], data.is_demo);
  }, 300));

  // Modal close
  document.getElementById('modal-close-btn')?.addEventListener('click', () => {
    document.getElementById('alert-modal')?.classList.remove('open');
  });

  document.getElementById('alert-modal')?.addEventListener('click', e => {
    if (e.target === e.currentTarget) e.currentTarget.classList.remove('open');
  });

  // Keyboard: Escape closes modal
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.getElementById('alert-modal')?.classList.remove('open');
  });

  // Reload button
  document.getElementById('reload-btn')?.addEventListener('click', () => {
    loaders[state.currentSection]?.();
    toast('Data refreshed', 'success');
  });

  // Start on dashboard
  navigate('dashboard');

  // Start real-time live polling for Suricata alert updates
  startLivePolling();
});

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// CURSOR GLOW TRACKING
// ─────────────────────────────────────────────────────────────────────────────
// Sets --mouse-x and --mouse-y CSS custom properties on hoverable cards
// so the radial glow follows the cursor. Efficient: uses a single delegated
// listener with requestAnimationFrame throttling.
function initCursorGlow() {
  // Respect prefers-reduced-motion
  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  let ticking = false;
  document.addEventListener('mousemove', (e) => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const target = e.target.closest('.card, .stat-card, .status-card, .team-card, .arch-node');
      if (target) {
        const rect = target.getBoundingClientRect();
        const x = ((e.clientX - rect.left) / rect.width) * 100;
        const y = ((e.clientY - rect.top) / rect.height) * 100;
        target.style.setProperty('--mouse-x', x);
        target.style.setProperty('--mouse-y', y);
      }
      ticking = false;
    });
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// REAL-TIME LIVE POLLING
// ─────────────────────────────────────────────────────────────────────────────
// Automatically checks for new Suricata alerts every 3 seconds while
// viewing the dashboard or alert data, updating counts, charts, and tables
// without requiring manual browser reloads.
function startLivePolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  state.pollTimer = setInterval(pollLiveUpdates, 3000);
}

async function pollLiveUpdates() {
  // Guard against overlapping requests if network/server is slow
  if (state.isPolling) return;
  state.isPolling = true;

  try {
    const stats = await apiFetch('/api/stats');

    // Detect if alert total has changed
    const hasChanged = state.lastTotalAlerts !== null && stats.total_alerts !== state.lastTotalAlerts;
    state.lastTotalAlerts = stats.total_alerts;

    // Update stat cards (smooth cubic ease-out animation only runs if values changed)
    renderStatCards(stats);

    // If new alerts were written by Suricata, refresh active views seamlessly
    if (hasChanged) {
      if (state.currentSection === 'dashboard') {
        loadRecentAlerts(false);
        refreshDashboardCharts();
      } else if (state.currentSection === 'alerts') {
        fetchAndRenderAlerts(false);
      }
    }
  } catch (err) {
    // Non-fatal: if connection drops momentarily, keep polling smoothly
    console.debug('Live polling tick:', err);
  } finally {
    state.isPolling = false;
  }
}

