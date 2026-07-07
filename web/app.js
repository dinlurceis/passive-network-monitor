// ─────────────────────────────────────────────────────────────────────────────
// PNADS Dashboard — app.js
// ─────────────────────────────────────────────────────────────────────────────
const API_BASE = '/api';
let currentCharts = [];
let currentPage   = 'dashboard';

// Per-table pagination state
const pagination = {
    assets:   { page: 1, page_size: 20, total: 0, total_pages: 1, active_only: false },
    alerts:   { page: 1, page_size: 20, total: 0, total_pages: 1, unacked: false, severity: '' },
    events:   { page: 1, page_size: 20, total: 0, total_pages: 1, type: '', protocol: '' },
};

// Định dạng ngày an toàn — trả về '—' nếu giá trị rỗng hoặc không hợp lệ
function fmtDate(ts, fmt = 'DD/MM HH:mm:ss') {
    if (!ts) return '—';
    const m = moment(ts);
    return m.isValid() ? m.format(fmt) : '—';
}
function fmtRelative(ts) {
    if (!ts) return '—';
    const m = moment(ts);
    return m.isValid() ? m.fromNow() : '—';
}

// ── Safe JSON fetch helper ────────────────────────────────────────────────────
// Always checks res.ok first; throws a descriptive error instead of
// "Unexpected end of JSON input" when the server returns an empty 500 body.
async function safeJson(res) {
    const text = await res.text();
    if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try { const j = JSON.parse(text); msg = j.error || j.message || msg; } catch (_) {}
        throw new Error(msg);
    }
    if (!text || text.trim() === '') throw new Error(`Empty response from server (${res.status})`);
    return JSON.parse(text);
}


// ── DOM refs ──────────────────────────────────────────────────────────────────
const pageContainer  = document.getElementById('page-container');
const pageTitle      = document.getElementById('page-title');
const navItems       = document.querySelectorAll('.nav-item');
const alertBadge     = document.getElementById('alert-badge');
const apiStatusDot   = document.getElementById('api-status-dot');
const apiStatusText  = document.getElementById('api-status-text');

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    setupModalClose();
    setupPcapUploadDrop();
    loadPage(currentPage);
    startHealthCheck();
    startRealtimePolling();
    startPcapStatusPolling();
});

// ─────────────────────────────────────────────────────────────────────────────
// Navigation
// ─────────────────────────────────────────────────────────────────────────────
function setupNavigation() {
    navItems.forEach(item => {
        item.addEventListener('click', e => {
            e.preventDefault();
            const page = item.getAttribute('data-page');
            navItems.forEach(n => n.classList.remove('active'));
            item.classList.add('active');
            loadPage(page);
        });
    });
}

function loadPage(page) {
    currentPage = page;
    pageTitle.textContent = page.charAt(0).toUpperCase() + page.slice(1);
    currentCharts.forEach(c => c.destroy());
    currentCharts = [];
    switch (page) {
        case 'dashboard': renderDashboard(); break;
        case 'assets':    renderAssets();    break;
        case 'events':    renderEvents();    break;
        case 'alerts':    renderAlerts();    break;
        case 'watchlist': renderWatchlist(); break;
    }
}

function refreshCurrentPage() { loadPage(currentPage); fetchAlertCount(); }

// ─────────────────────────────────────────────────────────────────────────────
// Modal management
// ─────────────────────────────────────────────────────────────────────────────
function setupModalClose() {
    document.querySelectorAll('.close-modal').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
        });
    });
    // Close on backdrop click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
        overlay.addEventListener('click', e => {
            if (e.target === overlay) overlay.classList.remove('active');
        });
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Pagination helper
// ─────────────────────────────────────────────────────────────────────────────
function renderPagination(containerId, state, onPageChange) {
    const el = document.getElementById(containerId);
    if (!el) return;
    if (state.total_pages <= 1) { el.innerHTML = ''; return; }

    const prev = state.page > 1;
    const next = state.page < state.total_pages;

    // Compute visible page buttons (max 7)
    const pages = [];
    const delta = 2;
    for (let i = Math.max(1, state.page - delta); i <= Math.min(state.total_pages, state.page + delta); i++) {
        pages.push(i);
    }

    el.innerHTML = `
        <div class="pagination">
            <button class="pg-btn" ${!prev ? 'disabled' : ''} onclick="(${onPageChange})(${state.page - 1})">
                <i class="fa-solid fa-chevron-left"></i>
            </button>
            ${state.page > 3 ? `<button class="pg-btn" onclick="(${onPageChange})(1)">1</button>
                ${state.page > 4 ? '<span class="pg-ellipsis">…</span>' : ''}` : ''}
            ${pages.map(p => `<button class="pg-btn ${p === state.page ? 'active' : ''}"
                onclick="(${onPageChange})(${p})">${p}</button>`).join('')}
            ${state.page < state.total_pages - 2 ?
                `${state.page < state.total_pages - 3 ? '<span class="pg-ellipsis">…</span>' : ''}
                <button class="pg-btn" onclick="(${onPageChange})(${state.total_pages})">${state.total_pages}</button>` : ''}
            <button class="pg-btn" ${!next ? 'disabled' : ''} onclick="(${onPageChange})(${state.page + 1})">
                <i class="fa-solid fa-chevron-right"></i>
            </button>
            <span class="pg-info">${state.total} total</span>
        </div>
    `;
}

// ─────────────────────────────────────────────────────────────────────────────
// Real-time polling
// ─────────────────────────────────────────────────────────────────────────────
let pollingInterval     = null;
let lastKnownEventCount = 0;
let lastKnownAlertCount = 0;

function startRealtimePolling() {
    if (pollingInterval) clearInterval(pollingInterval);
    pollingInterval = setInterval(async () => {
        try {
            const res   = await fetch(`${API_BASE}/stats`);
            const stats = await safeJson(res);

            if (stats.total_events > lastKnownEventCount && lastKnownEventCount > 0) {
                showToast('New Activity', 'New network events processed', 'success');
            }
            if (stats.alerts_unacknowledged > lastKnownAlertCount && lastKnownAlertCount > 0) {
                showToast('New Alert', 'A new security alert was generated', 'danger');
            }
            lastKnownEventCount = stats.total_events;
            lastKnownAlertCount = stats.alerts_unacknowledged;

            // Update nav badge
            if (stats.alerts_unacknowledged > 0) {
                alertBadge.textContent = stats.alerts_unacknowledged;
                alertBadge.style.display = 'inline-block';
            } else {
                alertBadge.style.display = 'none';
            }

            // Silent refresh of current view
            if (currentPage === 'dashboard') updateDashboardSilently(stats);
        } catch (e) { /* ignore */ }
    }, 3000);
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP Status polling
// ─────────────────────────────────────────────────────────────────────────────
function startPcapStatusPolling() {
    setInterval(updatePcapStatus, 2000);
    updatePcapStatus();
}

async function updatePcapStatus() {
    try {
        const res    = await fetch(`${API_BASE}/pcap/status`);
        const status = await safeJson(res);

        const modeBadge   = document.getElementById('pcap-mode-badge');
        const currentFile = document.getElementById('pcap-current-file');

        if (modeBadge) {
            modeBadge.textContent = status.mode === 'stable_loop' ? 'Loop' :
                                    status.mode === 'priority'    ? 'Priority' : 'Idle';
            modeBadge.className = 'pcap-mode-badge ' +
                (status.mode === 'stable_loop' ? 'pcap-loop' :
                 status.mode === 'priority'    ? 'pcap-priority' : 'pcap-idle');
        }
        if (currentFile) {
            currentFile.textContent = status.current || '—';
            currentFile.title       = status.current || '';
        }

        // Update upload modal too
        const modalMode = document.getElementById('upload-modal-mode');
        const modalCur  = document.getElementById('upload-modal-current');
        if (modalMode) {
            modalMode.textContent = modeBadge ? modeBadge.textContent : status.mode;
            modalMode.className   = 'pcap-mode-badge ' +
                (status.mode === 'stable_loop' ? 'pcap-loop' :
                 status.mode === 'priority'    ? 'pcap-priority' : 'pcap-idle');
        }
        if (modalCur) modalCur.textContent = status.current || '—';
    } catch (e) { /* ignore */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// Toast notifications
// ─────────────────────────────────────────────────────────────────────────────
function showToast(title, desc, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast     = document.createElement('div');
    toast.className = `toast toast-${type}`;
    const icon = type === 'danger' ? 'fa-triangle-exclamation' :
                 type === 'success' ? 'fa-check-circle' : 'fa-info-circle';
    toast.innerHTML = `
        <div class="toast-title"><i class="fa-solid ${icon}"></i> ${title}</div>
        <div class="toast-desc">${desc}</div>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Check
// ─────────────────────────────────────────────────────────────────────────────
function startHealthCheck() {
    checkHealth();
    setInterval(checkHealth, 30000);
}

async function checkHealth() {
    try {
        const res = await fetch('/health');
        if (res.ok) {
            apiStatusDot.className = 'status-dot healthy';
            apiStatusText.textContent = 'Connected';
        } else throw new Error();
    } catch {
        apiStatusDot.className = 'status-dot error';
        apiStatusText.textContent = 'Disconnected';
    }
}

async function fetchAlertCount() {
    try {
        const res   = await fetch(`${API_BASE}/stats`);
        const stats = await safeJson(res);
        if (stats.alerts_unacknowledged > 0) {
            alertBadge.textContent = stats.alerts_unacknowledged;
            alertBadge.style.display = 'inline-block';
        } else {
            alertBadge.style.display = 'none';
        }
    } catch (e) { /* ignore */ }
}

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────
async function renderDashboard() {
    pageContainer.innerHTML = `
        <div class="dashboard-grid">
            <div class="card stat-card glass">
                <span class="stat-label">Total Assets</span>
                <span class="stat-value" id="stat-total-assets">-</span>
            </div>
            <div class="card stat-card glass">
                <span class="stat-label">Active Assets</span>
                <span class="stat-value" id="stat-active-assets">-</span>
            </div>
            <div class="card stat-card glass">
                <span class="stat-label">Total Events</span>
                <span class="stat-value" id="stat-total-events">-</span>
            </div>
            <div class="card stat-card glass">
                <span class="stat-label">Unacked Alerts</span>
                <span class="stat-value" id="stat-unacked-alerts">-</span>
            </div>
        </div>
        <div class="charts-grid mt-4">
            <div class="card glass">
                <h2>Events (Last 24h)</h2>
                <canvas id="chart-events-24h"></canvas>
            </div>
            <div class="card glass">
                <h2>Events (Last 7 Days)</h2>
                <canvas id="chart-events-7d"></canvas>
            </div>
        </div>`;

    try {
        const statsRes = await fetch(`${API_BASE}/stats`);
        const stats    = await safeJson(statsRes);
        document.getElementById('stat-total-assets').textContent  = stats.total_assets;
        document.getElementById('stat-active-assets').textContent = stats.active_assets;
        document.getElementById('stat-total-events').textContent  = stats.total_events;
        document.getElementById('stat-unacked-alerts').textContent= stats.alerts_unacknowledged;
        renderTimeseriesChart('chart-events-24h', 'hour', '24h');
        renderTimeseriesChart('chart-events-7d',  'day',  '7d');
    } catch (e) { console.error('Dashboard load error', e); }
}

async function updateDashboardSilently(stats) {
    const el = document.getElementById('stat-total-assets');
    if (!el) return;
    el.textContent = stats.total_assets;
    document.getElementById('stat-active-assets').textContent  = stats.active_assets;
    document.getElementById('stat-total-events').textContent   = stats.total_events;
    document.getElementById('stat-unacked-alerts').textContent = stats.alerts_unacknowledged;
}

async function renderTimeseriesChart(canvasId, interval, range) {
    try {
        const res    = await fetch(`${API_BASE}/stats/timeseries?interval=${interval}&range=${range}&group_by=event_type`);
        const data   = await safeJson(res);
        const ctx    = document.getElementById(canvasId).getContext('2d');
        const labels = data.series.map(s => s.bucket);
        const types  = new Set();
        data.series.forEach(s => Object.keys(s).forEach(k => { if (k !== 'bucket') types.add(k); }));
        const colors  = ['#3b82f6','#10b981','#f59e0b','#ef4444','#8b5cf6','#ec4899'];
        const datasets = Array.from(types).map((type, i) => ({
            label: type,
            data: data.series.map(s => s[type] || 0),
            borderColor: colors[i % colors.length],
            backgroundColor: colors[i % colors.length] + '28',
            tension: 0.3, fill: true
        }));
        const chart = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets },
            options: {
                responsive: true,
                interaction: { mode: 'index', intersect: false },
                plugins: { legend: { labels: { color: '#e2e8f0' } } },
                scales: {
                    x: { type: 'time', time: { unit: interval }, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { stacked: true, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                }
            }
        });
        currentCharts.push(chart);
    } catch (e) { console.error('Chart error', canvasId, e); }
}

// ─────────────────────────────────────────────────────────────────────────────
// ASSETS (paginated)
// ─────────────────────────────────────────────────────────────────────────────
function renderAssets() {
    pagination.assets.page = 1;
    pageContainer.innerHTML = `
        <div class="filters">
            <input type="text" class="form-control" id="search-asset" placeholder="Search MAC, IP, Hostname, Vendor..." style="max-width:320px;" oninput="onAssetSearch()">
            <select class="form-control" id="filter-active" style="max-width:150px;" onchange="onAssetFilter()">
                <option value="all">All Status</option>
                <option value="active">Active Only</option>
            </select>
        </div>
        <div class="card glass table-container">
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Vendor</th>
                        <th>OS Guess</th>
                        <th>Status</th>
                        <th>Last Seen</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="assets-tbody">
                    <tr><td colspan="8" class="text-center">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <div id="assets-pagination"></div>`;
    loadAssetsList();
}

let assetSearchTimeout = null;
function onAssetSearch() {
    clearTimeout(assetSearchTimeout);
    assetSearchTimeout = setTimeout(() => {
        pagination.assets.page = 1;
        loadAssetsList();
    }, 300);
}
function onAssetFilter() { pagination.assets.page = 1; loadAssetsList(); }
function goAssetsPage(p)  { pagination.assets.page = p; loadAssetsList(); }

async function loadAssetsList() {
    const tbody      = document.getElementById('assets-tbody');
    if (!tbody) return;
    const activeOnly = document.getElementById('filter-active')?.value === 'active';
    const search     = document.getElementById('search-asset')?.value.toLowerCase() || '';
    const ps         = pagination.assets;

    try {
        const url = `${API_BASE}/assets?active=${activeOnly}&page=${ps.page}&page_size=${ps.page_size}`;
        const res = await fetch(url);
        const pr  = await safeJson(res);

        // Update pagination state
        ps.total       = pr.total;
        ps.total_pages = pr.total_pages;

        // Client-side search filter
        const filtered = (pr.data || []).filter(a => {
            if (!search) return true;
            return (a.mac      && a.mac.toLowerCase().includes(search))   ||
                   (a.ip       && a.ip.toLowerCase().includes(search))    ||
                   (a.hostname && a.hostname.toLowerCase().includes(search)) ||
                   (a.vendor   && a.vendor.toLowerCase().includes(search));
        });

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-center">No assets found</td></tr>';
        } else {
            tbody.innerHTML = filtered.map(a => `
                <tr>
                    <td style="font-family:monospace;">${a.mac}</td>
                    <td>${a.ip || '—'}</td>
                    <td>${a.hostname || '—'}</td>
                    <td>${a.vendor || '—'}</td>
                    <td>${a.os_guess || '—'} ${a.os_confidence > 0 ? `<span class="confidence">(${(a.os_confidence*100).toFixed(0)}%)</span>` : ''}</td>
                    <td>${a.is_active ? '<span class="tag success">Active</span>' : '<span class="tag">Inactive</span>'}</td>
                    <td>${fmtRelative(a.last_seen)}</td>
                    <td>
                        <button class="btn btn-icon btn-primary" title="Timeline" onclick="showTimeline('${a.mac}')">
                            <i class="fa-solid fa-list-ul"></i>
                        </button>
                        <button class="btn btn-icon btn-warning" title="Add to Watchlist" onclick="quickAddToWatchlist('${a.mac}','${a.ip || ''}','${(a.hostname||'').replace(/'/g, '')}')">
                            <i class="fa-solid fa-shield-halved"></i>
                        </button>
                    </td>
                </tr>`).join('');
        }

        renderPagination('assets-pagination', ps, 'goAssetsPage');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-danger">Error: ${e.message}</td></tr>`;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EVENTS (paginated)
// ─────────────────────────────────────────────────────────────────────────────
function renderEvents() {
    pagination.events.page = 1;
    pageContainer.innerHTML = `
        <div class="filters">
            <select class="form-control" id="filter-event-type" style="max-width:180px;" onchange="onEventsFilter()">
                <option value="">All Types</option>
                <option value="new_asset">new_asset</option>
                <option value="ip_change">ip_change</option>
                <option value="arp_announce">arp_announce</option>
                <option value="arp_probe">arp_probe</option>
                <option value="dhcp_discover">dhcp_discover</option>
                <option value="dhcp_request">dhcp_request</option>
                <option value="dhcp_ack">dhcp_ack</option>
                <option value="mdns_announce">mdns_announce</option>
                <option value="ssdp_notify">ssdp_notify</option>
            </select>
            <select class="form-control" id="filter-protocol" style="max-width:140px;" onchange="onEventsFilter()">
                <option value="">All Protocols</option>
                <option value="arp">ARP</option>
                <option value="dhcp">DHCP</option>
                <option value="mdns">mDNS</option>
                <option value="ssdp">SSDP</option>
                <option value="dns">DNS</option>
            </select>
        </div>
        <div class="card glass table-container">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>MAC</th>
                        <th>Event Type</th>
                        <th>Protocol</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody id="events-tbody">
                    <tr><td colspan="5" class="text-center">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <div id="events-pagination"></div>`;
    loadEventsList();
}

function onEventsFilter() { pagination.events.page = 1; loadEventsList(); }
function goEventsPage(p)  { pagination.events.page = p; loadEventsList(); }

async function loadEventsList() {
    const tbody = document.getElementById('events-tbody');
    if (!tbody) return;
    const pe    = pagination.events;
    const type  = document.getElementById('filter-event-type')?.value || '';
    const proto = document.getElementById('filter-protocol')?.value || '';

    try {
        const url = `${API_BASE}/events?type=${type}&protocol=${proto}&page=${pe.page}&page_size=${pe.page_size}`;
        const res = await fetch(url);
        const pr  = await safeJson(res);

        pe.total       = pr.total;
        pe.total_pages = pr.total_pages;

        if (!pr.data || pr.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No events found</td></tr>';
        } else {
            const protocolColors = {
                arp: '#f59e0b', dhcp: '#3b82f6', mdns: '#10b981',
                ssdp: '#8b5cf6', dns: '#ec4899'
            };
            tbody.innerHTML = pr.data.map(e => {
                const detail = e.old_value && e.new_value ?
                    `${e.old_value} → ${e.new_value}` : (e.new_value || e.old_value || '');
                const pColor = protocolColors[e.protocol] || '#94a3b8';
                return `<tr>
                    <td style="white-space:nowrap;">${fmtDate(e.ts)}</td>
                    <td style="font-family:monospace;font-size:0.8em;">${e.mac}</td>
                    <td><span class="tag">${e.event_type}</span></td>
                    <td><span class="tag" style="background:${pColor}22;color:${pColor};border:1px solid ${pColor}44;">${e.protocol}</span></td>
                    <td class="text-secondary" style="font-size:0.85em;">${detail}</td>
                </tr>`;
            }).join('');
        }
        renderPagination('events-pagination', pe, 'goEventsPage');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-danger">Error: ${e.message}</td></tr>`;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ALERTS (paginated)
// ─────────────────────────────────────────────────────────────────────────────
function renderAlerts() {
    pagination.alerts.page = 1;
    pageContainer.innerHTML = `
        <div class="filters">
            <select class="form-control" id="filter-ack" style="max-width:180px;" onchange="onAlertsFilter()">
                <option value="false">Unacknowledged</option>
                <option value="all">All Alerts</option>
            </select>
            <select class="form-control" id="filter-severity" style="max-width:140px;" onchange="onAlertsFilter()">
                <option value="">All Severity</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
            </select>
        </div>
        <div class="card glass table-container">
            <table>
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>Message</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="alerts-tbody">
                    <tr><td colspan="5" class="text-center">Loading...</td></tr>
                </tbody>
            </table>
        </div>
        <div id="alerts-pagination"></div>`;
    loadAlertsList();
}

function onAlertsFilter() { pagination.alerts.page = 1; loadAlertsList(); }
function goAlertsPage(p)  { pagination.alerts.page = p; loadAlertsList(); }

async function loadAlertsList() {
    const tbody = document.getElementById('alerts-tbody');
    if (!tbody) return;
    const pa  = pagination.alerts;
    const ack = document.getElementById('filter-ack')?.value === 'false';
    const sev = document.getElementById('filter-severity')?.value || '';

    try {
        const url = `${API_BASE}/alerts?ack=${ack ? 'false' : 'all'}&severity=${sev}&page=${pa.page}&page_size=${pa.page_size}`;
        const res = await fetch(url);
        const pr  = await safeJson(res);

        pa.total       = pr.total;
        pa.total_pages = pr.total_pages;

        if (!pr.data || pr.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">No alerts found</td></tr>';
        } else {
            tbody.innerHTML = pr.data.map(a => {
                const sevClass = a.severity === 'high' ? 'danger' :
                                 a.severity === 'medium' ? 'warning' : 'info';
                return `<tr style="${a.acknowledged ? 'opacity:0.5;' : ''}">
                    <td>${fmtDate(a.ts)}</td>
                    <td><span class="tag ${sevClass}">${a.severity.toUpperCase()}</span></td>
                    <td><span class="tag">${a.rule_type}</span></td>
                    <td>${a.message}</td>
                    <td>
                        ${!a.acknowledged
                            ? `<button class="btn btn-icon btn-primary" title="Acknowledge" onclick="ackAlert(${a.id})">
                                 <i class="fa-solid fa-check"></i>
                               </button>`
                            : '<span class="text-secondary" style="font-size:0.8em;">Acked</span>'}
                    </td>
                </tr>`;
            }).join('');
        }
        renderPagination('alerts-pagination', pa, 'goAlertsPage');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-danger">Error: ${e.message}</td></tr>`;
    }
}

async function ackAlert(id) {
    try {
        await fetch(`${API_BASE}/alerts/${id}/ack`, { method: 'POST' });
        loadAlertsList();
        fetchAlertCount();
        showToast('Alert Acknowledged', 'Alert marked as resolved', 'success');
    } catch (e) {
        showToast('Error', 'Failed to acknowledge alert', 'danger');
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WATCHLIST
// ─────────────────────────────────────────────────────────────────────────────
async function renderWatchlist() {
    pageContainer.innerHTML = `
        <div class="card glass mb-4" style="max-width:600px;">
            <h2>Add to Watchlist</h2>
            <form id="watchlist-form" class="mt-4">
                <div class="form-group">
                    <label>MAC Address</label>
                    <input type="text" id="wl-mac" class="form-control" placeholder="AA:BB:CC:DD:EE:FF">
                </div>
                <div class="form-group">
                    <label>IP Address</label>
                    <input type="text" id="wl-ip" class="form-control" placeholder="192.168.1.1">
                </div>
                <div class="form-group">
                    <label>Label <span style="color:var(--danger)">*</span></label>
                    <input type="text" id="wl-label" class="form-control" placeholder="Suspicious Device" required>
                </div>
                <div class="form-group">
                    <label>Note</label>
                    <input type="text" id="wl-note" class="form-control" placeholder="Context about this device...">
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="fa-solid fa-plus"></i> Add Entry
                </button>
            </form>
        </div>
        <div class="card glass table-container">
            <h2>Current Watchlist</h2>
            <table class="mt-4">
                <thead>
                    <tr><th>MAC</th><th>IP</th><th>Label</th><th>Note</th><th>Action</th></tr>
                </thead>
                <tbody id="watchlist-tbody">
                    <tr><td colspan="5" class="text-center">Loading...</td></tr>
                </tbody>
            </table>
        </div>`;

    document.getElementById('watchlist-form').addEventListener('submit', async e => {
        e.preventDefault();
        const mac   = document.getElementById('wl-mac').value;
        const ip    = document.getElementById('wl-ip').value;
        const label = document.getElementById('wl-label').value;
        const note  = document.getElementById('wl-note').value;
        try {
            const res = await fetch(`${API_BASE}/watchlist`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mac, ip, label, note })
            });
            if (res.ok) {
                document.getElementById('watchlist-form').reset();
                loadWatchlist();
                showToast('Added', 'Device added to watchlist', 'success');
            } else {
                const err = await safeJson(res);
                showToast('Error', err.error, 'danger');
            }
        } catch (e) {
            showToast('Error', 'Failed to add to watchlist', 'danger');
        }
    });

    loadWatchlist();
}

async function loadWatchlist() {
    const tbody = document.getElementById('watchlist-tbody');
    try {
        const res  = await fetch(`${API_BASE}/watchlist`);
        const list = await safeJson(res);
        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center">Watchlist is empty</td></tr>';
            return;
        }
        tbody.innerHTML = list.map(e => `
            <tr>
                <td style="font-family:monospace;">${e.mac || '—'}</td>
                <td>${e.ip || '—'}</td>
                <td><strong>${e.label}</strong></td>
                <td>${e.note || '—'}</td>
                <td>
                    <button class="btn btn-icon btn-danger" title="Delete" onclick="deleteWatchlist(${e.id})">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            </tr>`).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-danger">Error loading watchlist</td></tr>`;
    }
}

async function deleteWatchlist(id) {
    if (!confirm('Remove this entry from watchlist?')) return;
    try {
        await fetch(`${API_BASE}/watchlist/${id}`, { method: 'DELETE' });
        loadWatchlist();
        showToast('Removed', 'Entry removed from watchlist', 'success');
    } catch (e) {
        showToast('Error', 'Failed to delete', 'danger');
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Quick-add asset to Watchlist (from Assets table row button)
// ─────────────────────────────────────────────────────────────────────────────
async function quickAddToWatchlist(mac, ip, hostname) {
    const label = prompt(
        `Add to Watchlist\nMAC: ${mac}\nIP: ${ip || '—'}\nHostname: ${hostname || '—'}\n\nEnter a label (e.g. "Suspicious Device"):`,
        hostname || mac
    );
    if (label === null) return; // user cancelled
    if (!label.trim()) { showToast('Error', 'Label is required', 'danger'); return; }

    try {
        const res = await fetch(`${API_BASE}/watchlist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac, ip, label: label.trim(), note: `Auto-added from Assets table` })
        });
        if (res.ok) {
            showToast('Added to Watchlist', `${mac} added with label "${label.trim()}"`, 'success');
        } else {
            const err = await safeJson(res).catch(() => ({ error: 'Unknown error' }));
            showToast('Error', err.error || 'Failed to add', 'danger');
        }
    } catch (e) {
        showToast('Error', 'Network error: ' + e.message, 'danger');
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeline Modal
// ─────────────────────────────────────────────────────────────────────────────
async function showTimeline(mac) {
    const modal   = document.getElementById('timeline-modal');
    const content = document.getElementById('timeline-content');
    document.getElementById('timeline-title').textContent = `Timeline: ${mac}`;
    content.innerHTML = '<div class="text-center">Loading events...</div>';
    modal.classList.add('active');

    try {
        const res    = await fetch(`${API_BASE}/assets/${mac}/events?limit=100`);
        const events = await safeJson(res);
        if (events.length === 0) {
            content.innerHTML = '<div class="text-center text-secondary">No events found.</div>';
            return;
        }
        content.innerHTML = `
            <div class="timeline">
                ${events.map(e => `
                    <div class="timeline-item">
                        <div class="timeline-time">${fmtDate(e.ts, 'DD/MM/YYYY HH:mm:ss')}</div>
                        <div class="timeline-title">${e.event_type} <span class="tag" style="margin-left:8px">${e.protocol}</span></div>
                        <div class="timeline-desc">
                            ${e.old_value && e.new_value ? `${e.old_value} &rarr; ${e.new_value}` : (e.new_value || e.old_value || '')}
                        </div>
                    </div>`).join('')}
            </div>`;
    } catch (e) {
        content.innerHTML = `<div class="text-danger">Failed to load events: ${e.message}</div>`;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP Upload Modal
// ─────────────────────────────────────────────────────────────────────────────
let pcapUploadFile = null;

function openPcapUploadModal() {
    const modal = document.getElementById('pcap-upload-modal');
    // Reset state
    pcapUploadFile = null;
    document.getElementById('pcap-file-input').value = '';
    document.getElementById('upload-file-info').style.display = 'none';
    document.getElementById('upload-progress-container').style.display = 'none';
    document.getElementById('upload-result').style.display = 'none';
    document.getElementById('upload-submit-btn').disabled = true;
    document.getElementById('upload-drop-zone').classList.remove('drag-over');

    modal.classList.add('active');
    updatePcapStatus();
}

function setupPcapUploadDrop() {
    const fileInput = document.getElementById('pcap-file-input');
    const dropZone  = document.getElementById('upload-drop-zone');
    if (!fileInput || !dropZone) return;

    fileInput.addEventListener('change', e => {
        if (e.target.files[0]) setPcapFile(e.target.files[0]);
    });

    dropZone.addEventListener('dragover', e => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
    dropZone.addEventListener('drop', e => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file && (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng'))) {
            setPcapFile(file);
        } else {
            showToast('Invalid file', 'Please drop a .pcap or .pcapng file', 'danger');
        }
    });
}

function setPcapFile(file) {
    pcapUploadFile = file;
    const info = document.getElementById('upload-file-info');
    info.style.display = 'flex';
    document.getElementById('upload-file-name').textContent = file.name;
    document.getElementById('upload-file-size').textContent = formatFileSize(file.size);
    document.getElementById('upload-submit-btn').disabled = false;
}

function formatFileSize(bytes) {
    if (bytes < 1024)        return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
}

async function submitPcapUpload() {
    if (!pcapUploadFile) return;

    const progressContainer = document.getElementById('upload-progress-container');
    const progressFill      = document.getElementById('upload-progress-fill');
    const progressText      = document.getElementById('upload-progress-text');
    const resultDiv         = document.getElementById('upload-result');
    const submitBtn         = document.getElementById('upload-submit-btn');

    submitBtn.disabled = true;
    progressContainer.style.display = 'block';
    resultDiv.style.display = 'none';
    progressFill.style.width = '0%';
    progressText.textContent = 'Uploading...';

    try {
        // Use XMLHttpRequest for upload progress
        await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', `${API_BASE}/pcap/upload?filename=${encodeURIComponent(pcapUploadFile.name)}`);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');

            xhr.upload.onprogress = e => {
                if (e.lengthComputable) {
                    const pct = Math.round(e.loaded / e.total * 100);
                    progressFill.style.width = pct + '%';
                    progressText.textContent = `Uploading... ${pct}%`;
                }
            };

            xhr.onload = () => {
                if (xhr.status === 200) {
                    progressFill.style.width = '100%';
                    progressText.textContent = 'Upload complete!';
                    resolve(JSON.parse(xhr.responseText));
                } else {
                    reject(new Error(`HTTP ${xhr.status}`));
                }
            };
            xhr.onerror = () => reject(new Error('Network error'));
            xhr.send(pcapUploadFile);
        });

        resultDiv.style.display = 'block';
        resultDiv.innerHTML = `
            <div class="upload-success">
                <i class="fa-solid fa-circle-check"></i>
                <div>
                    <strong>${pcapUploadFile.name}</strong> uploaded successfully.<br>
                    <span class="text-secondary">The stable loop is paused. Processing will begin shortly...</span>
                </div>
            </div>`;

        showToast('Upload Successful', `${pcapUploadFile.name} queued for processing`, 'success');
        updatePcapStatus();

        // Close modal after 2.5s
        setTimeout(() => {
            document.getElementById('pcap-upload-modal').classList.remove('active');
        }, 2500);

    } catch (e) {
        progressContainer.style.display = 'none';
        resultDiv.style.display = 'block';
        resultDiv.innerHTML = `
            <div class="upload-error">
                <i class="fa-solid fa-circle-xmark"></i>
                <span>Upload failed: ${e.message}</span>
            </div>`;
        submitBtn.disabled = false;
        showToast('Upload Failed', e.message, 'danger');
    }
}

