const API_BASE = '/api';
let currentCharts = [];

// DOM Elements
const pageContainer = document.getElementById('page-container');
const pageTitle = document.getElementById('page-title');
const navItems = document.querySelectorAll('.nav-item');
const alertBadge = document.getElementById('alert-badge');
const apiStatusDot = document.getElementById('api-status-dot');
const apiStatusText = document.getElementById('api-status-text');

// State
let currentPage = 'dashboard';

// Init
document.addEventListener('DOMContentLoaded', () => {
    setupNavigation();
    loadPage(currentPage);
    startHealthCheck();
    fetchAlertCount();
});

// Routing
function setupNavigation() {
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
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
    
    // Cleanup charts
    currentCharts.forEach(c => c.destroy());
    currentCharts = [];

    switch(page) {
        case 'dashboard': renderDashboard(); break;
        case 'assets': renderAssets(); break;
        case 'alerts': renderAlerts(); break;
        case 'watchlist': renderWatchlist(); break;
    }
}

function refreshCurrentPage() {
    loadPage(currentPage);
    fetchAlertCount();
}

// Health Check
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
        } else {
            throw new Error('Not OK');
        }
    } catch (e) {
        apiStatusDot.className = 'status-dot error';
        apiStatusText.textContent = 'Disconnected';
    }
}

async function fetchAlertCount() {
    try {
        const res = await fetch(`${API_BASE}/stats`);
        const stats = await res.json();
        if (stats.alerts_unacknowledged > 0) {
            alertBadge.textContent = stats.alerts_unacknowledged;
            alertBadge.style.display = 'inline-block';
        } else {
            alertBadge.style.display = 'none';
        }
    } catch (e) {
        console.error(e);
    }
}

// ── Views ────────────────────────────────────────────────────────────────────

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
        </div>
    `;

    try {
        const statsRes = await fetch(`${API_BASE}/stats`);
        const stats = await statsRes.json();
        
        document.getElementById('stat-total-assets').textContent = stats.total_assets;
        document.getElementById('stat-active-assets').textContent = stats.active_assets;
        document.getElementById('stat-total-events').textContent = stats.total_events;
        document.getElementById('stat-unacked-alerts').textContent = stats.alerts_unacknowledged;

        // Render charts
        renderTimeseriesChart('chart-events-24h', 'hour', '24h');
        renderTimeseriesChart('chart-events-7d', 'day', '7d');

    } catch (e) {
        console.error("Failed to load dashboard stats", e);
    }
}

async function renderTimeseriesChart(canvasId, interval, range) {
    try {
        const res = await fetch(`${API_BASE}/stats/timeseries?interval=${interval}&range=${range}&group_by=event_type`);
        const data = await res.json();
        
        const ctx = document.getElementById(canvasId).getContext('2d');
        const labels = data.series.map(s => s.bucket);
        
        // Find all unique event types
        const types = new Set();
        data.series.forEach(s => {
            Object.keys(s).forEach(k => { if (k !== 'bucket') types.add(k); });
        });

        // Colors
        const colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];
        
        const datasets = Array.from(types).map((type, i) => {
            return {
                label: type,
                data: data.series.map(s => s[type] || 0),
                borderColor: colors[i % colors.length],
                backgroundColor: colors[i % colors.length] + '40',
                tension: 0.3,
                fill: true
            };
        });

        const chart = new Chart(ctx, {
            type: 'line',
            data: { labels, datasets },
            options: {
                responsive: true,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { labels: { color: '#e2e8f0' } }
                },
                scales: {
                    x: { type: 'time', time: { unit: interval }, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
                    y: { stacked: true, ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
                }
            }
        });
        currentCharts.push(chart);
    } catch (e) {
        console.error("Failed to render chart", canvasId, e);
    }
}

async function renderAssets() {
    pageContainer.innerHTML = `
        <div class="filters">
            <input type="text" class="form-control" id="search-asset" placeholder="Search MAC, IP, Hostname..." style="max-width: 300px;">
            <select class="form-control" id="filter-active" style="max-width: 150px;">
                <option value="all">All Status</option>
                <option value="active">Active Only</option>
            </select>
            <button class="btn btn-primary" onclick="loadAssetsList()">Apply</button>
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
    `;
    loadAssetsList();
}

async function loadAssetsList() {
    const tbody = document.getElementById('assets-tbody');
    const activeFilter = document.getElementById('filter-active').value;
    const search = document.getElementById('search-asset').value.toLowerCase();
    
    try {
        const url = activeFilter === 'active' ? `${API_BASE}/assets?active=true` : `${API_BASE}/assets`;
        const res = await fetch(url);
        const assets = await res.json();
        
        const filtered = assets.filter(a => {
            if (!search) return true;
            return (a.mac && a.mac.toLowerCase().includes(search)) ||
                   (a.ip && a.ip.toLowerCase().includes(search)) ||
                   (a.hostname && a.hostname.toLowerCase().includes(search)) ||
                   (a.vendor && a.vendor.toLowerCase().includes(search));
        });

        if (filtered.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center;">No assets found</td></tr>';
            return;
        }

        tbody.innerHTML = filtered.map(a => `
            <tr>
                <td style="font-family: monospace;">${a.mac}</td>
                <td>${a.ip || '-'}</td>
                <td>${a.hostname || '-'}</td>
                <td>${a.vendor || '-'}</td>
                <td>${a.os_guess || '-'} ${a.os_confidence > 0 ? `<span style="opacity: 0.5; font-size: 0.75em;">(${(a.os_confidence*100).toFixed(0)}%)</span>` : ''}</td>
                <td>${a.is_active ? '<span class="tag success">Active</span>' : '<span class="tag">Inactive</span>'}</td>
                <td>${moment(a.last_seen).fromNow()}</td>
                <td>
                    <button class="btn btn-icon btn-primary" title="Timeline" onclick="showTimeline('${a.mac}')">
                        <i class="fa-solid fa-list-ul"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="8" style="color: var(--danger)">Error loading assets: ${e.message}</td></tr>`;
    }
}

async function renderAlerts() {
    pageContainer.innerHTML = `
        <div class="filters">
            <select class="form-control" id="filter-ack" style="max-width: 150px;">
                <option value="false">Unacknowledged</option>
                <option value="all">All Alerts</option>
            </select>
            <button class="btn btn-primary" onclick="loadAlertsList()">Apply</button>
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
    `;
    loadAlertsList();
}

async function loadAlertsList() {
    const tbody = document.getElementById('alerts-tbody');
    const ackFilter = document.getElementById('filter-ack').value;
    
    try {
        const url = ackFilter === 'false' ? `${API_BASE}/alerts?ack=false` : `${API_BASE}/alerts`;
        const res = await fetch(url);
        const alerts = await res.json();
        
        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No alerts found</td></tr>';
            return;
        }

        tbody.innerHTML = alerts.map(a => {
            let sevClass = 'info';
            if (a.severity === 'high') sevClass = 'danger';
            else if (a.severity === 'medium') sevClass = 'warning';
            
            return `
            <tr style="${a.acknowledged ? 'opacity: 0.5;' : ''}">
                <td>${moment(a.ts).format('YYYY-MM-DD HH:mm:ss')}</td>
                <td><span class="tag ${sevClass}">${a.severity.toUpperCase()}</span></td>
                <td>${a.rule_type}</td>
                <td>${a.message}</td>
                <td>
                    ${!a.acknowledged ? `<button class="btn btn-icon btn-primary" title="Acknowledge" onclick="ackAlert(${a.id})"><i class="fa-solid fa-check"></i></button>` : 'Acked'}
                </td>
            </tr>
        `}).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" style="color: var(--danger)">Error loading alerts: ${e.message}</td></tr>`;
    }
}

async function ackAlert(id) {
    try {
        await fetch(`${API_BASE}/alerts/${id}/ack`, { method: 'POST' });
        loadAlertsList();
        fetchAlertCount();
    } catch (e) {
        alert('Failed to ack alert');
    }
}

async function renderWatchlist() {
    pageContainer.innerHTML = `
        <div class="card glass mb-4" style="max-width: 600px;">
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
                    <label>Label (Required)</label>
                    <input type="text" id="wl-label" class="form-control" placeholder="Suspicious Device" required>
                </div>
                <div class="form-group">
                    <label>Note</label>
                    <input type="text" id="wl-note" class="form-control">
                </div>
                <button type="submit" class="btn btn-primary">Add Entry</button>
            </form>
        </div>

        <div class="card glass table-container">
            <h2>Current Watchlist</h2>
            <table class="mt-4">
                <thead>
                    <tr>
                        <th>MAC</th>
                        <th>IP</th>
                        <th>Label</th>
                        <th>Note</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="watchlist-tbody">
                    <tr><td colspan="5" class="text-center">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    `;

    document.getElementById('watchlist-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const mac = document.getElementById('wl-mac').value;
        const ip = document.getElementById('wl-ip').value;
        const label = document.getElementById('wl-label').value;
        const note = document.getElementById('wl-note').value;
        
        try {
            const res = await fetch(`${API_BASE}/watchlist`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mac, ip, label, note })
            });
            if (res.ok) {
                document.getElementById('watchlist-form').reset();
                loadWatchlist();
            } else {
                const err = await res.json();
                alert('Error: ' + err.error);
            }
        } catch (e) {
            alert('Failed to add to watchlist');
        }
    });

    loadWatchlist();
}

async function loadWatchlist() {
    const tbody = document.getElementById('watchlist-tbody');
    try {
        const res = await fetch(`${API_BASE}/watchlist`);
        const list = await res.json();
        
        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">Watchlist is empty</td></tr>';
            return;
        }

        tbody.innerHTML = list.map(e => `
            <tr>
                <td style="font-family: monospace;">${e.mac || '-'}</td>
                <td>${e.ip || '-'}</td>
                <td><strong>${e.label}</strong></td>
                <td>${e.note || '-'}</td>
                <td>
                    <button class="btn btn-icon btn-danger" title="Delete" onclick="deleteWatchlist(${e.id})">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" style="color: var(--danger)">Error loading watchlist</td></tr>`;
    }
}

async function deleteWatchlist(id) {
    if (!confirm('Are you sure?')) return;
    try {
        await fetch(`${API_BASE}/watchlist/${id}`, { method: 'DELETE' });
        loadWatchlist();
    } catch (e) {
        alert('Failed to delete');
    }
}

// ── Modals ───────────────────────────────────────────────────────────────────

async function showTimeline(mac) {
    const modal = document.getElementById('timeline-modal');
    const content = document.getElementById('timeline-content');
    const title = document.getElementById('timeline-title');
    
    title.textContent = `Timeline: ${mac}`;
    content.innerHTML = '<div class="text-center">Loading events...</div>';
    modal.classList.add('active');

    try {
        const res = await fetch(`${API_BASE}/assets/${mac}/events?limit=50`);
        const events = await res.json();
        
        if (events.length === 0) {
            content.innerHTML = '<div class="text-center text-secondary">No events found.</div>';
            return;
        }

        content.innerHTML = `
            <div class="timeline">
                ${events.map(e => `
                    <div class="timeline-item">
                        <div class="timeline-time">${moment(e.ts).format('YYYY-MM-DD HH:mm:ss')}</div>
                        <div class="timeline-title">${e.event_type} <span class="tag" style="margin-left: 8px">${e.protocol}</span></div>
                        <div class="timeline-desc">
                            ${e.old_value && e.new_value ? `${e.old_value} &rarr; ${e.new_value}` : (e.new_value || e.old_value || '')}
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (e) {
        content.innerHTML = `<div class="text-danger">Failed to load events: ${e.message}</div>`;
    }
}

document.querySelectorAll('.close-modal').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
    });
});
