// DOM Elements
const timeDisplay = document.getElementById('time-display');
const statTotal = document.getElementById('stat-total');
const statActive = document.getElementById('stat-active');
const statSystem = document.getElementById('stat-system');
const tableBody = document.getElementById('table-body');
const searchInput = document.getElementById('search-input');

let allAssets = [];
let searchTerm = "";

// Update live clock
function updateClock() {
    const now = new Date();
    timeDisplay.textContent = now.toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// Fetch stats from /api/stats
async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error('API Error');
        const data = await response.json();
        
        statTotal.textContent = data.total_assets;
        statActive.textContent = data.active_assets;
        
        statSystem.textContent = 'OK';
        statSystem.className = 'stat-value status-ok';
    } catch (error) {
        console.error('Failed to fetch stats:', error);
        statSystem.textContent = 'ERR';
        statSystem.className = 'stat-value status-err';
    }
}

// Format ISO date
function formatRelativeTime(isoString) {
    if (!isoString) return 'Never';
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = Math.abs(now - date);
    
    if (diffMs < 60000) {
        const s = Math.floor(diffMs / 1000);
        if (s > 0) return `${s}s ago`;
        return `${diffMs}ms ago`;
    }
    
    const diffSecs = Math.floor(diffMs / 1000);
    if (diffSecs < 3600) return `${Math.floor(diffSecs/60)}m ago`;
    if (diffSecs < 86400) return `${Math.floor(diffSecs/3600)}h ago`;
    return `${Math.floor(diffSecs/86400)}d ago`;
}

// Render Table
function renderTable() {
    tableBody.innerHTML = '';
    
    const filtered = allAssets.filter(a => {
        const term = searchTerm.toLowerCase();
        return (a.mac && a.mac.toLowerCase().includes(term)) ||
               (a.ip && a.ip.toLowerCase().includes(term)) ||
               (a.hostname && a.hostname.toLowerCase().includes(term)) ||
               (a.vendor && a.vendor.toLowerCase().includes(term)) ||
               (a.os_guess && a.os_guess.toLowerCase().includes(term));
    });

    if (filtered.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="7" class="empty-state">No devices found.</td></tr>`;
        return;
    }

    filtered.forEach(asset => {
        const tr = document.createElement('tr');
        
        const statusClass = asset.is_active ? 'online' : 'offline';
        const statusText = asset.is_active ? 'Active' : 'Offline';
        
        // Tạo chuỗi OS với style tuỳ thuộc
        let osBadge = '-';
        if (asset.os_guess) {
            let colorClass = 'style="color: var(--accent-blue); border-color: rgba(56,189,248,0.2);"';
            if (asset.os_guess.toLowerCase().includes('windows')) {
                colorClass = 'style="color: #60a5fa; border-color: rgba(96,165,250,0.2);"'; // Blue
            } else if (asset.os_guess.toLowerCase().includes('linux') || asset.os_guess.toLowerCase().includes('android')) {
                colorClass = 'style="color: #10b981; border-color: rgba(16,185,129,0.2);"'; // Green
            } else if (asset.os_guess.toLowerCase().includes('apple') || asset.os_guess.toLowerCase().includes('mac') || asset.os_guess.toLowerCase().includes('ios')) {
                colorClass = 'style="color: #f472b6; border-color: rgba(244,114,182,0.2);"'; // Pink
            }
            osBadge = `<span class="os-badge" ${colorClass}>${asset.os_guess}</span>`;
        }

        tr.innerHTML = `
            <td>
                <span class="status-dot ${statusClass}"></span>
                ${statusText}
            </td>
            <td class="mac-text">${asset.mac}</td>
            <td class="ip-text">${asset.ip || '-'}</td>
            <td>${asset.hostname || '-'}</td>
            <td>${asset.vendor || '-'}</td>
            <td>${osBadge}</td>
            <td style="color: var(--text-secondary)">${formatRelativeTime(asset.last_seen)}</td>
        `;
        tableBody.appendChild(tr);
    });
}

// Fetch assets from /api/assets
async function fetchAssets() {
    try {
        const response = await fetch('/api/assets');
        if (!response.ok) throw new Error('API Error');
        const data = await response.json();
        
        // Sắp xếp: Active lên trên, mới cập nhật lên trên
        allAssets = data.sort((a, b) => {
            if (a.is_active !== b.is_active) return b.is_active ? 1 : -1;
            return new Date(b.last_seen) - new Date(a.last_seen);
        });
        
        renderTable();
    } catch (error) {
        console.error('Failed to fetch assets:', error);
    }
}

// Search input listener
searchInput.addEventListener('input', (e) => {
    searchTerm = e.target.value;
    renderTable();
});

// Initial load
fetchStats();
fetchAssets();

// Auto-refresh every 3 seconds
setInterval(() => {
    fetchStats();
    fetchAssets();
}, 3000);
