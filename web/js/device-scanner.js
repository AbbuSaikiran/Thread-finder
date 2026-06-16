/**
 * AppGuard Device Scanner — Frontend
 * 
 * Communicates with the Python backend server (server.py) to
 * scan real Android devices via ADB and display results.
 */

(function() {
    'use strict';

    const { analyzeApp, getRiskLevel, RiskLevel, getInstallSourceLabel, PERM_LOOKUP } = window.RiskEngine;

    // API base — same origin when served by server.py,
    // or localhost:5000 when served separately
    const API_BASE = window.location.port === '5000' ? '' : 'http://localhost:5000';

    let deviceReports = [];
    let deviceSortAsc = false;

    document.addEventListener('DOMContentLoaded', () => {
        initDeviceScanner();
    });

    function initDeviceScanner() {
        const connectBtn = document.getElementById('deviceConnectBtn');
        const startScanBtn = document.getElementById('startScanBtn');
        const scanThirdPartyBtn = document.getElementById('scanThirdPartyBtn');
        const scanSingleBtn = document.getElementById('scanSingleBtn');
        const sortBtn = document.getElementById('deviceSortBtn');
        const exportJsonBtn = document.getElementById('deviceExportJsonBtn');
        const exportHtmlBtn = document.getElementById('deviceExportHtmlBtn');

        // Check server status on tab switch
        document.getElementById('tabDevice')?.addEventListener('click', () => {
            checkServerStatus();
        });

        connectBtn?.addEventListener('click', () => checkServerStatus());
        startScanBtn?.addEventListener('click', () => scanDevice(false));
        scanThirdPartyBtn?.addEventListener('click', () => scanDevice(true));
        scanSingleBtn?.addEventListener('click', () => {
            const pkg = document.getElementById('singlePackageInput')?.value?.trim();
            if (pkg) scanSinglePackage(pkg);
        });

        sortBtn?.addEventListener('click', () => {
            deviceSortAsc = !deviceSortAsc;
            const sorted = [...deviceReports].sort((a, b) =>
                deviceSortAsc ? a.finalRiskScore - b.finalRiskScore : b.finalRiskScore - a.finalRiskScore
            );
            renderDeviceTable(sorted);
            sortBtn.textContent = deviceSortAsc ? 'Sort by Risk ↑' : 'Sort by Risk ↓';
        });

        exportJsonBtn?.addEventListener('click', () => exportDeviceJson());
        exportHtmlBtn?.addEventListener('click', () => exportDeviceHtml());

        // Auto-check on page load (delayed)
        setTimeout(() => checkServerStatus(), 1000);
    }

    // ── Server Status Check ──
    async function checkServerStatus() {
        const statusIcon = document.getElementById('deviceStatusIcon');
        const statusTitle = document.getElementById('deviceStatusTitle');
        const statusMsg = document.getElementById('deviceStatusMsg');
        const connectBtn = document.getElementById('deviceConnectBtn');
        const setupInstr = document.getElementById('setupInstructions');
        const deviceInfo = document.getElementById('deviceInfoPanel');

        statusIcon.textContent = '⏳';
        statusTitle.textContent = 'Connecting...';
        statusMsg.textContent = 'Checking for AppGuard backend server';
        connectBtn.disabled = true;

        try {
            // Check if server is running
            const statusResp = await fetchApi('/api/status');

            if (!statusResp.adbAvailable) {
                setStatus('⚠️', 'ADB Not Found',
                    'Server is running but ADB is not installed. Install Android Platform Tools.',
                    'warning');
                setupInstr?.classList.remove('hidden');
                deviceInfo?.classList.add('hidden');
                connectBtn.disabled = false;
                connectBtn.innerHTML = '<span class="btn-icon">🔄</span> Retry';
                return;
            }

            // Check for connected devices
            const devicesResp = await fetchApi('/api/devices');
            const devices = devicesResp.devices || [];
            const readyDevices = devices.filter(d => d.status === 'device');

            if (readyDevices.length === 0) {
                setStatus('📵', 'No Device Connected',
                    devices.length > 0
                        ? 'Device found but not authorized. Accept the USB debugging prompt on your phone.'
                        : 'Connect your Android device via USB and enable USB Debugging.',
                    'warning');
                setupInstr?.classList.remove('hidden');
                deviceInfo?.classList.add('hidden');
                connectBtn.disabled = false;
                connectBtn.innerHTML = '<span class="btn-icon">🔄</span> Retry';
                return;
            }

            // Device connected! Get info
            const info = await fetchApi('/api/device-info');
            setStatus('📱', `${info.manufacturer || ''} ${info.model || 'Device'} Connected`,
                `Android ${info.android_version} | SDK ${info.sdk_version}`,
                'success');

            // Populate device info panel
            document.getElementById('devModel').textContent = info.model || '—';
            document.getElementById('devAndroid').textContent = info.android_version || '—';
            document.getElementById('devBrand').textContent = `${info.manufacturer || ''} ${info.brand || ''}`.trim() || '—';
            document.getElementById('devSdk').textContent = info.sdk_version || '—';

            setupInstr?.classList.add('hidden');
            deviceInfo?.classList.remove('hidden');
            connectBtn.disabled = false;
            connectBtn.innerHTML = '<span class="btn-icon">🔄</span> Refresh';

        } catch (err) {
            setStatus('🔴', 'Server Not Running',
                'Start the AppGuard server: python server.py',
                'error');
            setupInstr?.classList.remove('hidden');
            deviceInfo?.classList.add('hidden');
            connectBtn.disabled = false;
            connectBtn.innerHTML = '<span class="btn-icon">🔄</span> Retry';
        }
    }

    function setStatus(icon, title, msg, type) {
        document.getElementById('deviceStatusIcon').textContent = icon;
        document.getElementById('deviceStatusTitle').textContent = title;
        document.getElementById('deviceStatusMsg').textContent = msg;

        const card = document.getElementById('deviceStatusCard');
        card.className = 'device-status-card';
        if (type) card.classList.add(`status-${type}`);
    }

    // ── Device Scanning ──
    async function scanDevice(thirdPartyOnly = true) {
        const progress = document.getElementById('scanProgress');
        const progressBar = document.getElementById('scanProgressBar');
        const progressText = document.getElementById('scanProgressText');
        const results = document.getElementById('deviceResults');

        progress?.classList.remove('hidden');
        results?.classList.add('hidden');

        progressBar.style.width = '10%';
        progressText.textContent = 'Fetching app list from device...';

        try {
            // Get packages first
            const pkgResp = await fetchApi(`/api/packages?thirdParty=${thirdPartyOnly}`);
            const totalApps = pkgResp.count || 0;

            progressBar.style.width = '20%';
            progressText.textContent = `Found ${totalApps} apps. Scanning...`;

            // Full scan
            const scanResp = await fetchApi(`/api/scan?thirdParty=${thirdPartyOnly}`);

            progressBar.style.width = '80%';
            progressText.textContent = 'Analyzing security risks...';

            const apps = scanResp.apps || [];

            // Run risk analysis on each app
            deviceReports = apps.map(app => {
                // Add default icon/bg for device-scanned apps
                app.icon = app.icon || '📦';
                app.iconBg = app.iconBg || '#6366f1';
                return analyzeApp(app);
            });

            progressBar.style.width = '100%';
            progressText.textContent = `Analysis complete! ${deviceReports.length} apps scanned.`;

            // Render results
            setTimeout(() => {
                progress?.classList.add('hidden');
                results?.classList.remove('hidden');
                renderDeviceResults(deviceReports);
            }, 500);

        } catch (err) {
            progressBar.style.width = '100%';
            progressBar.style.background = 'var(--accent-red)';
            progressText.textContent = `Scan failed: ${err.message}`;
            console.error('Scan error:', err);
        }
    }

    async function scanSinglePackage(packageName) {
        const progress = document.getElementById('scanProgress');
        const progressBar = document.getElementById('scanProgressBar');
        const progressText = document.getElementById('scanProgressText');
        const results = document.getElementById('deviceResults');

        progress?.classList.remove('hidden');
        results?.classList.add('hidden');

        progressBar.style.width = '30%';
        progressText.textContent = `Scanning ${packageName}...`;

        try {
            const appData = await fetchApi(`/api/scan-package?package=${encodeURIComponent(packageName)}`);
            appData.icon = '📦';
            appData.iconBg = '#6366f1';

            progressBar.style.width = '80%';
            progressText.textContent = 'Analyzing...';

            const report = analyzeApp(appData);
            deviceReports = [report];

            progressBar.style.width = '100%';

            setTimeout(() => {
                progress?.classList.add('hidden');
                results?.classList.remove('hidden');
                renderDeviceResults(deviceReports);
            }, 400);

        } catch (err) {
            progressBar.style.width = '100%';
            progressBar.style.background = 'var(--accent-red)';
            progressText.textContent = `Failed: ${err.message}`;
        }
    }

    // ── Rendering ──
    function renderDeviceResults(reports) {
        renderSummaryCards('deviceRiskSummary', reports);
        renderChart('deviceRiskChart', reports);
        renderDeviceTable(reports);
    }

    function renderSummaryCards(containerId, reports) {
        const container = document.getElementById(containerId);
        if (!container) return;
        const dist = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
        reports.forEach(r => dist[r.riskLevel.name]++);

        const cards = [
            { level: RiskLevel.CRITICAL, count: dist.CRITICAL, label: 'Critical' },
            { level: RiskLevel.HIGH, count: dist.HIGH, label: 'High Risk' },
            { level: RiskLevel.MEDIUM, count: dist.MEDIUM, label: 'Medium' },
            { level: RiskLevel.LOW, count: dist.LOW, label: 'Low Risk' },
        ];

        container.innerHTML = cards.map(c => `
            <div class="risk-summary-card">
                <div class="count" style="color:${c.level.color}">${c.count}</div>
                <div class="label">${c.level.emoji} ${c.label}</div>
            </div>
        `).join('');
    }

    function renderChart(containerId, reports) {
        const container = document.getElementById(containerId);
        if (!container) return;
        const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        reports.forEach(r => dist[r.riskLevel.name]++);
        const maxCount = Math.max(...Object.values(dist), 1);
        const levels = [
            { key: 'CRITICAL', level: RiskLevel.CRITICAL },
            { key: 'HIGH', level: RiskLevel.HIGH },
            { key: 'MEDIUM', level: RiskLevel.MEDIUM },
            { key: 'LOW', level: RiskLevel.LOW },
        ];
        container.innerHTML = levels.map(({ key, level }) => {
            const count = dist[key];
            const height = Math.max((count / maxCount) * 120, 8);
            return `
                <div class="chart-bar-group">
                    <div class="chart-bar" data-count="${count}" 
                         style="height:${height}px;background:${level.color}"></div>
                    <div class="chart-label" style="color:${level.color}">${level.emoji} ${key}</div>
                </div>
            `;
        }).join('');
    }

    function renderDeviceTable(reports) {
        const tbody = document.getElementById('deviceTableBody');
        if (!tbody) return;
        const sorted = [...reports].sort((a, b) => b.finalRiskScore - a.finalRiskScore);

        tbody.innerHTML = sorted.map((report, i) => {
            const app = report.app;
            const level = report.riskLevel;
            const source = getInstallSourceLabel(app.installerPackage);
            const topConcern = report.flaggedIssues.length > 0
                ? report.flaggedIssues[0].description : 'No concerns';
            const sourceColor = source.includes('Play Store') ? 'var(--accent-green)'
                : source.includes('Sideloaded') ? 'var(--accent-red)' : 'var(--text-secondary)';

            return `
                <tr>
                    <td style="color:var(--text-dim)">${i + 1}</td>
                    <td class="app-name-cell">
                        <span style="margin-right:8px">${app.icon || '📦'}</span>
                        ${app.appLabel || app.packageName}
                    </td>
                    <td class="package-cell">${app.packageName}</td>
                    <td>
                        <span class="risk-score-badge" style="background:${level.bgColor};color:${level.color};border:1px solid ${level.borderColor}">
                            ${report.finalRiskScore}/100
                        </span>
                    </td>
                    <td>
                        <span class="risk-level-badge" style="color:${level.color}">
                            ${level.emoji} ${level.name}
                        </span>
                    </td>
                    <td class="source-cell" style="color:${sourceColor}">${source}</td>
                    <td class="concern-cell" title="${topConcern}">${topConcern}</td>
                    <td>
                        <button class="details-btn" onclick="window.DeviceScanner.showDetail(${i})">
                            View Details
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function showDetail(index) {
        const sorted = [...deviceReports].sort((a, b) => b.finalRiskScore - a.finalRiskScore);
        const report = sorted[index];
        if (!report) return;

        // Reuse the same modal as the demo
        if (window.AppGuard && window.AppGuard.showAppDetail) {
            // Temporarily swap demo reports
            const origShowDetail = window.AppGuard.showAppDetail;
        }

        // Build modal content directly
        const app = report.app;
        const level = report.riskLevel;
        const source = getInstallSourceLabel(app.installerPackage);
        const overlay = document.getElementById('appDetailModal');
        const content = document.getElementById('modalContent');

        const circumference = 2 * Math.PI * 68;
        const offset = circumference - (report.finalRiskScore / 100) * circumference;

        const allPerms = (app.requestedPermissions || []).map(p => {
            const info = PERM_LOOKUP[p];
            const shortName = p.split('.').pop();
            return `<span class="modal-perm-tag ${info ? 'dangerous' : 'safe'}">${shortName}</span>`;
        }).join('');

        const issuesHtml = report.flaggedIssues.map(issue => {
            const colors = {
                critical: { bg: 'rgba(248,113,113,0.15)', color: '#f87171' },
                high: { bg: 'rgba(251,146,60,0.15)', color: '#fb923c' },
                medium: { bg: 'rgba(251,191,36,0.15)', color: '#fbbf24' },
                low: { bg: 'rgba(148,163,184,0.1)', color: '#94a3b8' },
            };
            const c = colors[issue.severity] || colors.low;
            return `
                <div class="issue-item severity-${issue.severity}">
                    <span class="issue-severity-tag" style="background:${c.bg};color:${c.color}">${issue.severity.toUpperCase()}</span>
                    <span>${issue.description} <strong>(+${issue.riskPoints}pts)</strong></span>
                </div>`;
        }).join('');

        content.innerHTML = `
            <div class="modal-app-header">
                <div class="modal-app-icon" style="background:${app.iconBg || '#6366f1'}">${app.icon || '📦'}</div>
                <div>
                    <div class="modal-app-name">${app.appLabel || app.packageName}</div>
                    <div class="modal-app-package">${app.packageName}</div>
                </div>
            </div>
            <div style="text-align:center;margin-bottom:24px">
                <div class="score-ring" style="width:140px;height:140px;margin:0 auto 12px">
                    <svg viewBox="0 0 152 152">
                        <circle class="ring-bg" cx="76" cy="76" r="68" />
                        <circle class="ring-fill" cx="76" cy="76" r="68"
                            style="stroke:${level.color};stroke-dasharray:${circumference};stroke-dashoffset:${offset};transition:stroke-dashoffset 1s ease" />
                    </svg>
                    <div class="score-value">
                        <span class="score-number" style="color:${level.color};font-size:2.2rem">${report.finalRiskScore}</span>
                        <span class="score-label">/ 100</span>
                    </div>
                </div>
                <div class="result-risk-level" style="background:${level.bgColor};color:${level.color};border:1px solid ${level.borderColor}">
                    ${level.emoji} ${level.name}
                </div>
            </div>
            <div class="modal-section">
                <h4>📋 App Information</h4>
                <div class="modal-info-grid">
                    <div class="modal-info-item"><div class="info-label">Version</div><div class="info-value">${app.versionName || 'N/A'}</div></div>
                    <div class="modal-info-item"><div class="info-label">Install Source</div><div class="info-value" style="color:${source.includes('Play') ? 'var(--accent-green)' : 'var(--accent-red)'}">${source}</div></div>
                    <div class="modal-info-item"><div class="info-label">Target SDK</div><div class="info-value">${app.targetSdk || 'N/A'}</div></div>
                    <div class="modal-info-item"><div class="info-label">Dangerous Perms</div><div class="info-value" style="color:var(--accent-orange)">${report.dangerousPermissions.length}</div></div>
                </div>
            </div>
            ${report.flaggedIssues.length > 0 ? `<div class="modal-section"><h4>⚠️ Flagged Issues (${report.flaggedIssues.length})</h4>${issuesHtml}</div>` : ''}
            <div class="modal-section">
                <h4>🔑 Permissions (${(app.requestedPermissions || []).length})</h4>
                <div class="modal-perm-list">${allPerms || '<span style="color:var(--text-dim)">None</span>'}</div>
            </div>`;

        overlay.classList.add('active');
    }

    // ── Export ──
    function exportDeviceJson() {
        const data = {
            scanInfo: { source: 'AppGuard Device Scan', timestamp: new Date().toISOString(), totalApps: deviceReports.length },
            apps: deviceReports.map(r => ({
                name: r.app.appLabel, package: r.app.packageName,
                riskScore: r.finalRiskScore, riskLevel: r.riskLevel.name,
                flaggedIssues: r.flaggedIssues.map(i => ({ severity: i.severity, description: i.description, points: i.riskPoints })),
                permissions: r.app.requestedPermissions,
            })),
        };
        downloadFile(JSON.stringify(data, null, 2), 'appguard_device_report.json', 'application/json');
    }

    function exportDeviceHtml() {
        // Reuse the HTML generator from app.js logic
        const sorted = [...deviceReports].sort((a, b) => b.finalRiskScore - a.finalRiskScore);
        const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        deviceReports.forEach(r => dist[r.riskLevel.name]++);
        const rows = sorted.map(r => {
            const level = r.riskLevel;
            const concern = r.flaggedIssues[0]?.description || 'No concerns';
            return `<tr><td style="font-weight:600">${r.app.appLabel || r.app.packageName}</td><td style="font-family:monospace;font-size:0.85rem;color:#64748b">${r.app.packageName}</td><td><span style="background:${level.bgColor};color:${level.color};padding:4px 12px;border-radius:6px;font-weight:700">${r.finalRiskScore}/100</span></td><td style="color:${level.color};font-weight:600">${level.emoji} ${level.name}</td><td style="font-size:0.85rem;color:#94a3b8">${concern}</td></tr>`;
        }).join('');
        const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>AppGuard Device Report</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}.header{text-align:center;margin-bottom:2rem}.header h1{font-size:2rem;color:#38bdf8}.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}.stat{background:#1e293b;border-radius:12px;padding:1.5rem;text-align:center}.stat .n{font-size:2rem;font-weight:bold}.stat .l{color:#94a3b8;font-size:.85rem}table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden}th{background:#334155;padding:1rem;text-align:left;font-size:.85rem;text-transform:uppercase;color:#94a3b8}td{padding:.75rem 1rem;border-bottom:1px solid #334155}tr:hover{background:#334155}</style></head><body><div class="header"><h1>🛡️ AppGuard Device Report</h1><p style="color:#94a3b8">${new Date().toLocaleDateString()} — ${deviceReports.length} apps scanned</p></div><div class="summary"><div class="stat"><div class="n" style="color:#ef4444">${dist.CRITICAL}</div><div class="l">Critical</div></div><div class="stat"><div class="n" style="color:#f97316">${dist.HIGH}</div><div class="l">High</div></div><div class="stat"><div class="n" style="color:#eab308">${dist.MEDIUM}</div><div class="l">Medium</div></div><div class="stat"><div class="n" style="color:#22c55e">${dist.LOW}</div><div class="l">Low</div></div></div><table><thead><tr><th>App</th><th>Package</th><th>Risk</th><th>Level</th><th>Concern</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
        downloadFile(html, 'appguard_device_report.html', 'text/html');
    }

    // ── Utilities ──
    async function fetchApi(endpoint) {
        const url = `${API_BASE}${endpoint}`;
        const resp = await fetch(url, { signal: AbortSignal.timeout(60000) });
        if (!resp.ok) {
            const err = await resp.json().catch(() => ({ error: resp.statusText }));
            throw new Error(err.error || `HTTP ${resp.status}`);
        }
        return resp.json();
    }

    function downloadFile(content, filename, type) {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename;
        document.body.appendChild(a); a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // Public API
    window.DeviceScanner = {
        showDetail,
        checkServerStatus,
    };

})();
