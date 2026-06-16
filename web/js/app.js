/**
 * AppGuard Web App — Main Application Logic
 * 
 * Handles UI interactions, rendering, tab switching, modal, exports,
 * and wires up the risk engine with demo data and manual input.
 */

(function() {
    'use strict';

    const { analyzeApp, getRiskLevel, RiskLevel, DANGEROUS_PERMISSIONS, 
            PERM_LOOKUP, getPermissionsByCategory, getInstallSourceLabel } = window.RiskEngine;

    // ── State ──
    let demoReports = [];
    let sortAscending = false;

    // ── DOM Ready ──
    document.addEventListener('DOMContentLoaded', () => {
        initNavbar();
        initHeroAnimations();
        initTabs();
        initDemoMode();
        initManualMode();
        initModal();
        initExport();
        animateCounters();
    });

    // ── Navigation ──
    function initNavbar() {
        const nav = document.getElementById('navbar');
        let lastScroll = 0;

        window.addEventListener('scroll', () => {
            const scrollY = window.scrollY;
            if (scrollY > 50) {
                nav.classList.add('scrolled');
            } else {
                nav.classList.remove('scrolled');
            }
            lastScroll = scrollY;
        });

        // Smooth scroll for nav links
        document.querySelectorAll('a[href^="#"]').forEach(link => {
            link.addEventListener('click', e => {
                e.preventDefault();
                const target = document.querySelector(link.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }
            });
        });
    }

    // ── Hero Animations ──
    function initHeroAnimations() {
        const appList = document.getElementById('heroAppList');
        if (!appList) return;

        const demoApps = window.DEMO_APPS.slice(0, 7);
        demoApps.forEach((app, i) => {
            const report = analyzeApp(app);
            const level = report.riskLevel;

            const item = document.createElement('div');
            item.className = 'phone-app-item';
            item.style.animationDelay = `${0.3 + i * 0.15}s`;

            item.innerHTML = `
                <div class="app-icon-sm" style="background:${app.iconBg}">${app.icon}</div>
                <div class="app-info-sm">
                    <div class="name">${app.appLabel}</div>
                    <div class="pkg">${app.packageName}</div>
                </div>
                <div class="risk-badge-sm" style="background:${level.bgColor};color:${level.color};border:1px solid ${level.borderColor}">
                    ${report.finalRiskScore}
                </div>
            `;
            appList.appendChild(item);
        });
    }

    // ── Counter Animation ──
    function animateCounters() {
        const counters = document.querySelectorAll('[data-target]');
        const observer = new IntersectionObserver(entries => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const el = entry.target;
                    const target = parseInt(el.dataset.target);
                    animateValue(el, 0, target, 1500);
                    observer.unobserve(el);
                }
            });
        }, { threshold: 0.5 });

        counters.forEach(c => observer.observe(c));
    }

    function animateValue(el, start, end, duration) {
        const startTime = performance.now();
        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            el.textContent = Math.floor(eased * (end - start) + start);
            if (progress < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
    }

    // ── Tab Switching ──
    function initTabs() {
        document.querySelectorAll('.analyzer-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                const tabName = tab.dataset.tab;
                
                document.querySelectorAll('.analyzer-tab').forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                document.querySelectorAll('.analyzer-panel').forEach(p => p.classList.remove('active'));
                document.getElementById(`panel${capitalize(tabName)}`).classList.add('active');
            });
        });
    }

    // ── Demo Mode ──
    function initDemoMode() {
        // Analyze all demo apps
        demoReports = window.DEMO_APPS.map(app => analyzeApp(app));

        renderRiskSummary(demoReports);
        renderRiskChart(demoReports);
        renderAppTable(demoReports);

        // Sort button
        document.getElementById('sortByRisk').addEventListener('click', () => {
            sortAscending = !sortAscending;
            const sorted = [...demoReports].sort((a, b) => 
                sortAscending 
                    ? a.finalRiskScore - b.finalRiskScore 
                    : b.finalRiskScore - a.finalRiskScore
            );
            renderAppTable(sorted);
            document.getElementById('sortByRisk').textContent = 
                sortAscending ? 'Sort by Risk ↑' : 'Sort by Risk ↓';
        });
    }

    function renderRiskSummary(reports) {
        const container = document.getElementById('riskSummary');
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

    function renderRiskChart(reports) {
        const container = document.getElementById('riskChart');
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

    function renderAppTable(reports) {
        const tbody = document.getElementById('appTableBody');
        const sorted = [...reports].sort((a, b) => b.finalRiskScore - a.finalRiskScore);

        tbody.innerHTML = sorted.map((report, i) => {
            const app = report.app;
            const level = report.riskLevel;
            const source = getInstallSourceLabel(app.installerPackage);
            const topConcern = report.flaggedIssues.length > 0 
                ? report.flaggedIssues[0].description 
                : 'No concerns';
            const sourceColor = source.includes('Play Store') ? 'var(--accent-green)' 
                : source.includes('Sideloaded') ? 'var(--accent-red)' : 'var(--text-secondary)';

            return `
                <tr>
                    <td style="color:var(--text-dim)">${i + 1}</td>
                    <td class="app-name-cell">
                        <span style="margin-right:8px">${app.icon || '📦'}</span>
                        ${app.appLabel}
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
                        <button class="details-btn" onclick="window.AppGuard.showAppDetail(${i})">
                            View Details
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    // ── Manual Input Mode ──
    function initManualMode() {
        renderPermissionCategories();

        document.getElementById('analyzeBtn').addEventListener('click', () => {
            runManualAnalysis();
        });
    }

    function renderPermissionCategories() {
        const container = document.getElementById('permissionCategories');
        const categories = getPermissionsByCategory();

        container.innerHTML = Object.entries(categories).map(([catName, cat]) => {
            const permsHtml = cat.perms.map(p => {
                const riskColor = p.weight >= 20 ? 'var(--accent-red)' 
                    : p.weight >= 10 ? 'var(--accent-orange)' 
                    : 'var(--text-dim)';
                const riskBg = p.weight >= 20 ? 'rgba(248,113,113,0.1)' 
                    : p.weight >= 10 ? 'rgba(251,146,60,0.1)' 
                    : 'rgba(148,163,184,0.05)';

                return `
                    <label class="perm-item">
                        <input type="checkbox" value="${p.full}" class="perm-checkbox">
                        <span class="perm-name">${p.name}</span>
                        <span class="perm-risk" style="color:${riskColor};background:${riskBg}">+${p.weight}</span>
                    </label>
                `;
            }).join('');

            return `
                <div class="perm-category">
                    <div class="perm-category-header" onclick="this.parentElement.classList.toggle('collapsed')">
                        <span class="cat-name">${cat.icon} ${catName}</span>
                        <button class="cat-toggle" onclick="event.stopPropagation(); window.AppGuard.toggleCategory(this, '${catName}')">
                            Select All
                        </button>
                    </div>
                    <div class="perm-list">${permsHtml}</div>
                </div>
            `;
        }).join('');
    }

    function runManualAnalysis() {
        const appName = document.getElementById('appName').value || 'Unknown App';
        const packageName = document.getElementById('packageName').value || 'com.unknown.app';
        const targetSdk = document.getElementById('targetSdk').value || '34';
        const installSource = document.getElementById('installSource').value;
        const certSelfSigned = document.getElementById('certSelfSigned').checked;
        const certDebug = document.getElementById('certDebug').checked;
        const certExpired = document.getElementById('certExpired').checked;

        const selectedPerms = [];
        document.querySelectorAll('.perm-checkbox:checked').forEach(cb => {
            selectedPerms.push(cb.value);
        });

        const appData = {
            packageName,
            appLabel: appName,
            icon: '📦',
            iconBg: '#6366f1',
            versionName: '1.0.0',
            installerPackage: installSource === 'sideloaded' ? '' : installSource,
            targetSdk,
            isSystemApp: false,
            requestedPermissions: selectedPerms,
            certificate: {
                isSelfSigned: certSelfSigned,
                isDebugSigned: certDebug,
                isExpired: certExpired,
            },
        };

        const report = analyzeApp(appData);
        renderManualResults(report);
    }

    function renderManualResults(report) {
        const placeholder = document.getElementById('resultsPlaceholder');
        const content = document.getElementById('resultsContent');
        const level = report.riskLevel;

        placeholder.style.display = 'none';
        content.classList.remove('hidden');

        // Score ring
        const circumference = 2 * Math.PI * 68;
        const offset = circumference - (report.finalRiskScore / 100) * circumference;

        const issuesHtml = report.flaggedIssues.map(issue => `
            <div class="issue-item severity-${issue.severity}">
                <span class="issue-severity-tag" style="background:${getSeverityBg(issue.severity)};color:${getSeverityColor(issue.severity)}">
                    ${issue.severity.toUpperCase()}
                </span>
                <span>${issue.description}</span>
            </div>
        `).join('');

        content.innerHTML = `
            <div class="result-score-display">
                <div class="score-ring">
                    <svg viewBox="0 0 152 152">
                        <circle class="ring-bg" cx="76" cy="76" r="68" />
                        <circle class="ring-fill" cx="76" cy="76" r="68"
                            style="stroke:${level.color};stroke-dasharray:${circumference};stroke-dashoffset:${offset}" />
                    </svg>
                    <div class="score-value">
                        <span class="score-number" style="color:${level.color}">${report.finalRiskScore}</span>
                        <span class="score-label">Risk Score</span>
                    </div>
                </div>
                <div class="result-risk-level" style="background:${level.bgColor};color:${level.color};border:1px solid ${level.borderColor}">
                    ${level.emoji} ${level.name} RISK
                </div>
            </div>

            ${report.flaggedIssues.length > 0 ? `
                <div class="result-issues">
                    <h4>⚠️ Flagged Issues (${report.flaggedIssues.length})</h4>
                    ${issuesHtml}
                </div>
            ` : '<p style="color:var(--text-dim);text-align:center;padding:20px">No security issues found. This app appears safe.</p>'}

            <div class="result-issues">
                <h4>📊 Analysis Summary</h4>
                <div class="issue-item severity-low">
                    <span>Dangerous permissions: <strong>${report.dangerousPermissions.length}</strong> | 
                    Total requested: <strong>${report.app.requestedPermissions.length}</strong> | 
                    Base risk: <strong>${report.baseRiskScore}/100</strong></span>
                </div>
            </div>
        `;

        // Animate the score ring
        requestAnimationFrame(() => {
            const ring = content.querySelector('.ring-fill');
            if (ring) {
                ring.style.strokeDashoffset = circumference;
                requestAnimationFrame(() => {
                    ring.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4, 0, 0.2, 1)';
                    ring.style.strokeDashoffset = offset;
                });
            }
        });
    }

    // ── App Detail Modal ──
    function initModal() {
        const overlay = document.getElementById('appDetailModal');
        const closeBtn = document.getElementById('modalClose');

        closeBtn.addEventListener('click', () => {
            overlay.classList.remove('active');
        });

        overlay.addEventListener('click', e => {
            if (e.target === overlay) overlay.classList.remove('active');
        });

        document.addEventListener('keydown', e => {
            if (e.key === 'Escape') overlay.classList.remove('active');
        });
    }

    function showAppDetail(index) {
        const sorted = [...demoReports].sort((a, b) => b.finalRiskScore - a.finalRiskScore);
        const report = sorted[index];
        if (!report) return;

        const app = report.app;
        const level = report.riskLevel;
        const source = getInstallSourceLabel(app.installerPackage);
        const overlay = document.getElementById('appDetailModal');
        const content = document.getElementById('modalContent');

        const circumference = 2 * Math.PI * 68;
        const offset = circumference - (report.finalRiskScore / 100) * circumference;

        // Permissions
        const allPerms = (app.requestedPermissions || []).map(p => {
            const info = PERM_LOOKUP[p];
            const shortName = p.split('.').pop();
            const isDangerous = !!info;
            return `<span class="modal-perm-tag ${isDangerous ? 'dangerous' : 'safe'}">${shortName}</span>`;
        }).join('');

        // Flagged issues
        const issuesHtml = report.flaggedIssues.map(issue => `
            <div class="issue-item severity-${issue.severity}">
                <span class="issue-severity-tag" style="background:${getSeverityBg(issue.severity)};color:${getSeverityColor(issue.severity)}">
                    ${issue.severity.toUpperCase()}
                </span>
                <span>${issue.description} <strong>(+${issue.riskPoints}pts)</strong></span>
            </div>
        `).join('');

        content.innerHTML = `
            <div class="modal-app-header">
                <div class="modal-app-icon" style="background:${app.iconBg || '#6366f1'}">${app.icon || '📦'}</div>
                <div>
                    <div class="modal-app-name">${app.appLabel}</div>
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
                    <div class="modal-info-item">
                        <div class="info-label">Version</div>
                        <div class="info-value">${app.versionName || 'N/A'}</div>
                    </div>
                    <div class="modal-info-item">
                        <div class="info-label">Install Source</div>
                        <div class="info-value" style="color:${source.includes('Play') ? 'var(--accent-green)' : 'var(--accent-red)'}">${source}</div>
                    </div>
                    <div class="modal-info-item">
                        <div class="info-label">Target SDK</div>
                        <div class="info-value">${app.targetSdk || 'N/A'}</div>
                    </div>
                    <div class="modal-info-item">
                        <div class="info-label">Dangerous Perms</div>
                        <div class="info-value" style="color:var(--accent-orange)">${report.dangerousPermissions.length}</div>
                    </div>
                </div>
            </div>

            ${report.flaggedIssues.length > 0 ? `
                <div class="modal-section">
                    <h4>⚠️ Flagged Issues (${report.flaggedIssues.length})</h4>
                    ${issuesHtml}
                </div>
            ` : ''}

            <div class="modal-section">
                <h4>🔑 Permissions (${(app.requestedPermissions || []).length})</h4>
                <div class="modal-perm-list">${allPerms || '<span style="color:var(--text-dim)">No permissions requested</span>'}</div>
            </div>
        `;

        overlay.classList.add('active');
    }

    // ── Export ──
    function initExport() {
        document.getElementById('exportJsonBtn').addEventListener('click', () => {
            const data = {
                scanInfo: {
                    source: 'AppGuard Web Demo',
                    timestamp: new Date().toISOString(),
                    totalApps: demoReports.length,
                },
                apps: demoReports.map(r => ({
                    name: r.app.appLabel,
                    package: r.app.packageName,
                    riskScore: r.finalRiskScore,
                    riskLevel: r.riskLevel.name,
                    flaggedIssues: r.flaggedIssues.map(i => ({
                        severity: i.severity,
                        description: i.description,
                        points: i.riskPoints,
                    })),
                    permissions: r.app.requestedPermissions,
                })),
            };
            downloadFile(
                JSON.stringify(data, null, 2),
                'appguard_report.json',
                'application/json'
            );
        });

        document.getElementById('exportHtmlBtn').addEventListener('click', () => {
            const html = generateHtmlReport(demoReports);
            downloadFile(html, 'appguard_report.html', 'text/html');
        });
    }

    function generateHtmlReport(reports) {
        const sorted = [...reports].sort((a, b) => b.finalRiskScore - a.finalRiskScore);
        const dist = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        reports.forEach(r => dist[r.riskLevel.name]++);

        const rows = sorted.map(r => {
            const level = r.riskLevel;
            const concern = r.flaggedIssues[0]?.description || 'No concerns';
            return `<tr>
                <td style="font-weight:600">${r.app.icon} ${r.app.appLabel}</td>
                <td style="font-family:monospace;font-size:0.85rem;color:#64748b">${r.app.packageName}</td>
                <td><span style="background:${level.bgColor};color:${level.color};padding:4px 12px;border-radius:6px;font-weight:700">${r.finalRiskScore}/100</span></td>
                <td style="color:${level.color};font-weight:600">${level.emoji} ${level.name}</td>
                <td style="font-size:0.85rem;color:#94a3b8">${concern}</td>
            </tr>`;
        }).join('');

        return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AppGuard Security Report</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:2rem}
.header{text-align:center;margin-bottom:2rem}.header h1{font-size:2rem;color:#38bdf8}.header p{color:#94a3b8;margin-top:.5rem}
.summary{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin-bottom:2rem}
.stat{background:#1e293b;border-radius:12px;padding:1.5rem;text-align:center}.stat .n{font-size:2rem;font-weight:bold}.stat .l{color:#94a3b8;font-size:.85rem;margin-top:.25rem}
table{width:100%;border-collapse:collapse;background:#1e293b;border-radius:12px;overflow:hidden}
th{background:#334155;padding:1rem;text-align:left;font-size:.85rem;text-transform:uppercase;color:#94a3b8}
td{padding:.75rem 1rem;border-bottom:1px solid #334155}tr:hover{background:#334155}</style></head>
<body><div class="header"><h1>🛡️ AppGuard Security Report</h1><p>Generated ${new Date().toLocaleDateString()}</p></div>
<div class="summary">
<div class="stat"><div class="n" style="color:#ef4444">${dist.CRITICAL}</div><div class="l">Critical</div></div>
<div class="stat"><div class="n" style="color:#f97316">${dist.HIGH}</div><div class="l">High Risk</div></div>
<div class="stat"><div class="n" style="color:#eab308">${dist.MEDIUM}</div><div class="l">Medium</div></div>
<div class="stat"><div class="n" style="color:#22c55e">${dist.LOW}</div><div class="l">Low Risk</div></div>
</div><table><thead><tr><th>App</th><th>Package</th><th>Risk</th><th>Level</th><th>Top Concern</th></tr></thead>
<tbody>${rows}</tbody></table></body></html>`;
    }

    function downloadFile(content, filename, type) {
        const blob = new Blob([content], { type });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    // ── Helpers ──
    function capitalize(str) {
        return str.charAt(0).toUpperCase() + str.slice(1);
    }

    function getSeverityColor(severity) {
        const map = {
            critical: '#f87171',
            high: '#fb923c',
            medium: '#fbbf24',
            low: '#94a3b8',
        };
        return map[severity] || '#94a3b8';
    }

    function getSeverityBg(severity) {
        const map = {
            critical: 'rgba(248,113,113,0.15)',
            high: 'rgba(251,146,60,0.15)',
            medium: 'rgba(251,191,36,0.15)',
            low: 'rgba(148,163,184,0.1)',
        };
        return map[severity] || 'rgba(148,163,184,0.1)';
    }

    // ── Toggle category checkboxes ──
    function toggleCategory(btn, catName) {
        const category = btn.closest('.perm-category');
        const checkboxes = category.querySelectorAll('.perm-checkbox');
        const allChecked = Array.from(checkboxes).every(cb => cb.checked);
        
        checkboxes.forEach(cb => cb.checked = !allChecked);
        btn.textContent = allChecked ? 'Select All' : 'Deselect All';
    }

    // ── Public API ──
    window.AppGuard = {
        showAppDetail,
        toggleCategory,
    };

})();
