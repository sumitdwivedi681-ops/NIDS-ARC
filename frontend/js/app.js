/**
 * NIDS ARC SOC Dashboard — Main Application
 * Client-side router, page rendering, and real-time updates.
 */
(function () {
    'use strict';

    // --- State ---
    let currentPage = 'overview';
    let refreshInterval = null;
    let dashboardData = null;

    // --- Router ---
    function navigate(page) {
        currentPage = page;
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === page);
        });
        const names = {
            overview: 'Overview', alerts: 'Live Alerts', events: 'Event Explorer',
            incidents: 'Incidents', timeline: 'Attack Timeline', network: 'Network Activity',
            sensors: 'Sensors', engines: 'Detection Engines', health: 'System Health',
            'threat-intel': 'Threat Intelligence', models: 'ML Models', rules: 'Rules',
            responses: 'Response Actions', audit: 'Audit Logs', settings: 'Settings',
        };
        document.getElementById('breadcrumbs').innerHTML =
            `<span>Dashboard</span> › <span>${names[page] || page}</span>`;
        renderPage(page);
    }

    function initRouter() {
        window.addEventListener('hashchange', () => {
            const hash = location.hash.slice(2) || 'overview';
            navigate(hash);
        });
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                location.hash = '#/' + item.dataset.page;
                // Auto close mobile drawer on tap
                const sidebar = document.getElementById('sidebar');
                const backdrop = document.getElementById('sidebarBackdrop');
                if (sidebar && sidebar.classList.contains('open')) {
                    sidebar.classList.remove('open');
                    if (backdrop) backdrop.classList.remove('active');
                }
            });
        });
        const hash = location.hash.slice(2) || 'overview';
        navigate(hash);
    }

    // --- Helpers ---
    function severityBadge(severity) {
        return `<span class="badge badge-${severity}">${severity}</span>`;
    }

    function timeAgo(dateStr) {
        if (!dateStr) return '—';
        const diff = Date.now() - new Date(dateStr).getTime();
        const mins = Math.floor(diff / 60000);
        if (mins < 1) return 'just now';
        if (mins < 60) return `${mins}m ago`;
        const hrs = Math.floor(mins / 60);
        if (hrs < 24) return `${hrs}h ago`;
        return `${Math.floor(hrs / 24)}d ago`;
    }

    function formatNumber(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }

    function donutSVG(segments, total) {
        const radius = 54, cx = 64, cy = 64, circumference = 2 * Math.PI * radius;
        let offset = 0;
        const paths = segments.map(seg => {
            const pct = total > 0 ? seg.value / total : 0;
            const dashLen = circumference * pct;
            const path = `<circle cx="${cx}" cy="${cy}" r="${radius}" fill="none" stroke="${seg.color}" stroke-width="12" stroke-dasharray="${dashLen} ${circumference - dashLen}" stroke-dashoffset="${-offset}" />`;
            offset += dashLen;
            return path;
        });
        return `<svg viewBox="0 0 128 128">${paths.join('')}</svg>`;
    }

    // --- Page Renderers ---
    async function renderPage(page) {
        const el = document.getElementById('pageContent');
        el.innerHTML = '<div class="loading-screen"><div class="loading-spinner"></div><p>Loading...</p></div>';

        switch (page) {
            case 'overview': return renderOverview(el);
            case 'alerts': return renderAlerts(el);
            case 'events': return renderEvents(el);
            case 'incidents': return renderIncidents(el);
            case 'engines': return renderEngines(el);
            case 'threat-intel': return renderThreatIntel(el);
            case 'responses': return renderResponses(el);
            case 'health': return renderHealth(el);
            case 'sensors': return renderSensors(el);
            case 'timeline': return renderTimeline(el);
            case 'models': return renderModels(el);
            case 'rules': return renderRules(el);
            case 'audit': return renderAudit(el);
            case 'network': return renderNetwork(el);
            case 'settings': return renderSettings(el);
            default: el.innerHTML = `<div class="empty-state"><div class="empty-icon">🔍</div><p class="empty-text">Page not found</p></div>`;
        }
    }

    async function renderOverview(el) {
        const data = await API.getDashboardOverview();
        if (data.error) {
            el.innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><p class="empty-text">${data.error.message}<br><small>Make sure the backend is running at port 8000</small></p></div>`;
            return;
        }
        dashboardData = data;

        const sevDist = data.severity_distribution || {};
        const total = Object.values(sevDist).reduce((a, b) => a + b, 0);
        const segments = [
            { value: sevDist.critical || 0, color: '#ef4444', label: 'Critical' },
            { value: sevDist.high || 0, color: '#f97316', label: 'High' },
            { value: sevDist.medium || 0, color: '#eab308', label: 'Medium' },
            { value: sevDist.low || 0, color: '#3b82f6', label: 'Low' },
            { value: sevDist.info || 0, color: '#8b5cf6', label: 'Info' },
        ];

        const engines = data.detection_engines?.detectors || [];
        const alertsList = (data.recent_alerts || []).map(a => `
            <div class="alert-item" onclick="location.hash='#/alerts'">
                <div class="alert-severity ${a.severity}"></div>
                <div class="alert-body">
                    <div class="alert-title">${a.title}</div>
                    <div class="alert-meta">
                        ${severityBadge(a.severity)}
                        <span class="mono">${a.src_ip || '—'}</span>
                        <span>→</span>
                        <span class="mono">${a.dst_ip || '—'}</span>
                        <span>${timeAgo(a.created_at)}</span>
                    </div>
                </div>
            </div>
        `).join('') || '<div class="empty-state"><div class="empty-icon">✅</div><p class="empty-text">No recent alerts</p></div>';

        const engineCards = engines.map(e => `
            <div class="engine-card">
                <div class="engine-name">
                    <span class="status-dot ${e.status === 'active' ? 'healthy' : 'down'}"></span>
                    ${e.name}
                </div>
                <div class="engine-status">v${e.version} · ${e.status}</div>
            </div>
        `).join('');

        el.innerHTML = `
            <div class="page-header">
                <div>
                    <h1 class="page-title">Security Overview</h1>
                    <p class="page-subtitle">Real-time security posture — ${data.mode?.toUpperCase()} mode</p>
                </div>
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-icon">📊</div>
                    <div class="metric-value">${formatNumber(data.total_events_24h || 0)}</div>
                    <div class="metric-label">Events (24h)</div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon">🔔</div>
                    <div class="metric-value">${formatNumber(data.active_alerts || 0)}</div>
                    <div class="metric-label">Active Alerts</div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon">🔗</div>
                    <div class="metric-value">${data.correlation?.active_groups || 0}</div>
                    <div class="metric-label">Active Incidents</div>
                </div>
                <div class="metric-card">
                    <div class="metric-icon">🛡️</div>
                    <div class="metric-value">${data.threat_intel?.total_iocs || 0}</div>
                    <div class="metric-label">Active IOCs</div>
                </div>
            </div>

            <div class="content-grid">
                <div class="card">
                    <div class="card-header"><span class="card-title">Alert Severity Distribution</span></div>
                    <div style="display:flex;align-items:center;gap:2rem;">
                        <div class="donut-chart">
                            ${donutSVG(segments, total)}
                            <div class="donut-center">
                                <span class="value">${total}</span>
                                <span class="label">Total</span>
                            </div>
                        </div>
                        <div class="legend">
                            ${segments.map(s => `<div class="legend-item"><span class="legend-dot" style="background:${s.color}"></span>${s.label}: ${s.value}</div>`).join('')}
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header"><span class="card-title">Detection Engines</span></div>
                    <div class="engine-grid">${engineCards || '<p style="color:var(--text-tertiary)">No engines registered</p>'}</div>
                </div>
            </div>

            <div style="margin-top:var(--space-xl)">
                <div class="section-title">Recent Alerts</div>
                ${alertsList}
            </div>
        `;

        document.getElementById('alertBadge').textContent = data.active_alerts || 0;
    }

    async function renderAlerts(el) {
        const data = await API.getAlerts({ page_size: 50, sort_order: 'desc' });
        if (data.error) { el.innerHTML = `<div class="empty-state"><p class="empty-text">${data.error.message}</p></div>`; return; }

        const alerts = data.data || [];
        const rows = alerts.map(a => `
            <tr>
                <td>${severityBadge(a.severity)}</td>
                <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${a.title}</td>
                <td><span class="badge badge-${a.status === 'new' ? 'warning' : a.status === 'resolved' ? 'success' : 'info'}">${a.status}</span></td>
                <td class="mono">${a.src_ip || '—'}</td>
                <td class="mono">${a.dst_ip || '—'}</td>
                <td>${a.risk_score ? a.risk_score.toFixed(1) : '—'}</td>
                <td>${timeAgo(a.created_at)}</td>
            </tr>
        `).join('');

        el.innerHTML = `
            <div class="page-header">
                <div><h1 class="page-title">Live Alerts</h1><p class="page-subtitle">${alerts.length} alerts</p></div>
                <button class="btn btn-primary btn-sm" onclick="renderPage('alerts')">🔄 Refresh</button>
            </div>
            <div class="filter-bar">
                <select id="filterSeverity"><option value="">All Severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
                <select id="filterStatus"><option value="">All Statuses</option><option>new</option><option>acknowledged</option><option>investigating</option><option>resolved</option></select>
            </div>
            <div class="card" style="padding:0;overflow:auto;">
                <table class="data-table">
                    <thead><tr><th>Severity</th><th>Title</th><th>Status</th><th>Source</th><th>Destination</th><th>Risk</th><th>Time</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="7" style="text-align:center;padding:2rem;color:var(--text-tertiary)">No alerts</td></tr>'}</tbody>
                </table>
            </div>
            ${data.pagination ? `<div class="pagination"><span class="page-info">Page ${data.pagination.page} of ${data.pagination.total_pages} (${data.pagination.total} total)</span></div>` : ''}
        `;
    }

    async function renderEvents(el) {
        const data = await API.getEvents({ page_size: 50 });
        if (data.error) { el.innerHTML = `<div class="empty-state"><p class="empty-text">${data.error.message}</p></div>`; return; }
        const events = data.data || [];
        const rows = events.map(e => `
            <tr>
                <td>${severityBadge(e.severity)}</td>
                <td class="mono">${e.src_ip}:${e.src_port || '*'}</td>
                <td class="mono">${e.dst_ip}:${e.dst_port || '*'}</td>
                <td>${e.protocol || '—'}</td>
                <td>${e.event_type}</td>
                <td><span class="badge badge-${e.source_type === 'simulation' ? 'info' : 'success'}">${e.source_type}</span></td>
                <td>${e.attack_category || '—'}</td>
                <td>${timeAgo(e.timestamp)}</td>
            </tr>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Event Explorer</h1><p class="page-subtitle">${data.pagination?.total || 0} events</p></div></div>
            <div class="card" style="padding:0;overflow:auto;">
                <table class="data-table">
                    <thead><tr><th>Sev</th><th>Source</th><th>Destination</th><th>Proto</th><th>Type</th><th>Mode</th><th>Category</th><th>Time</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="8" style="text-align:center;padding:2rem;">No events</td></tr>'}</tbody>
                </table>
            </div>
            ${data.pagination ? `<div class="pagination"><span class="page-info">Page ${data.pagination.page} of ${data.pagination.total_pages}</span></div>` : ''}
        `;
    }

    async function renderIncidents(el) {
        const data = await API.getIncidents();
        const incidents = data.data || [];
        const cards = incidents.map(i => `
            <div class="alert-item">
                <div class="alert-severity ${i.severity}"></div>
                <div class="alert-body">
                    <div class="alert-title">${severityBadge(i.severity)} ${i.detection_count} detections from ${i.detectors?.join(', ') || '—'}</div>
                    <div class="alert-meta">
                        <span>Sources: ${(i.src_entities || []).slice(0, 3).map(ip => `<span class="mono">${ip}</span>`).join(', ')}</span>
                        <span>Stages: ${(i.attack_stages || []).join(' → ') || '—'}</span>
                        <span>${timeAgo(i.first_seen)}</span>
                    </div>
                </div>
            </div>
        `).join('') || '<div class="empty-state"><div class="empty-icon">🔗</div><p class="empty-text">No correlated incidents yet</p></div>';

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Incidents</h1><p class="page-subtitle">${incidents.length} correlated incidents</p></div></div>
            ${cards}
        `;
    }

    async function renderEngines(el) {
        const data = await API.getEngines();
        const engines = data.data?.detectors || [];
        const cards = engines.map(e => `
            <div class="engine-card">
                <div class="engine-name"><span class="status-dot ${e.status === 'active' ? 'healthy' : e.status === 'not_loaded' ? 'degraded' : 'down'}"></span>${e.name}</div>
                <div class="engine-status">Version: ${e.version} · Status: ${e.status}</div>
                ${e.model_name ? `<div class="engine-status" style="margin-top:4px">Model: ${e.model_name} v${e.model_version}</div>` : ''}
                ${e.inference_count !== undefined ? `<div class="engine-status">Inferences: ${e.inference_count} · Avg: ${e.avg_inference_ms}ms</div>` : ''}
            </div>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Detection Engines</h1><p class="page-subtitle">${engines.length} engines registered</p></div></div>
            <div class="metrics-grid">
                <div class="metric-card"><div class="metric-value">${data.data?.total_events_processed || 0}</div><div class="metric-label">Events Processed</div></div>
                <div class="metric-card"><div class="metric-value">${data.data?.total_detections || 0}</div><div class="metric-label">Total Detections</div></div>
            </div>
            <div class="engine-grid">${cards}</div>
        `;
    }

    async function renderThreatIntel(el) {
        const data = await API.getThreatIntel();
        const iocs = data.iocs || [];
        const rows = iocs.map(i => `
            <tr>
                <td><span class="badge badge-info">${i.indicator_type}</span></td>
                <td class="mono">${i.value}</td>
                <td>${i.source}</td>
                <td>${(i.confidence * 100).toFixed(0)}%</td>
                <td>${severityBadge(i.severity || 'medium')}</td>
                <td>${(i.tags || []).map(t => `<span class="badge badge-info">${t}</span>`).join(' ')}</td>
            </tr>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Threat Intelligence</h1><p class="page-subtitle">IOC Database — ${data.data?.data_source === 'mock' ? '⚠️ MOCK DATA' : 'Live'}</p></div></div>
            ${data.data?.data_source === 'mock' ? '<div class="form-error">⚠️ Using MOCK threat intelligence data — not real threat feeds</div>' : ''}
            <div class="metrics-grid">
                <div class="metric-card"><div class="metric-value">${data.data?.total_iocs || 0}</div><div class="metric-label">Total IOCs</div></div>
                <div class="metric-card"><div class="metric-value">${data.data?.active_iocs || 0}</div><div class="metric-label">Active IOCs</div></div>
            </div>
            <div class="card" style="padding:0;overflow:auto;">
                <table class="data-table">
                    <thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Confidence</th><th>Severity</th><th>Tags</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    async function renderResponses(el) {
        const data = await API.getResponseActions();
        const actions = data.data || [];
        const stats = data.stats || {};
        const rows = actions.map(a => `
            <tr>
                <td><span class="badge badge-${a.is_dry_run ? 'warning' : 'info'}">${a.action_type}</span></td>
                <td><span class="badge badge-${a.status === 'dry_run' ? 'warning' : a.status === 'pending_approval' ? 'medium' : 'success'}">${a.status}</span></td>
                <td class="mono">${a.target?.entity || '—'}</td>
                <td>${(a.confidence * 100).toFixed(0)}%</td>
                <td>${a.policy_name || a.policy_id || '—'}</td>
                <td>${timeAgo(a.timestamp)}</td>
            </tr>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Response Actions</h1><p class="page-subtitle">${actions.length} actions · Dry-run: ${stats.dry_run_mode ? 'ON' : 'OFF'} · Manual approval: ${stats.manual_approval ? 'ON' : 'OFF'}</p></div></div>
            <div class="metrics-grid">
                <div class="metric-card"><div class="metric-value">${stats.total_actions || 0}</div><div class="metric-label">Total Actions</div></div>
                <div class="metric-card"><div class="metric-value">${stats.pending || 0}</div><div class="metric-label">Pending Approval</div></div>
                <div class="metric-card"><div class="metric-value">${stats.policies || 0}</div><div class="metric-label">Active Policies</div></div>
            </div>
            <div class="card" style="padding:0;overflow:auto;">
                <table class="data-table">
                    <thead><tr><th>Type</th><th>Status</th><th>Target</th><th>Confidence</th><th>Policy</th><th>Time</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="6" style="text-align:center;padding:2rem;">No response actions</td></tr>'}</tbody>
                </table>
            </div>
        `;
    }

    async function renderHealth(el) {
        const health = await API.getHealth();
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">System Health</h1><p class="page-subtitle">Infrastructure status</p></div></div>
            <div class="engine-grid">
                <div class="engine-card"><div class="engine-name"><span class="status-dot ${health.status === 'healthy' ? 'healthy' : 'down'}"></span>API Server</div><div class="engine-status">Status: ${health.status || 'unknown'}</div></div>
                <div class="engine-card"><div class="engine-name"><span class="status-dot ${health.components?.database === 'healthy' ? 'healthy' : 'down'}"></span>Database</div><div class="engine-status">Status: ${health.components?.database || 'unknown'}</div></div>
                <div class="engine-card"><div class="engine-name"><span class="status-dot healthy"></span>Mode</div><div class="engine-status">${(health.mode || 'unknown').toUpperCase()}</div></div>
                <div class="engine-card"><div class="engine-name"><span class="status-dot healthy"></span>Environment</div><div class="engine-status">${health.app_env || 'unknown'}</div></div>
            </div>
        `;
    }

    function renderSensors(el) {
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Sensors</h1><p class="page-subtitle">Network sensor management</p></div></div>
            <div class="engine-grid">
                <div class="engine-card">
                    <div class="engine-name"><span class="status-dot healthy"></span>Simulation Sensor</div>
                    <div class="engine-status">Type: simulation · Status: active</div>
                    <div class="engine-status"><span class="badge badge-info">SIMULATION</span></div>
                </div>
                <div class="engine-card">
                    <div class="engine-name"><span class="status-dot down"></span>Suricata Adapter</div>
                    <div class="engine-status">Type: suricata · Status: not configured</div>
                    <div class="engine-status"><span class="badge badge-warning">UNAVAILABLE</span></div>
                </div>
                <div class="engine-card">
                    <div class="engine-name"><span class="status-dot down"></span>Zeek Adapter</div>
                    <div class="engine-status">Type: zeek · Status: not configured</div>
                    <div class="engine-status"><span class="badge badge-warning">UNAVAILABLE</span></div>
                </div>
            </div>
        `;
    }

    function renderTimeline(el) {
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Attack Timeline</h1><p class="page-subtitle">Temporal event visualization</p></div></div>
            <div class="empty-state"><div class="empty-icon">📅</div><p class="empty-text">Attack timeline visualization — view alerts to see temporal patterns</p></div>
        `;
    }

    function renderModels(el) {
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">ML Models</h1><p class="page-subtitle">Machine learning model management</p></div></div>
            <div class="engine-grid">
                <div class="engine-card">
                    <div class="engine-name"><span class="status-dot healthy"></span>nids-arc-rf-v1</div>
                    <div class="engine-status">Algorithm: RandomForest · Status: active</div>
                    <div class="engine-status">Version: 1.0.0-synthetic</div>
                    <div class="engine-status" style="margin-top:8px"><span class="badge badge-warning">Trained on synthetic data</span></div>
                </div>
            </div>
        `;
    }

    function renderRules(el) {
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Detection Rules</h1><p class="page-subtitle">Signature and behavioral rules</p></div></div>
            <div class="card" style="padding:0;overflow:auto;">
                <table class="data-table">
                    <thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Category</th><th>Status</th></tr></thead>
                    <tbody>
                        <tr><td class="mono">SIG-001</td><td>Port Scan Detection</td><td>${severityBadge('medium')}</td><td>Reconnaissance</td><td><span class="badge badge-success">enabled</span></td></tr>
                        <tr><td class="mono">SIG-002</td><td>SSH Brute Force</td><td>${severityBadge('high')}</td><td>Credential Access</td><td><span class="badge badge-success">enabled</span></td></tr>
                        <tr><td class="mono">SIG-003</td><td>DNS Tunneling Indicator</td><td>${severityBadge('high')}</td><td>Exfiltration</td><td><span class="badge badge-success">enabled</span></td></tr>
                        <tr><td class="mono">SIG-004</td><td>Suspicious Outbound Traffic</td><td>${severityBadge('medium')}</td><td>C2</td><td><span class="badge badge-success">enabled</span></td></tr>
                        <tr><td class="mono">SIG-005</td><td>Large Data Transfer</td><td>${severityBadge('medium')}</td><td>Exfiltration</td><td><span class="badge badge-success">enabled</span></td></tr>
                        <tr><td class="mono">SIG-006</td><td>Telnet Connection</td><td>${severityBadge('high')}</td><td>Initial Access</td><td><span class="badge badge-success">enabled</span></td></tr>
                        <tr><td class="mono">SIG-007</td><td>FTP Data Transfer</td><td>${severityBadge('low')}</td><td>Lateral Movement</td><td><span class="badge badge-success">enabled</span></td></tr>
                        <tr><td class="mono">SIG-008</td><td>ICMP Flood Indicator</td><td>${severityBadge('medium')}</td><td>DoS</td><td><span class="badge badge-success">enabled</span></td></tr>
                    </tbody>
                </table>
            </div>
        `;
    }

    function renderAudit(el) {
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Audit Logs</h1><p class="page-subtitle">Immutable audit trail</p></div></div>
            <div class="empty-state"><div class="empty-icon">📝</div><p class="empty-text">Audit logs are recorded for all administrative actions, authentication events, and response actions.</p></div>
        `;
    }

    function renderNetwork(el) {
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Network Activity</h1><p class="page-subtitle">Traffic analysis and flow visualization</p></div></div>
            <div class="empty-state"><div class="empty-icon">🌐</div><p class="empty-text">Network activity visualization — event data available in Event Explorer</p></div>
        `;
    }

    function renderSettings(el) {
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Settings</h1><p class="page-subtitle">System configuration</p></div></div>
            <div class="content-grid">
                <div class="card">
                    <div class="card-header"><span class="card-title">General</span></div>
                    <div class="engine-status">Operating Mode: SIMULATION</div>
                    <div class="engine-status">Environment: development</div>
                    <div class="engine-status">Version: 0.1.0</div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Response</span></div>
                    <div class="engine-status">Default Mode: alert_only</div>
                    <div class="engine-status">Dry Run: enabled</div>
                    <div class="engine-status">Manual Approval: enabled</div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Detection</span></div>
                    <div class="engine-status">Signature: enabled</div>
                    <div class="engine-status">Anomaly: enabled</div>
                    <div class="engine-status">Behavioral: enabled</div>
                    <div class="engine-status">ML: enabled</div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Data Retention</span></div>
                    <div class="engine-status">Events: 90 days</div>
                    <div class="engine-status">Alerts: 365 days</div>
                    <div class="engine-status">Audit: 365 days</div>
                </div>
            </div>
        `;
    }

    // --- Login ---
    function initAuth() {
        API.loadToken();

        document.getElementById('loginBtn').addEventListener('click', () => {
            document.getElementById('loginModal').style.display = 'flex';
        });

        document.getElementById('loginModalClose').addEventListener('click', () => {
            document.getElementById('loginModal').style.display = 'none';
        });

        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            const password = document.getElementById('loginPassword').value;
            const errEl = document.getElementById('loginError');

            const result = await API.login(username, password);
            if (result.error) {
                errEl.textContent = result.error.message;
                errEl.style.display = 'block';
            } else {
                errEl.style.display = 'none';
                document.getElementById('loginModal').style.display = 'none';
                document.getElementById('userInfo').querySelector('.user-name').textContent = username;
                renderPage(currentPage);
            }
        });
    }

    // --- Clock & Auto-refresh ---
    function startClock() {
        function update() {
            document.getElementById('statusTime').textContent = new Date().toLocaleTimeString();
        }
        update();
        setInterval(update, 1000);
    }

    function startAutoRefresh() {
        refreshInterval = setInterval(() => {
            if (currentPage === 'overview' || currentPage === 'alerts') {
                renderPage(currentPage);
            }
        }, 15000); // Refresh every 15 seconds
    }

    // --- Init ---
    document.addEventListener('DOMContentLoaded', () => {
        initAuth();
        initRouter();
        startClock();
        startAutoRefresh();

        document.getElementById('refreshBtn').addEventListener('click', () => renderPage(currentPage));

        // Sidebar & Mobile Navigation
        const sidebar = document.getElementById('sidebar');
        const backdrop = document.getElementById('sidebarBackdrop');
        const mobileMenuBtn = document.getElementById('mobileMenuBtn');

        function toggleMobileSidebar(open) {
            const isOpen = open !== undefined ? open : !sidebar.classList.contains('open');
            sidebar.classList.toggle('open', isOpen);
            if (backdrop) backdrop.classList.toggle('active', isOpen);
        }

        if (mobileMenuBtn) {
            mobileMenuBtn.addEventListener('click', () => toggleMobileSidebar());
        }

        if (backdrop) {
            backdrop.addEventListener('click', () => toggleMobileSidebar(false));
        }

        const sidebarToggle = document.getElementById('sidebarToggle');
        if (sidebarToggle) {
            sidebarToggle.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    toggleMobileSidebar(false);
                } else {
                    sidebar.classList.toggle('collapsed');
                }
            });
        }
    });
})();
