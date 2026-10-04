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

    async function renderSensors(el) {
        const res = await API.getSensors();
        const sensors = res.sensors || [];
        const cards = sensors.map(s => `
            <div class="engine-card">
                <div class="engine-name">
                    <span class="status-dot ${s.status === 'online' ? 'healthy' : 'down'}"></span>
                    ${s.name}
                </div>
                <div class="engine-status">ID: <span class="mono">${s.sensor_id}</span></div>
                <div class="engine-status">Type: ${s.type} · Status: <strong>${s.status.toUpperCase()}</strong></div>
                ${s.diagnostic ? `<div class="engine-status" style="font-size:0.8rem;color:var(--text-tertiary);">${s.diagnostic}</div>` : ''}
                <div class="metrics-grid" style="margin-top:12px;grid-template-columns:1fr 1fr;">
                    <div class="metric-card" style="padding:8px 12px;">
                        <div class="metric-value" style="font-size:1.1rem;">${formatNumber(s.stats?.packets_captured || 0)}</div>
                        <div class="metric-label" style="font-size:0.75rem;">Packets</div>
                    </div>
                    <div class="metric-card" style="padding:8px 12px;">
                        <div class="metric-value" style="font-size:1.1rem;">${formatNumber(s.stats?.events_generated || 0)}</div>
                        <div class="metric-label" style="font-size:0.75rem;">Events</div>
                    </div>
                </div>
            </div>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Sensors</h1><p class="page-subtitle">Telemetry capture interfaces and sensor adapters</p></div></div>
            <div class="engine-grid">
                ${cards || '<div class="empty-state">No sensors configured</div>'}
            </div>
        `;
    }

    async function renderTimeline(el) {
        const data = await API.getAlerts({ page_size: 25 });
        const alerts = data.items || [];
        if (!alerts.length) {
            el.innerHTML = `
                <div class="page-header"><div><h1 class="page-title">Attack Timeline</h1><p class="page-subtitle">Temporal attack progression & incident sequence</p></div></div>
                <div class="empty-state"><div class="empty-icon">📅</div><p class="empty-text">No attack alerts recorded yet in this window.</p></div>
            `;
            return;
        }

        const entries = alerts.map(a => `
            <div class="timeline-entry">
                <div class="timeline-marker ${a.severity}"></div>
                <div class="timeline-card">
                    <div class="timeline-header">
                        <span class="timeline-title">${a.title}</span>
                        <span class="timeline-time">${timeAgo(a.created_at)}</span>
                    </div>
                    <p style="font-size:0.85rem;color:var(--text-secondary);margin-bottom:8px;">${a.description || 'Intrusion detection alert triggered by anomaly/signature rules.'}</p>
                    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                        ${severityBadge(a.severity)}
                        <span class="badge badge-info">${a.source_type}</span>
                        <span class="mono" style="font-size:0.85rem;">${a.src_ip || '0.0.0.0'} → ${a.dst_ip || 'internal'}</span>
                        <span style="margin-left:auto;font-size:0.85rem;font-weight:600;color:var(--accent-primary-hover);">Risk Score: ${(a.risk_score || 0).toFixed(0)}/100</span>
                    </div>
                </div>
            </div>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Attack Timeline</h1><p class="page-subtitle">Chronological sequence of detected security events</p></div></div>
            <div class="timeline-track">
                ${entries}
            </div>
        `;
    }

    async function renderModels(el) {
        const data = await API.getEngines();
        const detectors = data.data?.detectors || [];
        const mlDetector = detectors.find(d => d.name === 'ml') || {
            name: 'ML Zero-Day Detector',
            version: '1.0.0',
            enabled: true,
            status: 'active',
            inference_count: 0
        };

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">ML Models</h1><p class="page-subtitle">Machine learning intrusion detection models and inference telemetry</p></div></div>
            <div class="metrics-grid">
                <div class="metric-card"><div class="metric-value">${mlDetector.inference_count || 0}</div><div class="metric-label">Total Inferences</div></div>
                <div class="metric-card"><div class="metric-value">${mlDetector.average_latency_ms ? mlDetector.average_latency_ms.toFixed(2) + ' ms' : '< 1 ms'}</div><div class="metric-label">Avg Inference Latency</div></div>
                <div class="metric-card"><div class="metric-value">RandomForest</div><div class="metric-label">Model Architecture</div></div>
                <div class="metric-card"><div class="metric-value">12</div><div class="metric-label">Input Features</div></div>
            </div>
            <div class="card" style="margin-top:1.5rem;">
                <div class="card-header"><span class="card-title">Active Model: nids-arc-rf-v1</span><span class="badge badge-success">ONLINE</span></div>
                <p style="color:var(--text-secondary);font-size:0.9rem;margin-bottom:1rem;">
                    Pre-trained tree ensemble for classifying network flows into benign baseline vs suspicious multi-stage attacks based on statistical flow vectors.
                </p>
                <h4 style="font-size:0.9rem;margin-bottom:0.5rem;color:var(--text-primary);">Evaluated Flow Features:</h4>
                <div style="display:flex;flex-wrap:wrap;gap:8px;">
                    <span class="badge badge-info">bytes_sent</span>
                    <span class="badge badge-info">bytes_received</span>
                    <span class="badge badge-info">packets_sent</span>
                    <span class="badge badge-info">packets_received</span>
                    <span class="badge badge-info">duration_ms</span>
                    <span class="badge badge-info">src_port</span>
                    <span class="badge badge-info">dst_port</span>
                    <span class="badge badge-info">protocol_tcp</span>
                    <span class="badge badge-info">protocol_udp</span>
                    <span class="badge badge-info">protocol_icmp</span>
                    <span class="badge badge-info">bytes_ratio</span>
                    <span class="badge badge-info">packet_ratio</span>
                </div>
            </div>
        `;
    }

    async function renderRules(el) {
        const res = await API.getRules();
        const rules = res.rules || [];
        const rows = rules.map(r => `
            <tr>
                <td class="mono font-semibold">${r.id}</td>
                <td>
                    <div style="font-weight:600;">${r.name}</div>
                    <small style="color:var(--text-tertiary);">${r.description || ''}</small>
                </td>
                <td>${severityBadge(r.severity)}</td>
                <td><span class="badge badge-info">${r.category}</span></td>
                <td>${(r.mitre_attack || []).map(m => `<span class="badge badge-warning mono">${m}</span>`).join(' ')}</td>
                <td style="text-align:center;">
                    <label class="toggle-switch">
                        <input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="window.toggleNidsRule('${r.id}', this.checked)">
                        <span class="toggle-slider"></span>
                    </label>
                </td>
            </tr>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Detection Rules</h1><p class="page-subtitle">${rules.length} total rules · ${res.enabled_count || 0} active</p></div></div>
            <div class="card" style="padding:0;overflow:auto;">
                <table class="data-table">
                    <thead><tr><th>ID</th><th>Rule Name</th><th>Severity</th><th>Category</th><th>MITRE ATT&CK</th><th style="text-align:center;">Status</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="6" style="text-align:center;padding:2rem;">No rules found</td></tr>'}</tbody>
                </table>
            </div>
        `;
    }

    window.toggleNidsRule = async function(ruleId, enabled) {
        const res = await API.toggleRule(ruleId, enabled);
        if (res.error) {
            alert('Failed to toggle rule: ' + (res.error.message || 'Error'));
        }
    };

    async function renderAudit(el) {
        const data = await API.getAuditLogs({ page_size: 50 });
        const items = data.items || [];
        const rows = items.map(l => `
            <tr>
                <td style="font-size:0.8rem;color:var(--text-tertiary);">${l.timestamp ? new Date(l.timestamp).toLocaleString() : '—'}</td>
                <td><span class="mono badge badge-info">${l.actor_username || 'system'}</span></td>
                <td class="font-semibold">${l.action}</td>
                <td><span class="badge badge-${l.result === 'success' ? 'success' : 'danger'}">${l.result}</span></td>
                <td class="mono" style="font-size:0.8rem;">${l.source_ip || '—'}</td>
                <td style="font-size:0.8rem;color:var(--text-secondary);">${l.details ? JSON.stringify(l.details).slice(0, 60) : '—'}</td>
            </tr>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Audit Logs</h1><p class="page-subtitle">Immutable security event and administration audit trail</p></div></div>
            <div class="card" style="padding:0;overflow:auto;">
                <table class="data-table">
                    <thead><tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Result</th><th>IP</th><th>Details</th></tr></thead>
                    <tbody>${rows || '<tr><td colspan="6" style="text-align:center;padding:2rem;">No audit logs recorded yet</td></tr>'}</tbody>
                </table>
            </div>
        `;
    }

    async function renderNetwork(el) {
        const data = await API.getNetworkActivity(24);
        const protocols = data.protocols || [];
        const topSources = data.top_sources || [];
        const topPorts = data.top_ports || [];

        const protoRows = protocols.map(p => `
            <div style="margin-bottom:12px;">
                <div style="display:flex;justify-content:space-between;font-size:0.85rem;margin-bottom:4px;">
                    <span class="font-semibold">${p.protocol}</span>
                    <span class="mono">${formatNumber(p.count)} pkts (${formatNumber(p.bytes)} B)</span>
                </div>
                <div class="progress-bar-bg">
                    <div class="progress-bar-fill" style="width:${Math.min(100, Math.max(5, (p.count / (protocols[0]?.count || 1)) * 100))}%;"></div>
                </div>
            </div>
        `).join('');

        const srcRows = topSources.map(s => `
            <tr><td class="mono font-semibold">${s.ip}</td><td class="mono" style="text-align:right;">${formatNumber(s.count)}</td></tr>
        `).join('');

        const portRows = topPorts.map(p => `
            <tr><td class="mono font-semibold">Port ${p.port}</td><td class="mono" style="text-align:right;">${formatNumber(p.count)}</td></tr>
        `).join('');

        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Network Activity</h1><p class="page-subtitle">24-hour protocol breakdown, flow metrics, and top network talkers</p></div></div>
            <div class="content-grid" style="grid-template-columns: 1.5fr 1fr; margin-bottom:1.5rem;">
                <div class="card">
                    <div class="card-header"><span class="card-title">Protocol Distribution</span></div>
                    <div style="margin-top:1rem;">
                        ${protoRows || '<p style="color:var(--text-tertiary);">No protocol data yet</p>'}
                    </div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Top Destination Ports</span></div>
                    <table class="data-table" style="margin-top:0.5rem;">
                        <thead><tr><th>Port</th><th style="text-align:right;">Packets</th></tr></thead>
                        <tbody>${portRows || '<tr><td colspan="2" style="text-align:center;">No data</td></tr>'}</tbody>
                    </table>
                </div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Top Source Talkers</span></div>
                <table class="data-table" style="margin-top:0.5rem;">
                    <thead><tr><th>Source IP Address</th><th style="text-align:right;">Packets Generated</th></tr></thead>
                    <tbody>${srcRows || '<tr><td colspan="2" style="text-align:center;">No data</td></tr>'}</tbody>
                </table>
            </div>
        `;
    }

    async function renderSettings(el) {
        const settings = await API.getSettings();
        el.innerHTML = `
            <div class="page-header"><div><h1 class="page-title">Settings</h1><p class="page-subtitle">Configure runtime engine parameters, simulation rate, and firewall protection</p></div></div>
            <div class="content-grid" style="grid-template-columns: 1fr 1fr;">
                <div class="card">
                    <div class="card-header"><span class="card-title">Engine Mode & Ingestion</span></div>
                    <div style="margin-top:1rem;">
                        <label style="display:block;font-size:0.85rem;margin-bottom:6px;color:var(--text-secondary);">Operating Mode</label>
                        <select id="cfgMode" class="form-control" style="width:100%;padding:8px 12px;background:var(--bg-elevated);color:var(--text-primary);border:1px solid var(--border-primary);border-radius:var(--radius-sm);margin-bottom:1rem;">
                            <option value="simulation" ${settings.app_mode === 'simulation' ? 'selected' : ''}>Simulation Mode (Synthetic Generator)</option>
                            <option value="real" ${settings.app_mode === 'real' ? 'selected' : ''}>Real Mode (Live Wi-Fi/Ethernet Sniffing)</option>
                        </select>

                        <label style="display:block;font-size:0.85rem;margin-bottom:6px;color:var(--text-secondary);">Simulation Events Per Second</label>
                        <input id="cfgEps" type="number" min="1" max="100" value="${settings.simulation_events_per_second || 10}" style="width:100%;padding:8px 12px;background:var(--bg-elevated);color:var(--text-primary);border:1px solid var(--border-primary);border-radius:var(--radius-sm);margin-bottom:1.5rem;">

                        <button id="btnSaveEngineSettings" class="btn btn-primary" style="padding:8px 16px;background:var(--accent-primary);color:white;border:none;border-radius:var(--radius-sm);cursor:pointer;font-weight:600;">Apply Changes</button>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header"><span class="card-title">Autonomous Response & Firewall</span></div>
                    <div style="margin-top:1rem;">
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1rem;">
                            <div>
                                <div style="font-weight:600;">Dry-Run Mode</div>
                                <small style="color:var(--text-tertiary);">Log response actions without executing OS firewall rules</small>
                            </div>
                            <label class="toggle-switch">
                                <input type="checkbox" id="cfgDryRun" ${settings.response_dry_run ? 'checked' : ''}>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>

                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;">
                            <div>
                                <div style="font-weight:600;">Require Manual Approval</div>
                                <small style="color:var(--text-tertiary);">Hold critical block actions until analyst approval</small>
                            </div>
                            <label class="toggle-switch">
                                <input type="checkbox" id="cfgApproval" ${settings.response_manual_approval ? 'checked' : ''}>
                                <span class="toggle-slider"></span>
                            </label>
                        </div>

                        <button id="btnSaveResponseSettings" class="btn btn-primary" style="padding:8px 16px;background:var(--accent-primary);color:white;border:none;border-radius:var(--radius-sm);cursor:pointer;font-weight:600;">Save Response Policies</button>
                    </div>
                </div>

                <div class="card" style="grid-column: 1 / -1;">
                    <div class="card-header"><span class="card-title">Database Maintenance & Retention</span></div>
                    <p style="color:var(--text-secondary);font-size:0.9rem;margin:0.5rem 0 1rem;">
                        Purges older security events and telemetry beyond the retention threshold to optimize SQLite performance and shrink disk bloat.
                    </p>
                    <button id="btnCleanupDb" class="btn" style="padding:8px 16px;background:var(--severity-high);color:white;border:none;border-radius:var(--radius-sm);cursor:pointer;font-weight:600;">
                        🧹 Purge Stale Events & Optimize DB
                    </button>
                    <span id="cleanupStatus" style="margin-left:12px;font-size:0.85rem;color:var(--status-success);"></span>
                </div>
            </div>
        `;

        document.getElementById('btnSaveEngineSettings').addEventListener('click', async () => {
            const mode = document.getElementById('cfgMode').value;
            const eps = parseInt(document.getElementById('cfgEps').value, 10);
            await API.updateSettings({ app_mode: mode, simulation_events_per_second: eps });
            alert('Engine settings applied!');
            renderPage('settings');
        });

        document.getElementById('btnSaveResponseSettings').addEventListener('click', async () => {
            const dryRun = document.getElementById('cfgDryRun').checked;
            const approval = document.getElementById('cfgApproval').checked;
            await API.updateSettings({ response_dry_run: dryRun, response_manual_approval: approval });
            alert('Response settings saved!');
        });

        document.getElementById('btnCleanupDb').addEventListener('click', async () => {
            if (!confirm('Are you sure you want to purge old telemetry events?')) return;
            const res = await API.cleanupDb();
            document.getElementById('cleanupStatus').textContent = res.message || 'Cleaned up successfully!';
        });
    }

    // --- Notifications Toast ---
    function showNotification(title, severity) {
        let container = document.getElementById('nidsToastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'nidsToastContainer';
            container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:10px;pointer-events:none;';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.style.cssText = `
            pointer-events:auto;
            min-width: 280px;
            max-width: 360px;
            background: var(--bg-surface);
            border-left: 4px solid var(--severity-${severity || 'high'});
            border-radius: var(--radius-sm);
            box-shadow: var(--shadow-lg);
            padding: 12px 16px;
            color: var(--text-primary);
            font-size: 0.85rem;
            animation: slideIn 0.3s ease;
            transition: opacity 0.3s;
        `;
        toast.innerHTML = `
            <div style="font-weight:600;margin-bottom:4px;display:flex;justify-content:space-between;">
                <span>🚨 Threat Detected</span>
                <span class="badge badge-${severity}">${severity}</span>
            </div>
            <div style="color:var(--text-secondary);font-size:0.8rem;">${title}</div>
        `;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    // --- WebSockets ---
    let ws = null;
    function initWebSocket() {
        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${proto}//${location.host}/ws/live`;

        try {
            ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                console.log('⚡ NIDS ARC WebSocket stream connected');
            };

            ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    if (msg.type === 'alert' && msg.alert) {
                        const badge = document.getElementById('alertBadge');
                        if (badge) {
                            badge.textContent = String(parseInt(badge.textContent || '0', 10) + 1);
                        }
                        showNotification(msg.alert.title, msg.alert.severity);

                        if (currentPage === 'overview' || currentPage === 'alerts' || currentPage === 'timeline') {
                            renderPage(currentPage);
                        }
                    }
                } catch (e) {
                    console.error('WS parse error', e);
                }
            };

            ws.onclose = () => {
                setTimeout(initWebSocket, 4000);
            };

            ws.onerror = () => {
                if (ws) ws.close();
            };
        } catch (err) {
            console.warn('WebSocket connection not supported or failed', err);
        }
    }

    // --- Login ---
    async function initAuth() {
        const hasToken = API.loadToken();

        // Auto-login fallback with default admin in development if no token saved
        if (!hasToken) {
            try {
                const res = await API.login('admin', 'Sumit@2003');
                if (!res.error) {
                    document.getElementById('userInfo').querySelector('.user-name').textContent = 'admin';
                }
            } catch (e) {
                console.warn('Auto-login skipped', e);
            }
        }

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
        }, 15000);
    }

    // --- Init ---
    document.addEventListener('DOMContentLoaded', () => {
        initAuth();
        initRouter();
        startClock();
        startAutoRefresh();
        initWebSocket();

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
