/**
 * Patchi v2.0 Mission Control — Dashboard Logic
 * WebSocket streaming, command palette, tool execution, live updates
 */

(function () {
    'use strict';

    // ── State ──────────────────────────────────────────────────────
    const state = {
        ws: null,
        connected: false,
        feedPaused: false,
        tools: [],
        selectedTool: null,
        paletteIndex: 0,
    };

    const init = window.PATCHI_INIT || {};

    // ── DOM refs ───────────────────────────────────────────────────
    const $ = (sel) => document.querySelector(sel);
    const agentFeed = $('#agentFeed');
    const findingsList = $('#findingsList');
    const connectionStatus = $('#connectionStatus');
    const healthScore = $('#healthScore');

    // ── WebSocket ──────────────────────────────────────────────────
    function connectWS() {
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        const ws = new WebSocket(`${proto}://${location.host}/ws/v2`);
        state.ws = ws;

        ws.onopen = () => {
            state.connected = true;
            if (connectionStatus) {
                connectionStatus.classList.add('online');
                connectionStatus.parentElement.querySelector('span:last-child').textContent = 'Connected';
            }
            addFeedEntry('system', 'Connected to Patchi mission control', 'success');
            // Subscribe to all channels
            send({ action: 'subscribe', data: { channels: ['agents', 'council', 'attacks', 'tests'] } });
        };

        ws.onclose = () => {
            state.connected = false;
            if (connectionStatus) {
                connectionStatus.classList.remove('online');
                connectionStatus.parentElement.querySelector('span:last-child').textContent = 'Disconnected';
            }
            setTimeout(connectWS, 3000); // Reconnect
        };

        ws.onerror = () => ws.close();

        ws.onmessage = (ev) => {
            try {
                const msg = JSON.parse(ev.data);
                handleEvent(msg.event, msg.data || {});
            } catch (e) {
                console.error('Bad WS message', e);
            }
        };
    }

    function send(obj) {
        if (state.ws && state.ws.readyState === WebSocket.OPEN) {
            state.ws.send(JSON.stringify(obj));
        }
    }

    // ── Event handlers ─────────────────────────────────────────────
    function handleEvent(event, data) {
        switch (event) {
            case 'pong':
                break;
            case 'initial_state':
                updateInitialState(data);
                break;
            case 'subscribed':
                break;
            case 'agent_started':
                addFeedEntry(data.agent, `▶ started — ${data.description || ''}`, '');
                break;
            case 'agent_done':
                addFeedEntry(
                    data.agent,
                    `✓ done in ${data.duration_ms}ms (${data.finding_count} findings, ${data.passed} passed / ${data.failed} failed)`,
                    data.status === 'failed' ? 'error' : 'success'
                );
                break;
            case 'agent_finding':
                addFinding(data);
                break;
            case 'council_result':
                renderCouncilResult(data);
                break;
            case 'tool_result':
                handleToolResult(data);
                break;
            case 'scan_completed':
                addFeedEntry('brain', `Scan complete: ${data.file_count} files, ${data.route_count} routes in ${(data.duration || 0).toFixed(1)}s`, 'success');
                refreshScanResults();
                break;
            case 'red_team_completed':
                addFeedEntry('redteam', `Assessment done: ${data.findings} findings across scenarios`, data.findings > 0 ? 'warning' : 'success');
                break;
            case 'live_test_completed':
                addFeedEntry('tests', 'Live test run completed', 'success');
                break;
            case 'error':
                addFeedEntry('system', `Error: ${data.message}`, 'error');
                break;
            default:
                console.debug('Unhandled event:', event, data);
        }
    }

    function updateInitialState(data) {
        if (healthScore && typeof data.health_score === 'number') {
            healthScore.textContent = data.health_score;
            healthScore.style.color =
                data.health_score >= 80 ? 'var(--success)' :
                data.health_score >= 50 ? 'var(--warning)' : 'var(--danger)';
        }
    }

    // ── Feed ───────────────────────────────────────────────────────
    function addFeedEntry(agent, message, cls) {
        if (!agentFeed || state.feedPaused) return;

        // Remove empty placeholder
        const empty = agentFeed.querySelector('.feed-empty');
        if (empty) empty.remove();

        const entry = document.createElement('div');
        entry.className = `feed-entry ${cls || ''}`;
        const time = new Date().toLocaleTimeString();
        entry.innerHTML = `
            <span class="feed-time">${time}</span>
            <span class="feed-agent">[${escapeHtml(agent)}]</span>
            <span class="feed-message">${escapeHtml(message)}</span>
        `;
        agentFeed.prepend(entry);

        // Cap feed at 200 entries
        while (agentFeed.children.length > 200) {
            agentFeed.lastChild.remove();
        }
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    // ── Findings ───────────────────────────────────────────────────
    function addFinding(f) {
        const countBadge = $('#findingsCount');
        if (countBadge) {
            countBadge.textContent = parseInt(countBadge.textContent || '0', 10) + 1;
        }
        if (!findingsList) return;
        const empty = findingsList.querySelector('.feed-empty');
        if (empty) empty.remove();

        const item = document.createElement('article');
        item.className = 'finding-item';
        item.dataset.severity = f.severity || 'info';
        item.innerHTML = `
            <div class="finding-header">
                <span class="finding-severity severity-${f.severity || 'info'}">${f.severity || 'info'}</span>
                <span class="finding-type">${escapeHtml(f.type || '')}</span>
            </div>
            <p class="finding-message">${escapeHtml(f.message || '')}</p>
            <div class="finding-meta">
                <span class="finding-source">${escapeHtml(f.agent || '')}</span>
                ${f.file ? `<span class="finding-file">${escapeHtml(f.file)}:${f.line || 0}</span>` : ''}
            </div>
        `;
        findingsList.prepend(item);
    }

    // ── Council result rendering ───────────────────────────────────
    function renderCouncilResult(data) {
        let panel = document.getElementById('councilLivePanel');
        if (!panel) {
            panel = document.createElement('section');
            panel.id = 'councilLivePanel';
            panel.className = 'panel panel-full';
            document.querySelector('.content-area').prepend(panel);
        }
        panel.innerHTML = `
            <header class="panel-header">
                <h2 class="panel-title">🏛️ Council Deliberation</h2>
                <span class="consensus-badge ${data.consensus ? 'reached' : 'not-reached'}">
                    ${data.consensus ? 'Consensus Reached' : 'No Consensus'}
                </span>
            </header>
            <div class="panel-body">
                <p style="margin-bottom:12px;color:var(--text-secondary)">
                    <strong>Issue:</strong> ${escapeHtml(data.issue)}
                </p>
                <div class="council-synthesis">${escapeHtml(data.synthesis)}</div>
                ${renderActionPlan(data.action_plan)}
            </div>
        `;
    }

    function renderActionPlan(plan) {
        if (!plan || !plan.length) return '';
        return `
            <h4 style="margin-top:14px;margin-bottom:8px;font-size:12px;color:var(--text-muted);text-transform:uppercase;">
                Action Plan (${plan.length} steps)
            </h4>
            <ol style="padding-left:20px;font-size:13px;color:var(--text-secondary)">
                ${plan.map(s => `<li><code style="color:var(--accent)">${escapeHtml(s.tool)}</code> — ${escapeHtml((s.rationale || '').slice(0, 120))}</li>`).join('')}
            </ol>
        `;
    }

    // ── Command Palette ────────────────────────────────────────────
    const paletteModal = $('#commandPaletteModal');
    const paletteInput = $('#paletteInput');
    const paletteResults = $('#paletteResults');

    async function openPalette() {
        paletteModal.hidden = false;
        paletteInput.value = '';
        paletteInput.focus();
        await loadTools();
        renderPaletteResults('');
    }

    function closePalette() {
        paletteModal.hidden = true;
    }

    async function loadTools() {
        try {
            const res = await fetch('/api/v2/tools/list');
            const json = await res.json();
            state.tools = json.tools || [];
        } catch (e) {
            state.tools = [];
        }
    }

    function renderPaletteResults(query) {
        if (!paletteResults) return;
        const q = query.toLowerCase().trim();

        // If query doesn't match any tool and looks like a question → offer council
        const matches = state.tools.filter(t =>
            !q || t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q)
        );

        let html = '';

        if (q.length > 3 && !matches.some(t => t.name === q)) {
            html += `
                <div class="palette-result" data-council="${escapeHtml(query)}">
                    <span class="name">🏛️ Ask the Council: "${escapeHtml(query.slice(0, 60))}"</span>
                    <span class="category">AI</span>
                </div>`;
        }

        html += matches.map(t => `
            <div class="palette-result" data-tool="${t.name}">
                <span class="name">${escapeHtml(t.name)}</span>
                <span class="category">${escapeHtml(t.category)}${t.requires_confirmation ? ' ⚠' : ''}</span>
            </div>
        `).join('');

        paletteResults.innerHTML = html || '<div class="feed-empty">No matching commands</div>';
    }

    function selectPaletteItem(el) {
        const toolName = el.dataset.tool;
        const councilQuery = el.dataset.council;

        closePalette();

        if (toolName) {
            openToolConfirmation(toolName);
        } else if (councilQuery) {
            send({ action: 'council_query', data: { issue: councilQuery } });
            addFeedEntry('council', `Deliberating on: ${councilQuery}`, '');
        }
    }

    // ── Tool Confirmation ──────────────────────────────────────────
    const confirmModal = $('#toolConfirmModal');

    async function openToolConfirmation(toolName, presetParams = {}) {
        const tool = state.tools.find(t => t.name === toolName);
        if (!tool) return;

        $('#confirmToolName').textContent = toolName;
        $('#confirmToolDesc').textContent = tool.description;
        $('#confirmSideEffects').innerHTML = tool.side_effects
            ? `⚠ Side effects: ${escapeHtml(tool.side_effects)}` : '';

        // Simple parameter collection via prompt for required params
        const params = { ...presetParams };
        if (!Object.keys(presetParams).length) {
            const schemaRes = await fetch(`/api/v2/tools/list`);
            // For now use sensible defaults; a full form UI is future work
            params._defaults = true;
        }

        $('#confirmToolParams').textContent = JSON.stringify(params, null, 2);

        $('#confirmExecute').onclick = () => {
            delete params._defaults;
            executeTool(toolName, params);
            confirmModal.hidden = true;
        };
        $('#confirmCancel').onclick = () => { confirmModal.hidden = true; };

        confirmModal.hidden = false;
    }

    async function executeTool(toolName, parameters) {
        addFeedEntry('tools', `Executing ${toolName}...`, '');
        try {
            const res = await fetch('/api/v2/tools/execute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tool: toolName, parameters }),
            });
            const json = await res.json();
            if (json.success) {
                addFeedEntry('tools', `${toolName} completed`, 'success');
            } else {
                addFeedEntry('tools', `${toolName} failed: ${json.error || 'unknown error'}`, 'error');
            }
            handleToolResult(json);
        } catch (e) {
            addFeedEntry('tools', `${toolName} request failed: ${e.message}`, 'error');
        }
    }

    function handleToolResult(data) {
        if (!data.success) {
            addFeedEntry('tool', `Error: ${data.error || 'unknown'}`, 'error');
            return;
        }
        const resultStr = JSON.stringify(data.result).slice(0, 200);
        addFeedEntry(data.tool || 'tool', `→ ${resultStr}${resultStr.length >= 200 ? '…' : ''}`, 'success');
    }

    // ── Quick actions ──────────────────────────────────────────────
    function bindQuickActions() {
        document.querySelectorAll('.action-item[data-action]').forEach(item => {
            item.addEventListener('click', () => {
                const action = item.dataset.action;
                switch (action) {
                    case 'scan':
                        send({ action: 'start_scan', data: {} });
                        addFeedEntry('brain', 'Full scan started...', '');
                        break;
                    case 'redteam':
                        openToolConfirmation('red_team');
                        break;
                    case 'livetest':
                        openToolConfirmation('run_tests');
                        break;
                    case 'council':
                        openPalette();
                        break;
                }
            });
        });

        const quickScan = $('#quickScan');
        if (quickScan) {
            quickScan.addEventListener('click', async () => {
                quickScan.disabled = true;
                quickScan.querySelector('span').textContent = 'Scanning…';
                try {
                    const resp = await fetch('/api/scan/quick', { method: 'POST' });
                    const data = await resp.json();
                    if (data.ok) {
                        const n = data.agents_queued ? data.agents_queued.length : 0;
                        const d = data.domains ? Object.keys(data.domains).length : 0;
                        addFeedEntry('brain',
                            `Quick scan: ${n} agents, ${d} domains, ${data.changed_files ? data.changed_files.length : 0} files changed`,
                            '');
                    } else {
                        addFeedEntry('brain', `Quick scan failed: ${data.error}`, '');
                    }
                } catch (e) {
                    addFeedEntry('brain', `Quick scan error: ${e.message}`, '');
                } finally {
                    quickScan.disabled = false;
                    quickScan.querySelector('span').textContent = 'Scan';
                }
            });
        }

        const clearBtn = $('#clearFeed');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                agentFeed.innerHTML = '<div class="feed-empty">Feed cleared</div>';
            });
        }

        const pauseBtn = $('#pauseFeed');
        if (pauseBtn) {
            pauseBtn.addEventListener('click', () => {
                state.feedPaused = !state.feedPaused;
                pauseBtn.textContent = state.feedPaused ? 'Resume' : 'Pause';
                pauseBtn.setAttribute('aria-pressed', String(state.feedPaused));
            });
        }

        // Tool items in sidebar
        document.querySelectorAll('.tool-item[data-tool]').forEach(item => {
            item.addEventListener('click', () => openToolConfirmation(item.dataset.tool));
        });
    }

    // ── Keyboard shortcuts ─────────────────────────────────────────
    function bindKeyboard() {
        document.addEventListener('keydown', (e) => {
            // Cmd/Ctrl+K → palette
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                if (paletteModal.hidden) openPalette();
                else closePalette();
                return;
            }
            // Escape closes modals
            if (e.key === 'Escape') {
                closePalette();
                if (confirmModal) confirmModal.hidden = true;
                return;
            }
            if (paletteModal && !paletteModal.hidden) {
                const items = paletteResults.querySelectorAll('.palette-result');
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    state.paletteIndex = Math.min(state.paletteIndex + 1, items.length - 1);
                } else if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    state.paletteIndex = Math.max(state.paletteIndex - 1, 0);
                } else if (e.key === 'Enter') {
                    e.preventDefault();
                    if (items[state.paletteIndex]) selectPaletteItem(items[state.paletteIndex]);
                    return;
                } else {
                    state.paletteIndex = 0;
                }
                items.forEach((el, i) => el.classList.toggle('selected', i === state.paletteIndex));
            }
        });
    }

    // ── Init ───────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', () => {
        connectWS();

        const cmdBtn = $('#commandPalette');
        if (cmdBtn) cmdBtn.addEventListener('click', openPalette);

        if (paletteInput) {
            paletteInput.addEventListener('input', (e) => renderPaletteResults(e.target.value));
        }
        if (paletteResults) {
            paletteResults.addEventListener('click', (e) => {
                const item = e.target.closest('.palette-result');
                if (item) selectPaletteItem(item);
            });
        }

        // Click outside modal to close
        [paletteModal, confirmModal].forEach(m => {
            if (m) m.addEventListener('click', (e) => {
                if (e.target === m) m.hidden = true;
            });
        });

        bindQuickActions();
        bindKeyboard();

        // Health score color from init
        if (healthScore && typeof init.healthScore === 'number') {
            healthScore.style.color =
                init.healthScore >= 80 ? 'var(--success)' :
                init.healthScore >= 50 ? 'var(--warning)' : 'var(--danger)';
        }

        // Mode selector
        const modeSelect = $('#modeSelect');
        if (modeSelect) {
            modeSelect.addEventListener('change', () => {
                fetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: 'mode', value: modeSelect.value }),
                }).then(r => r.json()).then(j => {
                    if (!j.ok) addFeedEntry('config', `Failed to save mode: ${j.error || '?'}`, 'error');
                }).catch(() => addFeedEntry('config', 'Failed to save mode', 'error'));
            });
        }

        // Project switcher — multi-project support
        const projectSelect = $('#projectSelect');
        if (projectSelect) {
            (async () => {
                try {
                    const [disc, list] = await Promise.all([
                        fetch('/api/tenant/discover').then(r => r.json()),
                        fetch('/api/tenant/list').then(r => r.json()),
                    ]);
                    const options = new Map(); // path -> name
                    const currentPath = disc.current ? disc.current.root : (init.projectRoot || '');
                    for (const p of list.projects || []) options.set(p.root, p.name);
                    for (const d of disc.discovered || []) options.set(d.path, d.name);
                    if (currentPath && !options.has(currentPath)) {
                        options.set(currentPath, disc.current ? disc.current.name : currentPath);
                    }
                    projectSelect.innerHTML = '';
                    for (const [path, name] of options) {
                        const opt = document.createElement('option');
                        opt.value = path;
                        opt.textContent = name + (path === currentPath ? ' ●' : '');
                        opt.selected = path === currentPath;
                        if (path === currentPath) {
                            // 1:1 with CLI: show exactly which directory is being served
                            opt.textContent += ` — ${path}`;
                            document.title = `${name} — Patchi`;
                            projectSelect.title = path;
                        }
                        projectSelect.appendChild(opt);
                    }
                } catch (e) {
                    projectSelect.innerHTML = '<option value="">project?</option>';
                }
            })();

            projectSelect.addEventListener('change', async () => {
                const target = projectSelect.value;
                if (!target) return;
                addFeedEntry('system', `Switching project → ${target.split(/[\\/]/).pop()}…`, '');
                try {
                    const res = await fetch('/api/tenant/switch', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ path: target }),
                    });
                    const json = await res.json();
                    if (json.success) {
                        location.reload(); // re-render everything against the new root
                    } else {
                        addFeedEntry('system', `Switch failed: ${json.error || res.status}`, 'error');
                    }
                } catch (e) {
                    addFeedEntry('system', `Switch failed: ${e.message}`, 'error');
                }
            });
        }

        addFeedEntry('system', 'Mission control initialized', 'success');
    });

    // Heartbeat ping every 30s
    setInterval(() => send({ action: 'ping', data: {} }), 30000);

    // Refresh scan results after scan completes
    function refreshScanResults() {
        // Refresh findings list
        fetch('/api/scan')
            .then(r => r.json())
            .then(data => {
                const findings = data.findings || [];
                const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
                findings.forEach(f => {
                    const s = (f.severity || 'info').toLowerCase();
                    if (bySev[s] !== undefined) bySev[s]++;
                });
                // Update severity counts
                Object.keys(bySev).forEach(s => {
                    const el = document.getElementById('count-' + s);
                    if (el) el.textContent = bySev[s];
                });
                addFeedEntry('system', `Findings updated: ${findings.length} total (${Object.entries(bySev).map(([k,v]) => v + ' ' + k).join(', ')})`, 'success');
            })
            .catch(e => addFeedEntry('system', 'Failed to refresh findings: ' + e.message, 'error'));
    }
})();
