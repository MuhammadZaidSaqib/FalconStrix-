/* Full reload / refresh: stay at top (browser scroll restoration often restores mid-page) */
if ('scrollRestoration' in history) {
    history.scrollRestoration = 'manual';
}

function scrollAppToTop() {
    window.scrollTo(0, 0);
    document.documentElement.scrollTop = 0;
    document.body.scrollTop = 0;
    const mc = document.querySelector('.main-content');
    if (mc) mc.scrollTop = 0;
}

document.addEventListener("DOMContentLoaded", () => {
    scrollAppToTop();

    const socket = io();

    // ═══ Element References ══════════════════════════════════════════════
    const startupScreen = document.getElementById('startup-screen');
    const connectionBadge = document.getElementById('connection-badge');
    const statusBadge = document.getElementById('status-badge');
    const overlay = document.getElementById('defensive-overlay');
    const alertList = document.getElementById('alert-list-table');
    const eventList = document.getElementById('event-list');
    const stateHistoryList = document.getElementById('state-history-list');
    const epmValue = document.getElementById('epm-value');
    const activeAlertsValue = document.getElementById('active-alerts-value');
    const threatScoreValue = document.getElementById('threat-score-value');
    const responseActionsValue = document.getElementById('response-actions-value');
    const analysisState = document.getElementById('analysis-state');
    const analysisSummary = document.getElementById('analysis-summary');
    const highestSeverity = document.getElementById('highest-severity');
    const openIncidents = document.getElementById('open-incidents');
    const feedCount = document.getElementById('feed-count');
    const pageTitle = document.getElementById('page-title');
    const sidebarAlertCount = document.getElementById('sidebar-alert-count');
    const sidebarConn = document.getElementById('sidebar-connection');
    const sidebarConnText = document.getElementById('sidebar-conn-text');

    const severityEls = {
        LOW: document.getElementById('sev-low-count'),
        MEDIUM: document.getElementById('sev-medium-count'),
        HIGH: document.getElementById('sev-high-count'),
        CRITICAL: document.getElementById('sev-critical-count')
    };
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

    // ═══ Sidebar Navigation ══════════════════════════════════════════════
    const sidebar = document.getElementById('sidebar');
    const sidebarBackdrop = document.getElementById('sidebar-backdrop');
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const navItems = document.querySelectorAll('.nav-item');
    const pages = document.querySelectorAll('.page');

    const pageTitles = {
        'dashboard': 'Dashboard',
        'alerts': 'Live Alerts',
        'events': 'Events Log',
        'fsm': 'FSM State Machine',
        'os-concepts': 'OS Concepts Overview',
        'os-process': 'Process Creation & Management',
        'os-threads': 'Multithreading',
        'os-sync': 'Synchronization (Mutex)',
        'os-ipc': 'Inter-Process Communication',
        'os-signals': 'Signal Handling',
        'os-resources': 'Resource Monitoring',
        'red-team': 'Red Team Simulation',
        'response': 'Response Engine'
    };

    const laneMonitor = document.getElementById('thread-viz-monitor');
    const laneBehavior = document.getElementById('thread-viz-behavior');
    const laneResource = document.getElementById('thread-viz-resource');

    const vizOsProcessCaption = document.getElementById('viz-os-process-caption');
    const vizOsProcessParent = document.getElementById('viz-os-process-parent');
    const vizOsProcessChild = document.getElementById('viz-os-process-child');
    const vizMutexCaption = document.getElementById('viz-os-sync-caption');
    const vizMutexA = document.getElementById('viz-mutex-thread-a');
    const vizMutexB = document.getElementById('viz-mutex-thread-b');
    const vizMutexLock = document.getElementById('viz-mutex-lock');
    const vizIpcCaption = document.getElementById('viz-os-ipc-caption');
    const vizIpcDot = document.getElementById('viz-ipc-dot');
    const vizSigCaption = document.getElementById('viz-os-signals-caption');
    const vizSigNodes = document.querySelectorAll('[data-viz-sig-node]');
    const vizResCpu = document.getElementById('viz-res-cpu-fill');
    const vizResMem = document.getElementById('viz-res-mem-fill');
    const vizResCpuLabel = document.getElementById('viz-res-cpu-label');
    const vizResMemLabel = document.getElementById('viz-res-mem-label');
    const vizResCaption = document.getElementById('viz-os-resources-caption');
    const vizResPipeNodes = document.querySelectorAll('[data-viz-res-pipe]');
    const vizResBoxes = document.querySelectorAll('[data-viz-res-box]');
    const vizResAlertStrip = document.getElementById('viz-res-alert-strip');
    const vizResCpuFields = document.getElementById('viz-res-cpu-fields');
    const vizResMemFields = document.getElementById('viz-res-mem-fields');
    const vizResProcFields = document.getElementById('viz-res-proc-fields');
    const vizConceptNodes = document.querySelectorAll('[data-concept-viz-node]');
    const vizFsmBadge = document.getElementById('viz-response-fsm');
    const vizKillTarget = document.getElementById('viz-response-kill-target');
    const vizResponseCaption = document.getElementById('viz-response-caption');

    const rtLoginCaption = document.getElementById('viz-rt-login-caption');
    const rtLoginTrack = document.getElementById('viz-rt-login-track');
    const rtFloodCaption = document.getElementById('viz-rt-flood-caption');
    const rtFloodTrack = document.getElementById('viz-rt-flood-track');
    const rtFileCaption = document.getElementById('viz-rt-file-caption');
    const rtFileTrack = document.getElementById('viz-rt-file-track');
    const rtSuiteCaption = document.getElementById('viz-rt-suite-caption');
    const rtSuiteTrack = document.getElementById('viz-rt-suite-track');
    const rtJsonSample = document.getElementById('rt-json-sample');
    const rtJsonBadge = document.getElementById('rt-json-badge');
    const rtTermLog = document.getElementById('rt-term-log');
    const rtJsonPanel = document.getElementById('rt-json-panel');
    const rtTermPanel = document.getElementById('rt-term-panel');
    const redTeamGrid = document.getElementById('red-team-grid');
    const rtNextBtn = document.getElementById('rt-next-btn');
    const rtResetBtn = document.getElementById('rt-reset-btn');
    const rtStepHint = document.getElementById('rt-step-hint');

    const RT_SCENARIOS = [
        {
            badge: 'AUTH_FAILED',
            json:
                '{\n  "event_type": "AUTH_FAILED",\n  "severity": 2,\n  "description": "Failed login for root",\n  "source": "Auth_Log",\n  "process_name": "ssh_login_sim"\n}',
            lines: [
                '$ python login_simulator.py',
                '[RED TEAM] Starting login brute-force simulator',
                '[>] Sent Login Failure 1/5  →  append(hidrs_events)',
                '[BACKEND] Recv Event: AUTH_FAILED - Failed login…'
            ]
        },
        {
            badge: 'PROCESS_SPAM',
            json:
                '{\n  "event_type": "PROCESS_SPAM",\n  "severity": 3,\n  "description": "Rapid subprocess spawn",\n  "source": "Process_Subsystem"\n}',
            lines: [
                '$ python process_flood.py',
                '[spawn] sleep/timeout subprocesses → OS engine may see spike',
                '[>] PROCESS_SPAM JSON line → same pipe as C++',
                '[MONITOR] Process count: …  (blue team thread)'
            ]
        },
        {
            badge: 'FILE_TAMPER',
            json:
                '{\n  "event_type": "FILE_TAMPER",\n  "severity": 4,\n  "description": "Critical file modified",\n  "source": "File_System"\n}',
            lines: [
                '$ python file_tamper_simulator.py',
                '[~] touch dummy_passwd / tamper target',
                '[>] FILE_TAMPER severity 4 → CRITICAL',
                '[alert_service] create_alert → FSM may escalate'
            ]
        },
        {
            badge: 'CHAINED',
            json:
                '{\n  "event_type": "AUTH_FAILED",\n  "severity": 2,\n  "source": "Auth_Log"\n}\n{\n  "event_type": "PROCESS_SPAM",\n  "severity": 3\n}\n… suite runs multiple lines',
            lines: [
                '$ python attack_controller.py',
                '[1] login_simulator  [2] process_flood  [3] file_tamper',
                '[suite] full chain — same ipc_config.PIPE_PATH',
                '[dashboard] Live Alerts + Events show ingested rows'
            ]
        }
    ];

    let rtSelectedIndex = null;
    let rtRevealStep = 0;

    function rtSetCardActive(index) {
        document.querySelectorAll('.red-team-card').forEach((c) => {
            c.classList.toggle('red-team-card--active', index !== null && Number(c.dataset.rt) === index);
        });
    }

    function rtIdleOutputCopy() {
        if (rtJsonBadge) rtJsonBadge.textContent = '—';
        if (rtJsonSample) {
            rtJsonSample.textContent = 'Select a script, then use Next to show the JSON event.';
            rtJsonSample.classList.add('rt-json-pre--muted');
        }
        if (rtTermLog) {
            rtTermLog.textContent = 'Console output appears here one line per Next click.';
            rtTermLog.classList.add('rt-term-body--muted');
        }
        if (rtJsonPanel) rtJsonPanel.classList.add('rt-json-panel--idle');
        if (rtTermPanel) rtTermPanel.classList.add('rt-term-panel--idle');
    }

    function rtResetInteractive() {
        rtSelectedIndex = null;
        rtRevealStep = 0;
        rtSetCardActive(null);
        rtIdleOutputCopy();
        if (rtNextBtn) rtNextBtn.disabled = true;
        if (rtResetBtn) rtResetBtn.disabled = true;
        if (rtStepHint) {
            rtStepHint.innerHTML =
                'Choose a script card above, then press <strong>Next</strong> to reveal the payload and console line by line.';
        }
    }

    function rtApplyReveal() {
        if (rtSelectedIndex === null) return;
        const sc = RT_SCENARIOS[rtSelectedIndex];
        const maxStep = 1 + sc.lines.length;

        if (rtRevealStep >= 1) {
            if (rtJsonBadge) rtJsonBadge.textContent = sc.badge;
            if (rtJsonSample) {
                rtJsonSample.textContent = sc.json;
                rtJsonSample.classList.remove('rt-json-pre--muted');
            }
            if (rtJsonPanel) rtJsonPanel.classList.remove('rt-json-panel--idle');
        }

        if (rtRevealStep >= 2) {
            const n = rtRevealStep - 1;
            if (rtTermLog) {
                rtTermLog.textContent = sc.lines.slice(0, n).join('\n');
                rtTermLog.classList.remove('rt-term-body--muted');
            }
            if (rtTermPanel) rtTermPanel.classList.remove('rt-term-panel--idle');
        } else if (rtRevealStep === 1) {
            if (rtTermLog) {
                rtTermLog.textContent = 'Press Next for each console line…';
                rtTermLog.classList.add('rt-term-body--muted');
            }
        }

        if (rtNextBtn) rtNextBtn.disabled = rtRevealStep >= maxStep;
        if (rtResetBtn) rtResetBtn.disabled = false;

        if (rtStepHint) {
            if (rtRevealStep === 0) {
                rtStepHint.textContent = `${sc.badge} selected. Press Next to show the JSON payload, then one Next per console line (${sc.lines.length} lines).`;
            } else if (rtRevealStep < maxStep) {
                const shown = rtRevealStep <= 1 ? 0 : rtRevealStep - 1;
                rtStepHint.textContent = `Step ${rtRevealStep} of ${maxStep}: ${shown} console line(s) shown. Press Next to continue.`;
            } else {
                rtStepHint.textContent = 'Full path shown for this script. Choose another card or Reset to replay.';
            }
        }
    }

    function rtSelectCard(index) {
        rtSelectedIndex = index;
        rtRevealStep = 0;
        rtSetCardActive(index);
        rtIdleOutputCopy();
        if (rtNextBtn) rtNextBtn.disabled = false;
        if (rtResetBtn) rtResetBtn.disabled = false;
        rtApplyReveal();
    }

    function rtOnNext() {
        if (rtSelectedIndex === null) return;
        const sc = RT_SCENARIOS[rtSelectedIndex];
        const maxStep = 1 + sc.lines.length;
        if (rtRevealStep >= maxStep) return;
        rtRevealStep += 1;
        rtApplyReveal();
    }

    function rtOnReset() {
        if (rtSelectedIndex === null) return;
        rtRevealStep = 0;
        rtIdleOutputCopy();
        if (rtNextBtn) rtNextBtn.disabled = false;
        rtApplyReveal();
    }

    if (redTeamGrid) {
        redTeamGrid.addEventListener('click', (e) => {
            const card = e.target.closest('.red-team-card');
            if (!card || !redTeamGrid.contains(card)) return;
            const idx = Number(card.dataset.rt);
            if (!Number.isFinite(idx)) return;
            rtSelectCard(idx);
        });
        redTeamGrid.addEventListener('keydown', (e) => {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            const card = e.target.closest('.red-team-card');
            if (!card || !redTeamGrid.contains(card)) return;
            e.preventDefault();
            const idx = Number(card.dataset.rt);
            if (!Number.isFinite(idx)) return;
            rtSelectCard(idx);
        });
    }
    if (rtNextBtn) rtNextBtn.addEventListener('click', rtOnNext);
    if (rtResetBtn) rtResetBtn.addEventListener('click', rtOnReset);

    let conceptVizRaf = null;
    let conceptVizT0 = 0;
    let conceptVizPage = null;

    const VIZ_PAGES = new Set([
        'os-concepts',
        'os-process',
        'os-sync',
        'os-ipc',
        'os-signals',
        'os-resources',
        'os-threads',
        'red-team',
        'response'
    ]);

    function stopConceptViz() {
        if (conceptVizRaf != null) {
            cancelAnimationFrame(conceptVizRaf);
            conceptVizRaf = null;
        }
        conceptVizPage = null;
    }

    function setLaneVisual(lane, workScale, sleepScale) {
        if (!lane) return;
        const workEl = lane.querySelector('[data-thread-viz-work]');
        const sleepEl = lane.querySelector('[data-thread-viz-sleep]');
        if (workEl) {
            workEl.style.transform = `scaleX(${Math.max(0, Math.min(1, workScale))})`;
            workEl.style.opacity = workScale > 0.02 ? '1' : '0';
        }
        if (sleepEl) {
            sleepEl.style.transform = `scaleX(${Math.max(0, Math.min(1, sleepScale))})`;
        }
    }

    function setLaneSteps(lane, activeStep) {
        if (!lane) return;
        lane.querySelectorAll('[data-thread-viz-steps] [data-step]').forEach((li) => {
            li.classList.toggle('active', li.getAttribute('data-step') === activeStep);
        });
    }

    function setLaneCaption(lane, text) {
        const cap = lane && lane.querySelector('[data-thread-viz-status]');
        if (cap) cap.textContent = text;
    }

    function setRtLane(captionEl, trackEl, workScale, sleepScale, text) {
        if (captionEl) captionEl.textContent = text;
        if (trackEl) {
            const w = trackEl.querySelector('[data-thread-viz-work]');
            const s = trackEl.querySelector('[data-thread-viz-sleep]');
            if (w) {
                w.style.transform = `scaleX(${Math.max(0, Math.min(1, workScale))})`;
                w.style.opacity = workScale > 0.02 ? '1' : '0';
            }
            if (s) s.style.transform = `scaleX(${Math.max(0, Math.min(1, sleepScale))})`;
        }
    }

    function updateOsThreadsViz(elapsed) {
        const p1 = 5000;
        const w1 = 420;
        const m1 = elapsed % p1;
        if (m1 < w1) {
            const r = m1 / w1;
            const sub = r < 1 / 3 ? '0' : r < 2 / 3 ? '1' : '2';
            setLaneSteps(laneMonitor, sub);
            const demoCount = (Math.floor(elapsed / 5200) % 2 === 1) ? 612 : 247;
            if (sub === '0') {
                setLaneCaption(laneMonitor, '[MONITOR] get_process_count() → ' + demoCount);
            } else if (sub === '1') {
                setLaneCaption(laneMonitor, '[MONITOR] Process count: ' + demoCount);
            } else {
                setLaneCaption(
                    laneMonitor,
                    demoCount > 500
                        ? '[MONITOR] Warning: High process count (' + demoCount + ')'
                        : '[MONITOR] threshold OK (≤500)'
                );
            }
            setLaneVisual(laneMonitor, 0.18 + r * 0.12, 0);
        } else {
            setLaneSteps(laneMonitor, 'sleep');
            const sleepP = (m1 - w1) / (p1 - w1);
            setLaneCaption(
                laneMonitor,
                '[MONITOR] sleep(5) — next wake in ' + (5 * (1 - sleepP)).toFixed(1) + 's'
            );
            setLaneVisual(laneMonitor, 0, sleepP);
        }

        const p2 = 2000;
        const w2 = 520;
        const m2 = elapsed % p2;
        if (m2 < w2) {
            const r = m2 / w2;
            const sub = r < 0.34 ? '0' : r < 0.78 ? '1' : '2';
            setLaneSteps(laneBehavior, sub);
            if (sub === '0') {
                setLaneCaption(laneBehavior, '[DETECTOR] Δ process count vs last cycle');
            } else if (sub === '1') {
                setLaneCaption(laneBehavior, '[DETECTOR] scanning PIDs (mutex-protected)…');
            } else {
                setLaneCaption(
                    laneBehavior,
                    '[DETECTOR] checking cmdline for nc / ncat / netcat'
                );
            }
            setLaneVisual(laneBehavior, 0.2 + r * 0.12, 0);
        } else {
            setLaneSteps(laneBehavior, 'sleep');
            const sleepP = (m2 - w2) / (p2 - w2);
            setLaneCaption(
                laneBehavior,
                '[DETECTOR] sleep(2) — next wake in ' + (2 * (1 - sleepP)).toFixed(1) + 's'
            );
            setLaneVisual(laneBehavior, 0, sleepP);
        }

        const primeMs = 1000;
        if (elapsed < primeMs) {
            setLaneSteps(laneResource, 'prime');
            const r = elapsed / primeMs;
            setLaneCaption(
                laneResource,
                '[RES] priming CPU Δ (get_cpu_usage) — ' + (1 - r).toFixed(1) + 's'
            );
            setLaneVisual(laneResource, 0.15 + r * 0.2, 0);
        } else {
            const p3 = 5000;
            const w3 = 500;
            const m3 = (elapsed - primeMs) % p3;
            if (m3 < w3) {
                const r = m3 / w3;
                const sub = r < 0.34 ? '0' : r < 0.62 ? '1' : '2';
                setLaneSteps(laneResource, sub);
                const cpu = 12 + (Math.sin(elapsed / 900) * 0.5 + 0.5) * 35;
                const mem = 40 + (Math.cos(elapsed / 1200) * 0.5 + 0.5) * 35;
                if (sub === '0') {
                    setLaneCaption(laneResource, '[RES] get_cpu_usage() · get_memory_info()');
                } else if (sub === '1') {
                    setLaneCaption(
                        laneResource,
                        '[RES] CPU: ' + cpu.toFixed(1) + '% | MEM: ' + mem.toFixed(1) + '%'
                    );
                } else {
                    setLaneCaption(
                        laneResource,
                        cpu > 90 || mem > 90
                            ? '[RES] alert: HIGH_CPU / HIGH_MEMORY (threshold 90%)'
                            : '[RES] thresholds OK (≤90%)'
                    );
                }
                setLaneVisual(laneResource, 0.2 + r * 0.1, 0);
            } else {
                setLaneSteps(laneResource, 'sleep');
                const sleepP = (m3 - w3) / (p3 - w3);
                setLaneCaption(
                    laneResource,
                    '[RES] sleep(5) — next sample in ' + (5 * (1 - sleepP)).toFixed(1) + 's'
                );
                setLaneVisual(laneResource, 0, sleepP);
            }
        }
    }

    function updateOsProcessViz(elapsed) {
        const p = 12000;
        const t = elapsed % p;
        if (vizOsProcessParent) vizOsProcessParent.classList.toggle('viz-highlight', t < 2500 || (t > 9000 && t < 10500));
        if (vizOsProcessChild) vizOsProcessChild.classList.toggle('viz-highlight', t >= 2500 && t < 9000);
        let cap = '';
        if (t < 1500) cap = 'fork() — duplicate process, child PID assigned';
        else if (t < 2500) cap = 'child: run_child_engine() · parent: child_pid = pid';
        else if (t < 8000) cap = 'child: 3× pthread worker loops · parent: waitpid(pid, &status, 0) blocking';
        else if (t < 9000) cap = 'child _exit(0) · parent reaps with waitpid (no zombie)';
        else if (t < 10500) cap = 'alternate path: WIFEXITED / WIFSIGNALED → sleep(2) → restart';
        else cap = 'running flag checked → supervision loop continues';
        if (vizOsProcessCaption) vizOsProcessCaption.textContent = cap;
    }

    function updateOsSyncViz(elapsed) {
        const p = 5000;
        const t = elapsed % p;
        if (!vizMutexA || !vizMutexB || !vizMutexLock) return;
        let phase = 0;
        if (t < 1200) phase = 0;
        else if (t < 2600) phase = 1;
        else if (t < 4000) phase = 2;
        else phase = 3;
        vizMutexA.classList.toggle('viz-cs', phase === 1);
        vizMutexB.classList.toggle('viz-cs', phase === 3);
        vizMutexLock.classList.toggle('locked', phase === 1 || phase === 3);
        vizMutexLock.textContent = phase === 1 || phase === 3 ? '🔒' : '🔓';
        const lines = [
            'pthread_mutex_lock(&proc_mut) — Thread A enters critical section',
            'enumerate /proc via get_all_pids() — count PIDs',
            'pthread_mutex_unlock(&proc_mut) — release for thread B',
            'Thread B: lock → get_all_pids_safe() copy → unlock'
        ];
        if (vizMutexCaption) vizMutexCaption.textContent = lines[phase];
    }

    function updateOsIpcViz(elapsed) {
        const p = 3500;
        const w = p * 0.35;
        const t = elapsed % p;
        const pos = Math.min(1, Math.max(0, t / w));
        if (vizIpcDot) {
            vizIpcDot.style.left = `${pos * 100}%`;
        }
        if (vizIpcCaption) {
            const inFlight = t < w * 0.92;
            vizIpcCaption.textContent = inFlight
                ? 'C++ write() JSON line → FIFO buffer → Python readline()'
                : 'Backend: process_message(line) → DB / Socket.IO';
        }
    }

    function updateOsSignalsViz(elapsed) {
        const p = 6000;
        const t = elapsed % p;
        if (vizSigCaption) {
            if (t < 1200) vizSigCaption.textContent = 'Idle: signal(SIGINT/SIGTERM, handler) registered';
            else if (t < 2800) vizSigCaption.textContent = 'User: Ctrl+C → SIGINT to parent';
            else if (t < 4200) vizSigCaption.textContent = 'Parent: running=0 · kill(child_pid, signum)';
            else if (t < 5400) vizSigCaption.textContent = 'Child: SIGINT handler · running=0 · threads stop';
            else vizSigCaption.textContent = 'volatile sig_atomic_t — async-signal-safe flag';
        }
        if (vizSigNodes.length >= 3) {
            vizSigNodes[0].classList.toggle('viz-pulse', t >= 1200 && t < 2800);
            vizSigNodes[1].classList.toggle('viz-pulse', t >= 2800 && t < 4200);
            vizSigNodes[2].classList.toggle('viz-pulse', t >= 4200 && t < 5600);
        }
    }

    function updateOsResourcesViz(elapsed) {
        const cpu = 18 + (Math.sin(elapsed / 1100) * 0.5 + 0.5) * 52;
        const mem = 35 + (Math.cos(elapsed / 1400) * 0.5 + 0.5) * 48;
        const c = Math.min(100, cpu);
        const m = Math.min(100, mem);
        if (vizResCpu) vizResCpu.style.width = `${c.toFixed(1)}%`;
        if (vizResMem) vizResMem.style.width = `${m.toFixed(1)}%`;
        if (vizResCpuLabel) vizResCpuLabel.textContent = `${c.toFixed(1)}%`;
        if (vizResMemLabel) vizResMemLabel.textContent = `${m.toFixed(1)}%`;

        const phase = Math.floor(elapsed / 720) % 6;
        vizResPipeNodes.forEach((node) => {
            const i = parseInt(node.getAttribute('data-viz-res-pipe'), 10);
            node.classList.toggle('res-node-active', i === phase);
        });

        const boxForPhase = ['cpu', 'cpu', 'mem', 'mem', 'proc', null];
        const activeName = boxForPhase[phase];
        vizResBoxes.forEach((box) => {
            const name = box.getAttribute('data-viz-res-box');
            box.classList.toggle('res-box-active', activeName != null && name === activeName);
        });
        if (vizResAlertStrip) {
            vizResAlertStrip.classList.toggle('res-alert-hot', phase === 5);
        }

        const u = Math.floor(elapsed / 200) % 10000;
        const n = Math.floor(elapsed / 300) % 5000;
        if (vizResCpuFields) {
            vizResCpuFields.textContent =
                'user=' + u + ' nice=… system=… idle=… → Δidle/Δtotal';
        }
        if (vizResMemFields) {
            vizResMemFields.textContent =
                'MemTotal / MemAvailable → used_kb →';
        }
        if (vizResProcFields) {
            vizResProcFields.textContent =
                'pid=… utime=' + n + ' stime=… vsize=… rss=… threads=…';
        }

        const captions = [
            '[RES] parse /proc/stat line 1 → fill CpuUsage jiffies',
            '[RES] diff vs prev sample → cpu.usage_percent',
            '[RES] scan /proc/meminfo keys → MemoryInfo fields',
            '[RES] MemTotal − MemAvailable → mem.usage_percent',
            '[RES] optional get_process_stats(pid) → /proc/[pid]/stat',
            '[RES] if usage > 90 → send_event_to_backend(HIGH_CPU | HIGH_MEMORY)'
        ];
        if (vizResCaption) {
            vizResCaption.textContent = captions[phase];
        }
    }

    function updateOsConceptsViz(elapsed) {
        if (!vizConceptNodes.length) return;
        const i = Math.floor(elapsed / 1800) % vizConceptNodes.length;
        vizConceptNodes.forEach((node, j) => node.classList.toggle('viz-active', j === i));
    }

    function updateRedTeamViz(elapsed) {
        const p1 = 3200;
        const w1 = 600;
        const m1 = elapsed % p1;
        if (m1 < w1) {
            const r = m1 / w1;
            setRtLane(
                rtLoginCaption,
                rtLoginTrack,
                0.2 + r * 0.15,
                0,
                'login_simulator.py → AUTH_FAILED burst → pipe'
            );
        } else {
            setRtLane(
                rtLoginCaption,
                rtLoginTrack,
                0,
                (m1 - w1) / (p1 - w1),
                'sleep between attempts · MEDIUM severity'
            );
        }

        const p2 = 4000;
        const w2 = 900;
        const m2 = elapsed % p2;
        if (m2 < w2) {
            const r = m2 / w2;
            setRtLane(
                rtFloodCaption,
                rtFloodTrack,
                0.25 + r * 0.2,
                0,
                'process_flood.py → spawn workers → PROCESS_SPIKE'
            );
        } else {
            setRtLane(
                rtFloodCaption,
                rtFloodTrack,
                0,
                (m2 - w2) / (p2 - w2),
                'cooldown · HIGH severity'
            );
        }

        const p3 = 4500;
        const w3 = 700;
        const m3 = elapsed % p3;
        if (m3 < w3) {
            const r = m3 / w3;
            setRtLane(
                rtFileCaption,
                rtFileTrack,
                0.22 + r * 0.12,
                0,
                'file_tamper_simulator.py → tamper event → CRITICAL'
            );
        } else {
            setRtLane(
                rtFileCaption,
                rtFileTrack,
                0,
                (m3 - w3) / (p3 - w3),
                'idle / reset scenario'
            );
        }

        const p4 = 8000;
        const w4 = 2800;
        const m4 = elapsed % p4;
        if (m4 < w4) {
            const r = m4 / w4;
            setRtLane(
                rtSuiteCaption,
                rtSuiteTrack,
                0.15 + r * 0.2,
                0,
                'attack_controller.py → orchestrate login → flood → tamper'
            );
        } else {
            setRtLane(
                rtSuiteCaption,
                rtSuiteTrack,
                0,
                (m4 - w4) / (p4 - w4),
                'suite cooldown · full pipeline test'
            );
        }
    }

    function updateResponseViz(elapsed) {
        const p = 9000;
        const t = elapsed % p;
        if (vizFsmBadge) {
            vizFsmBadge.classList.remove('state-normal', 'state-warn', 'state-locked');
            if (t < 3000) {
                vizFsmBadge.classList.add('state-normal');
                vizFsmBadge.textContent = 'FSM: NORMAL';
            } else if (t < 6000) {
                vizFsmBadge.classList.add('state-warn');
                vizFsmBadge.textContent = 'FSM: WARNING';
            } else {
                vizFsmBadge.classList.add('state-locked');
                vizFsmBadge.textContent = 'FSM: LOCKED';
            }
        }
        if (vizKillTarget) {
            const strike = t >= 6500 && t < 8200;
            vizKillTarget.classList.toggle('struck', strike);
            vizKillTarget.textContent = strike
                ? 'PID 8842 — malicious_proc — SIGKILL (done)'
                : 'PID 8842 — malicious_proc — candidate → kill(pid, SIGKILL)';
        }
        if (vizResponseCaption) {
            if (t < 3000) vizResponseCaption.textContent = 'Idle: monitor alerts · no escalation';
            else if (t < 6000) {
                vizResponseCaption.textContent = 'Escalation: HIGH/MEDIUM thresholds → WARNING';
            } else if (t < 8200) {
                vizResponseCaption.textContent = 'LOCKED: active_defense() · os.kill(pid, SIGKILL)';
            } else vizResponseCaption.textContent = 'C++ response_engine.cpp · trigger_response(pid)';
        }
    }

    let conceptVizFrameSkip = 1;
    function conceptVizFrame(now) {
        /* IPC / sync / signals: lower FPS to cut CPU; other viz pages stay ~30fps */
        const throttle =
            conceptVizPage === 'os-ipc' || conceptVizPage === 'os-sync' || conceptVizPage === 'os-signals'
                ? 4
                : 2;
        conceptVizFrameSkip = (conceptVizFrameSkip + 1) % throttle;
        if (conceptVizFrameSkip !== 0) {
            conceptVizRaf = requestAnimationFrame(conceptVizFrame);
            return;
        }
        const elapsed = now - conceptVizT0;
        switch (conceptVizPage) {
            case 'os-threads':
                updateOsThreadsViz(elapsed);
                break;
            case 'os-process':
                updateOsProcessViz(elapsed);
                break;
            case 'os-sync':
                updateOsSyncViz(elapsed);
                break;
            case 'os-ipc':
                updateOsIpcViz(elapsed);
                break;
            case 'os-signals':
                updateOsSignalsViz(elapsed);
                break;
            case 'os-resources':
                updateOsResourcesViz(elapsed);
                break;
            case 'os-concepts':
                updateOsConceptsViz(elapsed);
                break;
            case 'red-team':
                updateRedTeamViz(elapsed);
                break;
            case 'response':
                updateResponseViz(elapsed);
                break;
            default:
                break;
        }
        conceptVizRaf = requestAnimationFrame(conceptVizFrame);
    }

    function startConceptViz(pageName) {
        stopConceptViz();
        if (!VIZ_PAGES.has(pageName)) return;
        conceptVizPage = pageName;
        conceptVizT0 = performance.now();
        conceptVizFrameSkip = 1;
        if (pageName === 'red-team') rtResetInteractive();
        conceptVizRaf = requestAnimationFrame(conceptVizFrame);
    }

    let ipcStatusTimer = null;

    function refreshIpcStatus() {
        const dot = document.getElementById('ipc-status-dot');
        const textEl = document.getElementById('ipc-status-text');
        const pathEl = document.getElementById('ipc-path-display');
        if (!textEl && !pathEl) return;
        fetch('/api/ipc/status')
            .then((r) => r.json())
            .then((data) => {
                if (pathEl) pathEl.textContent = data.path || '';
                if (!textEl) return;
                if (data.ok === false) {
                    textEl.textContent = data.error || 'API error';
                    if (dot) dot.className = 'ipc-status-dot ipc-off';
                    return;
                }
                if (data.exists && data.readable) {
                    textEl.textContent = data.is_fifo
                        ? 'FIFO ready (POSIX) — path matches C++ open()'
                        : 'Pipe file ready (Windows) — backend created path';
                    if (dot) dot.className = 'ipc-status-dot ipc-ok';
                } else if (data.exists) {
                    textEl.textContent = 'Path exists but not readable — check permissions';
                    if (dot) dot.className = 'ipc-status-dot ipc-warn';
                } else {
                    textEl.textContent =
                        'Not created yet — run: python backend/main_backend.py';
                    if (dot) dot.className = 'ipc-status-dot ipc-warn';
                }
            })
            .catch(() => {
                if (textEl) {
                    textEl.textContent =
                        'Cannot reach /api/ipc/status (start gui_dashboard / check PORT in terminal)';
                }
                if (dot) dot.className = 'ipc-status-dot ipc-off';
            });
    }

    function switchPage(pageName) {
        pages.forEach(p => p.classList.remove('active'));
        navItems.forEach(n => n.classList.remove('active'));

        const targetPage = document.getElementById('page-' + pageName);
        const targetNav = document.querySelector(`[data-page="${pageName}"]`);

        if (targetPage) targetPage.classList.add('active');
        if (targetNav) targetNav.classList.add('active');
        if (pageTitle && pageTitles[pageName]) pageTitle.textContent = pageTitles[pageName];
        window.scrollTo(0, 0);

        if (ipcStatusTimer) {
            clearInterval(ipcStatusTimer);
            ipcStatusTimer = null;
        }
        if (pageName === 'os-ipc') {
            refreshIpcStatus();
            ipcStatusTimer = setInterval(refreshIpcStatus, 8000);
        }

        stopConceptViz();
        startConceptViz(pageName);

        // REST fallback: when navigating to Events Log, immediately refresh
        // recent_events even if a Socket.IO update was missed.
        if (pageName === 'events') {
            fetch('/api/dashboard_snapshot')
                .then((r) => r.json())
                .then((snap) => {
                    if (window.renderEvents) {
                        window.renderEvents((snap && snap.recent_events) || []);
                    }
                })
                .catch(() => {});
        }
    }
    window.switchPage = switchPage; // Expose to global scope for onclick attributes

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const page = item.getAttribute('data-page');
            switchPage(page);
        });
    });

    // Concept cards can jump directly to their matching concept pages.
    document.querySelectorAll('.concept-card').forEach(card => {
        card.addEventListener('click', () => switchPage(card.dataset.page || 'os-concepts'));
    });

    document.querySelectorAll('.os-detail-card').forEach(card => {
        card.addEventListener('click', () => {
            if (card.dataset.page) switchPage(card.dataset.page);
        });
    });

    // Menu button opens the sidebar as an overlay.
    const menuToggle = document.getElementById('menu-toggle');
    if (menuToggle && sidebar) {
        menuToggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }
    if (sidebarBackdrop && sidebar) {
        sidebarBackdrop.addEventListener('click', () => {
            sidebar.classList.remove('open');
        });
    }
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (sidebar) {
                sidebar.classList.remove('open');
            }
        });
    });

    // ═══ Startup Sequence ════════════════════════════════════════════════
    const startDashboard = () => {
        if (!startupScreen || startupScreen.classList.contains('fade-out')) {
            document.body.classList.add('dashboard-ready');
            scrollAppToTop();
            return;
        }
        startupScreen.classList.add('fade-out');
        document.body.classList.add('dashboard-ready');
        scrollAppToTop();
        setTimeout(() => {
            if (startupScreen && startupScreen.parentNode) startupScreen.remove();
            scrollAppToTop();
        }, 900);
    };
    setTimeout(startDashboard, 2800);

    window.addEventListener('load', () => scrollAppToTop());

    // ═══ Utility Functions ═══════════════════════════════════════════════
    const getHighestSeverity = (counts = {}) =>
        severityOrder.find(level => (counts[level] || 0) > 0) || 'LOW';

    const computeThreatScore = (counts = {}, eventsLastMin = 0) => {
        const weighted =
            (counts.LOW || 0) * 5 +
            (counts.MEDIUM || 0) * 15 +
            (counts.HIGH || 0) * 28 +
            (counts.CRITICAL || 0) * 40;
        return Math.min(100, weighted + Math.min(eventsLastMin * 2, 30));
    };

    const updateAnalysis = (state, counts = {}, activeAlerts = 0, eventsLastMin = 0) => {
        const highest = getHighestSeverity(counts);
        const threatScore = computeThreatScore(counts, eventsLastMin);

        if (vulnChart) {
            vulnChart.data.datasets[0].data = [counts.CRITICAL || 0, counts.HIGH || 0, counts.MEDIUM || 0];
            vulnChart.update('none');
            const dc = document.querySelector('.donut-center');
            if (dc) {
                const total = (counts.CRITICAL || 0) + (counts.HIGH || 0) + (counts.MEDIUM || 0);
                const perc = total > 0 ? Math.round(((counts.CRITICAL || 0) + (counts.HIGH || 0)) / total * 100) : 0;
                dc.innerHTML = `<strong>${perc}%</strong><span>High Risk</span>`;
            }
        }
        
        const vulnStats = document.querySelector('.vuln-stats');
        if (vulnStats) {
            vulnStats.innerHTML = `
                <div class="vs-item"><span class="vs-dot red-bg"></span> <strong>${counts.CRITICAL || 0}</strong> Critical</div>
                <div class="vs-item"><span class="vs-dot yellow-bg"></span> <strong>${counts.HIGH || 0}</strong> High</div>
                <div class="vs-item"><span class="vs-dot green-bg"></span> <strong>${counts.MEDIUM || 0}</strong> Medium</div>
            `;
        }

        if (analysisState) {
            analysisState.textContent =
                state === 'LOCKED' ? 'Locked Response' :
                state === 'WARNING' ? 'Warning Escalation' : 'Normal Watch';
            analysisState.className =
                'analysis-state ' +
                (state === 'LOCKED' ? 'state-locked' : state === 'WARNING' ? 'state-warning' : 'state-normal');
        }

        if (analysisSummary) {
            analysisSummary.textContent =
                state === 'LOCKED'
                    ? 'FalconStrix detected repeated high-risk behavior. Defensive response workflows are active.'
                    : state === 'WARNING'
                        ? 'Suspicious activity accumulating. Review alerts before FSM escalates to locked response.'
                        : 'Telemetry monitored. No escalation pattern active. Live events and alerts under watch.';
        }

        if (highestSeverity) highestSeverity.textContent = highest;
        if (openIncidents) openIncidents.textContent = activeAlerts;
        if (threatScoreValue) threatScoreValue.textContent = threatScore;
    };

    const updateOsConceptsStripState = (state) => {
        const st = state || 'NORMAL';
        const strip = document.querySelector('.os-concepts-strip');
        const note = document.getElementById('os-concepts-security-note');
        const cap = document.getElementById('os-concepts-panel-caption');
        if (strip) {
            strip.classList.toggle('os-concepts-strip--locked', st === 'LOCKED');
            strip.classList.toggle('os-concepts-strip--warn', st === 'WARNING');
        }
        if (note) {
            note.classList.remove('os-concepts-security-note--warn');
            if (st === 'LOCKED') {
                note.classList.remove('hidden');
                note.textContent =
                    'FSM LOCKED — Repeated failed sign-ins (or policy) escalated the finite-state machine. OS concepts (processes, threads, IPC, signals, sync) are in defensive review; check FSM history and User Activity.';
            } else if (st === 'WARNING') {
                note.classList.remove('hidden');
                note.classList.add('os-concepts-security-note--warn');
                note.textContent =
                    'FSM WARNING — Elevated monitoring across process lifecycle, IPC pipes, signal handlers, and mutex-protected paths.';
            } else {
                note.classList.add('hidden');
                note.textContent = '';
            }
        }
        if (cap) {
            if (st === 'LOCKED') cap.textContent = '10 concepts — lock-down review';
            else if (st === 'WARNING') cap.textContent = '10 concepts — elevated watch';
            else cap.textContent = '10 concepts integrated';
        }
    };

    const applyGlobalStateUi = (state) => {
        const st = state || 'NORMAL';
        if (statusBadge) {
            statusBadge.textContent = 'STATE: ' + st;
            statusBadge.classList.remove('badge-normal', 'badge-warning', 'badge-locked');
        }
        document.body.classList.remove('theme-normal', 'theme-warning', 'theme-locked');
        if (overlay) overlay.classList.add('hidden');

        if (st === 'NORMAL') {
            if (statusBadge) statusBadge.classList.add('badge-normal');
            document.body.classList.add('theme-normal');
        } else if (st === 'WARNING') {
            if (statusBadge) statusBadge.classList.add('badge-warning');
            document.body.classList.add('theme-warning');
        } else if (st === 'LOCKED') {
            if (statusBadge) statusBadge.classList.add('badge-locked');
            document.body.classList.add('theme-locked');
            if (overlay) overlay.classList.remove('hidden');
        }

        updateFsmDiagram(st);
        updateOsConceptsStripState(st);
    };

    const updateFsmDiagram = (state) => {
        const fsmState = document.getElementById('fsm-current-state');
        if (fsmState) {
            fsmState.textContent = state;
            fsmState.className = 'analysis-state ' +
                (state === 'LOCKED' ? 'state-locked' : state === 'WARNING' ? 'state-warning' : 'state-normal');
        }

        ['normal', 'warning', 'locked'].forEach(s => {
            const node = document.getElementById('fsm-node-' + s);
            if (node) {
                node.classList.toggle('active-fsm-node', state.toLowerCase() === s);
                const led = node.querySelector('.fsm-led');
                if (led) led.style.opacity = (state.toLowerCase() === s) ? '1' : '0.3';
            }
        });
    };

    // ═══ Render Functions ════════════════════════════════════════════════
    const renderEmptyState = (listEl, message) => {
        if (listEl) listEl.innerHTML = `<li class="empty-state">${message}</li>`;
    };

    const renderAlerts = (alerts = [], recentForSidebar = null) => {
        const tableBody = document.getElementById('alert-list-table');
        if (tableBody) {
            if (!alerts.length) {
                tableBody.innerHTML = '<tr><td colspan="8" style="text-align:center; padding: 20px;">No security alerts found.</td></tr>';
                if (feedCount) feedCount.textContent = '0 tracked';
            } else {
                tableBody.innerHTML = alerts.map(alert => `
                    <tr class="sev-${alert.severity}">
                        <td><span class="expander">›</span> ${alert.timestamp}</td>
                        <td class="blue-link">${alert.agent || '004'}</td>
                        <td>${alert.agent_name || 'Windows'}</td>
                        <td class="blue-link">${alert.technique || 'T1059'}</td>
                        <td>${alert.tactic || 'Execution'}</td>
                        <td>${alert.message}</td>
                        <td class="level">${alert.level || 10}</td>
                        <td class="blue-link">${alert.rule_id || '255000'}</td>
                    </tr>
                `).join('');
                if (feedCount) feedCount.textContent = `${alerts.length} tracked/SIEM`;
            }
        }

        const dashRecent = document.getElementById('dash-recent-alerts');
        if (dashRecent) {
            const sidebar = Array.isArray(recentForSidebar) ? recentForSidebar.slice(0, 5) : [];
            if (!sidebar.length) {
                dashRecent.innerHTML = '<div class="al-item"><span class="al-empty">No alerts in the last 7 days</span></div>';
            } else {
                dashRecent.innerHTML = sidebar.map((alert) => {
                    const bg = alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'red-bg' : 'yellow-bg';
                    const ts = typeof alert.timestamp === 'string' && alert.timestamp.length > 11
                        ? alert.timestamp.slice(11, 16)
                        : (alert.timestamp || '');
                    return `
                        <div class="al-item">
                            <div class="al-icon ${bg}">⚠</div>
                            <div class="al-info">
                                <h4>${alert.event_type || 'Alert'}</h4>
                                <span>FalconStrix • ${ts}</span>
                            </div>
                            <div class="al-meta"><span class="${alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'red-text' : 'yellow-text'}">${alert.severity} ›</span><br><a href="javascript:void(0)" onclick="window.switchPage('alerts')">View Details</a></div>
                        </div>
                    `;
                }).join('');
            }
        }
    };

    const renderEvents = (events = []) => {
        if (!eventList) return;
        if (!events.length) {
            renderEmptyState(eventList, 'No recent events returned by backend.');
            return;
        }
        eventList.innerHTML = events.map(event => `
            <li class="event-item">
                <strong>${event.event_type}</strong>
                <span class="item-meta">${event.timestamp}${event.process_name ? ` | ${event.process_name}` : ''}</span>
                <div class="item-body">${event.description}</div>
            </li>
        `).join('');
    };

    // Expose for REST fallback refresh in switchPage()
    window.renderEvents = renderEvents;

    const renderStateHistory = (history = []) => {
        if (!stateHistoryList) return;
        if (!history.length) {
            renderEmptyState(stateHistoryList, 'No FSM transition history available.');
            return;
        }
        stateHistoryList.innerHTML = history.map(item => `
            <li class="history-item">
                <strong>${item.previous_state} → ${item.new_state}</strong>
                <span class="item-meta">${item.changed_at}</span>
                <div class="item-body">${item.reason}</div>
            </li>
        `).join('');
    };

    const renderProcesses = (processes = []) => {
        const tableBody = document.getElementById('process-list-table');
        if (!tableBody) return;
        if (!processes.length) {
            tableBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 20px;">No process data available.</td></tr>';
            return;
        }
        tableBody.innerHTML = processes.map(p => `
            <tr class="p-row-${p.threat.toLowerCase()}">
                <td>${p.pid}</td>
                <td><strong>${p.name}</strong></td>
                <td>${p.user}</td>
                <td>${p.cpu}%</td>
                <td>${p.mem}%</td>
                <td><span class="level-badge">${p.threat}</span></td>
                <td><button class="kill-btn" onclick="window.killProcess(${p.pid}, '${p.name}')">Kill</button></td>
            </tr>
        `).join('');
    };

    window.killProcess = (pid, name) => {
        if (confirm(`Are you sure you want to terminate ${name} (PID: ${pid})?`)) {
            socket.emit('kill_process', { pid, name });
        }
    };

    const applySeverityCounts = (counts = {}) => {
        Object.entries(severityEls).forEach(([level, el]) => {
            if (el) el.textContent = counts[level] || 0;
        });
    };

    // ═══ IPC message counter (tracked locally) ═══════════════════════════
    let ipcMessageCount = 0;
    let killCount = 0;

    const updateConceptStats = (data) => {
        const ipcStat = document.getElementById('ipc-stat');
        const osIpcStat = document.getElementById('os-ipc-stat');
        const killStat = document.getElementById('kill-stat');
        const osKillStat = document.getElementById('os-kill-stat');

        if (ipcStat && data && data.ipc_total !== undefined) {
            ipcStat.textContent = data.ipc_total + ' msgs';
        }
        if (killStat && data && data.kill_cnt !== undefined) {
            killStat.textContent = data.kill_cnt + ' killed';
        }
    };

    // ═══ Modern Dashboard Charts ═════════════════════════════════════════
    if (typeof Chart !== 'undefined') {
        Chart.defaults.animation = false;
        if (Chart.defaults.transitions && Chart.defaults.transitions.active) {
            Chart.defaults.transitions.active.animation = { duration: 0 };
        }
    }

    let threatChart = null;
    const ctxThreat = document.getElementById('threatActivityChart');
    if (ctxThreat) {
        threatChart = new Chart(ctxThreat.getContext('2d'), {
            type: 'line',
            data: {
                labels: Array.from({length: 15}, (_, i) => i),
                datasets: [
                    { label: 'Malware', data: [12,19,3,5,2,3,15,10,25,30,12,8,5,10,20], borderColor: '#60a5fa', backgroundColor: 'rgba(96,165,250,0.2)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 },
                    { label: 'Phishing', data: [5,2,10,15,8,5,20,5,12,8,2,7,12,5,10], borderColor: '#f87171', backgroundColor: 'rgba(248,113,113,0.1)', fill: false, tension: 0.4, borderWidth: 2, pointRadius: 0 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { display: false } },
                interaction: { intersect: false, mode: 'index' },
                scales: { y: { display: false }, x: { display: false } }
            }
        });
    }

    let incidentsChart = null;
    const ctxIncidents = document.getElementById('incidentsChart');
    if (ctxIncidents) {
        incidentsChart = new Chart(ctxIncidents.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['1','2','3','4','5','6','7','8','9','10','11','12'],
                datasets: [
                    { label: 'Resolved', data: [15,20,10,25,30,15,10,5,20,35,25,30], backgroundColor: '#60a5fa' },
                    { label: 'Unresolved', data: [5,10,2,5,8,3,5,2,10,5,8,12], backgroundColor: '#f87171' }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { display: false } },
                scales: { y: { display: false }, x: { display: false } }
            }
        });
    }

    // Incidents (Weekly / Monthly / Yearly) tab-driven chart updates.
    // The dashboard_snapshot handler assigns `cachedIncidentTrends` and calls `applyIncidentChart(incidentsPeriod)`.
    let cachedIncidentTrends = null;
    let incidentsPeriod = 'weekly';

    function applyIncidentChart(period) {
        if (!incidentsChart || !cachedIncidentTrends) return;
        const p = period && cachedIncidentTrends[period] ? cachedIncidentTrends[period] : cachedIncidentTrends.weekly;
        if (!p || !p.labels) return;
        incidentsChart.data.labels = p.labels;
        if (incidentsChart.data.datasets && incidentsChart.data.datasets.length >= 2) {
            incidentsChart.data.datasets[0].data = p.resolved || [];
            incidentsChart.data.datasets[1].data = p.unresolved || [];
        }
        incidentsChart.update('none');
    }

    const incidentTabs = document.querySelectorAll('.widget-incidents .tabs button[data-period]');
    if (incidentTabs && incidentTabs.length) {
        // Initialize period from the active tab.
        const activeBtn =
            Array.from(incidentTabs).find((b) => b.classList.contains('active')) || incidentTabs[0];
        incidentsPeriod = activeBtn?.dataset?.period || 'weekly';

        incidentTabs.forEach((btn) => {
            btn.addEventListener('click', () => {
                incidentsPeriod = btn.dataset.period || 'weekly';
                incidentTabs.forEach((b) => b.classList.toggle('active', b === btn));
                btn.setAttribute('aria-selected', 'true');
                incidentTabs.forEach((b) => {
                    if (b !== btn) b.setAttribute('aria-selected', 'false');
                });
                applyIncidentChart(incidentsPeriod);
            });
        });
    }

    let vulnChart = null;
    const ctxVuln = document.getElementById('vulnChart');
    if (ctxVuln) {
        vulnChart = new Chart(ctxVuln.getContext('2d'), {
            type: 'doughnut',
            data: {
                datasets: [{ data: [0, 0, 0], backgroundColor: ['#ef4444', '#eab308', '#22c55e'], borderWidth: 0, cutout: '75%' }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } }
            }
        });
    }

    let cpuGauge = null;
    let memGauge = null;
    const ctxCPU = document.getElementById('cpuGauge');
    const ctxMem = document.getElementById('memoryGauge');

    if (ctxCPU) {
        cpuGauge = new Chart(ctxCPU.getContext('2d'), {
            type: 'doughnut',
            data: {
                datasets: [{ data: [0, 100], backgroundColor: ['#00c3ff', 'rgba(255,255,255,0.05)'], borderWidth: 0, cutout: '85%' }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } }
            }
        });
    }

    if (ctxMem) {
        memGauge = new Chart(ctxMem.getContext('2d'), {
            type: 'doughnut',
            data: {
                datasets: [{ data: [0, 16], backgroundColor: ['#00c3ff', 'rgba(255,255,255,0.05)'], borderWidth: 0, cutout: '85%' }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { display: false }, tooltip: { enabled: false } }
            }
        });
    }

    let dataPoints = 15;

    // ═══ Processor Performance History Chart (CPU Line Graph) ════════════
    let cpuHistoryChart = null;
    const ctxCPUHistory = document.getElementById('cpuHistoryChart');
    if (ctxCPUHistory) {
        cpuHistoryChart = new Chart(ctxCPUHistory.getContext('2d'), {
            type: 'line',
            data: {
                labels: Array.from({length: 30}, () => ''),
                datasets: [{
                    label: 'CPU Usage %',
                    data: Array(30).fill(0),
                    borderColor: '#00c3ff',
                    backgroundColor: 'rgba(0, 195, 255, 0.1)',
                    fill: true,
                    tension: 0.4,
                    borderWidth: 2,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                plugins: { legend: { display: false } },
                interaction: { intersect: false, mode: 'index' },
                scales: {
                    y: { 
                        min: 0, max: 100, 
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#888', font: { size: 10 } }
                    },
                    x: { display: false }
                }
            }
        });
    }

    // ═══ Network Traffic (defined before snapshot/metrics so handlers can batch DOM updates) ═══
    const networkMapArea = document.getElementById('network-map-area');
    const netInRateEl = document.getElementById('net-in-rate');
    const netOutRateEl = document.getElementById('net-out-rate');
    const netTotalInEl = document.getElementById('net-total-in');
    const netTotalOutEl = document.getElementById('net-total-out');

    function netRateToSpeedFactor(rateStr) {
        if (!rateStr || typeof rateStr !== 'string') return 1;
        const m = rateStr.trim().match(/^([\d.]+)\s*(KB|MB|GB|TB)\/s/i);
        if (!m) return 1;
        let mbPerSec = parseFloat(m[1]);
        const u = m[2].toUpperCase();
        if (u === 'KB') mbPerSec /= 1024;
        else if (u === 'GB') mbPerSec *= 1024;
        else if (u === 'TB') mbPerSec *= 1024 * 1024;
        return Math.min(16, Math.max(0.25, 0.35 + mbPerSec * 1.8));
    }

    const updateNetwork = (network) => {
        const n = network || {};
        const inRate = n.in != null ? String(n.in) : '—';
        const outRate = n.out != null ? String(n.out) : '—';
        const tin = n.total_in != null ? String(n.total_in) : '—';
        const tout = n.total_out != null ? String(n.total_out) : '—';

        if (netInRateEl) netInRateEl.textContent = '⬆ ' + inRate.replace(/^\s*/, '');
        if (netOutRateEl) netOutRateEl.textContent = '⬇ ' + outRate.replace(/^\s*/, '');
        if (netTotalInEl) netTotalInEl.textContent = tin;
        if (netTotalOutEl) netTotalOutEl.textContent = tout;

        if (networkMapArea) {
            const fin = netRateToSpeedFactor(inRate);
            const fout = netRateToSpeedFactor(outRate);
            networkMapArea.style.setProperty('--net-in-speed', String(fin));
            networkMapArea.style.setProperty('--net-out-speed', String(fout));
        }
    };

    let netStatsQueued = null;
    let netStatsRaf = null;
    function queueNetworkStatsUpdate(data) {
        netStatsQueued = data;
        if (netStatsRaf != null) return;
        netStatsRaf = requestAnimationFrame(() => {
            netStatsRaf = null;
            if (netStatsQueued) updateNetwork(netStatsQueued);
        });
    }

    updateNetwork({
        in: '0.00 MB/s',
        out: '0.00 MB/s',
        total_in: '0.00 GB',
        total_out: '0.00 GB'
    });

    socket.on('network_stats', (data) => {
        queueNetworkStatsUpdate(data);
    });

    let netHttpPollTimer = null;

    // ═══ Socket.IO Events ════════════════════════════════════════════════
    const onConnect = () => {
        console.log('Connected to SOC backend.');
        connectionBadge.textContent = 'BACKEND ONLINE';
        connectionBadge.classList.remove('offline');
        connectionBadge.classList.add('online');
        sidebarConn.classList.remove('offline');
        sidebarConn.classList.add('online');
        sidebarConnText.textContent = 'Connected';
        if (netHttpPollTimer) {
            clearInterval(netHttpPollTimer);
            netHttpPollTimer = null;
        }
    };

    socket.on('connect', onConnect);
    if (socket.connected) onConnect(); // Handle case where it connects before listener is ready

    socket.on('disconnect', () => {
        connectionBadge.textContent = 'BACKEND OFFLINE';
        connectionBadge.classList.remove('online');
        connectionBadge.classList.add('offline');
        sidebarConn.classList.remove('online');
        sidebarConn.classList.add('offline');
        sidebarConnText.textContent = 'Offline';
        if (netHttpPollTimer) return;
        netHttpPollTimer = setInterval(() => {
            fetch('/api/network')
                .then((r) => r.json())
                .then((d) => updateNetwork(d))
                .catch(() => {});
        }, 750);
    });

    socket.on('state_change', (data) => {
        applyGlobalStateUi(data.state);
    });

    socket.on('dashboard_snapshot', (data) => {
        const counts = data.severity_counts || {};
        const activeAlerts = data.active_alerts || [];

        if (activeAlertsValue) activeAlertsValue.textContent = activeAlerts.length;
        if (responseActionsValue) responseActionsValue.textContent = data.kill_cnt || 0;
        if (sidebarAlertCount) sidebarAlertCount.textContent = activeAlerts.length;
        
        // Update new dashboard elements
        const dashActive = document.getElementById('dash-active-threats');
        const dashResolved = document.getElementById('dash-resolved');
        const dashKills = document.getElementById('dash-kills');
        const dashVuln = document.getElementById('dash-vuln');
        const dashStatus = document.getElementById('dash-status');
        
        if (dashActive) dashActive.textContent = activeAlerts.length;
        if (dashResolved) dashResolved.textContent = Math.max(0, (data.kill_cnt || 0) * 3); 
        if (dashKills) dashKills.textContent = data.kill_cnt || 0;
        if (dashVuln) dashVuln.textContent = (counts.HIGH || 0) + (counts.CRITICAL || 0);
        if (dashStatus) {
            dashStatus.textContent = data.state || 'NORMAL';
            dashStatus.className = 'ov-badge ' + (data.state === 'NORMAL' ? 'green-bg' : (data.state === 'WARNING' ? 'yellow-bg' : (data.state === 'LOCKED' ? 'red-bg' : 'yellow-bg')));
        }

        // Update device status list
        const deviceList = document.querySelector('.device-list');
        if (deviceList && data.devices) {
            deviceList.innerHTML = data.devices.map(d => `
                <div class="dl-item"><span class="dl-icon">🖥</span> <span>${d.name}</span> <span class="${d.health === 'green' ? 'green-text' : 'red-text'}">${d.status} ›</span></div>
            `).join('');
        }

        // Update User Activity
        const userList = document.querySelector('.user-list');
        if (userList && data.user_activity) {
            if (data.user_activity.length > 0) {
                const escUa = (s) =>
                    String(s ?? '')
                        .replace(/&/g, '&amp;')
                        .replace(/</g, '&lt;')
                        .replace(/"/g, '&quot;');
                userList.innerHTML = data.user_activity.map((u) => {
                    const ic = u.icon || 'gray';
                    const sym = u.icon_char || '👤';
                    const actor = u.actor
                        ? `<span class="ul-actor">${escUa(u.actor)}</span><span class="ul-sep">·</span>`
                        : '';
                    const text = escUa(u.description || u.event_type);
                    return `<div class="ul-item"><span class="ul-icon ${ic}">${sym}</span><span class="ul-line">${actor}<span>${text}</span></span><span class="ul-time">${escUa(u.timestamp || '')} ›</span></div>`;
                }).join('');
            } else {
                userList.innerHTML = '<div class="ul-item"><span>No recent auth activity</span></div>';
            }
        }

        // Incident trends (Weekly / Monthly / Yearly chart)
        if (data.incident_trends) {
            cachedIncidentTrends = data.incident_trends;
            applyIncidentChart(incidentsPeriod);
        }

        // Update Incident Summary
        const summaryList = document.querySelector('.summary-list');
        if (summaryList && data.incident_summary) {
            if (data.incident_summary.length > 0) {
                summaryList.innerHTML = data.incident_summary.map((s) => {
                    const color = s.color || (s.severity === 'CRITICAL' || s.severity === 'HIGH' ? 'red' : 'blue');
                    const icon = s.icon || (s.severity === 'CRITICAL' || s.severity === 'HIGH' ? '⚠' : 'ℹ');
                    return `<div class="sl-item"><span class="sl-icon ${color}">${icon}</span> <span>${s.title}</span> <span class="sl-time">${s.time} ›</span></div>`;
                }).join('');
            } else {
                summaryList.innerHTML = '<div class="sl-item"><span>No active incidents</span></div>';
            }
        }

        applyGlobalStateUi(data.state);
        applySeverityCounts(counts);
        renderAlerts(activeAlerts, data.recent_alerts);
        renderEvents(data.recent_events || []);
        renderStateHistory(data.state_history || []);
        renderProcesses(data.processes || []);
        updateAnalysis(data.state || 'NORMAL', counts, activeAlerts.length, Number(epmValue?.textContent) || 0);
        updateConceptStats(data);
        queueNetworkStatsUpdate(data.network);
        updateResourceWidgets(data.resources);
    });

    const updateResourceWidgets = (res) => {
        if (!res) return;

        // Update CPU
        const cpuVal = document.getElementById('cpu-gauge-val');
        const cpuUtil = document.getElementById('cpu-util');
        const cpuFreq = document.getElementById('cpu-freq');
        const cpuProc = document.getElementById('cpu-proc-count');
        const cpuUptime = document.getElementById('cpu-uptime');

        if (cpuVal) cpuVal.textContent = res.cpu.util;
        if (cpuUtil) cpuUtil.textContent = res.cpu.util;
        if (cpuFreq) cpuFreq.textContent = res.cpu.freq;
        if (cpuProc) cpuProc.textContent = res.cpu.procs;
        if (cpuUptime) cpuUptime.textContent = res.cpu.uptime;

        if (cpuGauge) {
            cpuGauge.data.datasets[0].data = [res.cpu.util, 100 - res.cpu.util];
            cpuGauge.update('none');
        }

        if (cpuHistoryChart) {
            cpuHistoryChart.data.datasets[0].data.push(res.cpu.util);
            cpuHistoryChart.data.datasets[0].data.shift();
            cpuHistoryChart.update('none');
        }

        // Update Memory
        const memVal = document.getElementById('mem-gauge-val');
        const memInUse = document.getElementById('mem-in-use');
        const memAvail = document.getElementById('mem-avail');
        const memCommit = document.getElementById('mem-commit');
        const memCached = document.getElementById('mem-cached');

        if (memVal) memVal.textContent = res.memory.in_use;
        if (memInUse) memInUse.textContent = res.memory.in_use;
        if (memAvail) memAvail.textContent = res.memory.avail;
        if (memCommit) memCommit.textContent = res.memory.commit;
        if (memCached) memCached.textContent = res.memory.cached;

        if (memGauge) {
            memGauge.data.datasets[0].data = [res.memory.in_use, 16 - res.memory.in_use];
            memGauge.update('none');
        }

        // Also update the legacy OS Concepts strip if it exists
        const osCpuStat = document.getElementById('cpu-stat');
        if (osCpuStat) osCpuStat.textContent = res.cpu.util + '% CPU';
    };

    socket.on('new_alert', (alert) => {
        if (!alertList) return;
        const tr = document.createElement('tr');
        tr.className = 'sev-' + alert.severity;
        tr.innerHTML = `
            <td><span class="expander">›</span> ${alert.timestamp}</td>
            <td class="blue-link">${alert.agent || '004'}</td>
            <td>${alert.agent_name || 'Windows'}</td>
            <td class="blue-link">${alert.technique || 'T1218'}</td>
            <td>${alert.tactic || 'Defense Evasion'}</td>
            <td>${alert.message}</td>
            <td class="level">${alert.level || 10}</td>
            <td class="blue-link">${alert.rule_id || '255563'}</td>
        `;
        alertList.prepend(tr);
        if (alertList.children.length > 50) alertList.removeChild(alertList.lastChild);

        const dashRecent = document.getElementById('dash-recent-alerts');
        if (dashRecent) {
            const bg = alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'red-bg' : 'yellow-bg';
            const html = `
                <div class="al-item">
                    <div class="al-icon ${bg}">⚠</div>
                    <div class="al-info">
                        <h4>${alert.event_type || 'System Event'}</h4>
                        <span>FalconStrix • New</span>
                    </div>
                    <div class="al-meta"><span class="${alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'red-text' : 'yellow-text'}">${alert.severity} ›</span><br><a href="javascript:void(0)" onclick="window.switchPage('alerts')">View Details</a></div>
                </div>
            `;
            dashRecent.insertAdjacentHTML('afterbegin', html);
            if (dashRecent.children.length > 5) dashRecent.removeChild(dashRecent.lastChild);
        }

        const trackedCount = alertList.querySelectorAll('tr').length;
        if (feedCount) feedCount.textContent = `${trackedCount} tracked/SIEM`;
        if (sidebarAlertCount) sidebarAlertCount.textContent = trackedCount;

        // Increment IPC message count
        ipcMessageCount++;
        updateConceptStats();
    });

    let metricsThreatTick = 1;
    socket.on('metrics_update', (data) => {
        const eventsLastMin = data.events_last_min || 0;
        const activeAlerts = data.active_alerts || 0;
        const counts = data.severity_counts || {};

        if (epmValue) epmValue.textContent = eventsLastMin;
        if (activeAlertsValue) activeAlertsValue.textContent = activeAlerts;
        if (responseActionsValue) responseActionsValue.textContent = data.kill_cnt || 0;
        const dashKills = document.getElementById('dash-kills');
        if (dashKills) dashKills.textContent = data.kill_cnt || 0;
        if (sidebarAlertCount) sidebarAlertCount.textContent = activeAlerts;

        applySeverityCounts(counts);
        updateAnalysis(statusBadge.textContent.replace('STATE: ', ''), counts, activeAlerts, eventsLastMin);
        /* Network widget: driven only by network_stats (+ queue on snapshot) to avoid double DOM/CSS work */

        if (threatChart) {
            metricsThreatTick = (metricsThreatTick + 1) % 2;
            if (metricsThreatTick === 0) {
                threatChart.data.labels.push(dataPoints++);
                threatChart.data.datasets[0].data.push(eventsLastMin + Math.random() * 5);
                threatChart.data.datasets[1].data.push(counts.HIGH || counts.MEDIUM || 0);
                if (threatChart.data.labels.length > 30) {
                    threatChart.data.labels.shift();
                    threatChart.data.datasets[0].data.shift();
                    threatChart.data.datasets[1].data.shift();
                }
                threatChart.update('none');
            }
        }

        // Increment IPC message counter (each metric is an IPC event)
        ipcMessageCount++;
        updateConceptStats(data);
    });

    // ═══ Initial Empty States ════════════════════════════════════════════
    renderEmptyState(alertList, 'Waiting for live alerts...');
    renderEmptyState(eventList, 'Waiting for recent events...');
    renderEmptyState(stateHistoryList, 'Waiting for FSM history...');
    updateFsmDiagram('NORMAL');

    // ═══ Report Generation ═══════════════════════════════════════════════
    const btnReport = document.getElementById('btn-generate-report');
    if (btnReport) {
        btnReport.addEventListener('click', () => {
            const dateStr = new Date().toISOString().replace(/[:.]/g, '-');
            const csvContent = "data:text/csv;charset=utf-8," 
                + "FalconStrix SOC Report\nGenerated: " + dateStr + "\n\n"
                + "Metric,Value\n"
                + "System Status," + statusBadge.textContent.replace('STATE: ', '') + "\n"
                + "Active Threats," + (document.getElementById('dash-active-threats')?.textContent || 0) + "\n"
                + "Resolved Cases," + (document.getElementById('dash-resolved')?.textContent || 0) + "\n"
                + "Vulnerabilities," + (document.getElementById('dash-vuln')?.textContent || 0) + "\n";
            
            const encodedUri = encodeURI(csvContent);
            const link = document.createElement('a');
            link.setAttribute('href', encodedUri);
            link.setAttribute('download', 'FalconStrix_Report_' + dateStr + '.csv');
            document.body.appendChild(link);
            link.click();
            link.remove();
        });
    }

    // ═══ Scan Now Button ══════════════════════════════════════════════════
    const btnScan = document.querySelector('.scan-btn');
    if (btnScan) {
        btnScan.addEventListener('click', () => {
            btnScan.textContent = 'Scanning...';
            btnScan.disabled = true;
            socket.emit('request_scan');
        });
    }

    socket.on('scan_start', () => {
        const titleEl = document.getElementById('page-title');
        titleEl.textContent = 'FalconStrix - Scanning...';
        titleEl.style.color = '#eab308';
    });

    socket.on('scan_complete', (data) => {
        const titleEl = document.getElementById('page-title');
        titleEl.textContent = 'FalconStrix';
        titleEl.style.color = 'var(--text-bright)';
        btnScan.textContent = 'Scan Now';
        btnScan.disabled = false;
        alert(data.message);
    });

    socket.on('alert_msg', (data) => {
        alert(data.text);
    });

    /* Start viz loop for whichever page is active on first load (HTML default is dashboard). */
    const initialActivePage = document.querySelector('.page.active');
    const initialPageName = initialActivePage?.id?.replace(/^page-/, '') || 'dashboard';
    startConceptViz(initialPageName);
    if (initialPageName === 'os-ipc') {
        refreshIpcStatus();
        ipcStatusTimer = setInterval(refreshIpcStatus, 8000);
    }
});
