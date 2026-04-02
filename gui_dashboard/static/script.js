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
    const currentUserRole = String(window.FALCON_USER_ROLE || 'user').toLowerCase();
    const currentUsername = String(window.FALCON_USERNAME || '').toLowerCase();
    const canResolveCases = true;

    const socket = io();

    // ═══ Element References ══════════════════════════════════════════════
    const startupScreen = document.getElementById('startup-screen');
    const connectionBadge = document.getElementById('connection-badge');
    const statusBadge = document.getElementById('status-badge');
    const overlay = document.getElementById('defensive-overlay');
    const defOverlaySummary = document.getElementById('def-overlay-summary');
    const defOverlayList = document.getElementById('def-overlay-list');
    const defOverlayOpenAlertsBtn = document.getElementById('def-overlay-open-alerts');
    const defOverlayOpenResolvedBtn = document.getElementById('def-overlay-open-resolved');
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
   const sidebarHoverTab = document.querySelector('.sidebar-hover-tab');
    const navItems = document.querySelectorAll('.nav-item');
    const pages = document.querySelectorAll('.page');

    const pageTitles = {
        'dashboard': 'Dashboard',
        'alerts': 'Live Alerts',
        'resolved-cases': 'Solved Cases',
        'terminated-processes': 'Terminated Processes Audit',
        'events': 'Events Log',
        'fsm': 'FSM State Machine',
        'os-concepts': 'OS Concepts Overview',
        'os-process': 'Process Creation & Management',
        'os-threads': 'Multithreading',
        'os-sync': 'Synchronization (Mutex)',
        'os-ipc': 'Inter-Process Communication',
        'os-signals': 'Signal Handling',
        'os-resources': 'Resource Monitoring',
        'os-procfs': '/proc Filesystem',
        'os-concurrency': 'Concurrency Design',
        'os-fault': 'Fault Tolerance',
        'red-team': 'Red Team Simulation',
        'response': 'Response Engine'
    };

    const setSidebarAlertCount = (nextCount) => {
        if (!sidebarAlertCount) return;
        const normalized = Math.max(0, Number(nextCount) || 0);
        const prev = Number(sidebarAlertCount.dataset.count || sidebarAlertCount.textContent || 0);
        sidebarAlertCount.textContent = String(normalized);
        sidebarAlertCount.dataset.count = String(normalized);
        if (normalized !== prev) {
            sidebarAlertCount.classList.remove('bump');
            void sidebarAlertCount.offsetWidth;
            sidebarAlertCount.classList.add('bump');
            const navAlertsBtn = document.getElementById('nav-alerts');
            if (navAlertsBtn) {
                navAlertsBtn.classList.remove('just-updated');
                void navAlertsBtn.offsetWidth;
                navAlertsBtn.classList.add('just-updated');
            }
        }
    };

    const laneMonitor = document.getElementById('thread-viz-monitor');
    const laneBehavior = document.getElementById('thread-viz-behavior');
    const laneResource = document.getElementById('thread-viz-resource');

    const vizOsProcessCaption = document.getElementById('viz-os-process-caption');
    const vizOsProcessParent = document.getElementById('viz-os-process-parent');
    const vizOsProcessChild = document.getElementById('viz-os-process-child');
    const vizOsProcessGraph = document.getElementById('viz-os-process-graph');
    const vizOsProcessPacket = document.getElementById('viz-os-process-packet');
    const vizOsProcessForkLabel = document.getElementById('viz-os-process-fork-label');
    const vizOsProcessExplainTitle = document.getElementById('viz-os-process-phase-title');
    const vizOsProcessExplainLead = document.getElementById('viz-os-process-phase-lead');
    const vizOsProcessExplainBullets = document.getElementById('viz-os-process-phase-bullets');
    const vizOsProcessCodeRef = document.getElementById('viz-os-process-code-ref');

    const escapeHtmlOs = (s) =>
        String(s ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/"/g, '&quot;');

    /** Long-form copy for Process Management page — keys match data-phase on #viz-os-process-graph */
    const OS_PROCESS_PHASE_COPY = {
        fork: {
            title: 'Step 1 — fork() creates the parent/child split',
            lead: 'The kernel copies the process: after this line, two processes exist, both about to test the value of pid.',
            bullets: [
                'If fork() fails (pid < 0), main() prints an error and exits — no child is created.',
                'In the child branch, pid == 0. That process calls run_child_engine() and never executes the parent’s waitpid() code.',
                'In the parent branch, pid is the new child’s process ID. Only the parent remembers this PID in child_pid.',
            ],
            codeRef: 'main.cpp → pid_t pid = fork();',
        },
        assign: {
            title: 'Step 2 — Parent records the child; child starts work',
            lead: 'The parent sets child_pid = pid so signal_handler can forward SIGINT/SIGTERM to the child. The child begins run_child_engine().',
            bullets: [
                'child_pid is global so the async signal handler can call kill(child_pid, signum) during shutdown.',
                'The child installs child_signal_handler for SIGINT/SIGTERM and sets running = 0 when stopping.',
                'The moving dot crossing “fork()” is a visual metaphor for control moving from one process to the other.',
            ],
            codeRef: 'Parent: child_pid = pid; Child: run_child_engine();',
        },
        threads: {
            title: 'Step 3 — Four pthread workers inside the child',
            lead: 'run_child_engine() passes the same running flag pointer to every thread so they can exit cleanly when signaled.',
            bullets: [
                'start_process_monitor — scans /proc, emits events.',
                'start_behavior_detector — patterns, load/memory checks.',
                'start_resource_monitor — CPU/memory sampling.',
                'start_response_engine — reads command FIFO, can SIGKILL targets.',
                'pthread_join waits for all four to finish before the child exits.',
            ],
            codeRef: 'run_child_engine() → pthread_create ×4, pthread_join ×4',
        },
        wait: {
            title: 'Step 4 — Parent blocks in waitpid()',
            lead: 'The parent does nothing else until the child process exits. This reaps the child and fills status (no zombie if you always wait).',
            bullets: [
                'waitpid(pid, &status, 0) is blocking: the parent is not spinning in a busy loop.',
                'While waiting, the child’s four threads keep running their loops until running becomes 0.',
                'If the child exits normally, the parent will read that outcome in the next step.',
            ],
            codeRef: 'Parent: waitpid(pid, &status, 0);',
        },
        recovery: {
            title: 'Step 5 — Read exit status; restart or stop',
            lead: 'Macros tell you how the child ended. If the engine should keep going, the parent sleeps 2 seconds and forks a fresh child.',
            bullets: [
                'WIFEXITED(status) + WEXITSTATUS(status) == 0 → clean exit; parent breaks out of while(running) in this implementation.',
                'Non-zero exit or WIFSIGNALED(status) while still “running” → log, sleep(2), continue → new fork().',
                'This is the supervision / fault-tolerance loop you see in the source.',
            ],
            codeRef: 'WIFEXITED / WEXITSTATUS / WIFSIGNALED / WTERMSIG → sleep(2) → continue',
        },
        shutdown: {
            title: 'Step 6 — Signals shut down parent and child together',
            lead: 'signal_handler sets running = 0, then forwards the signal to the child so both sides stop. waitpid then returns and the parent exits the loop.',
            bullets: [
                'volatile sig_atomic_t running is safe to set from a signal handler.',
                'kill(child_pid, signum) asks the child to run its handler and clear running for threads.',
                'After waitpid returns, if !running the parent skips restart and prints shutdown.',
            ],
            codeRef: 'signal_handler → running=0; kill(child_pid, signum);',
        },
    };
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
    const vizResPipelineAnim = document.getElementById('viz-res-pipeline-anim');
    const vizResPipelineFill = document.getElementById('viz-res-pipeline-fill');
    const vizResPipelineBeam = document.getElementById('viz-res-pipeline-beam');
    const resVizStepCaption = document.getElementById('res-viz-step-caption');
    const vizResBoxes = document.querySelectorAll('[data-viz-res-box]');
    const vizResAlertStrip = document.getElementById('viz-res-alert-strip');
    const vizResCpuFields = document.getElementById('viz-res-cpu-fields');
    const vizResMemFields = document.getElementById('viz-res-mem-fields');
    const vizResProcFields = document.getElementById('viz-res-proc-fields');
    const vizResScreenNodes = document.querySelectorAll('[data-viz-res-screen]');
    const vizResVideoStep = document.getElementById('viz-res-video-step');
    const vizResVideoTitle = document.getElementById('viz-res-video-title');
    const vizResVideoSubtitle = document.getElementById('viz-res-video-subtitle');
    const vizResCpuChip = document.getElementById('viz-res-cpu-chip');
    const vizResMemChip = document.getElementById('viz-res-mem-chip');
    const vizResVideoAlert = document.getElementById('viz-res-video-alert');
    const vizResLaneNodes = document.querySelectorAll('[data-viz-res-lane]');
    const vizResSummaryScreenNodes = document.querySelectorAll('[data-viz-res-summary-screen]');
    const vizResSummaryValueNodes = document.querySelectorAll('[data-viz-res-summary-value]');
    const vizConceptNodes = document.querySelectorAll('[data-concept-viz-node]');
    const vizFsmBadge = document.getElementById('viz-response-fsm');
    const vizKillTarget = document.getElementById('viz-response-kill-target');
    const vizResponseCaption = document.getElementById('viz-response-caption');
    const vizResponseRail = document.getElementById('viz-response-rail');
    const vizResponseSteps = document.querySelectorAll('[data-response-phase]');
    const vizResponseConsoleFsm = document.getElementById('viz-response-console-fsm');
    const vizResponseConsolePython = document.getElementById('viz-response-console-python');
    const vizResponseConsoleCpp = document.getElementById('viz-response-console-cpp');
    const vizResponsePhaseTitle = document.getElementById('viz-response-phase-title');
    const vizResponsePhaseLead = document.getElementById('viz-response-phase-lead');
    const vizResponsePhaseBullets = document.getElementById('viz-response-phase-bullets');
    const vizResponseCodeRef = document.getElementById('viz-response-code-ref');

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
    const resolvedCasesTable = document.getElementById('resolved-cases-table');
    const terminatedProcessesTable = document.getElementById('terminated-processes-table');
    const resolvedFilterCaseId = document.getElementById('resolved-filter-case-id');
    const resolvedFilterText = document.getElementById('resolved-filter-text');
    const resolvedFilterPid = document.getElementById('resolved-filter-pid');
    const resolvedFilterFrom = document.getElementById('resolved-filter-from');
    const resolvedFilterTo = document.getElementById('resolved-filter-to');
    const resolvedFilterClear = document.getElementById('resolved-filter-clear');
    const resolvedChipToday = document.getElementById('resolved-chip-today');
    const resolvedChip24h = document.getElementById('resolved-chip-24h');
    const resolvedChip7d = document.getElementById('resolved-chip-7d');
    const resolvedExportCsv = document.getElementById('resolved-export-csv');
    const resolvedExportPdf = document.getElementById('resolved-export-pdf');
    const terminatedFilterUser = document.getElementById('terminated-filter-user');
    const terminatedFilterPid = document.getElementById('terminated-filter-pid');
    const terminatedFilterText = document.getElementById('terminated-filter-text');
    const terminatedFilterFrom = document.getElementById('terminated-filter-from');
    const terminatedFilterTo = document.getElementById('terminated-filter-to');
    const terminatedFilterClear = document.getElementById('terminated-filter-clear');
    const terminatedChipToday = document.getElementById('terminated-chip-today');
    const terminatedChip24h = document.getElementById('terminated-chip-24h');
    const terminatedChip7d = document.getElementById('terminated-chip-7d');
    const terminatedExportCsv = document.getElementById('terminated-export-csv');
    const terminatedExportPdf = document.getElementById('terminated-export-pdf');
    const userActivityExportCsv = document.getElementById('user-activity-export-csv');
    const incidentSummaryExportCsv = document.getElementById('incident-summary-export-csv');

    let resolvedCasesAll = [];
    let terminatedProcessesAll = [];
    let resolvedCasesFiltered = [];
    let terminatedProcessesFiltered = [];
    let userActivityCurrent = [];
    let incidentSummaryCurrent = [];
    let overlayAcknowledgedLocked = false;
    let lockAutoReevalInFlight = false;
    let lockAutoReevalUnsupported = false;

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

    // Start/Stop controls for OS concept animations
    const conceptPages = ['os-process', 'os-threads', 'os-sync', 'os-ipc', 'os-signals', 'os-resources', 'os-procfs', 'os-concurrency', 'os-fault', 'response'];
    conceptPages.forEach((pageName) => {
        const startBtn = document.getElementById(`viz-btn-start-${pageName}`);
        const stopBtn = document.getElementById(`viz-btn-stop-${pageName}`);
        if (startBtn) {
            startBtn.addEventListener('click', () => {
                if (conceptVizPage === pageName) resumeResourcesViz();
            });
        }
        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                if (conceptVizPage === pageName) pauseResourcesViz();
            });
        }
    });
    const resPrevBtn = document.getElementById('viz-btn-prev-os-resources');
    const resNextBtn = document.getElementById('viz-btn-next-os-resources');
    const responsePrevBtn = document.getElementById('viz-btn-prev-response');
    const responseNextBtn = document.getElementById('viz-btn-next-response');
    if (resPrevBtn) {
        resPrevBtn.addEventListener('click', () => stepConceptViz('os-resources', -1));
    }
    if (resNextBtn) {
        resNextBtn.addEventListener('click', () => stepConceptViz('os-resources', 1));
    }
    if (responsePrevBtn) {
        responsePrevBtn.addEventListener('click', () => stepConceptViz('response', -1));
    }
    if (responseNextBtn) {
        responseNextBtn.addEventListener('click', () => stepConceptViz('response', 1));
    }

    let conceptVizRaf = null;
    let conceptVizT0 = 0;
    let conceptVizPage = null;
    let conceptVizPaused = false;
    let conceptVizFrozenElapsed = 0;
    const RESOURCE_VIZ_STEP_MS = 5000;
    const RESOURCE_VIZ_STEP_COUNT = 6;
    const RESPONSE_VIZ_PERIOD_MS = 9000;
    const RESPONSE_VIZ_STEP_OFFSETS_MS = [0, 3000, 6000, 6900, 8200];
    const lastConceptCodePhase = {};

    function syncConceptCodeHighlight(scrollId, phase) {
        if (!scrollId || !phase) return;
        const pre = document.getElementById(scrollId);
        if (!pre) return;
        pre.querySelectorAll('.code-step-block[data-code-phase]').forEach((el) => {
            el.classList.toggle('is-active', el.getAttribute('data-code-phase') === phase);
        });
        if (lastConceptCodePhase[scrollId] === phase) return;
        lastConceptCodePhase[scrollId] = phase;
        const active = pre.querySelector(`.code-step-block[data-code-phase="${phase}"]`);
        if (active) {
            requestAnimationFrame(() => {
                active.scrollIntoView({ behavior: 'smooth', block: 'center', inline: 'nearest' });
            });
        }
    }

    const CONCEPT_SCROLL_BY_PAGE = {
        'os-process': 'os-process-code-scroll',
        'os-threads': 'os-threads-code-scroll',
        'os-sync': 'os-sync-code-scroll',
        'os-ipc': 'os-ipc-code-scroll',
        'os-signals': 'os-signals-code-scroll',
        'os-resources': 'os-resources-code-scroll',
        'os-procfs': 'os-procfs-code-scroll',
        'os-concurrency': 'os-concurrency-code-scroll',
        'os-fault': 'os-fault-code-scroll',
        'response': 'response-code-scroll',
    };

    const VIZ_PAGES = new Set([
        'os-concepts',
        'os-process',
        'os-sync',
        'os-ipc',
        'os-signals',
        'os-resources',
        'os-procfs',
        'os-concurrency',
        'os-fault',
        'os-threads',
        'red-team',
        'response'
    ]);

    // OS concept pages with Start/Stop controls
    const CONCEPT_CONTROL_PAGES = new Set([
        'os-process',
        'os-threads',
        'os-sync',
        'os-ipc',
        'os-signals',
        'os-resources',
        'os-procfs',
        'os-concurrency',
        'os-fault',
        'response',
    ]);

    function stopConceptViz() {
        if (conceptVizRaf != null) {
            cancelAnimationFrame(conceptVizRaf);
            conceptVizRaf = null;
        }
        conceptVizPage = null;
        conceptVizPaused = false;
        conceptVizFrozenElapsed = 0;
        updateResVizToolbar();
        document.body.classList.remove('os-viz-paused');
    }

    function updateResVizToolbar() {
        CONCEPT_CONTROL_PAGES.forEach((pageName) => {
            const startBtn = document.getElementById(`viz-btn-start-${pageName}`);
            const stopBtn = document.getElementById(`viz-btn-stop-${pageName}`);
            const stateEl = document.getElementById(`viz-state-${pageName}`);
            const isActive = conceptVizPage === pageName;
            const running = isActive && !conceptVizPaused;

            if (startBtn) startBtn.disabled = !isActive || running; // enable only while paused
            if (stopBtn) stopBtn.disabled = !isActive || !running; // enable only while running
            if (stateEl) stateEl.textContent = isActive
                ? (conceptVizPaused ? 'Paused' : 'Running')
                : '';
        });
        const resourceCanStep = conceptVizPage === 'os-resources' && conceptVizPaused;
        if (resPrevBtn) resPrevBtn.disabled = !resourceCanStep;
        if (resNextBtn) resNextBtn.disabled = !resourceCanStep;
        const responseCanStep = conceptVizPage === 'response' && conceptVizPaused;
        if (responsePrevBtn) responsePrevBtn.disabled = !responseCanStep;
        if (responseNextBtn) responseNextBtn.disabled = !responseCanStep;
    }

    function stepConceptViz(pageName, dir) {
        if (conceptVizPage !== pageName || !conceptVizPaused) return;

        if (pageName === 'os-resources') {
            const currentPhase = Math.floor(conceptVizFrozenElapsed / RESOURCE_VIZ_STEP_MS) % RESOURCE_VIZ_STEP_COUNT;
            const nextPhase = (currentPhase + dir + RESOURCE_VIZ_STEP_COUNT) % RESOURCE_VIZ_STEP_COUNT;
            conceptVizFrozenElapsed = nextPhase * RESOURCE_VIZ_STEP_MS;
            updateOsResourcesViz(conceptVizFrozenElapsed);
            updateResVizToolbar();
            return;
        }

        if (pageName === 'response') {
            const t = conceptVizFrozenElapsed % RESPONSE_VIZ_PERIOD_MS;
            let currentIdx = RESPONSE_VIZ_STEP_OFFSETS_MS.length - 1;
            for (let i = 0; i < RESPONSE_VIZ_STEP_OFFSETS_MS.length; i++) {
                const start = RESPONSE_VIZ_STEP_OFFSETS_MS[i];
                const end = i === RESPONSE_VIZ_STEP_OFFSETS_MS.length - 1
                    ? RESPONSE_VIZ_PERIOD_MS
                    : RESPONSE_VIZ_STEP_OFFSETS_MS[i + 1];
                if (t >= start && t < end) {
                    currentIdx = i;
                    break;
                }
            }
            const nextIdx =
                (currentIdx + dir + RESPONSE_VIZ_STEP_OFFSETS_MS.length) % RESPONSE_VIZ_STEP_OFFSETS_MS.length;
            conceptVizFrozenElapsed = RESPONSE_VIZ_STEP_OFFSETS_MS[nextIdx];
            updateResponseViz(conceptVizFrozenElapsed);
            updateResponseVizTeaching(conceptVizFrozenElapsed);
            updateResVizToolbar();
        }
    }

    function pauseResourcesViz() {
        if (!CONCEPT_CONTROL_PAGES.has(conceptVizPage) || conceptVizPaused) return;
        conceptVizPaused = true;
        conceptVizFrozenElapsed = performance.now() - conceptVizT0;
        if (conceptVizRaf != null) {
            cancelAnimationFrame(conceptVizRaf);
            conceptVizRaf = null;
        }
        if (vizResPipelineAnim) vizResPipelineAnim.classList.add('res-pipeline-anim--paused');
        document.body.classList.add('os-viz-paused');
        updateResVizToolbar();
    }

    function resumeResourcesViz() {
        if (!CONCEPT_CONTROL_PAGES.has(conceptVizPage) || !conceptVizPaused) return;
        conceptVizPaused = false;
        conceptVizT0 = performance.now() - conceptVizFrozenElapsed;
        if (vizResPipelineAnim) vizResPipelineAnim.classList.remove('res-pipeline-anim--paused');
        if (conceptVizRaf == null) {
            conceptVizRaf = requestAnimationFrame(conceptVizFrame);
        }
        document.body.classList.remove('os-viz-paused');
        updateResVizToolbar();
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

        const tStep = 5000;
        const ti = Math.floor(elapsed / tStep) % 3;
        const threadPhases = ['thread-monitor', 'thread-behavior', 'thread-resource'];
        syncConceptCodeHighlight('os-threads-code-scroll', threadPhases[ti]);
        if (laneMonitor) laneMonitor.classList.toggle('thread-viz-lane--code-focus', ti === 0);
        if (laneBehavior) laneBehavior.classList.toggle('thread-viz-lane--code-focus', ti === 1);
        if (laneResource) laneResource.classList.toggle('thread-viz-lane--code-focus', ti === 2);
    }

    function updateOsProcessViz(elapsed) {
        /* Six equal-length steps; full loop 30s (5s per step) for even reading time */
        const STEP_MS = 5000;
        const p = STEP_MS * 6;
        const T1 = STEP_MS * 1;
        const T2 = STEP_MS * 2;
        const T3 = STEP_MS * 3;
        const T4 = STEP_MS * 4;
        const T5 = STEP_MS * 5;
        const t = elapsed % p;
        let phase = 'fork';
        if (t < T1) phase = 'fork';
        else if (t < T2) phase = 'assign';
        else if (t < T3) phase = 'threads';
        else if (t < T4) phase = 'wait';
        else if (t < T5) phase = 'recovery';
        else phase = 'shutdown';

        if (vizOsProcessGraph) vizOsProcessGraph.dataset.phase = phase;

        const parentLit = t < T2 || (t >= T3 && t < p);
        const childLit = t >= T2 && t < T4;
        if (vizOsProcessParent) vizOsProcessParent.classList.toggle('viz-highlight', parentLit);
        if (vizOsProcessChild) vizOsProcessChild.classList.toggle('viz-highlight', childLit);

        if (vizOsProcessForkLabel) {
            vizOsProcessForkLabel.classList.toggle('viz-fork-join--pulse', phase === 'fork' || phase === 'assign');
        }

        if (vizOsProcessPacket) {
            /* Dot centered in each equal segment: (2k-1)/12 for k = 1..6 */
            const phaseU = {
                fork: 1 / 12,
                assign: 3 / 12,
                threads: 5 / 12,
                wait: 7 / 12,
                recovery: 9 / 12,
                shutdown: 11 / 12,
            };
            const lo = 12;
            const hi = 88;
            const frac = phaseU[phase] ?? 0.5;
            const pos = lo + frac * (hi - lo);
            const wide = typeof window !== 'undefined' && window.innerWidth >= 520;
            if (wide) {
                vizOsProcessPacket.style.left = `${pos}%`;
                vizOsProcessPacket.style.top = '50%';
                vizOsProcessPacket.style.transform = 'translate(-50%, -50%)';
            } else {
                vizOsProcessPacket.style.top = `${pos}%`;
                vizOsProcessPacket.style.left = '50%';
                vizOsProcessPacket.style.transform = 'translate(-50%, -50%)';
            }
        }

        let cap = '';
        if (t < T1) cap = '① fork() — kernel duplicates parent; returns 0 in child, pid in parent';
        else if (t < T2) cap = '② parent: child_pid = pid; child: run_child_engine() starts';
        else if (t < T3) cap = '③ child: pthread_create ×4 (monitor, behavior, resource, response) + shared running flag';
        else if (t < T4) cap = '④ parent: waitpid(pid,&status,0) blocks — child threads loop until running=0';
        else if (t < T5) cap = '⑤ WIFEXITED / WIFSIGNALED → sleep(2) → continue (restart) or break on clean exit';
        else cap = '⑥ signal_handler: running=0 → kill(child_pid, signum) — coordinated shutdown';
        if (vizOsProcessCaption) vizOsProcessCaption.textContent = cap;

        const story = OS_PROCESS_PHASE_COPY[phase];
        if (story) {
            if (vizOsProcessExplainTitle) vizOsProcessExplainTitle.textContent = story.title;
            if (vizOsProcessExplainLead) vizOsProcessExplainLead.textContent = story.lead;
            if (vizOsProcessExplainBullets) {
                vizOsProcessExplainBullets.innerHTML = story.bullets
                    .map((b) => `<li>${escapeHtmlOs(b)}</li>`)
                    .join('');
            }
            if (vizOsProcessCodeRef) {
                vizOsProcessCodeRef.textContent = story.codeRef ? `Code reference: ${story.codeRef}` : '';
            }
        }

        syncConceptCodeHighlight('os-process-code-scroll', phase);
    }

    function updateOsSyncViz(elapsed) {
        const STEP = 5000;
        const p = STEP * 4;
        const t = elapsed % p;
        const phase = Math.min(3, Math.floor(t / STEP));
        const codePhases = ['sync-raw', 'sync-count', 'sync-safe', 'sync-use'];
        syncConceptCodeHighlight('os-sync-code-scroll', codePhases[phase]);
        if (!vizMutexA || !vizMutexB || !vizMutexLock) return;
        vizMutexA.classList.toggle('viz-cs', phase === 1);
        vizMutexB.classList.toggle('viz-cs', phase === 2);
        vizMutexLock.classList.toggle('locked', phase === 1 || phase === 2);
        vizMutexLock.textContent = phase === 1 || phase === 2 ? '🔒' : '🔓';
        const lines = [
            'Raw get_all_pids(): walk /proc (not thread-safe; mutex protects callers)',
            'get_process_count(): lock → get_all_pids().size() → unlock (monitor thread)',
            'get_all_pids_safe(): lock → copy vector → unlock (detector thread)',
            'behavior_detector.cpp: get_all_pids_safe() then scan cmdlines for nc / ncat / netcat',
        ];
        if (vizMutexCaption) vizMutexCaption.textContent = lines[phase];
    }

    function updateOsIpcViz(elapsed) {
        const STEP = 5000;
        const p = STEP * 4;
        const t = elapsed % p;
        const phase = Math.min(3, Math.floor(t / STEP));
        const codePhases = ['ipc-config', 'ipc-cpp', 'ipc-python', 'ipc-red'];
        syncConceptCodeHighlight('os-ipc-code-scroll', codePhases[phase]);
        const dotPos = [0.08, 0.38, 0.62, 0.92][phase];
        if (vizIpcDot) {
            vizIpcDot.style.left = `${dotPos * 100}%`;
        }
        const ipcCaps = [
            'ipc_config.py — PIPE_PATH + setup_named_pipe() (FIFO or Windows file)',
            'C++ send_event_to_backend() — open(O_NONBLOCK) · write JSON line · close',
            'Python main_backend — open(PIPE_PATH) · readline() loop · process_message()',
            'Red Team — append JSON to same PIPE_PATH (login_simulator pattern)',
        ];
        if (vizIpcCaption) vizIpcCaption.textContent = ipcCaps[phase];
    }

    function updateOsSignalsViz(elapsed) {
        const STEP = 5000;
        const p = STEP * 5;
        const t = elapsed % p;
        const phase = Math.min(4, Math.floor(t / STEP));
        const codePhases = ['sig-globals', 'sig-parent', 'sig-child', 'sig-register', 'sig-flow'];
        syncConceptCodeHighlight('os-signals-code-scroll', codePhases[phase]);
        if (vizSigCaption) {
            const caps = [
                'Global state: volatile sig_atomic_t running · static child_pid for forward',
                'Parent signal_handler: set running=0 · kill(child_pid, signum)',
                'Child child_signal_handler: running=0 so pthread workers exit loops',
                'Registration: signal(SIGINT/SIGTERM, handler) in main()',
                'Flow: Ctrl+C → parent handler → child receives same signal → clean shutdown',
            ];
            vizSigCaption.textContent = caps[phase];
        }
        if (vizSigNodes.length >= 3) {
            vizSigNodes[0].classList.toggle('viz-pulse', phase === 3 || phase === 4);
            vizSigNodes[1].classList.toggle('viz-pulse', phase === 1 || phase === 4);
            vizSigNodes[2].classList.toggle('viz-pulse', phase === 2 || phase === 4);
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
        if (vizResCpuChip) vizResCpuChip.textContent = `${c.toFixed(1)}%`;
        if (vizResMemChip) vizResMemChip.textContent = `${m.toFixed(1)}%`;
        vizResSummaryValueNodes.forEach((node) => {
            const kind = node.getAttribute('data-viz-res-summary-value');
            if (kind === 'cpu') node.textContent = `${c.toFixed(1)}%`;
            if (kind === 'mem') node.textContent = `${m.toFixed(1)}%`;
        });

        const phase = Math.floor(elapsed / RESOURCE_VIZ_STEP_MS) % RESOURCE_VIZ_STEP_COUNT;
        const resCodePhases = ['res-cpu-read', 'res-cpu-delta', 'res-mem', 'res-mem-pct', 'res-thread', 'res-alert'];
        const rk = resCodePhases[phase];
        syncConceptCodeHighlight('os-resources-code-scroll', rk);
        syncConceptCodeHighlight('os-resources-h-code-scroll', rk);
        vizResPipeNodes.forEach((node) => {
            const i = parseInt(node.getAttribute('data-viz-res-pipe'), 10);
            node.classList.toggle('res-node-active', i === phase);
        });
        vizResScreenNodes.forEach((node) => {
            const i = parseInt(node.getAttribute('data-viz-res-screen'), 10);
            node.classList.toggle('is-active', i === phase);
        });
        vizResSummaryScreenNodes.forEach((node) => {
            const i = parseInt(node.getAttribute('data-viz-res-summary-screen'), 10);
            node.classList.toggle('is-active', i === phase);
        });
        const activeLane = ['cpu', 'cpu', 'mem', 'mem', 'proc', 'alert'][phase];
        vizResLaneNodes.forEach((node) => {
            node.classList.toggle('is-active', node.getAttribute('data-viz-res-lane') === activeLane);
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
        if (vizResVideoAlert) {
            const alertHot = c > 90 || m > 90 || phase === 5;
            vizResVideoAlert.textContent = alertHot ? 'ALERT ARM' : 'NORMAL';
            vizResVideoAlert.classList.toggle('is-hot', alertHot);
            vizResSummaryValueNodes.forEach((node) => {
                if (node.getAttribute('data-viz-res-summary-value') === 'alert') {
                    node.textContent = alertHot ? 'ALERT ARM' : 'NORMAL';
                    node.classList.toggle('is-hot', alertHot);
                }
            });
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
            '[RES] /proc/stat cpu line → jiffies into struct CpuUsage (see .h)',
            '[RES] Δidle / Δtotal vs static prev_* → cpu.usage_percent',
            '[RES] /proc/meminfo key:value lines → MemoryInfo members',
            '[RES] used = MemTotal − MemAvailable → mem.usage_percent',
            '[RES] struct ProcessStats + get_process_stats (per-pid /proc/[pid]/stat)',
            '[RES] thread loop: thresholds → send_event_to_backend (declared in .h)',
        ];
        if (vizResCaption) {
            vizResCaption.textContent = captions[phase];
        }
        if (vizResVideoTitle) {
            const titles = [
                'Sampling /proc/stat',
                'Deriving CpuUsage',
                'Reading /proc/meminfo',
                'Computing MemoryInfo',
                'Inspecting ProcessStats',
                'Preparing alert emission',
            ];
            vizResVideoTitle.textContent = titles[phase];
        }
        if (vizResVideoSubtitle) {
            const subtitles = [
                'Kernel jiffies enter the monitor as raw counters.',
                'The previous sample turns raw counters into a percentage.',
                'Key-value memory data is parsed into the struct fields.',
                'Available memory becomes a used-memory percentage.',
                'Per-process stats provide PID, RSS, threads, and timing.',
                'Threshold logic decides whether HIGH_CPU or HIGH_MEMORY is sent.',
            ];
            vizResVideoSubtitle.textContent = subtitles[phase];
        }

        if (vizResPipelineAnim) {
            vizResPipelineAnim.dataset.phase = String(phase);
        }
        if (vizResPipelineFill) {
            vizResPipelineFill.style.width = `${((phase + 1) / 6) * 100}%`;
        }
        if (vizResPipelineBeam) {
            const pct = ((phase + 0.5) / 6) * 100;
            vizResPipelineBeam.style.left = `${pct}%`;
        }
        if (resVizStepCaption) {
            const steps = [
                'Step 1/6: Read CPU values from /proc/stat',
                'Step 2/6: Compute CPU usage percentage',
                'Step 3/6: Read memory values from /proc/meminfo',
                'Step 4/6: Compute memory usage percentage',
                'Step 5/6: Read per-process stats from /proc/[pid]/stat',
                'Step 6/6: If threshold crossed, send HIGH_CPU/HIGH_MEMORY event',
            ];
            resVizStepCaption.textContent = steps[phase];
        }
        if (vizResVideoStep) {
            vizResVideoStep.textContent = `Step ${phase + 1}/6`;
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

    function updateResponseVizTeaching(elapsed) {
        const p = 9000;
        const t = elapsed % p;
        let phase = 'response-idle';
        if (t >= 3000 && t < 6000) phase = 'response-warning';
        else if (t >= 6000 && t < 6900) phase = 'response-query';
        else if (t >= 6900 && t < 8200) phase = 'response-kill';
        else if (t >= 8200) phase = 'response-log';

        if (vizResponseRail) vizResponseRail.setAttribute('data-phase', phase);
        if (vizResponseSteps.length) {
            vizResponseSteps.forEach((step) => {
                step.classList.toggle('is-active', step.getAttribute('data-response-phase') === phase);
            });
        }
        if (vizKillTarget) {
            if (phase === 'response-log') {
                vizKillTarget.classList.remove('struck');
                vizKillTarget.textContent = 'PID 8842 â€” malicious_proc â€” event logged, alert resolved';
            }
        }
        if (vizResponseConsoleFsm) {
            if (phase === 'response-idle') vizResponseConsoleFsm.textContent = 'NORMAL â€” watching alert counts';
            else if (phase === 'response-warning') vizResponseConsoleFsm.textContent = 'WARNING â€” thresholds crossed, escalation building';
            else vizResponseConsoleFsm.textContent = 'LOCKED â€” active response permitted';
        }
        if (vizResponseConsolePython) {
            if (phase === 'response-idle') vizResponseConsolePython.textContent = 'active_defense() not running';
            else if (phase === 'response-warning') vizResponseConsolePython.textContent = 'Waiting for LOCKED before querying unresolved alerts';
            else if (phase === 'response-query') vizResponseConsolePython.textContent = 'Running SQL query for unresolved HIGH/CRITICAL/MEDIUM processes';
            else if (phase === 'response-kill') vizResponseConsolePython.textContent = 'Looping through bad_procs and calling os.kill(pid, SIGKILL)';
            else vizResponseConsolePython.textContent = 'Writing RESPONSE_ACTION event and resolving linked alert';
        }
        if (vizResponseConsoleCpp) {
            if (phase === 'response-kill') vizResponseConsoleCpp.textContent = 'trigger_response(pid) / kill(pid, SIGKILL) executing';
            else if (phase === 'response-log') vizResponseConsoleCpp.textContent = 'Kill completed â€” control returns to monitoring';
            else vizResponseConsoleCpp.textContent = 'trigger_response(pid) idle';
        }
        if (vizResponsePhaseTitle && vizResponsePhaseLead && vizResponsePhaseBullets && vizResponseCodeRef) {
            const responseExplain = {
                'response-idle': {
                    title: 'Idle monitoring',
                    lead: 'The response engine is armed but passive. Alerts are still being counted, so no process termination happens yet.',
                    bullets: [
                        'FSM stays in NORMAL while risk thresholds are not crossed.',
                        'No PID is selected, so kill() and os.kill() are not called.',
                        'The code highlight stays on the idle block to show the engine waiting.'
                    ],
                    code: 'Code focus: response_engine.cpp setup â†’ no target PID yet'
                },
                'response-warning': {
                    title: 'Threshold crossed',
                    lead: 'Accumulated MEDIUM/HIGH alerts move the FSM into WARNING, which is the pre-response stage.',
                    bullets: [
                        'The system has enough suspicious evidence to escalate.',
                        'Response logic is getting ready, but termination is still not active.',
                        'This separates observation from active defense.'
                    ],
                    code: 'Code focus: escalation rules â†’ NORMAL to WARNING'
                },
                'response-query': {
                    title: 'Query unresolved alerts',
                    lead: 'Once the FSM reaches LOCKED, Python enters active_defense() and fetches suspicious processes tied to unresolved alerts.',
                    bullets: [
                        'The SQL query joins Processes, Events, Alerts, and Severity.',
                        'Only unresolved alerts are considered.',
                        'The result is a list of PIDs that can be neutralized.'
                    ],
                    code: 'Code focus: process_service.py â†’ query + fetch_query(query)'
                },
                'response-kill': {
                    title: 'Terminate the target',
                    lead: 'The response loop selects a PID from bad_procs and terminates it with SIGKILL for immediate neutralization.',
                    bullets: [
                        'Python calls os.kill(pid, SIGKILL) inside active_defense().',
                        'The C++ response path mirrors the same behavior with kill(pid, SIGKILL).',
                        'The target line is struck through to show the kill has been issued.'
                    ],
                    code: 'Code focus: active_defense() / trigger_response(pid) â†’ kill'
                },
                'response-log': {
                    title: 'Log and resolve',
                    lead: 'After the kill, the backend records a RESPONSE_ACTION event and marks the linked alert as resolved.',
                    bullets: [
                        'The event log preserves what process was terminated.',
                        'The alert row is updated so it no longer remains unresolved.',
                        'Control returns to monitoring, ready for the next escalation.'
                    ],
                    code: 'Code focus: execute_query(INSERT ...) + UPDATE Alerts SET is_resolved=TRUE'
                }
            }[phase];
            vizResponsePhaseTitle.textContent = responseExplain.title;
            vizResponsePhaseLead.textContent = responseExplain.lead;
            vizResponsePhaseBullets.innerHTML = responseExplain.bullets.map((item) => `<li>${item}</li>`).join('');
            vizResponseCodeRef.textContent = responseExplain.code;
        }
        syncConceptCodeHighlight('response-code-scroll', phase);
    }

    function updateOsProcfsViz(elapsed) {
        const p = 8000;
        const t = elapsed % p;
        let phase = 'procfs-scan';
        if (t >= 2000 && t < 4000) phase = 'procfs-comm';
        else if (t >= 4000 && t < 6000) phase = 'procfs-cmdline';
        else if (t >= 6000) phase = 'procfs-status';

        const rail = document.getElementById('viz-procfs-rail');
        if (rail) rail.setAttribute('data-phase', phase);
        document.querySelectorAll('[data-procfs-phase]').forEach((node) => {
            node.classList.toggle('is-active', node.getAttribute('data-procfs-phase') === phase);
        });
        const status = document.getElementById('viz-procfs-status');
        if (status) {
            status.textContent =
                phase === 'procfs-scan'
                    ? 'Scanning /proc for numeric PID directories...'
                    : phase === 'procfs-comm'
                        ? 'Reading /proc/[pid]/comm to get short process names.'
                        : phase === 'procfs-cmdline'
                            ? 'Reading /proc/[pid]/cmdline for full launch command.'
                            : 'Reading /proc/[pid]/status (state, threads, memory fields).';
        }
        syncConceptCodeHighlight('os-procfs-code-scroll', phase);
    }

    function updateOsConcurrencyViz(elapsed) {
        const p = 8000;
        const t = elapsed % p;
        let phase = 'conc-fork';
        if (t >= 2000 && t < 4000) phase = 'conc-thread';
        else if (t >= 4000 && t < 6000) phase = 'conc-join';
        else if (t >= 6000) phase = 'conc-service';

        const rail = document.getElementById('viz-concurrency-rail');
        if (rail) rail.setAttribute('data-phase', phase);
        document.querySelectorAll('[data-concurrency-phase]').forEach((node) => {
            node.classList.toggle('is-active', node.getAttribute('data-concurrency-phase') === phase);
        });
        const status = document.getElementById('viz-concurrency-status');
        if (status) {
            status.textContent =
                phase === 'conc-fork'
                    ? 'Parent forks; child prepares worker threads.'
                    : phase === 'conc-thread'
                        ? 'Monitor, detector, resource, and response threads run in parallel.'
                        : phase === 'conc-join'
                            ? 'Child joins all worker threads before returning.'
                            : 'Python backend/dashboard fan out into service-level concurrency.';
        }
        syncConceptCodeHighlight('os-concurrency-code-scroll', phase);
    }

    function updateOsFaultViz(elapsed) {
        const p = 8000;
        const t = elapsed % p;
        let phase = 'fault-wait';
        if (t >= 2000 && t < 4000) phase = 'fault-check';
        else if (t >= 4000 && t < 6000) phase = 'fault-restart';
        else if (t >= 6000) phase = 'fault-stable';

        const rail = document.getElementById('viz-fault-rail');
        if (rail) rail.setAttribute('data-phase', phase);
        document.querySelectorAll('[data-fault-phase]').forEach((node) => {
            node.classList.toggle('is-active', node.getAttribute('data-fault-phase') === phase);
        });
        const status = document.getElementById('viz-fault-status');
        if (status) {
            status.textContent =
                phase === 'fault-wait'
                    ? 'Parent is blocking in waitpid() while child runs.'
                    : phase === 'fault-check'
                        ? 'Exit status is evaluated with WIFEXITED/WIFSIGNALED.'
                        : phase === 'fault-restart'
                            ? 'Abnormal exit path -> sleep(2) then restart child.'
                            : 'Stable cycle complete; supervisor keeps monitoring.';
        }
        syncConceptCodeHighlight('os-fault-code-scroll', phase);
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
            case 'os-procfs':
                updateOsProcfsViz(elapsed);
                break;
            case 'os-concurrency':
                updateOsConcurrencyViz(elapsed);
                break;
            case 'os-fault':
                updateOsFaultViz(elapsed);
                break;
            case 'os-concepts':
                updateOsConceptsViz(elapsed);
                break;
            case 'red-team':
                updateRedTeamViz(elapsed);
                break;
            case 'response':
                updateResponseViz(elapsed);
                updateResponseVizTeaching(elapsed);
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
        conceptVizPaused = false;
        conceptVizFrozenElapsed = 0;
        if (pageName === 'red-team') rtResetInteractive();
        const sid = CONCEPT_SCROLL_BY_PAGE[pageName];
        if (sid) lastConceptCodePhase[sid] = null;
        if (pageName === 'os-resources') lastConceptCodePhase['os-resources-h-code-scroll'] = null;
        if (pageName === 'os-resources' && vizResPipelineAnim) {
            vizResPipelineAnim.classList.remove('res-pipeline-anim--paused');
        }
        conceptVizRaf = requestAnimationFrame(conceptVizFrame);
        updateResVizToolbar();
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
        if (sidebar) sidebar.classList.remove('hover-open');

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

        // REST fallback: when navigating to Events/Resolved pages, refresh
        // data immediately even if a Socket.IO update was missed.
        if (pageName === 'events' || pageName === 'resolved-cases' || pageName === 'terminated-processes') {
            fetch('/api/dashboard_snapshot')
                .then((r) => r.json())
                .then((snap) => {
                    if (pageName === 'events' && window.renderEvents) {
                        window.renderEvents((snap && snap.recent_events) || []);
                    }
                    if (pageName === 'resolved-cases') {
                        renderResolvedCases((snap && snap.resolved_cases_rows) || []);
                    }
                    if (pageName === 'terminated-processes') {
                        renderTerminatedProcesses((snap && snap.terminated_process_rows) || []);
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
    if (defOverlayOpenAlertsBtn) {
        defOverlayOpenAlertsBtn.addEventListener('click', () => {
            overlayAcknowledgedLocked = true;
            if (overlay) overlay.classList.add('hidden');
            switchPage('alerts');
        });
    }
    if (defOverlayOpenResolvedBtn) {
        defOverlayOpenResolvedBtn.addEventListener('click', () => {
            overlayAcknowledgedLocked = true;
            if (overlay) overlay.classList.add('hidden');
            switchPage('resolved-cases');
        });
    }
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
            menuToggle.setAttribute('aria-expanded', String(sidebar.classList.contains('open')));
        });
    }
    if (sidebarHoverTab && sidebar) {
        sidebarHoverTab.addEventListener('mouseenter', () => {
            if (!sidebar.classList.contains('open') && !sidebar.classList.contains('pinned')) {
                sidebar.classList.add('hover-open');
            }
        });
    }
    if (sidebar) {
        sidebar.addEventListener('mouseleave', () => {
            if (!sidebar.classList.contains('open') && !sidebar.classList.contains('pinned')) {
                sidebar.classList.remove('hover-open');
            }
        });
    }
    if (sidebarBackdrop && sidebar) {
        sidebarBackdrop.addEventListener('click', () => {
            sidebar.classList.remove('open');
            sidebar.classList.remove('hover-open');
        });
    }
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Escape' || !sidebar) return;
        sidebar.classList.remove('open');
        sidebar.classList.remove('hover-open');
    });
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (sidebar) {
                sidebar.classList.remove('open');
                sidebar.classList.remove('hover-open');
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
        if (st !== 'LOCKED') overlayAcknowledgedLocked = false;

        if (st === 'NORMAL') {
            if (statusBadge) statusBadge.classList.add('badge-normal');
            document.body.classList.add('theme-normal');
        } else if (st === 'WARNING') {
            if (statusBadge) statusBadge.classList.add('badge-warning');
            document.body.classList.add('theme-warning');
        } else if (st === 'LOCKED') {
            if (statusBadge) statusBadge.classList.add('badge-locked');
            document.body.classList.add('theme-locked');
            if (overlay && !overlayAcknowledgedLocked) overlay.classList.remove('hidden');
        }

        updateFsmDiagram(st);
        updateOsConceptsStripState(st);
    };

    const updateDefensiveOverlay = (data = {}) => {
        const st = (data.state || 'NORMAL').toUpperCase();
        if (st !== 'LOCKED') return;
        const lockCtx = data.fsm_lock_context || {};
        const counts = data.severity_counts || {};
        const activeCount = Number.isFinite(Number(lockCtx.unresolved_total))
            ? Number(lockCtx.unresolved_total)
            : (Array.isArray(data.active_alerts) ? data.active_alerts.length : 0);
        const critical = Number.isFinite(Number(lockCtx.critical)) ? Number(lockCtx.critical) : (counts.CRITICAL || 0);
        const high = Number.isFinite(Number(lockCtx.high)) ? Number(lockCtx.high) : (counts.HIGH || 0);
        const medium = Number.isFinite(Number(lockCtx.medium)) ? Number(lockCtx.medium) : (counts.MEDIUM || 0);
        const reason = String(lockCtx.reason || '').trim();
        if (defOverlaySummary) {
            if (activeCount > 0) {
                defOverlaySummary.textContent = `LOCKED because unresolved alerts remain (${activeCount}). Open Live Alerts and solve to return to NORMAL.`;
            } else if (lockAutoReevalUnsupported) {
                defOverlaySummary.textContent = 'LOCKED with zero unresolved shown. Backend route update is not loaded yet — restart gui_dashboard/app.py.';
            } else {
                defOverlaySummary.textContent = 'No active alerts detected. Auto re-checking FSM now to return to NORMAL.';
            }
        }
        if (defOverlayList) {
            defOverlayList.innerHTML = `
                <li><strong>State:</strong> ${st}</li>
                <li><strong>Open Alerts:</strong> ${activeCount}</li>
                <li><strong>Critical / High / Medium:</strong> ${critical} / ${high} / ${medium}</li>
                <li><strong>Lock reason (backend/DB):</strong> ${escHtml(reason || 'Awaiting lock reason from FSM history')}</li>
            `;
        }
        if (activeCount === 0 && !lockAutoReevalInFlight && !lockAutoReevalUnsupported) {
            lockAutoReevalInFlight = true;
            fetch('/api/fsm/reevaluate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
            })
                .then((r) => {
                    if (r.status === 404) {
                        lockAutoReevalUnsupported = true;
                    }
                    return r.json().catch(() => ({}));
                })
                .then((payload) => {
                    if (payload && payload.snapshot) {
                        applyGlobalStateUi(payload.snapshot.state);
                    }
                })
                .catch(() => {})
                .finally(() => {
                    setTimeout(() => { lockAutoReevalInFlight = false; }, 2000);
                });
        }
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

    const escHtml = (s) =>
        String(s ?? '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/"/g, '&quot;');
    const escAttr = (s) => String(s ?? '').replace(/"/g, '&quot;');

    const flashDetailRow = (rowEl, severity) => {
        if (!rowEl) return;
        const sev = String(severity || '').toUpperCase();
        rowEl.classList.remove('row-jump-highlight', 'jump-sev-critical', 'jump-sev-high', 'jump-sev-medium', 'jump-sev-low');
        if (sev === 'CRITICAL') rowEl.classList.add('jump-sev-critical');
        else if (sev === 'HIGH') rowEl.classList.add('jump-sev-high');
        else if (sev === 'MEDIUM') rowEl.classList.add('jump-sev-medium');
        else rowEl.classList.add('jump-sev-low');
        rowEl.classList.add('row-jump-highlight');
        rowEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        setTimeout(() => {
            rowEl.classList.remove('row-jump-highlight', 'jump-sev-critical', 'jump-sev-high', 'jump-sev-medium', 'jump-sev-low');
        }, 2200);
    };

    const jumpToAlertDetail = (alertId, pageName, severity) => {
        const idNum = Number(alertId);
        if (!Number.isFinite(idNum) || idNum <= 0) {
            switchPage(pageName || 'alerts');
            return;
        }
        const targetPage = pageName === 'resolved-cases' ? 'resolved-cases' : 'alerts';
        switchPage(targetPage);
        const tryHighlight = () => {
            const selector = targetPage === 'resolved-cases'
                ? `#resolved-cases-table tr[data-alert-id="${idNum}"]`
                : `#alert-list-table tr[data-alert-id="${idNum}"]`;
            const row = document.querySelector(selector);
            if (row) {
                flashDetailRow(row, severity || row.getAttribute('data-severity'));
                return true;
            }
            return false;
        };
        if (tryHighlight()) return;
        fetch('/api/dashboard_snapshot')
            .then((r) => r.json())
            .then((snap) => {
                if (targetPage === 'resolved-cases') {
                    renderResolvedCases((snap && snap.resolved_cases_rows) || []);
                } else {
                    renderAlerts((snap && snap.active_alerts) || [], (snap && snap.recent_alerts) || []);
                }
                setTimeout(() => {
                    tryHighlight();
                }, 80);
            })
            .catch(() => {});
    };

    const renderUserActivity = (items = []) => {
        const userList = document.querySelector('.user-list');
        if (!userList) return;
        userActivityCurrent = Array.isArray(items) ? items.slice() : [];
        const escUa = (s) =>
            String(s ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/"/g, '&quot;');
        if (!Array.isArray(items) || !items.length) {
            userList.innerHTML = '<div class="ul-item"><span>No recent user activity</span></div>';
            return;
        }
        userList.innerHTML = items.map((u) => {
            const ic = u.icon || 'gray';
            const sym = u.icon_char || '👤';
            const actor = u.actor
                ? `<span class="ul-actor">${escUa(u.actor)}</span><span class="ul-sep">·</span>`
                : '';
            const text = escUa(u.description || u.event_type);
            return `<div class="ul-item"><span class="ul-icon ${ic}">${sym}</span><span class="ul-line">${actor}<span>${text}</span></span><span class="ul-time">${escUa(u.timestamp || '')} ›</span></div>`;
        }).join('');
    };

    const resolveLiveAlertCase = async (alertId, buttonEl) => {
        const idNum = Number(alertId);
        if (!Number.isFinite(idNum) || idNum <= 0) return;
        if (buttonEl) {
            buttonEl.disabled = true;
            buttonEl.textContent = 'Resolving...';
        }
        try {
            const res = await fetch(`/api/alerts/${idNum}/resolve`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
            });
            const raw = await res.text();
            let data = null;
            try {
                data = raw ? JSON.parse(raw) : {};
            } catch (_) {
                data = null;
            }

            if (!res.ok || !data || !data.ok) {
                let msg = 'Failed to resolve case';
                if (data && (data.message || data.error)) {
                    msg = data.message || data.error;
                } else if (res.status === 404) {
                    msg = 'Resolve API not found (restart gui_dashboard/app.py to load latest routes).';
                } else if (res.status === 401 || res.status === 403) {
                    msg = 'Session/permissions issue. Login as admin to solve while LOCKED.';
                } else if (raw && raw.trim().startsWith('<!doctype')) {
                    msg = 'Server returned HTML instead of JSON. Please refresh and restart app.py.';
                }
                alert(msg);
                if (buttonEl) {
                    buttonEl.disabled = false;
                    buttonEl.textContent = 'Solve';
                }
                return;
            }
            // Use immediate snapshot from backend if returned.
            if (data.snapshot) {
                applyGlobalStateUi(data.snapshot.state);
                applySeverityCounts(data.snapshot.severity_counts || {});
                renderAlerts(data.snapshot.active_alerts || [], data.snapshot.recent_alerts || []);
                renderResolvedCases(data.snapshot.resolved_cases_rows || []);
                renderUserActivity(data.snapshot.user_activity || []);
                renderEvents(data.snapshot.recent_events || []);
                renderStateHistory(data.snapshot.state_history || []);
                renderTerminatedProcesses(data.snapshot.terminated_process_rows || []);
                const dashResolved = document.getElementById('dash-resolved');
                if (dashResolved) dashResolved.textContent = data.snapshot.resolved_cases || 0;
                if (sidebarAlertCount) sidebarAlertCount.textContent = (data.snapshot.active_alerts || []).length;
            } else {
                fetch('/api/dashboard_snapshot')
                    .then((r) => r.json())
                    .then((snap) => {
                        renderAlerts((snap && snap.active_alerts) || [], (snap && snap.recent_alerts) || []);
                        renderResolvedCases((snap && snap.resolved_cases_rows) || []);
                        renderUserActivity((snap && snap.user_activity) || []);
                    })
                    .catch(() => {});
            }
            alert('Case solved and moved to Resolved Cases.');
        } catch (err) {
            alert(`Resolve failed: ${err}`);
            if (buttonEl) {
                buttonEl.disabled = false;
                buttonEl.textContent = 'Solve';
            }
        }
    };

    const renderAlerts = (alerts = [], recentForSidebar = null) => {
        const tableBody = document.getElementById('alert-list-table');
        const actionTh = document.getElementById('alert-action-th');
        if (actionTh) actionTh.style.display = canResolveCases ? '' : 'none';
        if (tableBody) {
            if (!alerts.length) {
                tableBody.innerHTML = `<tr><td colspan="${canResolveCases ? 9 : 8}" style="text-align:center; padding: 20px;">No security alerts found.</td></tr>`;
                if (feedCount) feedCount.textContent = '0 tracked';
            } else {
                tableBody.innerHTML = alerts.map(alert => `
                    <tr class="sev-${escHtml(alert.severity)}" data-alert-id="${escAttr(alert.alert_id)}" data-severity="${escAttr(alert.severity)}">
                        <td><span class="expander">›</span> ${escHtml(alert.timestamp)}</td>
                        <td class="blue-link">${escHtml(alert.agent || '004')}</td>
                        <td>${escHtml(alert.agent_name || 'Windows')}</td>
                        <td class="blue-link">${escHtml(alert.technique || 'T1059')}</td>
                        <td>${escHtml(alert.tactic || 'Execution')}</td>
                        <td>${escHtml(alert.message)}</td>
                        <td class="level">${escHtml(alert.level || 10)}</td>
                        <td class="blue-link">${escHtml(alert.rule_id || '255000')}</td>
                        ${canResolveCases ? `<td>${
                            alert.alert_id
                                ? `<button type="button" class="resolve-case-btn" data-resolve-alert-id="${escHtml(alert.alert_id)}">Solve</button>`
                                : '<span style="opacity:.6;">—</span>'
                        }</td>` : ''}
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
                    const isResolved = !!alert.is_resolved;
                    const bg = isResolved
                        ? 'green-bg'
                        : (alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'red-bg' : 'yellow-bg');
                    const ts = typeof alert.timestamp === 'string' && alert.timestamp.length > 11
                        ? alert.timestamp.slice(11, 16)
                        : (alert.timestamp || '');
                    const statusText = isResolved
                        ? 'SOLVED ✓'
                        : `${alert.severity} ›`;
                    const statusClass = isResolved
                        ? 'green-text'
                        : (alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'red-text' : 'yellow-text');
                    const targetPage = isResolved ? 'resolved-cases' : 'alerts';
                    return `
                        <div class="al-item">
                            <div class="al-icon ${bg}">⚠</div>
                            <div class="al-info">
                                <h4>${alert.event_type || 'Alert'}</h4>
                                <span>FalconStrix • ${ts}</span>
                            </div>
                            <div class="al-meta"><span class="${statusClass}">${statusText}</span><br><a href="javascript:void(0)" class="alert-detail-link" data-target-page="${targetPage}" data-alert-id="${escAttr(alert.alert_id)}" data-severity="${escAttr(alert.severity)}">View Details</a></div>
                        </div>
                    `;
                }).join('');
            }
        }
    };

    if (alertList) {
        alertList.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-resolve-alert-id]');
            if (!btn) return;
            const aid = btn.getAttribute('data-resolve-alert-id');
            resolveLiveAlertCase(aid, btn);
        });
    }
    const dashRecent = document.getElementById('dash-recent-alerts');
    if (dashRecent) {
        dashRecent.addEventListener('click', (e) => {
            const link = e.target.closest('.alert-detail-link');
            if (!link) return;
            e.preventDefault();
            jumpToAlertDetail(
                link.getAttribute('data-alert-id'),
                link.getAttribute('data-target-page'),
                link.getAttribute('data-severity')
            );
        });
    }

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

    const renderResolvedCases = (rows = []) => {
        resolvedCasesAll = Array.isArray(rows) ? rows.slice() : [];
        applyResolvedCaseFilters();
    };

    const drawResolvedCases = (rows = []) => {
        if (!resolvedCasesTable) return;
        if (!rows.length) {
            resolvedCasesTable.innerHTML =
                '<tr><td colspan="9" style="text-align:center; padding: 20px;">No resolved cases found.</td></tr>';
            return;
        }
        const esc = (s) =>
            String(s ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/"/g, '&quot;');
        resolvedCasesTable.innerHTML = rows
            .map(
                (r) => `
            <tr class="sev-${esc(r.severity)}" data-alert-id="${esc(r.alert_id)}" data-severity="${esc(r.severity)}">
                <td>${esc(r.alert_id)}</td>
                <td>${esc(r.severity)}</td>
                <td>${esc(r.trigger_event)}</td>
                <td>${esc(r.detected_at)}</td>
                <td>${esc(r.resolved_at || '—')}</td>
                <td>${esc(r.resolution_detail || 'Resolved flag set')}</td>
                <td>${esc(r.process_name || '—')}</td>
                <td>${esc(r.pid ?? '—')}</td>
                <td>${esc(r.process_created_at || '—')}</td>
            </tr>`
            )
            .join('');
    };

    const renderTerminatedProcesses = (rows = []) => {
        terminatedProcessesAll = Array.isArray(rows) ? rows.slice() : [];
        applyTerminatedProcessFilters();
    };

    const drawTerminatedProcesses = (rows = []) => {
        if (!terminatedProcessesTable) return;
        if (!rows.length) {
            terminatedProcessesTable.innerHTML =
                '<tr><td colspan="8" style="text-align:center; padding: 20px;">No terminated process records found.</td></tr>';
            return;
        }
        const esc = (s) =>
            String(s ?? '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/"/g, '&quot;');
        terminatedProcessesTable.innerHTML = rows
            .map(
                (r) => `
            <tr>
                <td>${esc(r.terminated_at || '—')}</td>
                <td>${esc(r.terminated_by || 'system')}</td>
                <td>${esc(r.action_type || 'PROCESS_KILLED')}</td>
                <td>${esc(r.process_name || '—')}</td>
                <td>${esc(r.pid ?? '—')}</td>
                <td>${esc(r.process_created_at || '—')}</td>
                <td>${esc(r.source || '—')}</td>
                <td>${esc(r.details || '—')}</td>
            </tr>`
            )
            .join('');
    };

    const parseDateInput = (s) => {
        if (!s) return null;
        const t = Date.parse(s);
        return Number.isFinite(t) ? t : null;
    };

    const toDateTimeLocal = (d) => {
        if (!(d instanceof Date)) return '';
        const pad = (n) => String(n).padStart(2, '0');
        return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
    };

    const applyQuickRange = (fromEl, toEl, mode) => {
        if (!fromEl || !toEl) return;
        const now = new Date();
        const from = new Date(now.getTime());
        if (mode === 'today') {
            from.setHours(0, 0, 0, 0);
        } else if (mode === '24h') {
            from.setHours(from.getHours() - 24);
        } else {
            from.setDate(from.getDate() - 7);
        }
        fromEl.value = toDateTimeLocal(from);
        toEl.value = toDateTimeLocal(now);
    };

    const exportRowsToCsv = (filenamePrefix, columns, rows) => {
        if (!rows || !rows.length) return;
        const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const header = columns.map((c) => esc(c.label)).join(',');
        const lines = rows.map((row) => columns.map((c) => esc(row[c.key])).join(','));
        const csv = [header, ...lines].join('\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        const ts = new Date().toISOString().replace(/[:.]/g, '-');
        a.href = url;
        a.download = `${filenamePrefix}_${ts}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    };

    const logUserAction = async (eventType, description) => {
        try {
            await fetch('/api/audit/action', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ event_type: eventType, description }),
            });
        } catch (_) {
            // Keep UX non-blocking if audit endpoint is unreachable.
        }
    };

    const downloadPdfReport = async (url, fallbackName, auditMessage) => {
        try {
            const res = await fetch(url, { credentials: 'same-origin' });
            if (!res.ok) {
                let details = '';
                try {
                    const t = await res.text();
                    if (t && t.trim().startsWith('{')) {
                        const j = JSON.parse(t);
                        details = j.error || j.message || '';
                    } else if (t && t.toLowerCase().includes('<title>sign in')) {
                        details = 'Session expired, please login again.';
                    }
                } catch (_) {}
                throw new Error(`Report request failed (${res.status})${details ? `: ${details}` : ''}`);
            }
            const blob = await res.blob();
            const dl = document.createElement('a');
            const objectUrl = URL.createObjectURL(blob);
            dl.href = objectUrl;
            const dispo = res.headers.get('content-disposition') || '';
            const m = dispo.match(/filename="?([^"]+)"?/i);
            dl.download = (m && m[1]) || fallbackName;
            document.body.appendChild(dl);
            dl.click();
            dl.remove();
            URL.revokeObjectURL(objectUrl);
            if (auditMessage) logUserAction('REPORT_GENERATED', auditMessage);
        } catch (err) {
            alert(`PDF report failed: ${err.message || err}`);
        }
    };

    function applyResolvedCaseFilters() {
        const caseId = (resolvedFilterCaseId?.value || '').trim();
        const q = (resolvedFilterText?.value || '').trim().toLowerCase();
        const pid = (resolvedFilterPid?.value || '').trim();
        const fromTs = parseDateInput(resolvedFilterFrom?.value || '');
        const toTs = parseDateInput(resolvedFilterTo?.value || '');
        const out = resolvedCasesAll.filter((r) => {
            if (caseId && String(r.alert_id ?? '').trim() !== caseId) return false;
            const blob = `${r.trigger_event || ''} ${r.process_name || ''} ${r.resolution_detail || ''}`.toLowerCase();
            if (q && !blob.includes(q)) return false;
            if (pid && String(r.pid ?? '').trim() !== pid) return false;
            const resolvedTs = parseDateInput(r.resolved_at || '');
            if (fromTs != null && (resolvedTs == null || resolvedTs < fromTs)) return false;
            if (toTs != null && (resolvedTs == null || resolvedTs > toTs)) return false;
            return true;
        });
        resolvedCasesFiltered = out;
        drawResolvedCases(out);
    }

    function applyTerminatedProcessFilters() {
        const user = (terminatedFilterUser?.value || '').trim().toLowerCase();
        const pid = (terminatedFilterPid?.value || '').trim();
        const q = (terminatedFilterText?.value || '').trim().toLowerCase();
        const fromTs = parseDateInput(terminatedFilterFrom?.value || '');
        const toTs = parseDateInput(terminatedFilterTo?.value || '');
        const out = terminatedProcessesAll.filter((r) => {
            if (user && !String(r.terminated_by || '').toLowerCase().includes(user)) return false;
            if (pid && String(r.pid ?? '').trim() !== pid) return false;
            const blob = `${r.process_name || ''} ${r.details || ''} ${r.action_type || ''}`.toLowerCase();
            if (q && !blob.includes(q)) return false;
            const termTs = parseDateInput(r.terminated_at || '');
            if (fromTs != null && (termTs == null || termTs < fromTs)) return false;
            if (toTs != null && (termTs == null || termTs > toTs)) return false;
            return true;
        });
        terminatedProcessesFiltered = out;
        drawTerminatedProcesses(out);
    }

    [resolvedFilterCaseId, resolvedFilterText, resolvedFilterPid, resolvedFilterFrom, resolvedFilterTo].forEach((el) => {
        if (!el) return;
        el.addEventListener('input', applyResolvedCaseFilters);
        el.addEventListener('change', applyResolvedCaseFilters);
    });
    if (resolvedFilterClear) {
        resolvedFilterClear.addEventListener('click', () => {
            if (resolvedFilterCaseId) resolvedFilterCaseId.value = '';
            if (resolvedFilterText) resolvedFilterText.value = '';
            if (resolvedFilterPid) resolvedFilterPid.value = '';
            if (resolvedFilterFrom) resolvedFilterFrom.value = '';
            if (resolvedFilterTo) resolvedFilterTo.value = '';
            applyResolvedCaseFilters();
        });
    }
    if (resolvedChipToday) {
        resolvedChipToday.addEventListener('click', () => {
            applyQuickRange(resolvedFilterFrom, resolvedFilterTo, 'today');
            applyResolvedCaseFilters();
        });
    }
    if (resolvedChip24h) {
        resolvedChip24h.addEventListener('click', () => {
            applyQuickRange(resolvedFilterFrom, resolvedFilterTo, '24h');
            applyResolvedCaseFilters();
        });
    }
    if (resolvedChip7d) {
        resolvedChip7d.addEventListener('click', () => {
            applyQuickRange(resolvedFilterFrom, resolvedFilterTo, '7d');
            applyResolvedCaseFilters();
        });
    }
    if (resolvedExportCsv) {
        resolvedExportCsv.addEventListener('click', () => {
            exportRowsToCsv(
                'resolved_cases_filtered',
                [
                    { key: 'alert_id', label: 'Case ID' },
                    { key: 'severity', label: 'Severity' },
                    { key: 'trigger_event', label: 'Trigger Event' },
                    { key: 'detected_at', label: 'Detected At' },
                    { key: 'resolved_at', label: 'Resolved At' },
                    { key: 'resolution_detail', label: 'How Resolved' },
                    { key: 'process_name', label: 'Process Name' },
                    { key: 'pid', label: 'PID' },
                    { key: 'process_created_at', label: 'Process Created' },
                ],
                resolvedCasesFiltered
            );
            logUserAction('CSV_EXPORT', `Exported resolved cases CSV (${resolvedCasesFiltered.length || 0} rows)`);
        });
    }
    if (resolvedExportPdf) {
        resolvedExportPdf.addEventListener('click', () => {
            downloadPdfReport('/api/reports/resolved-cases.pdf', 'FalconStrix_Resolved_Cases.pdf', 'Downloaded resolved cases PDF report');
        });
    }

    [terminatedFilterUser, terminatedFilterPid, terminatedFilterText, terminatedFilterFrom, terminatedFilterTo].forEach((el) => {
        if (!el) return;
        el.addEventListener('input', applyTerminatedProcessFilters);
        el.addEventListener('change', applyTerminatedProcessFilters);
    });
    if (terminatedFilterClear) {
        terminatedFilterClear.addEventListener('click', () => {
            if (terminatedFilterUser) terminatedFilterUser.value = '';
            if (terminatedFilterPid) terminatedFilterPid.value = '';
            if (terminatedFilterText) terminatedFilterText.value = '';
            if (terminatedFilterFrom) terminatedFilterFrom.value = '';
            if (terminatedFilterTo) terminatedFilterTo.value = '';
            applyTerminatedProcessFilters();
        });
    }
    if (terminatedChipToday) {
        terminatedChipToday.addEventListener('click', () => {
            applyQuickRange(terminatedFilterFrom, terminatedFilterTo, 'today');
            applyTerminatedProcessFilters();
        });
    }
    if (terminatedChip24h) {
        terminatedChip24h.addEventListener('click', () => {
            applyQuickRange(terminatedFilterFrom, terminatedFilterTo, '24h');
            applyTerminatedProcessFilters();
        });
    }
    if (terminatedChip7d) {
        terminatedChip7d.addEventListener('click', () => {
            applyQuickRange(terminatedFilterFrom, terminatedFilterTo, '7d');
            applyTerminatedProcessFilters();
        });
    }
    if (terminatedExportCsv) {
        terminatedExportCsv.addEventListener('click', () => {
            exportRowsToCsv(
                'terminated_processes_filtered',
                [
                    { key: 'terminated_at', label: 'Terminated At' },
                    { key: 'terminated_by', label: 'Terminated By' },
                    { key: 'action_type', label: 'Action Type' },
                    { key: 'process_name', label: 'Process Name' },
                    { key: 'pid', label: 'PID' },
                    { key: 'process_created_at', label: 'Process Created At' },
                    { key: 'source', label: 'Source' },
                    { key: 'details', label: 'Details' },
                ],
                terminatedProcessesFiltered
            );
            logUserAction('CSV_EXPORT', `Exported terminated processes CSV (${terminatedProcessesFiltered.length || 0} rows)`);
        });
    }
    if (terminatedExportPdf) {
        terminatedExportPdf.addEventListener('click', () => {
            downloadPdfReport('/api/reports/terminated-processes.pdf', 'FalconStrix_Terminated_Processes.pdf', 'Downloaded terminated processes PDF report');
        });
    }
    if (userActivityExportCsv) {
        userActivityExportCsv.addEventListener('click', () => {
            downloadPdfReport('/api/reports/user-activity.pdf', 'FalconStrix_User_Activity.pdf', 'Downloaded user activity PDF report');
        });
    }
    if (incidentSummaryExportCsv) {
        incidentSummaryExportCsv.addEventListener('click', () => {
            downloadPdfReport('/api/reports/incident-summary.pdf', 'FalconStrix_Incident_Summary.pdf', 'Downloaded incident summary PDF report');
        });
    }

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
                    {
                        label: 'Malware',
                        data: [12,19,3,5,2,3,15,10,25,30,12,8,5,10,20],
                        borderColor: '#60a5fa',
                        backgroundColor: 'rgba(96,165,250,0.2)',
                        fill: true,
                        tension: 0.5,
                        cubicInterpolationMode: 'monotone',
                        borderWidth: 2.5,
                        borderCapStyle: 'round',
                        borderJoinStyle: 'round',
                        pointRadius: 0
                    },
                    {
                        label: 'Phishing',
                        data: [5,2,10,15,8,5,20,5,12,8,2,7,12,5,10],
                        borderColor: '#f87171',
                        backgroundColor: 'rgba(248,113,113,0.1)',
                        fill: false,
                        tension: 0.5,
                        cubicInterpolationMode: 'monotone',
                        borderWidth: 2.5,
                        borderCapStyle: 'round',
                        borderJoinStyle: 'round',
                        pointRadius: 0
                    }
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
                scales: {
                    y: {
                        display: true,
                        beginAtZero: true,
                        ticks: { color: 'rgba(240, 218, 218, 0.55)', maxTicksLimit: 4 },
                        grid: { color: 'rgba(255, 255, 255, 0.05)' }
                    },
                    x: {
                        display: true,
                        ticks: {
                            color: 'rgba(240, 218, 218, 0.72)',
                            autoSkip: true,
                            maxRotation: 0
                        },
                        grid: { display: false }
                    }
                }
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
        const maxTicksByPeriod = period === 'weekly' ? 7 : (period === 'monthly' ? 10 : 12);
        let labels = Array.isArray(p.labels) ? p.labels.slice() : [];
        let resolved = Array.isArray(p.resolved) ? p.resolved.slice() : [];
        let unresolved = Array.isArray(p.unresolved) ? p.unresolved.slice() : [];

        // Normalize month/year ordering client-side so chart remains readable
        // even if backend sends rolling-window labels.
        if (period === 'weekly' && labels.length) {
            const weekOrder = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
            const norm = (v) => String(v || '').trim().slice(0, 3).toLowerCase();
            const rows = labels.map((lbl, i) => ({
                label: String(lbl || ''),
                key: norm(lbl),
                r: Number(resolved[i] || 0),
                u: Number(unresolved[i] || 0),
            }));
            const isWeekdayLike = rows.some((row) =>
                ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'].includes(row.key)
            );
            if (isWeekdayLike) {
                labels = weekOrder;
                resolved = weekOrder.map((d) => {
                    const hit = rows.find((row) => row.key === d.toLowerCase());
                    return hit ? hit.r : 0;
                });
                unresolved = weekOrder.map((d) => {
                    const hit = rows.find((row) => row.key === d.toLowerCase());
                    return hit ? hit.u : 0;
                });
            }
        } else if (period === 'monthly' && labels.length) {
            const monthOrder = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            const idxMap = monthOrder.map((m) => labels.indexOf(m));
            if (idxMap.some((idx) => idx !== -1)) {
                labels = monthOrder;
                resolved = idxMap.map((idx) => (idx >= 0 ? Number(resolved[idx] || 0) : 0));
                unresolved = idxMap.map((idx) => (idx >= 0 ? Number(unresolved[idx] || 0) : 0));
            }
        } else if (period === 'yearly' && labels.length) {
            const rows = labels.map((lbl, i) => ({
                label: String(lbl),
                year: Number.parseInt(lbl, 10),
                r: Number(resolved[i] || 0),
                u: Number(unresolved[i] || 0),
            }));
            if (rows.every((row) => Number.isFinite(row.year))) {
                rows.sort((a, b) => a.year - b.year);
                labels = rows.map((row) => row.label);
                resolved = rows.map((row) => row.r);
                unresolved = rows.map((row) => row.u);
            }
        }

        incidentsChart.data.labels = labels;
        if (incidentsChart.data.datasets && incidentsChart.data.datasets.length >= 2) {
            incidentsChart.data.datasets[0].data = resolved;
            incidentsChart.data.datasets[1].data = unresolved;
        }
        if (incidentsChart.options?.scales?.x?.ticks) {
            incidentsChart.options.scales.x.ticks.maxTicksLimit = maxTicksByPeriod;
            incidentsChart.options.scales.x.ticks.autoSkip = period !== 'weekly';
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
    let threatEmaA = null;
    let threatEmaB = null;
    let cpuEma = null;
    let lastThreatAppendMs = 0;
    let lastCpuAppendMs = 0;
    const THREAT_APPEND_INTERVAL_MS = 900;
    const CPU_APPEND_INTERVAL_MS = 700;

    const clampPercent = (v) => Math.max(0, Math.min(100, Number(v) || 0));
    const smoothEma = (prev, next, alpha = 0.28) =>
        prev == null ? next : prev + alpha * (next - prev);

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
        updateDefensiveOverlay(data);
        const counts = data.severity_counts || {};
        const activeAlerts = data.active_alerts || [];

        if (activeAlertsValue) activeAlertsValue.textContent = activeAlerts.length;
        if (responseActionsValue) responseActionsValue.textContent = data.kill_cnt || 0;
        setSidebarAlertCount(activeAlerts.length);
        
        // Update new dashboard elements
        const dashActive = document.getElementById('dash-active-threats');
        const dashResolved = document.getElementById('dash-resolved');
        const dashKills = document.getElementById('dash-kills');
        const dashVuln = document.getElementById('dash-vuln');
        const dashStatus = document.getElementById('dash-status');
        
        if (dashActive) dashActive.textContent = activeAlerts.length;
        if (dashResolved) dashResolved.textContent = data.resolved_cases || 0;
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
        renderUserActivity(data.user_activity || []);

        // Incident trends (Weekly / Monthly / Yearly chart)
        if (data.incident_trends) {
            cachedIncidentTrends = data.incident_trends;
            applyIncidentChart(incidentsPeriod);
        }

        // Update Incident Summary
        const summaryList = document.querySelector('.summary-list');
        if (summaryList && data.incident_summary) {
            incidentSummaryCurrent = Array.isArray(data.incident_summary) ? data.incident_summary.slice() : [];
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
        renderResolvedCases(data.resolved_cases_rows || []);
        renderTerminatedProcesses(data.terminated_process_rows || []);
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
            const now = Date.now();
            const rawCpu = clampPercent(res.cpu.util);
            cpuEma = smoothEma(cpuEma, rawCpu, 0.22);
            if (now - lastCpuAppendMs >= CPU_APPEND_INTERVAL_MS) {
                cpuHistoryChart.data.datasets[0].data.push(Number(cpuEma.toFixed(2)));
                cpuHistoryChart.data.datasets[0].data.shift();
                cpuHistoryChart.update('none');
                lastCpuAppendMs = now;
            }
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
        const solveCell = canResolveCases
            ? (alert.alert_id
                ? `<td><button type="button" class="resolve-case-btn" data-resolve-alert-id="${escHtml(alert.alert_id)}">Solve</button></td>`
                : '<td><span style="opacity:.6;">—</span></td>')
            : '';
        const tr = document.createElement('tr');
        tr.className = 'sev-' + alert.severity;
        if (alert.alert_id) tr.setAttribute('data-alert-id', String(alert.alert_id));
        if (alert.severity) tr.setAttribute('data-severity', String(alert.severity));
        tr.innerHTML = `
            <td><span class="expander">›</span> ${alert.timestamp}</td>
            <td class="blue-link">${alert.agent || '004'}</td>
            <td>${alert.agent_name || 'Windows'}</td>
            <td class="blue-link">${alert.technique || 'T1218'}</td>
            <td>${alert.tactic || 'Defense Evasion'}</td>
            <td>${alert.message}</td>
            <td class="level">${alert.level || 10}</td>
            <td class="blue-link">${alert.rule_id || '255563'}</td>
            ${solveCell}
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
                    <div class="al-meta"><span class="${alert.severity === 'CRITICAL' || alert.severity === 'HIGH' ? 'red-text' : 'yellow-text'}">${alert.severity} ›</span><br><a href="javascript:void(0)" class="alert-detail-link" data-target-page="alerts" data-alert-id="${escHtml(alert.alert_id)}" data-severity="${escHtml(alert.severity)}">View Details</a></div>
                </div>
            `;
            dashRecent.insertAdjacentHTML('afterbegin', html);
            if (dashRecent.children.length > 5) dashRecent.removeChild(dashRecent.lastChild);
        }

        const trackedCount = alertList.querySelectorAll('tr').length;
        if (feedCount) feedCount.textContent = `${trackedCount} tracked/SIEM`;
        setSidebarAlertCount(trackedCount);

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
        const dashResolved = document.getElementById('dash-resolved');
        if (dashKills) dashKills.textContent = data.kill_cnt || 0;
        if (dashResolved && data.resolved_cases !== undefined) dashResolved.textContent = data.resolved_cases || 0;
        setSidebarAlertCount(activeAlerts);

        applySeverityCounts(counts);
        updateAnalysis(statusBadge.textContent.replace('STATE: ', ''), counts, activeAlerts, eventsLastMin);
        /* Network widget: driven only by network_stats (+ queue on snapshot) to avoid double DOM/CSS work */

        if (threatChart) {
            metricsThreatTick = (metricsThreatTick + 1) % 2;
            if (metricsThreatTick === 0) {
                const now = Date.now();
                const rawA = Math.max(0, Number(eventsLastMin) || 0);
                const rawB = Math.max(0, Number((counts.HIGH || 0) + (counts.CRITICAL || 0)));
                threatEmaA = smoothEma(threatEmaA, rawA, 0.24);
                threatEmaB = smoothEma(threatEmaB, rawB, 0.3);

                if (now - lastThreatAppendMs >= THREAT_APPEND_INTERVAL_MS) {
                    threatChart.data.labels.push(dataPoints++);
                    threatChart.data.datasets[0].data.push(Number(threatEmaA.toFixed(2)));
                    threatChart.data.datasets[1].data.push(Number(threatEmaB.toFixed(2)));
                    if (threatChart.data.labels.length > 30) {
                        threatChart.data.labels.shift();
                        threatChart.data.datasets[0].data.shift();
                        threatChart.data.datasets[1].data.shift();
                    }
                    threatChart.update('none');
                    lastThreatAppendMs = now;
                }
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
            downloadPdfReport('/api/reports/dashboard.pdf', 'FalconStrix_Soc_Report.pdf', 'Generated full professional SOC PDF report');
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
