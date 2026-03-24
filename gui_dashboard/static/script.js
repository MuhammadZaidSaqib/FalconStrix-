/* global Chart, io, window */

const body = document.getElementById("body-root");
const startupSplash = document.getElementById("startup-splash");
const dashboardContent = document.getElementById("dashboard-content");
const splashName = document.getElementById("splash-name");
const lockedBanner = document.getElementById("locked-banner");
const fsmState = document.getElementById("fsm-state");
const fsmReason = document.getElementById("fsm-reason");
const ledStrip = document.getElementById("led-strip");
const alertFeed = document.getElementById("alert-feed");
const procFeed = document.getElementById("proc-feed");
const respFeed = document.getElementById("resp-feed");
const eventFeed = document.getElementById("event-feed");
const ovFsmState = document.getElementById("ov-fsm-state");
const ovFsmReason = document.getElementById("ov-fsm-reason");
const ovThreatLevel = document.getElementById("ov-threat-level");
const ovThreatStatus = document.getElementById("ov-threat-status");
const ovProcessCount = document.getElementById("ov-process-count");
const ovProcessSummary = document.getElementById("ov-process-summary");
const ovEventCount = document.getElementById("ov-event-count");
const ovEventSummary = document.getElementById("ov-event-summary");
const ovFunctionalSummary = document.getElementById("ov-functional-summary");
const ovConceptsCard = document.getElementById("ov-concepts-card");
const ovConceptsSummary = document.getElementById("ov-concepts-summary");
const ovActiveThreats = document.getElementById("ov-active-threats");
const ovResolvedCases = document.getElementById("ov-resolved-cases");
const ovVulnerabilities = document.getElementById("ov-vulnerabilities");
const ovSystemStatus = document.getElementById("ov-system-status");
const ovRiskRing = document.getElementById("ov-risk-ring");
const ovRecentAlerts = document.getElementById("ov-recent-alerts");
const ovCardFsm = document.getElementById("ov-card-fsm");
const ovCardThreat = document.getElementById("ov-card-threat");
const ovCardProcess = document.getElementById("ov-card-process");
const ovCardEvent = document.getElementById("ov-card-event");
const ovFunctionalCard = document.getElementById("ov-functional-card");
const navItems = Array.from(document.querySelectorAll(".nav-item"));
const layoutShell = document.getElementById("layout-shell");
const sidebarToggle = document.getElementById("sidebar-toggle");
const conceptProcfsSummary = document.getElementById("concept-procfs-summary");
const conceptResourceSummary = document.getElementById("concept-resource-summary");
const conceptSupervisionSummary = document.getElementById("concept-supervision-summary");
const netStatus = document.getElementById("net-status");
const netInRate = document.getElementById("net-in-rate");
const netOutRate = document.getElementById("net-out-rate");
const netInTotal = document.getElementById("net-in-total");
const netOutTotal = document.getElementById("net-out-total");

let gaugeChart;
let alertsChart;
let networkChart;
const netSeries = { labels: [], inData: [], outData: [] };
const sectionPanels = Array.from(document.querySelectorAll("main.grid > section.panel"));

const threatGaugeCenterPlugin = {
  id: "threatGaugeCenterPlugin",
  afterDraw(chart, args, options) {
    const value = Number(options?.value ?? 0);
    const tone = options?.tone || "#5ac8fa";
    const label = options?.label || "Low";
    const { ctx, chartArea } = chart;
    if (!chartArea) return;

    const centerX = (chartArea.left + chartArea.right) / 2;
    const centerY = (chartArea.top + chartArea.bottom) / 2;
    ctx.save();
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";

    ctx.fillStyle = "#dfe9f8";
    ctx.font = "700 20px Segoe UI";
    ctx.fillText(`${value}%`, centerX, centerY - 8);

    ctx.fillStyle = tone;
    ctx.font = "600 11px Segoe UI";
    ctx.fillText(label.toUpperCase(), centerX, centerY + 14);
    ctx.restore();
  },
};

function getThreatVisual(level) {
  if (level >= 80) return { tone: "#ff4d4d", label: "Critical" };
  if (level >= 60) return { tone: "#ff8c42", label: "High" };
  if (level >= 35) return { tone: "#f5c542", label: "Moderate" };
  return { tone: "#3ddc97", label: "Low" };
}

function startIntroAnimation() {
  if (!startupSplash || !dashboardContent) return;

  const finishSplash = () => {
    startupSplash.classList.add("fade-out");
    dashboardContent.classList.remove("hidden-on-load");
    dashboardContent.classList.add("visible");
  };

  if (!splashName) {
    setTimeout(finishSplash, 2000);
    return;
  }

  const fullText = splashName.dataset.text || "FalconStrix";
  const typingStepMs = 180;
  const typingStartDelayMs = 280;
  splashName.textContent = "";
  splashName.classList.add("typing");

  let index = 0;
  setTimeout(() => {
    const typer = setInterval(() => {
      index += 1;
      splashName.textContent = fullText.slice(0, index);
      if (index >= fullText.length) {
        clearInterval(typer);
        splashName.classList.remove("typing");
        splashName.classList.add("activated");
        setTimeout(finishSplash, 1100);
      }
    }, typingStepMs);
  }, typingStartDelayMs);
}

function renderGauge(level) {
  const ctx = document.getElementById("threatGauge");
  if (!ctx) return;
  const safeLevel = Math.max(0, Math.min(100, Number(level || 0)));
  const visual = getThreatVisual(safeLevel);
  const data = {
    labels: ["Threat"],
    datasets: [
      {
        data: [safeLevel, 100 - safeLevel],
        backgroundColor: [visual.tone, "#1b2434"],
        borderWidth: 0,
        hoverOffset: 0,
        borderRadius: 6,
      },
    ],
  };
  if (gaugeChart) gaugeChart.destroy();
  gaugeChart = new Chart(ctx, {
    type: "doughnut",
    data,
    options: {
      cutout: "70%",
      responsive: false,
      animation: { duration: 360, easing: "easeOutQuart" },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: false },
        threatGaugeCenterPlugin: {
          value: safeLevel,
          tone: visual.tone,
          label: visual.label,
        },
      },
    },
    plugins: [threatGaugeCenterPlugin],
  });
}

function renderAlertsChart(chart) {
  const ctx = document.getElementById("alertsChart");
  if (!ctx) return;
  const labels = chart.labels || [];
  const counts = chart.counts || [];
  if (alertsChart) alertsChart.destroy();
  alertsChart = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [
        {
          label: "Alerts / bucket",
          data: counts,
          borderColor: "#5ac8fa",
          backgroundColor: "rgba(90,200,250,0.15)",
          fill: true,
          tension: 0.25,
        },
      ],
    },
    options: {
      plugins: { legend: { labels: { color: "#c5d0e3" } } },
      scales: {
        x: { ticks: { color: "#8b98ad", maxRotation: 45, minRotation: 30 } },
        y: { ticks: { color: "#8b98ad" }, beginAtZero: true },
      },
    },
  });
}

function formatBytes(v) {
  const n = Number(v || 0);
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let idx = 0;
  let value = n;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(idx === 0 ? 0 : 2)} ${units[idx]}`;
}

function renderNetworkTraffic(net) {
  const status = String(net?.status || "unavailable").toUpperCase();
  const inMbps = Number(net?.in_mbps || 0);
  const outMbps = Number(net?.out_mbps || 0);
  const nowLabel = new Date().toLocaleTimeString();

  if (netStatus) netStatus.textContent = status;
  if (netInRate) netInRate.textContent = `${inMbps.toFixed(3)} Mbps`;
  if (netOutRate) netOutRate.textContent = `${outMbps.toFixed(3)} Mbps`;
  if (netInTotal) netInTotal.textContent = `Total: ${formatBytes(net?.in_total_bytes)}`;
  if (netOutTotal) netOutTotal.textContent = `Total: ${formatBytes(net?.out_total_bytes)}`;

  netSeries.labels.push(nowLabel);
  netSeries.inData.push(inMbps);
  netSeries.outData.push(outMbps);
  const maxPoints = 36;
  while (netSeries.labels.length > maxPoints) {
    netSeries.labels.shift();
    netSeries.inData.shift();
    netSeries.outData.shift();
  }

  const ctx = document.getElementById("networkTrafficChart");
  if (!ctx) return;
  const chartData = {
    labels: netSeries.labels,
    datasets: [
      {
        label: "Data In (Mbps)",
        data: netSeries.inData,
        borderColor: "#3ddc97",
        backgroundColor: "rgba(61,220,151,0.18)",
        fill: true,
        tension: 0.25,
      },
      {
        label: "Data Out (Mbps)",
        data: netSeries.outData,
        borderColor: "#5ac8fa",
        backgroundColor: "rgba(90,200,250,0.16)",
        fill: true,
        tension: 0.25,
      },
    ],
  };
  if (networkChart) {
    networkChart.data = chartData;
    networkChart.update("none");
    return;
  }
  networkChart = new Chart(ctx, {
    type: "line",
    data: chartData,
    options: {
      elements: {
        point: { radius: 2.5, hoverRadius: 4 },
      },
      plugins: { legend: { labels: { color: "#c5d0e3" } } },
      scales: {
        x: {
          ticks: { color: "#8b98ad", maxRotation: 45, minRotation: 30 },
          grid: { color: "rgba(76, 104, 140, 0.14)" },
        },
        y: {
          ticks: { color: "#8b98ad" },
          beginAtZero: true,
          grid: { color: "rgba(76, 104, 140, 0.14)" },
        },
      },
    },
  });
}

function card(html, cls) {
  const d = document.createElement("div");
  d.className = "card " + (cls || "");
  d.innerHTML = html;
  return d;
}

function applyFsm(snap) {
  const st = snap.fsm?.state_name || "NORMAL";
  fsmState.textContent = st;
  fsmReason.textContent = snap.fsm?.last_reason || "";
  const led = snap.hardware_led || "GREEN";
  ledStrip.setAttribute("data-led", led);
  if (st === "LOCKED") {
    body.classList.add("critical");
    lockedBanner.classList.remove("hidden");
  } else {
    body.classList.remove("critical");
    lockedBanner.classList.add("hidden");
  }
  renderGauge(snap.threat_level || 0);
}

function renderAlerts(alerts) {
  alertFeed.innerHTML = "";
  (alerts || []).forEach((a) => {
    const sev = a.severity_code || "INFO";
    alertFeed.appendChild(
      card(
        `<div><strong>${a.title || ""}</strong></div>
         <div class="meta">${a.created_at || ""} · ${sev} · ${a.event_type || ""}</div>
         <div>${a.details || ""}</div>`,
        "sev-" + sev
      )
    );
  });
}

function renderProcs(rows) {
  procFeed.innerHTML = "";
  (rows || []).forEach((p) => {
    procFeed.appendChild(
      card(
        `<div><strong>${p.process_name}</strong> <span class="meta">pid ${p.pid}</span></div>
         <div class="meta">${p.detected_at || ""} · ${p.event_type || ""}</div>
         <div class="meta">${p.cmdline || ""}</div>`
      )
    );
  });
}

function renderResp(rows) {
  respFeed.innerHTML = "";
  (rows || []).forEach((r) => {
    respFeed.appendChild(
      card(
        `<div><strong>${r.action}</strong> <span class="meta">pid ${r.target_pid ?? "-"}</span></div>
         <div class="meta">${r.created_at || ""}</div>
         <div>${r.detail || ""}</div>`
      )
    );
  });
}

function renderEvents(rows) {
  eventFeed.innerHTML = "";
  (rows || []).forEach((e) => {
    eventFeed.appendChild(
      card(
        `<div><strong>${e.event_type}</strong> <span class="meta">${e.source || ""}</span></div>
         <div class="meta">${e.created_at || ""}</div>
         <div>${e.description || ""}</div>`
      )
    );
  });
}

function getThreatBand(threatLevel) {
  if (threatLevel >= 80) return "Critical";
  if (threatLevel >= 60) return "High";
  if (threatLevel >= 35) return "Moderate";
  return "Low";
}

function applyTone(el, tone) {
  if (!el) return;
  el.classList.remove("tone-good", "tone-warn", "tone-danger", "tone-info");
  el.classList.add(tone);
}

function renderOverview(snap) {
  const stateName = snap.fsm?.state_name || "NORMAL";
  const stateReason = snap.fsm?.last_reason || "System monitoring in standard mode.";
  const threatLevel = Number(snap.threat_level || 0);
  const threatBand = getThreatBand(threatLevel);
  const processes = snap.processes || [];
  const events = snap.events || [];
  const responses = snap.responses || [];
  const alerts = snap.alerts || [];
  const concepts = snap.concepts || {};
  const latestProcess = processes[0];
  const latestEvent = events[0];
  const maxAlertSeverity = (alerts || []).reduce((max, a) => {
    const sev = String(a?.severity_code || "INFO").toUpperCase();
    if (sev === "CRITICAL") return Math.max(max, 4);
    if (sev === "HIGH") return Math.max(max, 3);
    if (sev === "MEDIUM") return Math.max(max, 2);
    return Math.max(max, 1);
  }, 0);

  if (ovFsmState) ovFsmState.textContent = stateName;
  if (ovFsmReason) ovFsmReason.textContent = stateReason;
  if (ovThreatLevel) ovThreatLevel.textContent = `${threatLevel}%`;
  if (ovThreatStatus) ovThreatStatus.textContent = `${threatBand} risk posture detected.`;
  if (ovActiveThreats) ovActiveThreats.textContent = String(alerts.length);
  if (ovResolvedCases) ovResolvedCases.textContent = String(responses.length);
  if (ovVulnerabilities) ovVulnerabilities.textContent = String(processes.length + Math.max(0, alerts.length - 1));
  if (ovSystemStatus) ovSystemStatus.textContent = stateName === "LOCKED" ? "CRITICAL" : "SECURE";
  if (ovRiskRing) {
    ovRiskRing.textContent = `${threatLevel}%`;
    ovRiskRing.style.background = `conic-gradient(#4f9cff 0deg, #4f9cff ${Math.round(
      3.6 * threatLevel
    )}deg, rgba(79, 156, 255, 0.14) ${Math.round(3.6 * threatLevel)}deg 360deg)`;
  }
  if (ovRecentAlerts) {
    ovRecentAlerts.innerHTML = "";
    (alerts || []).slice(0, 4).forEach((a) => {
      const sev = a.severity_code || "INFO";
      ovRecentAlerts.appendChild(
        card(
          `<div><strong>${a.title || "Alert"}</strong></div>
           <div class="meta">${a.created_at || ""} · ${sev}</div>`,
          "sev-" + sev
        )
      );
    });
    if (!alerts.length) {
      ovRecentAlerts.textContent = "No recent alerts.";
    }
  }

  if (ovProcessCount) {
    ovProcessCount.textContent = `${processes.length} active flags`;
  }
  if (ovProcessSummary) {
    ovProcessSummary.textContent = latestProcess
      ? `Latest: ${latestProcess.process_name || "Unknown process"} (pid ${latestProcess.pid ?? "-"})`
      : "No suspicious process activity.";
  }

  if (ovEventCount) {
    ovEventCount.textContent = `${events.length} events`;
  }
  if (ovEventSummary) {
    ovEventSummary.textContent = latestEvent
      ? `Latest: ${latestEvent.event_type || "Unknown event"} from ${latestEvent.source || "unknown source"}.`
      : "No recent security events captured.";
  }

  if (stateName === "LOCKED") {
    applyTone(ovCardFsm, "tone-danger");
  } else if (stateName === "WARNING") {
    applyTone(ovCardFsm, "tone-warn");
  } else {
    applyTone(ovCardFsm, "tone-good");
  }

  if (threatLevel >= 80) {
    applyTone(ovCardThreat, "tone-danger");
  } else if (threatLevel >= 35) {
    applyTone(ovCardThreat, "tone-warn");
  } else {
    applyTone(ovCardThreat, "tone-good");
  }

  if (processes.length >= 6) {
    applyTone(ovCardProcess, "tone-danger");
  } else if (processes.length >= 2) {
    applyTone(ovCardProcess, "tone-warn");
  } else {
    applyTone(ovCardProcess, "tone-good");
  }

  if (events.length >= 15 || maxAlertSeverity >= 4) {
    applyTone(ovCardEvent, "tone-danger");
  } else if (events.length >= 6 || maxAlertSeverity >= 3) {
    applyTone(ovCardEvent, "tone-warn");
  } else {
    applyTone(ovCardEvent, "tone-good");
  }

  if (ovFunctionalSummary) {
    const dbPart = snap.db_error
      ? "Database connection issue detected; telemetry may be partial."
      : "Database connectivity is healthy.";
    const modePart =
      stateName === "LOCKED"
        ? "Defensive mode is active with automated response controls."
        : "FSM control loop is operating in normal mode.";
    const activityPart = `Current stream: ${alerts.length} alerts, ${processes.length} process flags, ${responses.length} response actions, and ${events.length} events.`;
    ovFunctionalSummary.textContent = `${dbPart} ${modePart} ${activityPart}`;
  }

  const conceptItems = [
    ["procfs", "Process metadata (/proc cmdline/status)"],
    ["resource", "CPU/memory resource pressure telemetry"],
    ["supervision", "Fault tolerance and child supervision"],
  ];
  if (ovConceptsSummary) {
    const text = conceptItems
      .map(([key, label]) => {
        const item = concepts[key] || {};
        const status = String(item.status || "unknown").toUpperCase();
        const summary = item.summary || "No data.";
        return `${label}: ${status} - ${summary}`;
      })
      .join(" ");
    ovConceptsSummary.textContent = text;
  }

  if (snap.db_error || stateName === "LOCKED") {
    applyTone(ovFunctionalCard, "tone-danger");
  } else if (threatLevel >= 60 || maxAlertSeverity >= 3) {
    applyTone(ovFunctionalCard, "tone-warn");
  } else {
    applyTone(ovFunctionalCard, "tone-good");
  }

  const conceptStates = conceptItems.map(([key]) => String((concepts[key] || {}).status || "unknown"));
  if (conceptStates.includes("unknown")) {
    applyTone(ovConceptsCard, "tone-warn");
  } else if (conceptStates.every((s) => s === "active")) {
    applyTone(ovConceptsCard, "tone-good");
  } else {
    applyTone(ovConceptsCard, "tone-info");
  }
}

function renderConceptSections(snap) {
  const concepts = snap.concepts || {};
  const procfs = concepts.procfs || {};
  const resource = concepts.resource || {};
  const supervision = concepts.supervision || {};

  if (conceptProcfsSummary) {
    conceptProcfsSummary.textContent = `Status: ${String(procfs.status || "unknown").toUpperCase()} - ${
      procfs.summary || "No data."
    }`;
  }
  if (conceptResourceSummary) {
    conceptResourceSummary.textContent = `Status: ${String(resource.status || "unknown").toUpperCase()} - ${
      resource.summary || "No data."
    }`;
  }
  if (conceptSupervisionSummary) {
    conceptSupervisionSummary.textContent = `Status: ${String(
      supervision.status || "unknown"
    ).toUpperCase()} - ${supervision.summary || "No data."}`;
  }
}

function paint(snap) {
  const dbBanner = document.getElementById("db-banner");
  if (dbBanner) {
    if (snap.db_error) {
      dbBanner.innerHTML =
        "<strong>Database unavailable.</strong> Start MariaDB/MySQL (e.g. <code>docker compose up -d</code> from the repo root), then refresh. <span class=\"meta\">" +
        String(snap.db_error).replace(/</g, "&lt;") +
        "</span>";
      dbBanner.classList.remove("hidden");
    } else {
      dbBanner.classList.add("hidden");
      dbBanner.textContent = "";
    }
  }
  applyFsm(snap);
  renderAlerts(snap.alerts);
  renderProcs(snap.processes);
  renderResp(snap.responses);
  renderEvents(snap.events);
  renderOverview(snap);
  renderConceptSections(snap);
  renderNetworkTraffic(snap.network || {});
  renderAlertsChart(snap.chart || { labels: [], counts: [] });
}

function setupSidebarNav() {
  if (!navItems.length) return;

  const setActiveSection = (targetId) => {
    sectionPanels.forEach((section) => {
      section.classList.toggle("section-hidden", section.id !== targetId);
    });
    navItems.forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.target === targetId);
    });
  };

  const firstTarget = navItems[0]?.dataset.target;
  if (firstTarget) {
    setActiveSection(firstTarget);
  }

  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      const targetId = item.dataset.target;
      const target = document.getElementById(targetId);
      if (!target) return;

      setActiveSection(targetId);
    });
  });
}

function setupSidebarToggle() {
  if (!layoutShell || !sidebarToggle) return;
  sidebarToggle.addEventListener("click", () => {
    layoutShell.classList.toggle("sidebar-collapsed");
  });
}

function setupFsmStickyBehavior() {
  if (!ovCardFsm) return;
  const baseTop = 84;
  const onScroll = () => {
    const overviewSection = document.getElementById("overview-section");
    const overviewVisible = overviewSection && !overviewSection.classList.contains("section-hidden");
    if (!overviewVisible) {
      ovCardFsm.classList.remove("fsm-compact");
      ovCardFsm.style.top = `${baseTop}px`;
      return;
    }
    const y = Math.max(0, window.scrollY);
    const compact = y > 110;
    ovCardFsm.classList.toggle("fsm-compact", compact);
    if (compact) {
      const drift = Math.min(90, Math.round((y - 110) * 0.12));
      ovCardFsm.style.top = `${baseTop + drift}px`;
    } else {
      ovCardFsm.style.top = `${baseTop}px`;
    }
  };
  window.addEventListener("scroll", onScroll, { passive: true });
  onScroll();
}

const socket = io();
socket.on("connect", () => console.log("[soc] socket connected"));
socket.on("soc_update", (snap) => paint(snap));

if (window.__INITIAL__) {
  paint(window.__INITIAL__);
}
setupSidebarNav();
setupSidebarToggle();
setupFsmStickyBehavior();
startIntroAnimation();

