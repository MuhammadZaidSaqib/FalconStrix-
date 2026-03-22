/* global Chart, io, window */

const body = document.getElementById("body-root");
const lockedBanner = document.getElementById("locked-banner");
const fsmState = document.getElementById("fsm-state");
const fsmReason = document.getElementById("fsm-reason");
const ledStrip = document.getElementById("led-strip");
const alertFeed = document.getElementById("alert-feed");
const procFeed = document.getElementById("proc-feed");
const respFeed = document.getElementById("resp-feed");
const eventFeed = document.getElementById("event-feed");

let gaugeChart;
let alertsChart;

function renderGauge(level) {
  const ctx = document.getElementById("threatGauge");
  if (!ctx) return;
  const data = {
    labels: ["Threat"],
    datasets: [
      {
        data: [level, 100 - level],
        backgroundColor: ["#ff6b6b", "#1f2a3a"],
        borderWidth: 0,
        circumference: 180,
        rotation: 270,
      },
    ],
  };
  if (gaugeChart) gaugeChart.destroy();
  gaugeChart = new Chart(ctx, {
    type: "doughnut",
    data,
    options: {
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      cutout: "72%",
      responsive: false,
    },
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
  renderAlertsChart(snap.chart || { labels: [], counts: [] });
}

const socket = io();
socket.on("connect", () => console.log("[soc] socket connected"));
socket.on("soc_update", (snap) => paint(snap));

if (window.__INITIAL__) {
  paint(window.__INITIAL__);
}
