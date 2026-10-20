"use strict";

const $ = (id) => document.getElementById(id);
const PAGE_SIZE = 25;
const PROTOCOL_COLORS = {
  DNS: "#8967e8",
  TCP: "#4b8fe8",
  UDP: "#1caa78",
  ICMP: "#e89c45",
  OTHER: "#a0aabd",
};

const state = {
  sessions: [],
  selectedId: null,
  summary: null,
  packetOffset: 0,
  packetTotal: 0,
  selectionVersion: 0,
  protocolChart: null,
  trafficChart: null,
  toastTimer: null,
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

async function api(path, options = {}) {
  const response = await fetch(path, options);
  const contentType = response.headers.get("content-type") || "";
  const body = contentType.includes("application/json") ? await response.json() : null;
  if (!response.ok) {
    const detail = body?.detail || `Request failed (${response.status})`;
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return body;
}

function formatNumber(value) {
  return new Intl.NumberFormat().format(value || 0);
}

function formatBytes(value) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unit]}`;
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds <= 0) return "< 1 sec";
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} sec`;
  const mins = Math.floor(seconds / 60);
  const secs = Math.round(seconds % 60);
  if (mins < 60) return `${mins}m ${secs}s`;
  const hours = Math.floor(mins / 60);
  return `${hours}h ${mins % 60}m`;
}

function formatUtc(value, { withSeconds = true, includeDate = true } = {}) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const formatted = new Intl.DateTimeFormat(undefined, {
    ...(includeDate ? { month: "short", day: "2-digit" } : {}),
    hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "UTC",
    ...(withSeconds ? { second: "2-digit" } : {}),
  }).format(date);
  return `${formatted} UTC`;
}

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => node.classList.remove("show"), 3200);
}

function showError(message) {
  const node = $("page-error");
  node.textContent = message;
  node.hidden = false;
}

function clearError() {
  $("page-error").hidden = true;
  $("page-error").textContent = "";
}

function setLoading(visible, message = "Loading capture analysis…") {
  $("page-loading").hidden = !visible;
  if (visible) $("page-loading").lastElementChild.textContent = message;
}

function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem("netscope-theme", theme); } catch { /* Storage may be disabled. */ }
}

function currentSession() {
  return state.sessions.find((session) => session.id === state.selectedId) || null;
}

async function loadSessions(preferredId = state.selectedId) {
  const sessions = await api("/api/sessions?limit=200");
  state.sessions = sessions;
  $("session-count").textContent = formatNumber(sessions.length);
  renderSessions();
  if (!sessions.length) {
    state.selectedId = null;
    renderEmptyState();
    return;
  }
  const exists = sessions.some((item) => item.id === preferredId);
  const nextId = exists ? preferredId : sessions[0].id;
  if (nextId !== state.selectedId || !currentSession()) {
    await selectSession(nextId);
  }
}

function renderSessions() {
  const list = $("session-list");
  if (!state.sessions.length) {
    list.innerHTML = '<div class="side-loading">No captures yet</div>';
    return;
  }
  list.innerHTML = state.sessions.map((session) => {
    const active = session.id === state.selectedId;
    const status = String(session.status || "").toLowerCase();
    const dot = status === "processing" ? "processing" : status === "failed" ? "failed" : "";
    const statusText = status === "completed" ? "Ready" : status === "processing" ? "Processing" : "Failed";
    return `<button class="session-item${active ? " active" : ""}" type="button" data-session-id="${Number(session.id)}" aria-current="${active ? "page" : "false"}">
      <span class="session-file-icon">PC</span><span class="session-meta"><span class="session-name">${escapeHtml(session.name)}</span>
      <span class="session-subline"><i class="status-dot ${dot}"></i>${statusText}<span>·</span>${formatNumber(session.packet_count)} pkts</span></span></button>`;
  }).join("");
}

function renderEmptyState() {
  $("breadcrumb-session").textContent = "Overview";
  $("page-title").textContent = "Traffic overview";
  $("page-subtitle").textContent = "Import a capture to inspect protocols, endpoints, and security signals.";
  $("empty-state").hidden = false;
  $("dashboard-content").hidden = true;
  setLoading(false);
  destroyCharts();
  $("export-csv").hidden = true;
  $("export-json").hidden = true;
}

async function selectSession(sessionId) {
  state.selectedId = Number(sessionId);
  state.packetOffset = 0;
  state.selectionVersion += 1;
  const version = state.selectionVersion;
  clearError();
  renderSessions();
  $("empty-state").hidden = true;
  $("dashboard-content").hidden = true;
  setLoading(true);
  try {
    const session = await api(`/api/sessions/${state.selectedId}`);
    updateSessionInList(session);
    if (session.status === "processing") {
      $("page-title").textContent = session.name;
      $("breadcrumb-session").textContent = session.name;
      $("page-subtitle").textContent = "Upload received · parsing packet stream";
      setLoading(true, "Capture processing… this view will refresh when analysis is complete.");
      await waitForProcessing(session.id, version);
      return;
    }
    await loadSelectedDashboard(session, version);
  } catch (error) {
    setLoading(false);
    showError(error.message);
  }
}

function updateSessionInList(session) {
  const index = state.sessions.findIndex((item) => item.id === session.id);
  if (index >= 0) state.sessions[index] = session;
  else state.sessions.unshift(session);
  renderSessions();
}

async function waitForProcessing(sessionId, version) {
  for (let attempt = 0; attempt < 240; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    if (version !== state.selectionVersion) return;
    const session = await api(`/api/sessions/${sessionId}`);
    updateSessionInList(session);
    if (session.status !== "processing") {
      if (session.status === "failed") {
        setLoading(false);
        showError("The uploaded capture could not be processed. Check that it is a valid PCAP and try again.");
        return;
      }
      await loadSelectedDashboard(session, version);
      toast("Capture analysis is ready");
      return;
    }
  }
  if (version === state.selectionVersion) {
    setLoading(false);
    showError("Capture processing is taking longer than expected. You can select the session again to refresh its status.");
  }
}

async function loadSelectedDashboard(session, version = state.selectionVersion) {
  if (version !== state.selectionVersion) return;
  setLoading(true);
  $("empty-state").hidden = true;
  $("dashboard-content").hidden = true;
  try {
    const bucketSize = Number($("bucket-size").value);
    const [summary, alerts] = await Promise.all([
      api(`/api/sessions/${session.id}/summary?bucket_size=${bucketSize}`),
      api(`/api/sessions/${session.id}/alerts`),
    ]);
    if (version !== state.selectionVersion) return;
    state.summary = summary;
    $("export-csv").href = `/api/sessions/${session.id}/export?format=csv`;
    $("export-json").href = `/api/sessions/${session.id}/export?format=json`;
    $("export-csv").hidden = false;
    $("export-json").hidden = false;
    $("breadcrumb-session").textContent = session.name;
    $("page-title").textContent = session.name;
    const statusText = session.status === "failed" ? "Processing failed" : `${session.source.toUpperCase()} capture · ${session.status}`;
    $("page-subtitle").textContent = `${statusText} · Started ${formatUtc(session.started_at, { withSeconds: false })}`;
    renderSummary(session, summary, alerts);
    $("dashboard-content").hidden = false;
    setLoading(false);
    await loadPackets();
  } catch (error) {
    setLoading(false);
    showError(error.message);
  }
}

function renderSummary(session, summary, alerts) {
  $("metric-packets").textContent = formatNumber(session.packet_count);
  $("metric-bytes").textContent = formatBytes(session.byte_count);
  $("metric-duration").textContent = formatDuration(summary.duration_seconds);
  $("metric-alerts").textContent = formatNumber(alerts.length);
  $("metric-alerts-foot").textContent = alerts.length ? `${alerts.filter((item) => item.severity === "high").length} high severity` : "No rule matches found";
  $("protocol-total").textContent = formatNumber(summary.total_packets);
  $("alert-total").textContent = formatNumber(alerts.length);
  renderProtocol(summary.protocol_distribution || {});
  renderTraffic(summary.packets_per_second || []);
  renderRanks("sources-list", summary.top_sources || [], "address");
  renderRanks("destinations-list", summary.top_destinations || [], "address");
  renderAlerts(alerts);
}

function chartTextColor() {
  return getComputedStyle(document.documentElement).getPropertyValue("--muted").trim() || "#79869b";
}

function destroyCharts() {
  state.protocolChart?.destroy();
  state.trafficChart?.destroy();
  state.protocolChart = null;
  state.trafficChart = null;
}

function renderProtocol(distribution) {
  const entries = Object.entries(distribution).sort((a, b) => b[1] - a[1]);
  const legend = $("protocol-legend");
  if (!window.Chart || !entries.length) {
    legend.innerHTML = entries.length ? entries.map(([name, count]) => `<div class="legend-row"><i class="legend-swatch" style="background:${PROTOCOL_COLORS[name] || "#a0aabd"}"></i>${escapeHtml(name)}<strong>${formatNumber(count)}</strong></div>`).join("") : '<span class="mono">No protocol data</span>';
    state.protocolChart?.destroy();
    state.protocolChart = null;
    return;
  }
  state.protocolChart?.destroy();
  const colors = entries.map(([name]) => PROTOCOL_COLORS[name] || "#a0aabd");
  state.protocolChart = new Chart($("protocol-chart"), {
    type: "doughnut",
    data: { labels: entries.map(([name]) => name), datasets: [{ data: entries.map(([, count]) => count), backgroundColor: colors, borderWidth: 0, hoverOffset: 4 }] },
    options: { cutout: "76%", responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { padding: 10, displayColors: true } } },
  });
  legend.innerHTML = entries.map(([name, count], index) => `<div class="legend-row"><i class="legend-swatch" style="background:${colors[index]}"></i>${escapeHtml(name)}<strong>${formatNumber(count)}</strong></div>`).join("");
}

function renderTraffic(buckets) {
  const canvas = $("traffic-chart");
  const empty = $("traffic-empty");
  if (!window.Chart || !buckets.length) {
    empty.hidden = false;
    state.trafficChart?.destroy();
    state.trafficChart = null;
    return;
  }
  empty.hidden = true;
  state.trafficChart?.destroy();
  const color = getComputedStyle(document.documentElement).getPropertyValue("--primary").trim() || "#5859e8";
  const text = chartTextColor();
  state.trafficChart = new Chart(canvas, {
    type: "line",
    data: {
      labels: buckets.map((item) => formatUtc(item.timestamp, { includeDate: false })),
      datasets: [{ label: "Packets", data: buckets.map((item) => item.packets), borderColor: color, backgroundColor: `${color}20`, fill: true, tension: .35, pointRadius: buckets.length > 50 ? 0 : 2, pointHoverRadius: 4, borderWidth: 2 }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { intersect: false, mode: "index" },
      plugins: { legend: { display: false }, tooltip: { padding: 9 } },
      scales: {
        x: { grid: { display: false }, ticks: { color: text, maxTicksLimit: 7, maxRotation: 0, font: { size: 8 } }, border: { display: false } },
        y: { beginAtZero: true, grid: { color: getComputedStyle(document.documentElement).getPropertyValue("--line").trim() }, ticks: { color: text, precision: 0, maxTicksLimit: 5, font: { size: 8 } }, border: { display: false } },
      },
    },
  });
}

function renderRanks(targetId, rows, field) {
  const node = $(targetId);
  if (!rows.length) {
    node.innerHTML = '<div class="table-empty">No endpoint data available.</div>';
    return;
  }
  node.innerHTML = rows.slice(0, 10).map((row, index) => `<div class="rank-row"><span class="rank-number">${String(index + 1).padStart(2, "0")}</span><span class="rank-address" title="${escapeHtml(row[field])}">${escapeHtml(row[field])}</span><span class="rank-count">${formatNumber(row.count)}</span></div>`).join("");
}

function renderAlerts(alerts) {
  const node = $("alerts-list");
  if (!alerts.length) {
    node.innerHTML = '<div class="table-empty">No anomalies detected for this session.</div>';
    return;
  }
  node.innerHTML = alerts.map((alert) => {
    const severity = String(alert.severity || "low").toLowerCase();
    const source = alert.src_ip ? ` · ${escapeHtml(alert.src_ip)}` : "";
    const evidence = alert.alert_metadata && Object.entries(alert.alert_metadata)
      .filter(([key]) => !["query"].includes(key)).slice(0, 2)
      .map(([key, value]) => `${key.replaceAll("_", " ")}: ${typeof value === "object" ? "…" : value}`).join(" · ");
    return `<div class="alert-row"><span class="severity ${escapeHtml(severity)}">${escapeHtml(severity)}</span><div><div class="alert-description">${escapeHtml(alert.description)}</div><div class="alert-meta">${escapeHtml(alert.rule)}${source} · ${formatUtc(alert.first_seen)}${evidence ? ` · ${escapeHtml(evidence)}` : ""}</div></div></div>`;
  }).join("");
}

function endpoint(ip, port) {
  if (!ip) return "—";
  return `${escapeHtml(ip)}${port === null || port === undefined ? "" : `<span class="port-suffix">:${Number(port)}</span>`}`;
}

function packetDetails(packet) {
  const extra = packet.extra || {};
  if (extra.dns_query) return `DNS · ${extra.dns_query}`;
  if (packet.tcp_flags) return `TCP flags ${packet.tcp_flags}`;
  if (extra.icmp_type !== undefined && extra.icmp_type !== null) return `ICMP type ${extra.icmp_type}`;
  return "—";
}

async function loadPackets() {
  if (!state.selectedId) return;
  const formData = new FormData($("packet-filters"));
  const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(state.packetOffset) });
  for (const [key, value] of formData.entries()) {
    if (String(value).trim()) params.set(key, String(value).trim());
  }
  if (params.has("port") && !/^\d+$/.test(params.get("port"))) params.delete("port");
  try {
    const result = await api(`/api/sessions/${state.selectedId}/packets?${params.toString()}`);
    state.packetTotal = result.total;
    renderPackets(result);
  } catch (error) {
    showError(error.message);
  }
}

function renderPackets(result) {
  const rows = result.items || [];
  const body = $("packet-rows");
  $("packet-results").textContent = `${formatNumber(result.total)} RESULTS`;
  $("packet-empty").hidden = rows.length > 0;
  if (!rows.length) {
    body.innerHTML = "";
  } else {
    body.innerHTML = rows.map((packet) => {
      const protocol = String(packet.protocol || "OTHER").toUpperCase();
      return `<tr><td class="mono">${formatUtc(packet.timestamp)}</td><td class="endpoint">${endpoint(packet.src_ip, packet.src_port)}</td><td class="endpoint">${endpoint(packet.dst_ip, packet.dst_port)}</td><td><span class="protocol-badge ${escapeHtml(protocol.toLowerCase())}">${escapeHtml(protocol)}</span></td><td class="mono">${formatNumber(packet.length)} B</td><td><span class="packet-details" title="${escapeHtml(packetDetails(packet))}">${escapeHtml(packetDetails(packet))}</span></td></tr>`;
    }).join("");
  }
  const start = result.total === 0 ? 0 : result.offset + 1;
  const end = Math.min(result.offset + rows.length, result.total);
  $("page-range").textContent = `Showing ${formatNumber(start)}–${formatNumber(end)} of ${formatNumber(result.total)} packets`;
  const pages = Math.max(1, Math.ceil(result.total / result.limit));
  $("page-indicator").textContent = `${Math.floor(result.offset / result.limit) + 1} / ${pages}`;
  $("prev-page").disabled = result.offset <= 0;
  $("next-page").disabled = result.offset + result.limit >= result.total;
}

async function uploadSelectedFile(file) {
  if (!file) return;
  clearError();
  $("upload-button").disabled = true;
  $("upload-button").querySelector("span").textContent = "Uploading…";
  const form = new FormData();
  form.append("file", file);
  try {
    const session = await api("/api/sessions/upload", { method: "POST", body: form });
    toast("Capture uploaded · analysis started");
    await loadSessions(session.id);
  } catch (error) {
    showError(error.message);
    toast("Upload failed");
  } finally {
    $("upload-button").disabled = false;
    $("upload-button").querySelector("span").textContent = "Upload PCAP";
    $("pcap-file").value = "";
  }
}

function bindEvents() {
  $("upload-button").addEventListener("click", () => $("pcap-file").click());
  document.querySelectorAll('[data-action="choose-file"]').forEach((button) => button.addEventListener("click", () => $("pcap-file").click()));
  $("pcap-file").addEventListener("change", (event) => uploadSelectedFile(event.target.files?.[0]));
  $("upload-form").addEventListener("submit", (event) => event.preventDefault());
  $("session-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-session-id]");
    if (button) selectSession(Number(button.dataset.sessionId));
  });
  $("packet-filters").addEventListener("submit", (event) => {
    event.preventDefault();
    state.packetOffset = 0;
    loadPackets();
  });
  $("clear-filters").addEventListener("click", () => {
    $("packet-filters").reset();
    state.packetOffset = 0;
    loadPackets();
  });
  $("prev-page").addEventListener("click", () => {
    state.packetOffset = Math.max(0, state.packetOffset - PAGE_SIZE);
    loadPackets();
  });
  $("next-page").addEventListener("click", () => {
    if (state.packetOffset + PAGE_SIZE < state.packetTotal) {
      state.packetOffset += PAGE_SIZE;
      loadPackets();
    }
  });
  $("bucket-size").addEventListener("change", () => {
    if (currentSession() && state.summary) {
      loadSelectedDashboard(currentSession());
    }
  });
  $("theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    setTheme(next);
    if (state.summary) {
      renderProtocol(state.summary.protocol_distribution || {});
      renderTraffic(state.summary.packets_per_second || []);
    }
  });
}

async function init() {
  bindEvents();
  try {
    const savedTheme = localStorage.getItem("netscope-theme");
    if (savedTheme === "dark" || savedTheme === "light") setTheme(savedTheme);
  } catch { /* Storage may be disabled. */ }
  try {
    await loadSessions(null);
  } catch (error) {
    document.querySelector(".api-status").textContent = "API unavailable";
    showError(error.message || "Could not connect to the NetScope API.");
    $("session-list").innerHTML = '<div class="side-loading">Could not load sessions</div>';
    renderEmptyState();
  }
}

document.addEventListener("DOMContentLoaded", init);
