const app = document.querySelector("#app");
const nav = document.querySelector("#primary-nav");
const screenLabel = document.querySelector("#screen-label");
const runContext = document.querySelector("#run-context");
const toast = document.querySelector("#toast");

const screens = [
  { id: "overview", label: "Tổng quan", title: "Tổng quan hệ thống", icon: "⌂" },
  { id: "alerts", label: "Cảnh báo bảo mật", title: "Cảnh báo bảo mật", icon: "△" },
  { id: "evaluation", label: "Đánh giá mô hình", title: "Đánh giá mô hình & Benchmark", icon: "◎" },
  { id: "monitoring", label: "Giám sát CI/CD", title: "Giám sát CI/CD & Security Gate", icon: "⌁" },
];

const projects = [
  { id: "flask", name: "Flask Lab A", repo: "org/flask-lab-a", framework: "Flask 3.0", owner: "dev-01", env: "Development", health: "Cảnh báo", status: "warning", runs: 2, success: "50%", findings: 1, verified: 0, gate: "Chờ", phase: 4, activeRun: "M-105" },
  { id: "django", name: "Django Demo B", repo: "org/django-demo-b", framework: "Django 5.0", owner: "dev-03", env: "Development", health: "Lỗi · Degraded", status: "failed", runs: 2, success: "0%", findings: 0, verified: 0, gate: "Chưa cấu hình", phase: 4, activeRun: "M-104" },
  { id: "fastapi", name: "Python API C", repo: "org/python-api-c", framework: "FastAPI 0.109", owner: "dev-02", env: "Development", health: "Cảnh báo", status: "warning", runs: 1, success: "100%", findings: 1, verified: 0, gate: "Đạt", phase: 3, activeRun: null },
];

const runs = [
  { id: "M-101", project: "Flask Lab A", projectId: "flask", repo: "org/flask-lab-a", branch: "main", commit: "a3f2c1d", status: "Hoàn tất", statusKey: "completed", gate: "Đạt", gateKey: "pass", findings: 1, done: 6, duration: "4m 12s", trigger: "push", owner: "dev-01", started: "17:02 15/01/2024" },
  { id: "M-102", project: "Python API C", projectId: "fastapi", repo: "org/python-api-c", branch: "feature/auth", commit: "b8e4f2a", status: "Hoàn tất", statusKey: "completed", gate: "Đạt", gateKey: "pass", findings: 1, done: 6, duration: "5m 38s", trigger: "pull_request", owner: "dev-02", started: "17:18 15/01/2024" },
  { id: "M-103", project: "Django Demo B", projectId: "django", repo: "org/django-demo-b", branch: "main", commit: "c9d1e3b", status: "Thất bại", statusKey: "failed", gate: "Kết quả một phần", gateKey: "failed", findings: 0, done: 3, duration: "2m 07s", trigger: "push", owner: "dev-03", started: "17:30 15/01/2024" },
  { id: "M-104", project: "Django Demo B", projectId: "django", repo: "org/django-demo-b", branch: "feature/api-v2", commit: "d4a7f9c", status: "Đang chạy", statusKey: "running", gate: "Chờ kết quả", gateKey: "waiting", findings: 0, done: 2, duration: "—", trigger: "pull_request", owner: "dev-03", started: "18:45 15/01/2024" },
  { id: "M-105", project: "Flask Lab A", projectId: "flask", repo: "org/flask-lab-a", branch: "feature/upload", commit: "e2b5c8d", status: "Đang chạy", statusKey: "running", gate: "Chờ kết quả", gateKey: "waiting", findings: 0, done: 4, duration: "—", trigger: "push", owner: "dev-01", started: "18:51 15/01/2024" },
];

const findings = [
  { id: "F-001", severity: "HIGH", severityKey: "high", title: "SQL Injection", cwe: "CWE-89", file: "app/views/auth.py", line: 47, fn: "login_user()", project: "Flask Lab A", projectId: "flask", run: "M-101", source: "Combined", confidence: "91%", sast: "HIGH", policy: "AND", verify: "Chờ xác minh", commit: "a3f2c1d", snippet: `def login_user(username, password):\n    query = "SELECT * FROM users WHERE username='" + username + "'"\n    result = db.execute(query)  # Line 47\n    return result.fetchone()` },
  { id: "F-002", severity: "MEDIUM", severityKey: "medium", title: "Hardcoded Credentials", cwe: "CWE-798", file: "api/middleware/auth.py", line: 23, fn: "validate_token()", project: "Python API C", projectId: "fastapi", run: "M-102", source: "Checkmarx only", confidence: "—", sast: "MEDIUM", policy: "SAST", verify: "Chờ xác minh", commit: "b8e4f2a", snippet: `def validate_token(token):\n    fallback_key = "dev-secret-key"  # Line 23\n    return jwt.decode(token, fallback_key, algorithms=["HS256"])` },
];

const incidents = [
  { level: "HIGH", key: "high", title: "Scanner exit code 2 — partial results", run: "M-103", project: "Django Demo B", stage: "Checkmarx Scan", text: "Scanner có thể đã timeout hoặc mất kết nối với CxSAST server. Kết quả không đầy đủ — pipeline bị dừng.", fix: "Kiểm tra kết nối tới CxSAST server. Retry run #M-103 hoặc trigger run mới.", time: "17:32 15/01/2024" },
  { level: "MEDIUM", key: "medium", title: "Security Gate chưa được cấu hình", run: "M-104", project: "Django Demo B", stage: "Security Gate", text: "Policy chưa thiết lập cho dự án Django Demo B. Pipeline sẽ không block dù phát hiện vulnerability.", fix: "Cấu hình Security Gate policy trước khi merge vào main.", time: "18:45 15/01/2024" },
];

const phases = ["Khởi tạo dự án", "Thu thập dataset", "Fine-tune CodeBERT", "Tích hợp GitHub Actions", "Tích hợp Checkmarx", "Combination policy", "Security Gate", "Held-out evaluation", "Dashboard hoàn thiện", "Review & Docs", "Báo cáo tốt nghiệp"];

const state = {
  screen: "overview",
  range: "24h",
  selectedRun: "M-104",
  selectedTask: 2,
  selectedFinding: "F-001",
  projectFilter: "all",
  statusFilter: "all",
  alertFilters: { project: "all", severity: "all", cwe: "all", source: "all", verify: "all" },
  api: { connected: false, runs: 0, findings: 0 },
  live: null, apiRuns: [], apiProjects: [], apiFindings: [],
};

const esc = (value) => String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#039;");
const badge = (text, key = "") => `<span class="badge ${esc(key)}">${esc(text)}</span>`;
const selectedRun = () => runs.find((run) => run.id === state.selectedRun) || runs[3];
const projectFor = (run) => projects.find((project) => project.id === run.projectId) || projects[1];

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("show"), 2600);
}

function renderNav() {
  nav.innerHTML = screens.map((screen) => `<button class="nav-button ${state.screen === screen.id ? "active" : ""}" data-nav="${screen.id}" type="button"><span class="nav-icon">${screen.icon}</span><span>${screen.label}</span></button>`).join("");
}

function renderContext() {
  const run = selectedRun();
  screenLabel.textContent = screens.find((screen) => screen.id === state.screen)?.title || "Dashboard";
  runContext.innerHTML = `
    <span class="context-chip">⌂ <b>${esc(run.repo)}</b></span>
    <span class="context-chip">⑂ <b>${esc(run.branch)}</b></span>
    <span class="context-chip">◇ <b>${esc(run.commit)}</b></span>
    <span class="context-chip"># <b>${esc(run.id)} · ${esc(run.project)}</b></span>
    <span class="context-chip">◷ <b>${state.api.connected ? `API local · ${state.api.runs} run` : "API chưa kết nối"}</b></span>`;
}

function pageHead(title, subtitle, actions = "") {
  return `<div class="page-head"><div><h1>${title}</h1><p>${subtitle}</p></div>${actions}</div>`;
}

function metricCard(label, value, note, color, icon) {
  return `<article class="metric-card" style="--metric:${color}"><div class="metric-top"><span>${label}</span><span class="metric-icon">${icon}</span></div><div class="metric-value">${value}</div><small>${note}</small></article>`;
}

function projectCard(project) {
  const run = runs.find((item) => item.id === project.activeRun);
  const progress = run ? Math.round(run.done / 6 * 100) : 0;
  return `<article class="project-card">
    <div class="card-title"><div><h3>${project.name}</h3><p class="repo">${project.repo}</p></div>${badge(project.health, project.status === "failed" ? "red" : "yellow")}</div>
    <div class="meta-grid"><div><span>Framework</span><b>${project.framework}</b></div><div><span>Owner</span><b>${project.owner}</b></div><div><span>Môi trường</span><b>${project.env}</b></div><div><span>Scanner</span><b>CodeBERT, Checkmarx</b></div></div>
    ${run ? `<div class="run-strip"><div class="run-strip-top"><span>Run <b>#${run.id}</b> · ${run.done}/6 tasks</span><b>${progress}%</b></div><div class="progress"><span style="width:${progress}%"></span></div></div>` : `<div class="run-strip muted">Không có run đang hoạt động</div>`}
    <div class="stats-row"><div><b>${project.runs}</b><small>Runs</small></div><div><b>${project.success}</b><small>Thành công</small></div><div><b>${project.findings}</b><small>Findings</small></div><div><b>${project.gate}</b><small>Gate</small></div></div>
    <div class="phase-mini">Đề tài: ${project.phase}/11 phase (${Math.round(project.phase / 11 * 100)}%) · P${project.phase} đang thực hiện<div class="progress"><span style="width:${project.phase / 11 * 100}%"></span></div></div>
    <div class="card-actions"><button class="primary-button" data-monitor-project="${project.id}" type="button">Xem giám sát →</button><button class="soft-button" data-profile="${project.id}" type="button">Hồ sơ dự án</button></div>
  </article>`;
}

function incidentsMarkup(compact = false) {
  return `<div class="incident-list">${incidents.map((incident) => `<article class="incident-card"><span class="severity-dot ${incident.key}"></span><div><div>${badge(incident.level, incident.key)} <strong>${incident.title}</strong></div><p>#${incident.run} · ${incident.project} · ${incident.stage}</p><p>${incident.text}</p>${compact ? "" : `<p class="recommend">🔧 Đề xuất: ${incident.fix}</p>`}</div><div class="incident-side">${incident.time}<br>${compact ? "" : `<button class="soft-button" data-run="${incident.run}" type="button">Xem run →</button>`}</div></article>`).join("")}</div>`;
}

function runsTable() {
  return `<div class="table-wrap"><table><thead><tr><th>Run ID</th><th>Dự án</th><th>Branch / Commit</th><th>CI Status</th><th>Security Gate</th><th>Findings</th><th>Thời lượng</th><th>Khởi chạy</th></tr></thead><tbody>${runs.map((run) => `<tr data-action="run" data-run="${run.id}"><td class="mono">#${run.id}</td><td><b>${run.project}</b></td><td>${run.branch} · <span class="mono">${run.commit}</span></td><td>${badge(run.status, run.statusKey)}</td><td>${badge(run.gate, run.gateKey)}</td><td>${run.findings}</td><td>${run.duration}</td><td>${run.started}</td></tr>`).join("")}</tbody></table></div>`;
}

function chartsMarkup() {
  return `<div class="chart-grid">
    <article class="panel chart-card"><p class="chart-title">Runs theo trạng thái (${state.range})</p><svg viewBox="0 0 520 165" role="img" aria-label="Biểu đồ runs theo trạng thái"><path class="grid-line" d="M35 20H500M35 60H500M35 100H500M35 140H500"/><path d="M45 116 C120 113 143 68 210 84 S310 132 355 72 S440 35 493 54" fill="none" stroke="#2f80ed" stroke-width="3"/><path d="M45 132 C115 126 170 125 220 112 S340 100 400 116 S460 98 493 104" fill="none" stroke="#41d69b" stroke-width="2"/><circle cx="355" cy="72" r="4" fill="#2f80ed"/><text class="axis-label" x="40" y="158">08:00</text><text class="axis-label" x="145" y="158">09:00</text><text class="axis-label" x="250" y="158">10:00</text><text class="axis-label" x="355" y="158">11:00</text><text class="axis-label" x="465" y="158">12:00</text></svg></article>
    <article class="panel chart-card"><p class="chart-title">Xu hướng findings (7 ngày)</p><svg viewBox="0 0 520 165" role="img" aria-label="Biểu đồ xu hướng findings"><path class="grid-line" d="M35 20H500M35 60H500M35 100H500M35 140H500"/><defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#35c9d0" stop-opacity=".32"/><stop offset="1" stop-color="#35c9d0" stop-opacity="0"/></linearGradient></defs><path d="M42 121 L130 105 L218 118 L306 73 L394 89 L490 55 L490 140 L42 140Z" fill="url(#area)"/><path d="M42 121 L130 105 L218 118 L306 73 L394 89 L490 55" fill="none" stroke="#35c9d0" stroke-width="3"/><text class="axis-label" x="36" y="158">10/01</text><text class="axis-label" x="125" y="158">11/01</text><text class="axis-label" x="214" y="158">12/01</text><text class="axis-label" x="302" y="158">13/01</text><text class="axis-label" x="390" y="158">14/01</text><text class="axis-label" x="476" y="158">15/01</text></svg></article>
  </div>`;
}

function renderOverview() {
  const live = state.live;
  const connected = state.api.connected && live;

  // KPI values — live from API when connected, hardcoded demo when offline
  const kpiProjects  = connected ? live.projects                     : 3;
  const kpiTotal     = connected ? live.runs.total                   : 5;
  const kpiRunning   = connected ? live.runs.running                 : 2;
  const kpiCompleted = connected ? live.runs.completed               : 2;
  const kpiFailed    = connected ? live.runs.failed                  : 1;
  const kpiFindings  = connected ? live.findings.combined            : 2;
  const kpiAgreement = connected ? live.findings.agreement           : 0;
  const kpiHighCrit  = connected ? live.findings.high_critical       : 0;

  // Runs table — live or demo
  const displayRuns = connected && state.apiRuns?.length
    ? state.apiRuns.slice(0, 10).map((r) => ({
        id: r.id.slice(0, 8),
        project: r.project,
        branch: r.branch || "main",
        commit: r.commit_sha?.slice(0, 7) || "—",
        status: r.status === "completed" ? "Hoàn tất" : r.status === "failed" ? "Thất bại" : "Đang chạy",
        statusKey: r.status,
        gate: r.status === "completed" ? "Đạt" : "Chờ kết quả",
        gateKey: r.status === "completed" ? "pass" : "waiting",
        findings: "—",
        duration: r.duration_seconds ? `${r.duration_seconds.toFixed(1)}s` : "—",
        started: r.started_at ? new Date(r.started_at).toLocaleString("vi-VN") : "—",
      }))
    : runs;

  const liveRunsTable = () => `<div class="table-wrap"><table><thead><tr><th>Run ID</th><th>Dự án</th><th>Branch / Commit</th><th>CI Status</th><th>Security Gate</th><th>Thời lượng</th><th>Khởi chạy</th></tr></thead><tbody>${displayRuns.map((r) => `<tr><td class="mono">#${r.id}</td><td><b>${esc(r.project)}</b></td><td>${esc(r.branch)} · <span class="mono">${esc(r.commit)}</span></td><td>${badge(r.status, r.statusKey)}</td><td>${badge(r.gate, r.gateKey)}</td><td>${esc(r.duration)}</td><td>${esc(r.started)}</td></tr>`).join("")}</tbody></table></div>`;

  // Project cards — live or demo
  const displayProjects = connected && state.apiProjects?.length
    ? state.apiProjects.slice(0, 6).map((p) => ({
        name: p.project,
        repo: p.repository || p.project,
        framework: "Python",
        owner: "—",
        env: "Development",
        health: p.runs.failed > 0 ? "Lỗi" : p.runs.running > 0 ? "Cảnh báo" : "Hoạt động",
        status: p.runs.failed > 0 ? "failed" : p.runs.running > 0 ? "warning" : "ok",
        runs: p.runs.total,
        success: p.runs.total ? `${Math.round(p.runs.completed / p.runs.total * 100)}%` : "—",
        findings: p.findings.combined,
        gate: p.runs.running > 0 ? "Chờ" : p.runs.failed > 0 ? "Thất bại" : "Đạt",
        phase: 4,
        activeRun: p.latest_run?.id?.slice(0, 8) || null,
      }))
    : projects;

  const liveProjectCard = (p) => `<article class="project-card">
    <div class="card-title"><div><h3>${esc(p.name)}</h3><p class="repo">${esc(p.repo)}</p></div>${badge(p.health, p.status === "failed" ? "red" : p.status === "warning" ? "yellow" : "green")}</div>
    <div class="meta-grid"><div><span>Framework</span><b>${esc(p.framework)}</b></div><div><span>Runs</span><b>${p.runs}</b></div><div><span>Thành công</span><b>${esc(p.success)}</b></div><div><span>Gate</span><b>${esc(p.gate)}</b></div></div>
    <div class="stats-row"><div><b>${p.findings}</b><small>Findings</small></div><div><b>${p.runs}</b><small>Runs</small></div><div><b>${esc(p.success)}</b><small>Thành công</small></div><div><b>${esc(p.gate)}</b><small>Gate</small></div></div>
  </article>`;

  app.innerHTML = `${pageHead("Tổng quan hệ thống", `Trạng thái pipeline bảo mật — ${connected ? "live từ API" : "dữ liệu minh họa"}`, `<div class="segment">${["24h", "7d", "30d"].map((item) => `<button class="${state.range === item ? "active" : ""}" data-range="${item}" type="button">${item}</button>`).join("")}</div>`)}
    <section><div class="section-heading"><div><span class="section-icon">◈</span><h2>KPI ${state.range}</h2></div><small>${connected ? "✓ Live từ backend" : "Chế độ preview"}</small></div><div class="metric-grid">
      ${metricCard("Dự án có hoạt động", kpiProjects, "trong phạm vi theo dõi", "#35c9d0", "◇")}${metricCard("Tổng số runs", kpiTotal, `${kpiCompleted} hoàn tất`, "#2f80ed", "↻")}${metricCard("Đang chạy", kpiRunning, "pipeline active", "#2f80ed", "▶")}${metricCard("Hoàn tất", kpiCompleted, "security gate đạt", "#41d69b", "✓")}${metricCard("Thất bại", kpiFailed, "cần xử lý", "#f35d6a", "!")}${metricCard("Security findings", kpiFindings, `${kpiAgreement} agreement`, "#f38a4b", "△")}${metricCard("High/Critical", kpiHighCrit, "cần đánh giá gấp", "#9a7df2", "◆")}${metricCard("Security Gate", connected ? (kpiAgreement > 0 ? "Cần xem xét" : "—") : "—", "dựa trên AGREEMENT", "#f6bd4b", "▥")}
    </div></section>
    <section class="section"><div class="section-heading"><div><span class="section-icon">▦</span><h2>Danh mục dự án</h2></div><small>${displayProjects.length} dự án</small></div><div class="project-grid">${displayProjects.map(connected && state.apiProjects?.length ? liveProjectCard : projectCard).join("")}</div></section>
    <section class="section two-col"><div><div class="section-heading"><div><span class="section-icon">⚑</span><h2>Sự cố trong 24 giờ</h2></div><small>2</small></div>${incidentsMarkup()}</div><div><div class="section-heading"><div><span class="section-icon">⌁</span><h2>Health strip nguồn dữ liệu</h2></div></div><div class="health-grid" style="grid-template-columns:1fr 1fr">${healthCard("GitHub Actions", "Hoạt động", "120ms", "green")}${healthCard("CodeBERT", "Hoạt động", "340ms", "green")}${healthCard("Checkmarx", "Giảm hiệu năng", "—", "yellow")}${healthCard("VPS/API", state.api.connected ? "Hoạt động" : "Mất kết nối", state.api.connected ? "local" : "—", state.api.connected ? "green" : "red")}</div></div></section>
    <section class="section"><div class="section-heading"><div><span class="section-icon">↻</span><h2>Các lần chạy gần đây</h2></div><small>${displayRuns.length} run · ${connected ? "live" : "demo"}</small></div>${liveRunsTable()}</section>
    <section class="section"><div class="section-heading"><div><span class="section-icon">⌁</span><h2>Biểu đồ phân tích</h2></div></div>${chartsMarkup()}</section>`;
}


function healthCard(name, status, latency, key) {
  return `<article class="health-card"><div><h3>${name}</h3>${badge(status, key)}</div><p>Dữ liệu: 18:55 15/01/2024<br>Độ trễ: ${latency}</p></article>`;
}

function renderAlerts() {
  const filtered = findings.filter((finding) => (state.alertFilters.project === "all" || finding.projectId === state.alertFilters.project) && (state.alertFilters.severity === "all" || finding.severityKey === state.alertFilters.severity) && (state.alertFilters.cwe === "all" || finding.cwe === state.alertFilters.cwe) && (state.alertFilters.source === "all" || finding.source === state.alertFilters.source) && (state.alertFilters.verify === "all" || finding.verify === state.alertFilters.verify));
  if (!filtered.some((finding) => finding.id === state.selectedFinding)) state.selectedFinding = filtered[0]?.id || findings[0].id;
  const finding = findings.find((item) => item.id === state.selectedFinding);
  const filter = (key, label, values) => `<div class="filter"><label>${label}</label><select data-alert-filter="${key}">${values.map(([value, text]) => `<option value="${value}" ${state.alertFilters[key] === value ? "selected" : ""}>${text}</option>`).join("")}</select></div>`;
  app.innerHTML = `${pageHead("Cảnh báo bảo mật", "2 security findings · 0 confirmed vulnerabilities · dữ liệu 24 giờ", `<button class="soft-button" data-clear-alerts type="button">Xóa bộ lọc</button>`)}
    <div class="filters">${filter("project", "Dự án", [["all","Tất cả"],["flask","Flask Lab A"],["fastapi","Python API C"],["django","Django Demo B"]])}${filter("severity", "Severity", [["all","Tất cả"],["high","High"],["medium","Medium"],["low","Low"]])}${filter("cwe", "CWE", [["all","Tất cả"],["CWE-89","CWE-89"],["CWE-798","CWE-798"]])}${filter("source", "Nguồn", [["all","Tất cả"],["Combined","Combined"],["CodeBERT only","CodeBERT only"],["Checkmarx only","Checkmarx only"]])}${filter("verify", "Xác minh", [["all","Tất cả"],["Chờ xác minh","Chờ xác minh"],["Đã xác nhận","Đã xác nhận"],["False Positive","False Positive"]])}</div>
    <div class="note-banner"><b>CodeBERT-only prediction:</b> app/utils/helpers.py:89 (confidence 62%) — dưới ngưỡng kết hợp. <b>Không tính vào security finding.</b></div>
    <div class="alerts-layout"><section><div class="section-heading"><div><h2>${filtered.length} finding(s)</h2></div></div><div class="finding-list">${filtered.length ? filtered.map((item) => `<button class="finding-button ${item.id === state.selectedFinding ? "active" : ""}" data-finding="${item.id}" type="button"><span class="finding-id">${item.id}</span><span><strong>${item.title}</strong><small>${item.file}:${item.line} · ${item.project}</small></span>${badge(item.severity, item.severityKey)}</button>`).join("") : `<div class="empty-state">Không có finding phù hợp bộ lọc.</div>`}</div></section>
      ${findingDetail(finding)}
    </div>`;
}

function findingDetail(finding) {
  return `<article class="panel"><div class="detail-head"><div>${badge(finding.id, "blue")} ${badge(finding.severity, finding.severityKey)} ${badge(finding.verify, finding.verify === "Đã xác nhận" ? "green" : finding.verify === "False Positive" ? "red" : "yellow")}<h2>Lỗ hổng tiềm ẩn: ${finding.title} (${finding.cwe})</h2><p>${finding.file}:${finding.line} · ${finding.fn}</p></div><div class="action-row"><button class="primary-button" data-verify="confirmed" type="button">Xác nhận lỗ hổng</button><button class="soft-button danger-button" data-verify="false-positive" type="button">False Positive</button><button class="soft-button" data-recheck type="button">Kiểm tra lại</button></div></div>
    <div class="meta-grid"><div><span>Dự án</span><b>${finding.project}</b></div><div><span>Run ID</span><b>#${finding.run}</b></div><div><span>Commit</span><b class="mono">${finding.commit}</b></div><div><span>Nguồn</span><b>${finding.source}</b></div></div>
    <div class="tabs"><button class="active">Tổng quan</button><button>Bằng chứng</button><button>Khắc phục</button><button>Lịch sử</button></div>
    <div class="evidence-grid"><div class="evidence"><small>CodeBERT confidence</small><strong>${finding.confidence}</strong><span class="badge blue">VULNERABLE</span></div><div class="evidence"><small>Checkmarx severity</small><strong>${finding.sast}</strong><span class="badge ${finding.severityKey}">SAST result</span></div><div class="evidence"><small>Combination policy</small><strong>${finding.policy}</strong><span class="badge green">${finding.policy === "AND" ? "Cả hai nguồn phát hiện" : "Một nguồn"}</span></div></div>
    <p class="run-picker-label" style="margin-top:14px">CODE SNIPPET</p><pre class="code-block">${esc(finding.snippet)}</pre></article>`;
}

function renderEvaluation() {
  const requirements = [
    ["Held-out dataset", "Chưa có dữ liệu", "Thiếu", "red"], ["Ground truth", "Chưa có dữ liệu", "Thiếu", "red"], ["Số mẫu", "Chưa có dữ liệu", "Thiếu", "red"],
    ["Model checkpoint", "codebert-base-uncased (fine-tuned)", "Có sẵn", "green"], ["Tokenizer", "BertTokenizer (HuggingFace)", "Có sẵn", "green"], ["Threshold", "0.70 (tạm thời)", "Tạm thời", "yellow"],
    ["Checkmarx preset", "Python_Security (v9.3)", "Có sẵn", "green"], ["Combination policy", "AND – chưa chốt chính thức", "Tạm thời", "yellow"], ["Thời điểm đánh giá", "Chưa có dữ liệu", "Thiếu", "red"],
  ];
  const metrics = ["TP", "FP", "FN", "TN", "Precision", "Recall", "F1", "Coverage", "Runtime", "Dataset version", "Model/config version"];
  app.innerHTML = `${pageHead("Đánh giá mô hình & Kiểm thử Benchmark", "Bảng so sánh CodeBERT · Checkmarx · Combined — chỉ xuất số liệu khi có held-out dataset & ground truth")}
    <div class="empty-state"><strong>Chưa có dữ liệu đánh giá</strong>Held-out dataset và ground truth chưa xác nhận. Không có số liệu giả nào được tạo ra.</div>
    <section class="section"><div class="section-heading"><div><span class="section-icon">✓</span><h2>Điều kiện đánh giá</h2></div></div><div class="condition-grid">${requirements.map((item) => `<article class="condition-card"><small>${item[0]}</small><strong>${item[1]}</strong>${badge(item[2], item[3])}</article>`).join("")}</div></section>
    <section class="section"><div class="section-heading"><div><span class="section-icon">▤</span><h2>Bảng so sánh mô hình</h2></div>${badge("Chờ dữ liệu", "yellow")}</div><div class="table-wrap"><table class="benchmark"><thead><tr><th>Metric</th><th>CodeBERT Classifier</th><th>Checkmarx SAST</th><th>Combined (Ensemble)</th></tr></thead><tbody>${metrics.map((metric) => `<tr><td><b>${metric}</b></td><td>Chưa có dữ liệu</td><td>Chưa có dữ liệu</td><td>Chưa có dữ liệu</td></tr>`).join("")}</tbody></table></div></section>
    <section class="section"><div class="section-heading"><div><span class="section-icon">⌁</span><h2>Trực quan hóa PR/F1 & Confusion Matrix</h2></div></div><div class="placeholder-grid">${[["Confusion Matrix","Xuất hiện sau khi có ground truth và đánh giá trên held-out dataset."],["Precision–Recall Curve","Xuất hiện khi có đủ TP, FP, FN và threshold sweep."],["Runtime Breakdown","Thời gian scan từng giai đoạn khi có dữ liệu pipeline đầy đủ."],["Class Distribution","Cần để kiểm tra class imbalance trước khi đánh giá mô hình."]].map((item) => `<div class="placeholder"><div><strong>${item[0]}</strong><p>${item[1]}</p></div></div>`).join("")}</div></section>
    <section class="section"><div class="section-heading"><div><span class="section-icon">⚑</span><h2>Lưu ý & Cảnh báo</h2></div></div><div class="warning-list">${[["Chưa có kết quả thực nghiệm","Số liệu chỉ xuất hiện sau khi chạy evaluation."],["Class imbalance","Báo cáo phân bố lớp trước khi kết luận."],["Nguy cơ data leakage","Tách validation khỏi dữ liệu fine-tuning."],["Khả năng tái lập","Cố định checkpoint, tokenizer, threshold và preset."]].map((item) => `<div class="warning-item"><strong>${item[0]}</strong><p>${item[1]}</p></div>`).join("")}</div></section>`;
}

function taskData(run) {
  const names = ["Checkout", "Setup Python", "CodeBERT Detection", "Checkmarx Scan", "Correlate & Combine", "Security Gate & Report"];
  const times = ["12s", "49s", "parallel", "parallel", "waiting", "waiting"];
  return names.map((name, index) => {
    let status = index < run.done ? "done" : index === run.done && run.statusKey === "running" ? "running" : "waiting";
    if (run.statusKey === "failed" && index === run.done) status = "failed";
    return { name, time: times[index], status };
  });
}

function renderMonitoring() {
  const filteredRuns = runs.filter((run) => (state.projectFilter === "all" || run.projectId === state.projectFilter) && (state.statusFilter === "all" || run.statusKey === state.statusFilter));
  if (!filteredRuns.some((run) => run.id === state.selectedRun) && filteredRuns[0]) state.selectedRun = filteredRuns[0].id;
  const run = selectedRun(); const project = projectFor(run); const tasks = taskData(run); const task = tasks[state.selectedTask] || tasks[0];
  const filter = (key, label, values, current) => `<div class="filter"><label>${label}</label><select data-monitor-filter="${key}">${values.map(([value, text]) => `<option value="${value}" ${current === value ? "selected" : ""}>${text}</option>`).join("")}</select></div>`;
  app.innerHTML = `${pageHead("Giám sát CI/CD & Security Gate", "Theo dõi tiến trình, bằng chứng và quyết định gate theo từng run")}
    <div class="trace"><b>Dự án:</b> ${run.project}<span>›</span><b>Run:</b> #${run.id}<span>›</span><b>Stage:</b> Stage ${state.selectedTask + 1}<span>›</span><b>Task:</b> ${task.name}<span>›</span><b>Event:</b> ${task.name.includes("CodeBERT") ? "CodeBERT" : "GitHub Actions"}<span>›</span><b>Finding:</b> ${run.findings ? "F-001" : "—"}</div>
    <div class="filters">${filter("project", "Dự án", [["all","Tất cả"], ...projects.map((item) => [item.id,item.name])], state.projectFilter)}${filter("status", "Trạng thái", [["all","Tất cả"],["running","Đang chạy"],["completed","Hoàn tất"],["failed","Thất bại"]], state.statusFilter)}<span class="muted">${filteredRuns.length} run</span></div>
    <div class="monitor-layout"><aside class="panel run-picker"><p class="run-picker-label">CHỌN RUN</p><div class="run-list">${filteredRuns.map((item) => `<button class="run-option ${item.id === run.id ? "active" : ""}" data-select-run="${item.id}" type="button"><div><b>#${item.id}</b>${badge(item.status,item.statusKey)}</div><p>${item.project}</p><small>${item.branch} · ${item.commit} · ${item.done}/6 tasks</small><div class="progress"><span style="width:${item.done/6*100}%"></span></div></button>`).join("")}</div></aside>
      <div><article class="panel"><div class="project-info-head"><div><h2>${run.project}</h2><p class="repo">#${run.id} · ${run.repo}</p></div><div>${badge(run.status,run.statusKey)}${badge(run.gate,run.gateKey)}</div></div><div class="info-grid"><div><small>Repository</small><b>${run.repo}</b></div><div><small>Branch</small><b>${run.branch}</b></div><div><small>Commit</small><b class="mono">${run.commit}</b></div><div><small>Kích hoạt</small><b>${run.trigger}</b></div><div><small>Người dùng</small><b>${run.owner}</b></div><div><small>Môi trường</small><b>Development</b></div><div><small>Bắt đầu</small><b>${run.started}</b></div><div><small>Thời gian chạy</small><b>${run.duration}</b></div></div><div class="phase-mini">Tiến độ: ${run.done}/6 tasks hoàn tất${run.done < 6 ? ` · đang: ${tasks[run.done]?.name || "đã dừng"}` : ""}<div class="progress"><span style="width:${run.done/6*100}%"></span></div></div></article>
      <section class="section"><div class="section-heading"><div><span class="section-icon">⌁</span><h2>Sơ đồ pipeline — #${run.id}</h2></div></div><div class="pipeline">${tasks.map((item,index) => `<button class="task-node ${item.status} ${index === state.selectedTask ? "active" : ""}" data-task="${index}" type="button"><span class="task-state">${item.status === "done" ? "✓" : item.status === "failed" ? "!" : item.status === "running" ? "●" : "·"}</span><strong>${item.name}</strong><small>${item.status === "running" ? "running…" : item.time}</small></button>`).join("")}</div></section>
      <section class="section split-panel"><article class="panel"><p class="run-picker-label">TASK DETAIL — ${run.id}-T${state.selectedTask + 1}</p><div class="definition-grid"><div><small>Tên tác vụ</small><b>${task.name}</b></div><div><small>Trạng thái</small><b>${task.status === "done" ? "Hoàn tất" : task.status === "running" ? "Đang chạy" : task.status === "failed" ? "Thất bại" : "Chờ"}</b></div><div><small>Dependencies</small><b>${state.selectedTask ? `${run.id}-T${state.selectedTask}` : "—"}</b></div><div><small>Retry count</small><b>0</b></div></div><div class="log-line">&gt; ${task.status === "running" ? "Phân tích file 14/28: django_app/views/api.py" : task.status === "done" ? "Task completed successfully" : "Waiting for dependencies"}</div></article>
      <article class="panel"><p class="run-picker-label">PIPELINE EVENTS</p><div class="timeline">${[["18:45","GitHub Actions","Workflow triggered by pull_request"],["18:45","GitHub Actions","Checkout hoàn tất"],["18:46","CodeBERT","CodeBERT scan bắt đầu"],["18:46","Checkmarx","Checkmarx scan bắt đầu"]].map((event) => `<div class="event"><small>${event[0]} · ${event[1]}</small><p>${event[2]}</p></div>`).join("")}</div></article></section>
      <section class="section"><article class="panel gate"><div class="section-heading"><div><h2>Security Gate</h2></div>${badge(run.gate,run.gateKey)}</div><div class="gate-row"><div><small>POLICY</small><b>${project.gate === "Chưa cấu hình" ? "AND — chưa cấu hình chính thức" : "AND"}</b></div><div><small>NGUỒN DỮ LIỆU</small><b>CodeBERT + Checkmarx</b></div><div><small>FINDINGS</small><b>${run.findings}</b></div></div><p class="muted" style="margin-top:10px;font-size:10px">${run.statusKey === "running" ? "Chờ scanner hoàn tất. Security Gate chưa có đủ dữ liệu để đánh giá." : run.statusKey === "failed" ? "Kết quả scan một phần — không cho phép kết luận an toàn." : "Policy đã đánh giá và lưu cùng bằng chứng của run."}</p></article></section>
      <section class="section two-col"><div><div class="section-heading"><div><h2>Findings — #${run.id}</h2></div><small>${run.findings}</small></div>${run.findings ? `<div class="finding-list">${findings.filter((item) => item.run === run.id).map((item) => `<button class="finding-button" data-finding-go="${item.id}" type="button"><span class="finding-id">${item.id}</span><span><strong>${item.title}</strong><small>${item.file}:${item.line}</small></span>${badge(item.severity,item.severityKey)}</button>`).join("")}</div>` : `<div class="empty-state">${run.statusKey === "running" ? "Run đang chạy — findings sẽ xuất hiện sau khi hoàn tất" : "Không có finding đã kết hợp"}</div>`}</div><div><div class="section-heading"><div><h2>Sự cố liên quan</h2></div><small>2</small></div>${incidentsMarkup(true)}</div></section>
      <section class="section"><div class="section-heading"><div><h2>Tiến độ đề tài</h2></div><small>${project.phase}/11 phase · ${Math.round(project.phase/11*100)}%</small></div><div class="phase-grid">${phases.map((name,index) => `<div class="phase ${index < project.phase ? "done" : index === project.phase ? "current" : ""}"><b>P${index}</b><small>${name}</small></div>`).join("")}</div></section>
      <section class="section"><div class="section-heading"><div><h2>Audit trail</h2></div></div>${runsTable()}</section></div></div>`;
}

function render() {
  renderNav(); renderContext();
  ({ overview: renderOverview, alerts: renderAlerts, evaluation: renderEvaluation, monitoring: renderMonitoring })[state.screen]();
  window.scrollTo({ top: 0, behavior: "instant" });
}

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json", ...(options.headers || {}) }, ...options });
  if (!response.ok) throw new Error(`${response.status}`);
  return response.json();
}

async function syncBackend(silent = true) {
  try {
    const [summary, apiRuns, live, apiProjects, apiFindings] = await Promise.all([
      api("/api/v1/dashboard/summary"),
      api("/api/v1/runs?limit=50"),
      api("/api/v1/stats/live"),
      api("/api/v1/projects"),
      api("/api/v1/findings?source=combined&limit=100"),
    ]);
    state.api = { connected: true, runs: apiRuns.length, findings: summary.combined_findings || 0 };
    state.live = live;
    state.apiRuns = apiRuns;
    state.apiProjects = apiProjects;
    state.apiFindings = apiFindings;
    renderContext();
    if (state.screen === "overview") renderOverview();
    if (state.screen === "alerts") renderAlerts();
    if (!silent) showToast(`Đã đồng bộ ${apiRuns.length} run, ${live.findings.combined} finding từ API.`);
  } catch (error) {
    state.api.connected = false; renderContext();
    if (!silent) showToast("Không kết nối được API. Dashboard hiển thị dữ liệu minh họa.");
  }
}


nav.addEventListener("click", (event) => {
  const button = event.target.closest("[data-nav]"); if (!button) return;
  state.screen = button.dataset.nav; render(); document.querySelector(".sidebar").classList.remove("open");
});

app.addEventListener("click", (event) => {
  const target = event.target.closest("button"); if (!target) return;
  if (target.dataset.range) { state.range = target.dataset.range; renderOverview(); }
  if (target.dataset.monitorProject) { const run = runs.find((item) => item.projectId === target.dataset.monitorProject && item.statusKey === "running") || runs.find((item) => item.projectId === target.dataset.monitorProject); if (run) state.selectedRun = run.id; state.screen = "monitoring"; state.selectedTask = Math.min(run?.done || 0, 5); render(); }
  if (target.dataset.profile) showToast(`Hồ sơ ${projects.find((item) => item.id === target.dataset.profile)?.name} sẽ lấy từ API dự án.`);
  if (target.dataset.run) { state.selectedRun = target.dataset.run; state.screen = "monitoring"; state.selectedTask = Math.min(selectedRun().done, 5); render(); }
  if (target.dataset.finding) { state.selectedFinding = target.dataset.finding; renderAlerts(); }
  if (target.dataset.clearAlerts !== undefined) { state.alertFilters = { project: "all", severity: "all", cwe: "all", source: "all", verify: "all" }; renderAlerts(); }
  if (target.dataset.verify) { const finding = findings.find((item) => item.id === state.selectedFinding); finding.verify = target.dataset.verify === "confirmed" ? "Đã xác nhận" : "False Positive"; renderAlerts(); showToast(`Đã cập nhật ${finding.id}: ${finding.verify} (chỉ trong phiên demo).`); }
  if (target.dataset.recheck !== undefined) showToast("Đã đưa finding vào hàng đợi kiểm tra lại.");
  if (target.dataset.selectRun) { state.selectedRun = target.dataset.selectRun; state.selectedTask = Math.min(selectedRun().done, 5); renderMonitoring(); renderContext(); }
  if (target.dataset.task !== undefined) { state.selectedTask = Number(target.dataset.task); renderMonitoring(); }
  if (target.dataset.findingGo) { state.selectedFinding = target.dataset.findingGo; state.screen = "alerts"; render(); }
});

app.addEventListener("change", (event) => {
  if (event.target.dataset.alertFilter) { state.alertFilters[event.target.dataset.alertFilter] = event.target.value; renderAlerts(); }
  if (event.target.dataset.monitorFilter === "project") { state.projectFilter = event.target.value; renderMonitoring(); renderContext(); }
  if (event.target.dataset.monitorFilter === "status") { state.statusFilter = event.target.value; renderMonitoring(); renderContext(); }
});

document.querySelector("#seed-button").addEventListener("click", async (event) => {
  const button = event.currentTarget; button.disabled = true; button.textContent = "Đang tạo…";
  try { await api("/api/v1/demo/seed", { method: "POST", body: "{}" }); await syncBackend(false); }
  catch (error) { showToast("Không thể tạo run mẫu vì API chưa hoạt động."); }
  finally { button.disabled = false; button.textContent = "＋ Dữ liệu mẫu"; }
});

document.querySelector("#mobile-menu").addEventListener("click", () => document.querySelector(".sidebar").classList.toggle("open"));

render();
syncBackend();
