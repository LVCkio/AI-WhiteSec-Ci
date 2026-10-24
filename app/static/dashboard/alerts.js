import { esc, icon, badge, sectionHeading, fmtDate, timeAgo, runStatus, tasksFor } from './ui.js';
import { renderGateEvidence } from './gate-evidence.js';

const SEVERITY = {
  critical: ['Critical', 'danger'], high: ['High', 'danger'], medium: ['Medium', 'warning'],
  low: ['Low', 'info'], info: ['Info', 'muted'], unknown: ['Unknown', 'muted'],
};
const VERIFICATION = {
  unreviewed: ['Chưa xác minh', 'warning'], confirmed: ['Đã xác nhận', 'success'],
  'false-positive': ['False Positive', 'muted'],
};
const SOURCE = { Combined: 'Checkmarx + CodeBERT', 'Checkmarx only': 'Checkmarx', 'CodeBERT only': 'CodeBERT' };
const TABS = [['overview', 'Tổng quan'], ['evidence', 'Bằng chứng'], ['remediation', 'Khắc phục'], ['history', 'Lịch sử']];
const array = value => Array.isArray(value) ? value : [];
const score = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1 ? `${(value * 100).toFixed(1)}%` : 'Chưa có';
const sev = finding => SEVERITY[finding.severity] || SEVERITY.unknown;
const verified = finding => VERIFICATION[finding.verification] || VERIFICATION.unreviewed;
const sourceLabel = finding => SOURCE[finding.source] || 'Chưa xác định';
const severityRank = value => ({ critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 }[value] ?? 5);

function options(values, current) {
  return values.map(([value, label]) => `<option value="${esc(value)}"${value === current ? ' selected' : ''}>${esc(label)}</option>`).join('');
}

function filter(name, label, values, current) {
  return `<label class="alerts-filter"><span>${esc(label)}</span><select class="field" data-action="alert-filter" data-filter="${esc(name)}" aria-label="${esc(label)}">${options(values, current || 'all')}</select></label>`;
}

function findingRow(finding, selected, runs) {
  const run = runs.find(item => item.id === finding.runId);
  const [severity, tone] = sev(finding);
  const [verification, verificationTone] = verified(finding);
  return `<button class="alerts-list-row${selected ? ' is-selected' : ''}" data-action="finding" data-finding="${esc(finding.id)}" aria-pressed="${selected ? 'true' : 'false'}">
    <span class="alerts-row-top"><span class="alerts-finding-id mono">${esc(finding.id)}</span>${badge(severity, tone)}</span>
    <span class="alerts-row-title">${esc(finding.title || 'Finding chưa có tiêu đề')}</span>
    <span class="alerts-row-path mono">${icon('file-code-2')}${esc(finding.path || 'Chưa có vị trí')}${finding.line ? `:${esc(finding.line)}` : ''}</span>
    <span class="alerts-row-bottom">${badge(verification, verificationTone)}<span>${esc(sourceLabel(finding))}</span></span>
    <span class="alerts-row-meta"><span>${esc(run?.projectName || finding.projectId || 'Project chưa xác định')}</span><span>${run?.createdAt ? esc(timeAgo(run.createdAt)) : 'Chưa có thời gian'}</span></span>
  </button>`;
}

function signals(finding, run) {
  const [severity, tone] = sev(finding);
  const status = run ? runStatus(run) : { label: 'Chưa có run', tone: 'muted' };
  const decision = run?.decision || null;
  const decisionTone = decision === 'BLOCK' || decision === 'ERROR' ? 'danger' : decision === 'PASS' ? 'success' : decision === 'REVIEW' ? 'warning' : 'muted';
  return `<div class="alerts-signals">
    <div class="alerts-signal"><div>${icon('brain-circuit')}<span>CodeBERT score</span></div><strong>${esc(score(finding.score))}</strong><small>Điểm của unit / nhóm liên quan</small></div>
    <div class="alerts-signal"><div>${icon('shield-alert')}<span>SAST severity</span></div><strong>${finding.source === 'CodeBERT only' ? 'Chưa có SAST' : badge(severity, tone)}</strong><small>${finding.source === 'CodeBERT only' ? 'Nhánh Checkmarx chưa có finding tương ứng' : 'Mức độ nghiêm trọng theo báo cáo'}</small></div>
    <div class="alerts-signal"><div>${icon('git-merge')}<span>Gateway policy</span></div><strong>${decision ? badge(decision, decisionTone) : badge(status.label || 'Pending', status.tone || 'muted')}</strong><small>${typeof run?.allowDeploy === 'boolean' ? `allow_deploy = ${run.allowDeploy}` : 'allow_deploy chưa báo cáo'}</small></div>
  </div>`;
}

function sourcePanel(data, finding) {
  const isDemo = data.source === 'demo';
  const code = isDemo && typeof finding.code === 'string' ? finding.code : null;
  const lines = code ? code.split('\n') : [];
  return `<section class="alerts-code-section">
    <div class="alerts-inner-heading"><h3>${icon('code-2')}Source context</h3><span class="alerts-context-label">${isDemo ? 'DEMO FIXTURE' : 'SOURCE KHÔNG LƯU TRONG AUDIT'}</span></div>
    ${code ? `<div class="alerts-code-toolbar"><span class="mono">${esc(finding.path || 'sample.py')}</span><span>Chỉ là code mẫu</span></div><pre class="alerts-code"><ol>${lines.map(line => `<li><code>${esc(line || ' ')}</code></li>`).join('')}</ol></pre>` : `<div class="alerts-source-empty">${icon('file-lock-2')}<div><strong>${isDemo ? 'Chưa có source fixture cho finding này' : 'Source không được lưu trong audit API'}</strong><p>${isDemo ? 'Finding mẫu vẫn giữ metadata và các tín hiệu để kiểm tra giao diện.' : 'Dùng đường dẫn, line và commit bên dưới để mở snapshot trong repository của bạn.'}</p></div></div>`}
  </section>`;
}

function evidenceRows(finding, run) {
  const rows = [
    ['Finding ID', finding.id], ['Run ID', finding.runId],
    ['Repository', run?.repo || 'Chưa có'], ['Commit', run?.commit || 'Chưa có'],
    ['File / line', finding.path ? `${finding.path}${finding.line ? `:${finding.line}` : ''}` : 'Chưa có'],
    ['CWE', array(finding.cwes).join(', ') || 'Chưa map'],
    ['Model group', array(finding.groups).join(', ') || 'Chưa map'],
    ['Detector source', sourceLabel(finding)], ['Mode', run?.mode || 'Chưa có'],
  ];
  return `<dl class="alerts-evidence-grid">${rows.map(([key, value]) => `<div><dt>${esc(key)}</dt><dd class="mono">${esc(value)}</dd></div>`).join('')}</dl>`;
}

function overview(data, finding, run) {
  return `${signals(finding, run)}${sourcePanel(data, finding)}
    <section class="alerts-evidence-section">${sectionHeading('Bằng chứng liên quan', 'Giữ nguyên identity của finding và run')}${evidenceRows(finding, run)}</section>
    <section class="alerts-policy-section">${renderGateEvidence(data, run, {finding})}</section>`;
}

function evidence(data, finding, run) {
  return `<div class="alerts-tab-body">${sectionHeading('Evidence package', 'Metadata do detector và Security Gate cung cấp')}${evidenceRows(finding, run)}
    <div class="alerts-inline-info">${icon('info')}<span>Detector agreement và AI score chưa xác nhận ground truth. ${data.source === 'demo' ? 'Toàn bộ dữ liệu đang xem là fixture demo.' : 'Audit API cung cấp bằng chứng đọc; không cung cấp raw source.'}</span></div>
    ${renderGateEvidence(data, run, {finding})}
    <button class="btn small" data-action="export" data-export="evidence" data-finding="${esc(finding.id)}">${icon('download')}Xuất bằng chứng</button></div>`;
}

function remediation(data, finding, run) {
  return `<div class="alerts-tab-body">${sectionHeading('Khắc phục và kiểm chứng', 'Bằng chứng được chọn vẫn cần người phụ trách review')}
    <div class="alerts-remediation-status">${icon('wrench')}<div><strong>Chưa có hướng dẫn khắc phục đã được xác nhận</strong><p>API hiện chưa trả remediation hoặc bản vá cho finding này. Kiểm tra source tại đúng commit, review evidence, rồi chạy lại hai detector với snapshot đã sửa.</p></div></div>
    <ol class="alerts-review-steps"><li>Đối chiếu ${esc(finding.path || 'vị trí finding')} với evidence của ${esc(sourceLabel(finding))}.</li><li>Kiểm chứng hành vi trong môi trường và scope được phép.</li><li>Ghi nhận bản sửa và tạo run mới; giữ identity và source scope nhất quán giữa hai nhánh.</li></ol>
    <div class="alerts-inline-info">${icon('info')}<span>${data.source === 'demo' ? 'Các thao tác review chỉ đổi trạng thái fixture trong giao diện, không huấn luyện model hoặc phát hành artifact.' : 'Audit API chỉ đọc. Giao diện không xác nhận lỗ hổng hoặc gửi bản vá vào repository.'}</span></div>
    ${run ? `<button class="btn small" data-action="run" data-run="${esc(run.id)}">${icon('arrow-up-right')}Xem run</button>` : ''}</div>`;
}

function history(data, finding, run) {
  const tasks = run ? array(tasksFor(run)) : [];
  const events = tasks.filter(task => task.completedAt || task.startedAt);
  return `<div class="alerts-tab-body">${sectionHeading('Lịch sử run', 'Dấu thời gian có sẵn trong dữ liệu hiện tại')}
    ${events.length ? `<ol class="alerts-history">${events.map(task => `<li><span class="alerts-history-dot"></span><div><strong>${esc(task.name || task.id)}</strong><small>${esc(fmtDate(task.completedAt || task.startedAt))}</small><p>${esc(task.description || 'Run event')}</p></div></li>`).join('')}</ol>` : `<div class="alerts-empty-history">${icon('history')}<p>Chưa có event history đủ để dựng timeline cho finding này.</p></div>`}
    <div class="alerts-inline-info">${icon('info')}<span>${data.source === 'demo' ? `Trạng thái review của fixture: ${verified(finding)[0]}. Đây là thay đổi UI mẫu, không phải sự kiện audit của backend.` : 'API chưa có lịch sử xác nhận / False Positive cho từng finding. Không suy ra hoạt động review từ trạng thái run.'}</span></div></div>`;
}

function detail(data, state, finding, runs) {
  const run = runs.find(item => item.id === finding.runId);
  const [severity, tone] = sev(finding);
  const [verification, verificationTone] = verified(finding);
  const activeTab = TABS.some(([id]) => id === state.alertTab) ? state.alertTab : 'overview';
  const demo = data.source === 'demo';
  const actions = demo ? `<button class="btn primary" data-action="review-demo" data-value="confirmed" data-finding="${esc(finding.id)}">${icon('check')}Xác nhận lỗ hổng</button><button class="btn" data-action="review-demo" data-value="false-positive" data-finding="${esc(finding.id)}">${icon('shield-x')}False Positive</button><button class="btn" data-action="review-demo" data-value="unreviewed" data-finding="${esc(finding.id)}">${icon('rotate-cw')}Kiểm tra lại</button>` : `<button class="btn primary" data-action="export" data-export="evidence" data-finding="${esc(finding.id)}">${icon('download')}Xuất bằng chứng</button>${run ? `<button class="btn" data-action="run" data-run="${esc(run.id)}">${icon('arrow-up-right')}Xem run</button>` : ''}<button class="btn" disabled title="API audit hiện chỉ đọc">${icon('lock-keyhole')}Thẩm định finding</button>`;
  const tabContent = activeTab === 'evidence' ? evidence(data, finding, run) : activeTab === 'remediation' ? remediation(data, finding, run) : activeTab === 'history' ? history(data, finding, run) : overview(data, finding, run);
  return `<article class="card alerts-detail">
    <header class="alerts-detail-header"><div class="alerts-detail-badges"><span class="mono alerts-finding-id">${esc(finding.id)}</span>${badge(severity, tone)}${badge(verification, verificationTone)}<span class="alerts-source-tag">${esc(sourceLabel(finding))}</span></div>
      <h2>${esc(finding.title || 'Finding chưa có tiêu đề')}</h2>
      <div class="alerts-detail-path mono">${icon('file-code-2')}${esc(finding.path || 'Chưa có vị trí')}${finding.line ? `:${esc(finding.line)}` : ''}</div>
      <div class="alerts-detail-meta"><span>${icon('folder-git-2')}${esc(run?.projectName || finding.projectId || 'Project chưa xác định')}</span><span class="mono">${icon('git-commit-horizontal')}${esc(String(run?.commit || '').slice(0, 8) || 'Commit chưa có')}</span><button data-action="run" data-run="${esc(finding.runId || '')}" class="alerts-run-link">${icon('activity')}${esc(finding.runId || 'Run chưa có')}</button></div>
      <div class="alerts-actions">${actions}</div><p class="alerts-review-note">${demo ? 'DEMO · Các thao tác review chỉ cập nhật fixture trong giao diện.' : 'Audit API hiện chỉ đọc; thao tác xác nhận, False Positive và chạy lại finding chưa được hỗ trợ.'}</p>
    </header>
    <nav class="alerts-tabs" role="tablist" aria-label="Chi tiết finding">${TABS.map(([id, label]) => `<button role="tab" aria-selected="${activeTab === id ? 'true' : 'false'}" class="${activeTab === id ? 'is-active' : ''}" data-action="alert-tab" data-value="${id}">${esc(label)}</button>`).join('')}</nav>
    <div class="alerts-detail-content" role="tabpanel">${tabContent}</div>
  </article>`;
}

export function renderAlerts(data = {}, state = {}) {
  const runs = array(data.runs);
  const cutoff = Date.parse(state.focusSince);
  const all = array(data.findings).filter(item => {
    if (state.project && state.project !== 'all' && item.projectId !== state.project) return false;
    const created = Date.parse(runs.find(run => run.id === item.runId)?.createdAt);
    return !Number.isFinite(cutoff) || !Number.isFinite(created) || created >= cutoff;
  });
  const projects = array(data.projects).filter(item => !state.project || state.project === 'all' || item.id === state.project);
  const filters = state.filters || {};
  const selectedProject = filters.project && projects.some(item => item.id === filters.project) ? filters.project : 'all';
  const filtered = all.filter(item => (selectedProject === 'all' || item.projectId === selectedProject)
    && (!filters.severity || filters.severity === 'all' || (filters.severity === 'critical-high' ? ['critical','high'].includes(item.severity) : item.severity === filters.severity))
    && (!filters.cwe || filters.cwe === 'all' || array(item.cwes).includes(filters.cwe))
    && (!filters.source || filters.source === 'all' || item.source === filters.source)
    && (!filters.verification || filters.verification === 'all' || (filters.verification === 'actionable' ? !['false-positive','refuted'].includes(item.verification) : item.verification === filters.verification)))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  const selected = filtered.find(item => item.id === state.findingId) || filtered[0];
  const cwes = [...new Set(all.flatMap(item => array(item.cwes)))].sort();
  const unresolved = all.filter(item => item.verification !== 'confirmed' && item.verification !== 'false-positive').length;
  const critical = all.filter(item => item.severity === 'critical' || item.severity === 'high').length;
  return `<div class="alerts-page">
    <header class="alerts-page-header"><div><h1>Cảnh báo bảo mật</h1><p>Đối chiếu findings, bằng chứng và quyết định của Gateway Security Gate.</p></div><div class="alerts-page-counts">${badge(`${all.length} findings`, 'info')}${badge(`${critical} High / Critical`, critical ? 'danger' : 'muted')}${badge(`${unresolved} chưa xác minh`, unresolved ? 'warning' : 'muted')}<button class="btn small" data-action="reset-filters">${icon('rotate-ccw')}Reset</button></div></header>
    ${Number.isFinite(cutoff) ? `<div class="gate-focus-notice"><span>${icon('calendar-range')}Giới hạn từ ${esc(fmtDate(state.focusSince))}; giữ các run chưa có thời gian.</span><button class="btn small" data-action="clear-overview-focus">Bỏ giới hạn thời gian</button></div>` : ''}
    <section class="card alerts-filter-card"><div class="alerts-filters">${filter('project', 'Project', [['all', 'Tất cả project'], ...projects.map(item => [item.id, item.name || item.repo || item.id])], selectedProject)}${filter('severity', 'Severity', [['all', 'Tất cả severity'], ['critical-high', 'Critical / High'], ...Object.entries(SEVERITY).map(([id, [label]]) => [id, label])], filters.severity)}${filter('cwe', 'CWE', [['all', 'Tất cả CWE'], ...cwes.map(item => [item, item])], filters.cwe)}${filter('source', 'Detector source', [['all', 'Tất cả nguồn'], ...Object.entries(SOURCE)], filters.source)}${filter('verification', 'Verification', [['all', 'Tất cả trạng thái'], ['actionable', 'Cần xử lý / thẩm định'], ...Object.entries(VERIFICATION).map(([id, [label]]) => [id, label])], filters.verification)}</div></section>
    <div class="alerts-ai-hint">${icon('sparkles')}<span>AI score là điểm dự đoán; severity và việc xác nhận lỗ hổng cần evidence. ${data.source === 'demo' ? 'Đang xem dữ liệu demo.' : 'Dữ liệu hiện tại từ audit API.'}</span></div>
    <div class="alerts-workspace"><aside class="card alerts-master"><div class="alerts-master-header"><h2>Danh sách findings</h2>${badge(String(filtered.length), 'muted')}</div><div class="alerts-master-list">${filtered.length ? filtered.map(item => findingRow(item, item.id === selected?.id, runs)).join('') : `<div class="alerts-list-empty">${icon('list-filter')}<strong>Không có finding khớp bộ lọc</strong><p>Thử đổi project hoặc reset các điều kiện.</p><button class="btn small" data-action="reset-filters">Reset bộ lọc</button></div>`}</div></aside>${selected ? detail(data, state, selected, runs) : `<article class="card alerts-no-detail"><div>${icon('shield-check')}<h2>Chưa có finding để xem</h2><p>${all.length ? 'Bộ lọc đang ẩn các findings hiện có.' : 'Report chưa có findings không đồng nghĩa gate đã PASS. Xem trạng thái hai nhánh trong run.'}</p>${state.runId ? `<button class="btn" data-action="run" data-run="${esc(state.runId)}">${icon('arrow-up-right')}Xem run</button>` : ''}</div></article>`}</div>
  </div>`;
}
