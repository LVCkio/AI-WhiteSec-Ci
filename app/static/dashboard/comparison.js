import { esc, icon, badge, fmtDate, groupName } from './ui.js';

const list = value => Array.isArray(value) ? value : [];
const text = value => typeof value === 'string' ? value.trim() : '';
const stable = value => JSON.stringify(value && typeof value === 'object' && !Array.isArray(value)
  ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, JSON.parse(stable(item))]))
  : Array.isArray(value) ? value.map(item => JSON.parse(stable(item))) : value ?? null);
const tokens = value => [...new Set(list(value).map(item => text(item).toUpperCase()).filter(Boolean))].sort();
const normalizePath = value => text(value).replace(/\\/g, '/').replace(/^(?:\.\/)+/, '').replace(/\/{2,}/g, '/');
const repository = run => text(run?.repo || run?.projectId);
const finished = run => run?.status === 'decided' && run.checkmarx === 'completed' && run.codebert === 'completed' && run.decision && run.decision !== 'ERROR';
const decisionTone = value => value === 'PASS' ? 'success' : ['BLOCK', 'ERROR'].includes(value) ? 'danger' : value === 'REVIEW' ? 'warning' : 'muted';
const severity = value => ({critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info', unknown: 'Chưa rõ'}[value] || 'Chưa rõ');
const source = finding => finding?.source === 'CodeBERT only' ? 'Tín hiệu AI' : ['Combined', 'Checkmarx only'].includes(finding?.source) ? 'Checkmarx' : 'Chưa rõ nguồn';
const options = (runs, selected) => runs.map(run => `<option value="${esc(run.id)}"${run.id === selected ? ' selected' : ''}>${esc(`${run.id} · ${String(run.commit || '').slice(0, 8) || 'chưa có commit'} · ${run.decision || 'PENDING'}`)}</option>`).join('');

/** Keep selection in one repository. Explicit pending/same-run selections remain reviewable. */
export function ensureComparisonSelection(data = {}, state = {}) {
  const available = list(data.runs).filter(run => !state.project || state.project === 'all' || run.projectId === state.project || repository(run) === state.project)
    .sort((a, b) => (Date.parse(b.createdAt) || 0) - (Date.parse(a.createdAt) || 0));
  const targetChoice = available.find(run => run.id === state.compareTargetId);
  const baseChoice = available.find(run => run.id === state.compareBaseId);
  const repos = [...new Set(available.map(repository).filter(Boolean))];
  const chosenRepo = repository(targetChoice || baseChoice) || repos.find(repo => available.filter(run => repository(run) === repo && finished(run)).length > 1) || repos[0];
  const runs = available.filter(run => repository(run) === chosenRepo);
  const target = runs.find(run => run.id === state.compareTargetId) || runs.find(finished) || runs[0] || null;
  const alternatives = runs.filter(run => run.id !== target?.id);
  const beforeTarget = alternatives.filter(run => Date.parse(run.createdAt) <= Date.parse(target?.createdAt));
  const base = runs.find(run => run.id === state.compareBaseId) || beforeTarget.find(finished) || alternatives.find(finished) || beforeTarget[0] || alternatives[0] || null;
  state.compareBaseId = base?.id || null;
  state.compareTargetId = target?.id || null;
  if (!['all', 'new', 'persistent', 'not-observed', 'unknown'].includes(state.compareFilter)) state.compareFilter = 'all';
  return { runs, base, target };
}

function evidence(data, run) {
  const detail = data.details?.[run.id];
  const issues = [];
  if (!detail || typeof detail !== 'object') issues.push(`${run.id}: chưa có gói bằng chứng chi tiết.`);
  if (!finished(run)) issues.push(`${run.id}: lượt quét chưa hoàn tất hợp lệ ở cả hai nhánh.`);
  if (detail && (detail.checkmarx?.status !== 'completed' || detail.codebert?.status !== 'completed' || !detail.final_decision || detail.final_decision.decision === 'ERROR')) issues.push(`${run.id}: bằng chứng chi tiết còn pending, lỗi hoặc chưa đầy đủ.`);
  if (detail && (!Array.isArray(detail.checkmarx?.findings) || !Array.isArray(detail.codebert?.predictions))) issues.push(`${run.id}: thiếu danh sách bằng chứng của bộ phân tích.`);
  if (detail && [detail, detail.checkmarx, detail.codebert].some(item => !Array.isArray(item?.coverage_issues) || item.coverage_issues.length)) issues.push(`${run.id}: phạm vi phân tích chưa được xác nhận đầy đủ.`);
  if (detail && (!/^[a-f0-9]{64}$/i.test(text(detail.source_manifest_sha256)) || detail.checkmarx?.source_manifest_sha256 !== detail.source_manifest_sha256)) issues.push(`${run.id}: thiếu liên kết manifest giữa snapshot và phạm vi Checkmarx.`);
  const paths = [...new Set(list(detail?.units).map(unit => normalizePath(unit.path)).filter(Boolean))].sort();
  if (!paths.length) issues.push(`${run.id}: chưa có danh sách file trong phạm vi quét.`);
  const units = list(detail?.units);
  const scopes = units.map(unit => [normalizePath(unit.path), unit.start_line, unit.end_line]).sort((a, b) => stable(a).localeCompare(stable(b)));
  if (units.some(unit => !Number.isInteger(unit.start_line) || !Number.isInteger(unit.end_line) || unit.start_line < 1 || unit.end_line < unit.start_line)) issues.push(`${run.id}: thiếu khoảng dòng source được phân tích.`);
  if (detail && (list(detail.units).some(unit => !normalizePath(unit.path)) || (Number.isFinite(run.unitsCount) && run.unitsCount !== list(detail.units).length))) issues.push(`${run.id}: danh sách đơn vị source chưa đủ hoặc thiếu vị trí.`);
  const unitIds = units.map(unit => text(unit.unit_id));
  const predictionIds = list(detail?.codebert?.predictions).map(prediction => text(prediction.unit_id));
  if (detail && (unitIds.some(id => !id) || new Set(unitIds).size !== unitIds.length || new Set(predictionIds).size !== predictionIds.length || stable([...unitIds].sort()) !== stable([...predictionIds].sort()))) issues.push(`${run.id}: chưa có dự đoán khớp đầy đủ các đơn vị source.`);
  const identity = detail?.identity;
  if (detail && (text(identity?.repository) !== repository(run) || text(identity?.commit_sha) !== text(run.commit) || text(identity?.run_id) !== text(run.id))) issues.push(`${run.id}: identity của bằng chứng không khớp lượt chạy.`);
  if (detail && ((detail.checkmarx && detail.checkmarx.mode !== run.mode) || (detail.codebert && detail.codebert.mode !== run.mode))) issues.push(`${run.id}: chế độ của bằng chứng không khớp lượt chạy.`);
  const findings = list(data.findings).filter(finding => finding.runId === run.id);
  if (findings.some(finding => !signature(finding, detail))) issues.push(`${run.id}: có phát hiện thiếu vị trí hoặc loại để đối chiếu danh tính.`);
  const scannerCount = findings.filter(finding => ['Combined', 'Checkmarx only'].includes(finding.source)).length;
  if (detail && Array.isArray(detail.checkmarx?.findings) && scannerCount !== detail.checkmarx.findings.length) issues.push(`${run.id}: số finding chi tiết và danh sách hiển thị chưa khớp.`);
  if (Number.isFinite(run.findingsCount) && findings.length !== run.findingsCount) issues.push(`${run.id}: danh sách hiển thị chưa đủ số phát hiện đã báo cáo.`);
  return { detail, issues, paths, scopes, findings };
}

function signature(finding, detail) {
  const kind = finding.source === 'CodeBERT only' ? 'ai' : ['Combined', 'Checkmarx only'].includes(finding.source) ? 'scanner' : null;
  const path = normalizePath(finding.path);
  const line = Number.isInteger(finding.line) && finding.line > 0 ? finding.line : null;
  const raw = list(detail?.checkmarx?.findings).find(item => item.finding_id === finding.detectorId || `${finding.runId}::${item.finding_id}` === finding.id || item.finding_id === finding.id);
  const rule = kind === 'scanner' ? text(raw?.rule_id || finding.ruleId || finding.rule_id) : '';
  const groups = tokens(finding.groups);
  const cwes = tokens(finding.cwes);
  const detector = rule ? ['rule', rule, groups, cwes] : [kind === 'ai' ? 'groups' : 'category', groups, cwes];
  if (!kind || !path || !line || (!rule && !groups.length && !cwes.length)) return null;
  const loose = stable([kind, path, detector]);
  return { key: stable([kind, path, detector, line]), loose };
}

/** Pure calculation. "not-observed" is evidence absence, never a verified fix. */
export function compareRuns(data = {}, baseId, targetId) {
  const base = list(data.runs).find(run => run.id === baseId) || null;
  const target = list(data.runs).find(run => run.id === targetId) || null;
  const result = { valid: false, comparable: false, blockedReason: '', base, target, rows: [], counts: { new: 0, persistent: 0, 'not-observed': 0, unknown: 0 }, warnings: [] };
  if (!base || !target) { result.blockedReason = 'Cần hai lượt chạy trong cùng repository để so sánh.'; return result; }
  if (base.id === target.id) { result.blockedReason = 'Hai lựa chọn đang là cùng một lượt chạy. Chọn một lượt gốc khác.'; return result; }
  if (!repository(base) || repository(base) !== repository(target)) { result.blockedReason = 'Hai lượt chạy phải thuộc cùng repository; không đối chiếu findings giữa các dự án.'; return result; }
  if (base.mode !== target.mode) { result.blockedReason = 'Hai lượt chạy khác chế độ demo / thực tế. Chọn hai lượt cùng chế độ để đối chiếu.'; return result; }
  result.valid = true;
  const before = evidence(data, base);
  const after = evidence(data, target);
  result.warnings.push(...before.issues, ...after.issues);
  if (!['demo', 'real'].includes(base.mode)) result.warnings.push('Chế độ phân tích chưa được xác định.');
  if (stable(before.paths) !== stable(after.paths)) result.warnings.push('Danh sách file trong phạm vi quét đã thay đổi; không suy ra finding mới hoặc biến mất từ phạm vi khác.');
  if (stable(before.scopes) !== stable(after.scopes)) result.warnings.push('Khoảng dòng hoặc đơn vị source trong phạm vi quét đã thay đổi; cần đối chiếu source trước khi kết luận.');
  const presetBefore = text(before.detail?.checkmarx?.preset);
  const presetAfter = text(after.detail?.checkmarx?.preset);
  if (!presetBefore || !presetAfter || presetBefore !== presetAfter) result.warnings.push('Preset Checkmarx khác nhau hoặc chưa có thông tin.');
  const modelBefore = text(before.detail?.codebert?.model_version);
  const modelAfter = text(after.detail?.codebert?.model_version);
  if (!modelBefore || !modelAfter || modelBefore !== modelAfter) result.warnings.push('Phiên bản mô hình khác nhau hoặc chưa có thông tin.');
  const thresholdsBefore = before.detail?.codebert?.thresholds;
  const thresholdsAfter = after.detail?.codebert?.thresholds;
  if (!thresholdsBefore || !thresholdsAfter || !Object.keys(thresholdsBefore).length || stable(thresholdsBefore) !== stable(thresholdsAfter)) result.warnings.push('Ngưỡng CodeBERT khác nhau hoặc chưa được cung cấp.');
  result.comparable = result.warnings.length === 0;
  if (Date.parse(base.createdAt) > Date.parse(target.createdAt)) result.warnings.push('Lượt gốc được chọn mới hơn lượt đối chiếu; nhãn thay đổi đi theo chiều bạn đã chọn.');
  if (base.commit === target.commit) result.warnings.push('Hai lượt dùng cùng commit. Khác biệt có thể đến từ lần quét lại, chưa chứng minh thay đổi source.');
  if (stable(before.detail?.policy) !== stable(after.detail?.policy)) result.warnings.push('Policy của Security Gate đã thay đổi; quyết định Gate có thể đổi do policy.');
  const baseItems = before.findings.map(finding => ({ finding, signature: signature(finding, before.detail) }));
  const targetItems = after.findings.map(finding => ({ finding, signature: signature(finding, after.detail) }));
  const buckets = items => {
    const map = new Map();
    for (const item of items) if (item.signature) map.set(item.signature.key, [...(map.get(item.signature.key) || []), item]);
    return map;
  };
  const baseMap = buckets(baseItems);
  const targetMap = buckets(targetItems);
  const matched = new Set();
  const add = (status, oldFinding, newFinding, reason = '') => {
    result.rows.push({ status, base: oldFinding || null, target: newFinding || null, finding: newFinding || oldFinding, kind: source(newFinding || oldFinding), reason });
    result.counts[status]++;
  };
  for (const item of targetItems) {
    const key = item.signature?.key;
    const previous = key && baseMap.get(key);
    if (previous?.length === 1 && targetMap.get(key)?.length === 1) {
      matched.add(previous[0]);
      add('persistent', previous[0].finding, item.finding, 'Cùng file, quy tắc / nhóm, CWE và dòng trong cả hai lượt.');
      continue;
    }
    const moved = item.signature && baseItems.some(old => old.signature?.loose === item.signature.loose);
    const uncertain = !result.comparable || !item.signature || moved || previous?.length > 1 || (key && targetMap.get(key)?.length > 1);
    add(uncertain ? 'unknown' : 'new', null, item.finding, moved ? 'Có bằng chứng cùng file và quy tắc nhưng vị trí hoặc số lượng đã đổi; cần đối chiếu source.' : !item.signature ? 'Thiếu file, dòng hoặc quy tắc để tạo khóa đối chiếu.' : uncertain ? 'Chưa đủ điều kiện để kết luận đây là phát hiện mới.' : 'Chỉ ghi nhận trong lượt đối chiếu với cùng phạm vi và cấu hình.');
  }
  for (const item of baseItems) {
    if (matched.has(item)) continue;
    const key = item.signature?.key;
    const moved = item.signature && targetItems.some(next => next.signature?.loose === item.signature.loose);
    const uncertain = !result.comparable || !item.signature || moved || (key && baseMap.get(key)?.length > 1);
    add(uncertain ? 'unknown' : 'not-observed', item.finding, null, moved ? 'Vị trí hoặc số lượng của bằng chứng cùng loại đã đổi; chưa xác định cùng một finding.' : !item.signature ? 'Thiếu file, dòng hoặc quy tắc để tạo khóa đối chiếu.' : uncertain ? 'Chưa có đủ bằng chứng để kết luận không còn ghi nhận.' : 'Không xuất hiện ở lượt đối chiếu. Cần kiểm chứng bản sửa trước khi xác nhận khắc phục.');
  }
  const ranks = { new: 0, persistent: 1, 'not-observed': 2, unknown: 3 };
  result.rows.sort((a, b) => ranks[a.status] - ranks[b.status] || normalizePath(a.finding.path).localeCompare(normalizePath(b.finding.path)) || (a.finding.line || 0) - (b.finding.line || 0));
  return result;
}

const statusMeta = status => ({ new: ['Mới ghi nhận', 'danger', 'plus'], persistent: ['Còn ghi nhận', 'warning', 'equal'], 'not-observed': ['Không còn ghi nhận', 'info', 'minus'], unknown: ['Chưa thể kết luận', 'muted', 'circle-help'] }[status]);

function runCard(run, label, symbol) {
  return `<article class="compare-run-card"><div class="compare-run-label">${icon(symbol)}${esc(label)}<span>${esc(run.mode === 'demo' ? 'DEMO' : run.mode === 'real' ? 'THỰC TẾ' : 'CHƯA RÕ')}</span></div><div class="compare-run-title"><strong class="mono">${esc(run.id)}</strong>${badge(run.decision || 'PENDING', decisionTone(run.decision))}</div><span class="compare-commit mono">${icon('git-commit-horizontal')}${esc(String(run.commit || '').slice(0, 12) || 'Chưa có commit')}</span><p>${esc(fmtDate(run.createdAt))}</p><button class="btn text" data-action="run" data-run="${esc(run.id)}">Xem pipeline ${icon('arrow-up-right')}</button></article>`;
}

function comparisonRow(row) {
  const [label, tone] = statusMeta(row.status);
  const finding = row.finding;
  const position = item => item ? `${normalizePath(item.path) || 'Chưa có file'}${item.line ? `:${item.line}` : ''}` : '—';
  return `<tr><td>${badge(label, tone)}<span class="compare-row-note">${esc(row.reason)}</span></td><td><button class="compare-finding-link" data-action="finding" data-finding="${esc(finding.id)}">${esc(finding.title || list(finding.groups).map(groupName).join(', ') || 'Phát hiện chưa có tiêu đề')}${icon('arrow-up-right')}</button><span class="compare-row-tags"><span>${esc(row.kind)}</span>${list(finding.cwes).length ? `<span>${esc(list(finding.cwes).join(', '))}</span>` : ''}${badge(severity(finding.severity), ['critical', 'high'].includes(finding.severity) ? 'danger' : finding.severity === 'medium' ? 'warning' : 'muted')}</span>${row.kind === 'Tín hiệu AI' ? '<small class="compare-ai-note">Điểm dự đoán, chưa phải lỗ hổng đã xác nhận.</small>' : ''}</td><td class="mono compare-location">${esc(position(row.base))}</td><td class="mono compare-location">${esc(position(row.target))}</td></tr>`;
}

export function renderComparison(data = {}, state = {}) {
  const selection = ensureComparisonSelection(data, state);
  const result = compareRuns(data, state.compareBaseId, state.compareTargetId);
  const activeFilter = state.compareFilter || 'all';
  const rows = result.rows.filter(row => activeFilter === 'all' || row.status === activeFilter);
  const selectedProject = state.project || 'all';
  const projects = list(data.projects);
  const repo = repository(selection.target || selection.base);
  const header = `<header class="page-title-row"><div><h1 class="page-title">So sánh lượt quét</h1><p class="page-description">Theo dõi thay đổi của bằng chứng qua hai commit trong cùng repository.</p></div>${badge(data.source === 'demo' ? 'DỮ LIỆU MẪU' : 'BẰNG CHỨNG AUDIT', data.source === 'demo' ? 'warning' : 'info')}</header>`;
  const controls = `<section class="card compare-controls"><label><span>Repository</span><select class="field" data-action="project-filter" aria-label="Repository so sánh"><option value="all"${selectedProject === 'all' ? ' selected' : ''}>Tự chọn repository</option>${projects.map(project => `<option value="${esc(project.id)}"${selectedProject === project.id ? ' selected' : ''}>${esc(project.name || project.repo || project.id)}</option>`).join('')}</select></label><label><span>Lượt gốc</span><select class="field" data-action="compare-base" aria-label="Lượt quét gốc"${selection.runs.length ? '' : ' disabled'}>${selection.runs.length ? options(selection.runs, state.compareBaseId) : '<option>Chưa có lượt chạy</option>'}</select></label><button class="compare-selector-arrow" data-action="compare-swap" aria-label="Đổi chiều so sánh" title="Đổi chiều so sánh"${result.valid ? '' : ' disabled'}>${icon('arrow-right-left')}</button><label><span>Lượt đối chiếu</span><select class="field" data-action="compare-target" aria-label="Lượt quét đối chiếu"${selection.runs.length ? '' : ' disabled'}>${selection.runs.length ? options(selection.runs, state.compareTargetId) : '<option>Chưa có lượt chạy</option>'}</select></label><p>${icon('folder-git-2')}<span>${esc(repo || 'Chọn repository có ít nhất hai lượt chạy.')} · Chiều thay đổi: lượt gốc → lượt đối chiếu.</span></p></section>`;
  if (!result.valid) return `<div class="comparison-page">${header}${controls}<section class="card compare-empty">${icon('git-compare-arrows')}<h2>${selection.runs.length < 2 ? 'Chưa đủ hai lượt chạy' : 'Chọn lại hai lượt để so sánh'}</h2><p>${esc(result.blockedReason)}</p>${!list(data.runs).length ? '<p>Kết quả sẽ xuất hiện sau khi repository có các lượt quét được ghi nhận.</p>' : ''}</section></div>`;
  const warning = result.warnings.length ? `<aside class="compare-caution" role="status">${icon('triangle-alert')}<div><strong>${result.comparable ? 'Lưu ý khi đọc kết quả' : 'Chưa đủ điều kiện kết luận thay đổi'}</strong><p>${result.comparable ? 'Các nhãn dưới đây đi theo hai lượt bạn đã chọn.' : 'Chỉ các bằng chứng khớp chính xác được đánh dấu còn ghi nhận. Phát hiện chỉ có ở một lượt sẽ chờ đối chiếu.'}</p><ul>${[...new Set(result.warnings)].map(item => `<li>${esc(item)}</li>`).join('')}</ul></div></aside>` : `<div class="compare-ready">${icon('scan-line')}<span>Cùng repository, chế độ, phạm vi file và cấu hình phân tích. Đối chiếu theo vị trí bằng chứng.</span>${badge('Đủ điều kiện đối chiếu', 'success')}</div>`;
  const summary = `<div class="compare-summary">${['new', 'persistent', 'not-observed', 'unknown'].map(status => { const [label, tone, symbol] = statusMeta(status); return `<article class="card compare-summary-card ${tone}"><span>${icon(symbol)}${esc(label)}</span><strong>${result.counts[status]}</strong><small>${status === 'unknown' ? 'Cần thêm bằng chứng đối chiếu' : status === 'not-observed' ? 'Chưa xác nhận đã khắc phục' : status === 'persistent' ? 'Khớp file, loại và dòng' : 'Trong cùng phạm vi so sánh'}</small></article>`; }).join('')}</div>`;
  const gateMessage = !result.base.decision && !result.target.decision ? 'Cả hai lượt đang chờ quyết định Gate.' : !result.base.decision ? 'Lượt gốc đang chờ quyết định Gate.' : !result.target.decision ? 'Lượt đối chiếu đang chờ quyết định Gate.' : result.base.decision === result.target.decision ? 'Quyết định Gate giữ nguyên.' : 'Quyết định Gate đã thay đổi.';
  const gates = `<section class="card compare-gate"><div>${icon('shield-check')}<span><strong>Security Gate</strong><small>Quyết định do Gateway cung cấp</small></span></div><div class="compare-gate-values">${badge(result.base.decision || 'PENDING', decisionTone(result.base.decision))}${icon('arrow-right')}${badge(result.target.decision || 'PENDING', decisionTone(result.target.decision))}</div><p>${gateMessage} Xem pipeline để kiểm tra lý do và policy.</p></section>`;
  const filters = [['all', 'Tất cả', result.rows.length], ['new', 'Mới ghi nhận', result.counts.new], ['persistent', 'Còn ghi nhận', result.counts.persistent], ['not-observed', 'Không còn ghi nhận', result.counts['not-observed']], ['unknown', 'Chưa thể kết luận', result.counts.unknown]];
  const table = `<section class="card compare-evidence"><div class="compare-evidence-header"><div><h2>Bằng chứng đối chiếu</h2><p>Checkmarx và tín hiệu AI được theo dõi riêng.</p></div><div class="compare-evidence-actions"><span class="mono">${rows.length} / ${result.rows.length}</span><button class="btn small" data-action="compare-export">${icon('download')}Xuất so sánh</button></div></div><nav class="compare-filters" aria-label="Lọc thay đổi">${filters.map(([value, label, count]) => `<button data-action="compare-filter" data-value="${value}" class="${activeFilter === value ? 'active' : ''}" aria-pressed="${activeFilter === value}">${esc(label)}<span>${count}</span></button>`).join('')}</nav>${rows.length ? `<div class="table-wrap"><table class="table compare-table"><thead><tr><th>Thay đổi</th><th>Phát hiện / tín hiệu</th><th>Lượt gốc · ${esc(result.base.id)}</th><th>Đối chiếu · ${esc(result.target.id)}</th></tr></thead><tbody>${rows.map(comparisonRow).join('')}</tbody></table></div>` : `<div class="compare-table-empty">${icon(result.rows.length ? 'list-filter' : 'scan-line')}<strong>${result.rows.length ? 'Không có bằng chứng thuộc nhóm này' : result.comparable ? 'Hai lượt không ghi nhận finding hoặc tín hiệu vượt ngưỡng' : 'Chưa có bằng chứng để đối chiếu'}</strong><p>${result.comparable ? 'Kết quả quét không thay thế việc kiểm chứng bảo mật và thẩm định source.' : 'Hoàn tất các nhánh và kiểm tra gói bằng chứng của hai lượt.'}</p></div>`}</section>`;
  return `<div class="comparison-page">${header}${controls}<div class="compare-runs">${runCard(result.base, 'Lượt gốc', 'git-commit-horizontal')}<div class="compare-runs-arrow">${icon('arrow-right')}</div>${runCard(result.target, 'Lượt đối chiếu', 'git-pull-request-arrow')}</div>${warning}${summary}${gates}${table}<p class="compare-footnote">${icon('info')}“Không còn ghi nhận” chỉ mô tả báo cáo của lượt đối chiếu. Dòng bị dịch chuyển hoặc bằng chứng thiếu được giữ ở trạng thái chưa thể kết luận.${data.source === 'demo' ? ' Toàn bộ lượt chạy trên là fixture giao diện.' : ''}</p></div>`;
}
