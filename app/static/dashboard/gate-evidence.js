import { esc, icon, badge, groupName } from './ui.js';

const list = value => Array.isArray(value) ? value : [];
const object = value => value && typeof value === 'object' && !Array.isArray(value) ? value : {};
const probability = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
const thresholdValue = value => probability(value) && value > 0 && value < 1;
const fixed = value => probability(value) ? value.toFixed(4) : 'Chưa báo cáo';
const severityName = value => ({critical:'Critical',high:'High',medium:'Medium',low:'Low',info:'Info',unknown:'Chưa rõ'}[value] || value);

function detailFor(data, run) {
  return object(data.details?.[run?.id]);
}

function boundScannerFinding(detail, run, finding) {
  return list(detail.checkmarx?.findings).find(item => item.finding_id === finding?.detectorId
    || finding?.id === `${run?.id}::${item.finding_id}`);
}

function findingForSignal(findings, detail, run, unitId, group) {
  return findings.find(finding => finding.id === `${run.id}::AI::${unitId}::${group}`)
    || findings.find(finding => {
      const scanner = boundScannerFinding(detail, run, finding);
      return list(scanner?.unit_ids).includes(unitId) && list(scanner?.groups).includes(group);
    });
}

function recordedExplanation(reason) {
  let match = reason.match(/^Checkmarx (.+): (critical|high|medium|low|info|unknown) severity$/);
  if (match) return `Checkmarx ghi nhận ${match[1]} ở mức ${severityName(match[2])}.`;
  match = reason.match(/^CodeBERT (\w+) in (.+) \((\d+\.\d+) >= (\d+\.\d+)\)$/);
  if (match) return `Điểm ${groupName(match[1])} của ${match[2]} đạt hoặc vượt ngưỡng đã ghi trong lý do của Gateway.`;
  match = reason.match(/^CodeBERT (\w+) in (.+) is near its threshold$/);
  if (match) return `Điểm ${groupName(match[1])} của ${match[2]} nằm gần ngưỡng; Gateway ghi nhận cần xem xét.`;
  match = reason.match(/^Unresolved Checkmarx finding (.+) \((\w+)\)$/);
  if (match) return `Finding Checkmarx ${match[1]} (${severityName(match[2])}) vẫn cần thẩm định.`;
  return ({
    'Gateway joined both completed detector results for the same commit and source scope':'Gateway đã nhận đủ hai kết quả hoàn tất trên cùng commit và phạm vi mã nguồn.',
    'Demo results cannot authorize deployment':'Kết quả demo không cấp quyền deploy.',
    'Validated Security Gate policy is unavailable':'Chưa có policy Security Gate hợp lệ.',
    'CodeBERT did not cover every source unit':'CodeBERT chưa bao phủ đủ các đơn vị mã nguồn.',
    'Calibrated model thresholds are unavailable':'Chưa có đầy đủ ngưỡng đã hiệu chỉnh cho mô hình.',
    'Security Gate release policy has not been approved':'Policy phát hành chưa được phê duyệt.',
    'Detector identity or source manifest does not match the locked run':'Identity hoặc source manifest của bộ phân tích không khớp lượt chạy đã khóa.',
  })[reason] || reason;
}

function reasonFinding(reason, findings, detail, run) {
  return findings.find(finding => {
    const raw = boundScannerFinding(detail, run, finding);
    const id = raw?.finding_id || finding.detectorId;
    if (!id) return false;
    return reason.startsWith(`Checkmarx ${id}:`) || reason.startsWith(`Unresolved Checkmarx finding ${id} (`)
      || reason === `Unmapped Checkmarx finding ${id}` || reason === `Finding ${id} lacks complete source mapping`;
  }) || list(detail.codebert?.predictions).flatMap(prediction => Object.keys(object(prediction.scores)).map(group => ({prediction, group})))
    .filter(({prediction, group}) => reason.startsWith(`CodeBERT ${group} in ${prediction.unit_id} (`)
      || reason === `CodeBERT ${group} in ${prediction.unit_id} is near its threshold`)
    .map(({prediction, group}) => findingForSignal(findings, detail, run, prediction.unit_id, group)).find(Boolean);
}

/** Present recorded evidence only; comparisons do not reconstruct the Gate's decision. */
export function gateEvidenceModel(data = {}, run, focusedFinding = null) {
  const detail = detailFor(data, run);
  const policy = object(detail.policy);
  const model = object(detail.codebert);
  const final = object(detail.final_decision || detail.record?.decision || detail.decision);
  const findings = list(data.findings).filter(finding => finding.runId === run?.id);
  const rawFinding = focusedFinding ? boundScannerFinding(detail, run, focusedFinding) : null;
  const thresholds = object(model.thresholds);
  const margin = probability(policy.review_score_margin) ? policy.review_score_margin : null;
  const scores = [];
  for (const prediction of list(model.predictions)) {
    for (const [group, score] of Object.entries(object(prediction.scores))) {
      if (!probability(score)) continue;
      if (focusedFinding && !(rawFinding
        ? list(rawFinding.unit_ids).includes(prediction.unit_id) && list(rawFinding.groups).includes(group)
        : focusedFinding.id === `${run?.id}::AI::${prediction.unit_id}::${group}`)) continue;
      scores.push({unitId:prediction.unit_id, group, score, finding:findingForSignal(findings, detail, run, prediction.unit_id, group), origin:'prediction'});
    }
  }
  if (!scores.length) {
    // A projected finding score can be a maximum over units. Keep that limitation visible.
    for (const finding of focusedFinding ? [focusedFinding] : findings) {
      if (!probability(finding.score)) continue;
      const group = list(finding.groups).length === 1 ? finding.groups[0] : null;
      scores.push({unitId:null, group, score:finding.score, finding, origin:'finding'});
    }
  }
  for (const signal of scores) {
    signal.threshold = thresholdValue(thresholds[signal.group]) ? thresholds[signal.group] : null;
    signal.near = signal.threshold !== null && margin !== null ? Math.max(0, signal.threshold - margin) : null;
    signal.comparison = signal.threshold === null ? 'unknown' : signal.score >= signal.threshold ? 'hit'
      : signal.near !== null && signal.score >= signal.near ? 'near' : 'below';
  }
  const ranks = {hit:0,near:1,unknown:2,below:3};
  scores.sort((a,b) => ranks[a.comparison] - ranks[b.comparison] || b.score - a.score);
  const reasons = list(Array.isArray(final.reasons) ? final.reasons : run?.reasons).filter(reason => typeof reason === 'string')
    .map(reason => ({raw:reason, explanation:recordedExplanation(reason), finding:reasonFinding(reason, findings, detail, run)}));
  const coverage = [['Snapshot',detail.coverage_issues],['Checkmarx',detail.checkmarx?.coverage_issues],['CodeBERT',model.coverage_issues]];
  const reportedCoverage = coverage.filter(([, issues]) => Array.isArray(issues));
  const issues = coverage.flatMap(([source, values]) => list(values).filter(value => typeof value === 'string').map(message => ({source,message})));
  const units = list(detail.units);
  const predictedIds = new Set(list(model.predictions).filter(prediction => units.some(unit => unit.unit_id === prediction.unit_id)).map(prediction => prediction.unit_id));
  return {detail,policy,final,margin,scores,reasons,reportedCoverage,issues,units,predictedIds};
}

function findingLink(finding) {
  return finding ? `<button class="gate-evidence-link" data-action="finding" data-evidence-link="true" data-finding="${esc(finding.id)}">${icon('arrow-up-right')}Xem finding</button>` : '';
}

function scoreRow(signal) {
  const [label,tone] = ({hit:['Đạt / vượt ngưỡng','danger'],near:['Trong biên review','warning'],below:['Dưới ngưỡng','muted'],unknown:['Chưa có ngưỡng','muted']})[signal.comparison];
  return `<div class="gate-score-row"><div class="gate-score-heading"><div><strong>${esc(signal.group ? groupName(signal.group) : 'Điểm tổng hợp của finding')}</strong><small class="mono">${esc(signal.unitId || 'Unit chưa có mapping chi tiết')}</small></div>${badge(label,tone)}</div><div class="gate-score-values"><span>Điểm <b class="mono">${fixed(signal.score)}</b></span><span>Ngưỡng <b class="mono">${signal.threshold === null ? 'Chưa báo cáo' : fixed(signal.threshold)}</b></span></div><div class="gate-score-track" role="img" aria-label="${esc(`Điểm ${fixed(signal.score)}, ngưỡng ${signal.threshold === null ? 'chưa báo cáo' : fixed(signal.threshold)}`)}"><span class="${signal.comparison}" style="width:${signal.score*100}%"></span>${signal.threshold === null ? '' : `<i style="left:${signal.threshold*100}%" title="Ngưỡng ${fixed(signal.threshold)}"></i>`}</div>${signal.origin === 'finding' ? '<p class="gate-score-note">Điểm từ metadata finding; chưa có prediction theo unit để đối chiếu.</p>' : ''}${findingLink(signal.finding)}</div>`;
}

export function renderGateEvidence(data = {}, run, {finding = null} = {}) {
  const evidence = gateEvidenceModel(data, run, finding);
  const {policy,final,margin,scores,reasons,reportedCoverage,issues,units,predictedIds} = evidence;
  const severities = Array.isArray(policy.block_checkmarx_severities) ? policy.block_checkmarx_severities.map(severityName).join(', ') || 'Không cấu hình severity chặn' : 'Chưa báo cáo';
  const policyRows = [
    ['Phiên bản policy',policy.version || final.policy_version || 'Chưa báo cáo'],
    ['Severity Checkmarx được chặn',severities],
    ['Biên xem xét dưới ngưỡng',margin === null ? 'Chưa báo cáo' : fixed(margin)],
    ['Policy phát hành',typeof policy.release_approved === 'boolean' ? policy.release_approved ? 'Đã phê duyệt' : 'Chưa phê duyệt' : 'Chưa báo cáo'],
  ];
  const coverageText = !reportedCoverage.length ? 'Chưa báo cáo các kiểm tra phạm vi.' : issues.length
    ? `${issues.length} vấn đề phạm vi đã được báo cáo.` : 'Không ghi nhận vấn đề trong các trường phạm vi đã báo cáo.';
  return `<div class="gate-evidence">
    <section class="gate-recorded"><div class="gate-evidence-heading"><h3>${icon('message-square-text')}Lý do Gateway đã ghi</h3>${data.source === 'demo' || run?.mode === 'demo' ? badge('Dữ liệu mẫu','muted') : ''}</div><p class="gate-evidence-intro">Lý do dưới đây thuộc lượt ${esc(run?.id || 'chưa xác định')}${finding ? '; quyết định áp dụng cho toàn bộ run' : ''}.</p>${reasons.length ? `<ul class="gate-recorded-list">${reasons.map(reason => `<li><span class="gate-reason-dot"></span><div><p>${esc(reason.explanation)}</p>${reason.raw !== reason.explanation ? `<small class="mono">${esc(reason.raw)}</small>` : ''}${findingLink(reason.finding)}</div></li>`).join('')}</ul>` : '<p class="gate-evidence-empty">Chưa có lý do quyết định được ghi nhận. Xem trạng thái hai nhánh để biết bằng chứng đang chờ.</p>'}</section>
    <details class="gate-policy-details"><summary>${icon('sliders-horizontal')}Policy và phạm vi đã ghi${icon('chevron-down')}</summary><dl class="gate-policy-grid">${policyRows.map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><div class="gate-coverage"><h4>${icon('scan-search')}Phạm vi bằng chứng</h4><p>${esc(coverageText)}</p>${units.length ? `<p><b class="mono">${predictedIds.size}/${units.length}</b> source unit có prediction được liên kết trong dữ liệu.</p>` : '<p>Chưa có danh sách source unit để kiểm tra độ bao phủ.</p>'}${issues.length ? `<ul>${issues.map(issue=>`<li><b>${esc(issue.source)}:</b> ${esc(issue.message)}</li>`).join('')}</ul>` : ''}</div></details>
    <section class="gate-supporting"><div class="gate-evidence-heading"><h3>${icon('chart-no-axes-combined')}Đối chiếu điểm và ngưỡng</h3><span>${scores.length ? `${Math.min(scores.length,6)} / ${scores.length} tín hiệu` : 'Chưa có tín hiệu'}</span></div><p class="gate-evidence-intro">Số liệu hỗ trợ kiểm tra bằng chứng. Chỉ lý do đã ghi ở trên xác nhận điều kiện nào được Gateway nêu trong quyết định.</p>${scores.length ? `<div class="gate-scores">${scores.slice(0,6).map(scoreRow).join('')}</div>${scores.length > 6 ? '<p class="gate-score-note">Ưu tiên tín hiệu đạt ngưỡng và gần ngưỡng; xuất JSON để xem toàn bộ.</p>' : ''}` : '<p class="gate-evidence-empty">Chưa có score theo unit hoặc metadata finding để đối chiếu. Không suy ra điểm 0 hay kết quả sạch.</p>'}<p class="gate-authority-note">${icon('lock-keyhole')}Điểm CodeBERT không tự cấp quyền deploy. Gateway Security Gate quyết định cuối; kết quả demo luôn giữ deploy vô hiệu.</p></section>
  </div>`;
}
