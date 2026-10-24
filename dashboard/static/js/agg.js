// Gom số liệu từ các lượt quét trong phạm vi đang chọn (không tạo số mới ngoài phép cộng/đếm).
export const PRIO = {P1:0, P2:1, P3:2, P4:3};
export const DEC = {BLOCK:0, REVIEW:1, PASS:2};

export function allUnits(runs) {
  return runs.flatMap(r => r.units.map(u => ({...u, run:r, key:`${r.id}|${u.id}`})));
}
export function flagged(runs) {
  return allUnits(runs).filter(u => u.decision === 'BLOCK' || u.decision === 'REVIEW')
    .sort((a, b) => (DEC[a.decision] - DEC[b.decision]) || ((b.priority?.score ?? 0) - (a.priority?.score ?? 0))
      || a.run.id.localeCompare(b.run.id) || a.id.localeCompare(b.id));
}
export function decisionCounts(runs) {
  const c = {BLOCK:0, REVIEW:0, PASS:0};
  runs.forEach(r => Object.entries(r.summary?.decisions || {}).forEach(([k, v]) => { c[k] = (c[k] || 0) + v; }));
  return c;
}
export function stateCounts(runs) {
  const c = {agree:0, sast_only:0, codebert_only:0, conflict:0, pass:0};
  runs.forEach(r => Object.entries(r.summary?.compare_states || {}).forEach(([k, v]) => { c[k] = (c[k] || 0) + v; }));
  return c;
}
// Cộng bảng 09_eval_targets.py của các lượt có ground truth (như 26_targets_summary.py).
export function methodTotals(runs) {
  const tot = {};
  runs.filter(r => r.eval).forEach(r => r.eval.methods.forEach(m => {
    const t = tot[m.method] ||= {method:m.method, tp:0, gt:0, pred:0, vuln_units_flagged:0, vuln_units:0, flagged_safe:0, safe:0, runs:0};
    t.tp += m.tp; t.gt += m.gt; t.pred += m.n_predictions || 0; t.vuln_units_flagged += m.vuln_units_flagged;
    t.vuln_units += m.vuln_units || 0; t.flagged_safe += m.flagged_safe || 0; t.safe += m.safe || 0; t.runs += 1;
  }));
  return tot;
}
export const unitLang = u => u.language || (/\.py$/.test(u.file) ? 'Python' : /\.java$/.test(u.file) ? 'Java'
  : /\.(js|ts|jsx|tsx)$/.test(u.file) ? 'JavaScript' : /\.php$/.test(u.file) ? 'PHP' : 'Khác');
// Lý do Gate theo đúng chính sách của lượt quét (compare_gate.decide).
export function gateReason(u, run) {
  const policy = run.config?.policy || {};
  const strongest = (u.findings || []).filter(f => (f.classes || []).includes(u.vuln_class))
    .some(f => f.confidence === 'high') ? 'high' : 'audit';
  const st = u.compare_state;
  if (st === 'pass') return {rule:'pass', text:'Không có finding Semgrep thuộc 6 lớp và verifier không vượt ngưỡng.'};
  if (run.mode === 'degraded_sast_only') return {rule:`degraded_sast_only.${strongest}`, text:`Luồng CodeBERT lỗi; chỉ còn Semgrep, finding mạnh nhất tầng ${strongest}.`};
  if (run.mode === 'degraded_codebert_only') return {rule:'degraded_codebert_only', text:'Luồng Semgrep lỗi; chỉ còn CodeBERT nên tối đa REVIEW.'};
  const rule = policy[st];
  const key = typeof rule === 'object' && rule ? `${st}.${strongest}` : st;
  const texts = {
    agree:'Semgrep và CodeBERT cùng báo một lớp: hai bằng chứng độc lập trùng nhau.',
    sast_only:`Chỉ Semgrep báo; finding mạnh nhất của lớp này ở tầng ${strongest}.`,
    codebert_only:'Chỉ CodeBERT báo (verifier vượt ngưỡng), không có finding Semgrep: cần người xem.',
    conflict:'Hai luồng báo hai lớp khác nhau: chưa thống nhất nên cần người xem.',
  };
  return {rule:key, text:texts[st] || st};
}
