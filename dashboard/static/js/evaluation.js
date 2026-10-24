import { esc, icon, int, num, pct, ratio, sec, badge, barCell, CLASS_LABEL, CLASS_SHORT, method, appName } from './ui.js';
import { groupedHBar, lineChart, heatmap, legend, tip } from './charts.js';
import { methodTotals } from './agg.js';

const TABS = [['model', 'CodeBERT 6 lớp', 'brain-circuit'], ['verifier', 'Verifier p_vulnerable', 'gauge'], ['gate', 'Security Gate (val)', 'shield-check'],
  ['targets', 'Ứng dụng mục tiêu', 'target'], ['rules', 'Ruleset Semgrep', 'scan-search'], ['c06', 'Trước / sau fine-tune', 'git-branch']];
const LANGS = ['Python', 'Java', 'JavaScript', 'PHP'];
const S1 = 'var(--s1)', S2 = 'var(--s2)', S3 = 'var(--s3)';
const card = (title, ic, desc, body, right='') => `<div class="card"><div class="card-head"><div><h2>${icon(ic)}${esc(title)}</h2>${desc ? `<p>${desc}</p>` : ''}</div>${right ? `<div class="right">${right}</div>` : ''}</div><div class="card-body">${body}</div></div>`;
const stat = (label, value, note='') => `<div class="card stat"><div class="s-label">${esc(label)}</div><div class="s-value">${value}</div>${note ? `<div class="s-note">${note}</div>` : ''}</div>`;
const src = f => f ? `<span class="badge b-outline mono">${esc(f)}</span>` : '';
const missing = what => `<div class="card empty">${icon('file-question')}<strong>Chưa có ${esc(what)}</strong>Chạy script tương ứng rồi bấm Làm mới.</div>`;

function modelTab(ev) {
  const m = ev.model, j = ev.j01;
  if (!m) return missing('run_info.json của mô hình');
  const labels = m.labels;
  const cm = m.val.confusion_matrix || [];
  const rowsum = cm.map(r => r.reduce((a, b) => a + b, 0));
  const cmHtml = heatmap(labels.map((l, i) => ({label:CLASS_LABEL[l] || l, i})), labels.map((l, k) => ({label:CLASS_SHORT[l] || l, k})),
    (r, c) => { const v = cm[r.i]?.[c.k] ?? 0, t = rowsum[r.i] ? v / rowsum[r.i] : 0;
      return {t, text:int(v), sub:pct(t, 0), tip:tip(`Nhãn ${CLASS_LABEL[labels[r.i]]}`, [['', `Dự đoán ${CLASS_LABEL[labels[c.k]]}`, `${v} mẫu (${pct(t)} hàng)`]])}; },
    {rowW:'170px', corner:'Nhãn ↓ / Dự đoán →'});
  const langRows = LANGS.filter(l => m.val.by_language[l]).map(l => `<tr><td class="strong">${l}</td><td class="num">${int(m.val.by_language[l].n)}</td>
    <td style="min-width:200px">${barCell(m.val.by_language[l].macro_f1, 1, S1, num(m.val.by_language[l].macro_f1, 3))}</td>
    <td style="min-width:160px">${j?.classification?.[l] ? barCell(j.classification[l].codebert_acc, 1, S3, pct(j.classification[l].codebert_acc)) : '—'}</td></tr>`).join('');
  const cells = j?.cells || {};
  const cellHtml = heatmap(LANGS.map(l => ({label:l, l})), labels.map(c => ({label:CLASS_SHORT[c] || c, c})), (r, c) => {
    const x = cells[`${r.l}|${c.c}`];
    if (!x || !x.n) return null;
    return {t:x.codebert_acc, text:pct(x.codebert_acc, 0), sub:`n=${x.n}`, tip:tip(`${r.l} · ${CLASS_LABEL[c.c]}`, [[S3, 'CodeBERT accuracy', pct(x.codebert_acc)], [S2, 'Semgrep recall', pct(x.sast?.recall)], [S1, 'Gate recall', pct(x.gate?.recall)], ['', 'Số mẫu', int(x.n)]])};
  }, {rowW:'110px', corner:'Ngôn ngữ × lớp'});
  const curve = m.curve || [];
  const best = Math.max(...curve.map(p => p.value));
  const c01 = ev.c01 || [];
  const grid = {};
  c01.forEach(r => { const k = `${r.lr}|${r.class_weight}`; (grid[k] ||= []).push(r.val_macro_f1); });
  const gridRows = Object.entries(grid).map(([k, v]) => { const [lr, cw] = k.split('|'); const mean = v.reduce((a, b) => a + b, 0) / v.length;
    const sd = v.length > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (v.length - 1)) : null; return {lr, cw, mean, sd, n:v.length}; })
    .sort((a, b) => b.mean - a.mean);
  return `<div class="grid g4">
    ${stat('Macro-F1 (val, 4 ngôn ngữ)', num(m.val.macro_f1, 3), j?.macro_f1_ci ? `KTC 95% bootstrap ${num(j.macro_f1_ci[0], 3)}–${num(j.macro_f1_ci[1], 3)}` : '')}
    ${stat('Accuracy (val)', pct(m.val.accuracy), `${int(m.n_val)} mẫu val, ${int(m.n_train)} mẫu train`)}
    ${stat('Hàm bị cắt ở ' + int(m.max_len) + ' token', pct(m.val.truncated_rate, 0), 'Phần sau token 512 không được mô hình nhìn thấy (E07 xử lý hàm dài)')}
    ${stat('Huấn luyện', sec(m.train_seconds), `${esc(m.base_model)} · lr ${esc(m.lr)} · trọng số lớp ${esc(m.class_weight_mode)} · ${esc(m.device)}`)}
  </div>
  <div class="grid g2 space">
    ${card('Theo ngôn ngữ', 'languages', 'Macro-F1 từ run_info của mô hình; accuracy từ 22_j01_eval.py trên cùng 716 mẫu val.', `<div class="table-wrap"><table class="t"><thead><tr><th>Ngôn ngữ</th><th class="num">Mẫu</th><th>Macro-F1</th><th>Accuracy</th></tr></thead><tbody>${langRows}</tbody></table></div>`, src(m.dir))}
    ${card('Đường học (macro-F1 trên val theo epoch)', 'trending-up', `Early stopping theo macro-F1 val; tốt nhất ${num(best, 3)}.`, curve.length ? lineChart(curve.map(p => p.epoch), [{name:'macro-F1 val', color:S1, values:curve.map(p => p.value)}], {xLabel:'epoch', xFmt:v => num(v, 0), valueFmt:v => num(v, 3), yFmt:v => num(v, 2), height:230}) : '<p class="muted">Không có log_history.</p>')}
  </div>
  <div class="grid g2 space">
    ${card('Ma trận nhầm lẫn (val)', 'grid-3x3', 'Mỗi hàng là nhãn thật; màu theo tỉ lệ trong hàng. Ô ngoài đường chéo cho thấy cặp lớp hay nhầm.', cmHtml)}
    ${card('Accuracy theo ngôn ngữ × lớp', 'table-2', 'Ô “—” là chưa có mẫu thật. Rê chuột để so với Semgrep và Gate trên cùng ô.', cellHtml, j ? src(j.file) : '')}
  </div>
  ${gridRows.length ? `<div class="space">${card('Chọn siêu tham số (C01)', 'sliders-horizontal', 'Lưới chạy trên val Python 62 mẫu; cấu hình chọn (≥ 3 seed) được dùng lại cho C03 4 ngôn ngữ. Đây là hạn chế cần ghi trong báo cáo.',
    `<div class="table-wrap"><table class="t"><thead><tr><th>lr</th><th>Trọng số lớp</th><th class="num">Số seed</th><th>Macro-F1 val (TB)</th><th class="num">Độ lệch chuẩn</th></tr></thead><tbody>${gridRows.map((r, i) => `<tr${i === 0 ? ' class="hl"' : ''}><td class="mono">${esc(r.lr)}</td><td>${esc(r.cw)}</td><td class="num">${r.n}</td><td style="min-width:200px">${barCell(r.mean, 1, S1, num(r.mean, 3))}</td><td class="num">${r.sd == null ? '—' : num(r.sd, 3)}</td></tr>`).join('')}</tbody></table></div>`, src('reports/c01_grid.csv'))}</div>` : ''}`;
}

function verifierTab(ev) {
  const v = ev.verifier;
  if (!v) return missing('verifier');
  const bl = v.val?.by_language || {};
  return `<div class="grid g4">
    ${stat('ROC-AUC (val)', num(v.val?.roc_auc, 3), 'Phân biệt code có lỗ hổng với code sau vá')}
    ${stat('Đúng thứ tự cặp', pct(v.val?.pairwise_acc), `${int(v.val?.n_pairs)} cặp: p(trước vá) > p(sau vá)`)}
    ${stat('Dữ liệu train', int(v.n_train_rows), `hàng (cặp trước/sau vá 4 ngôn ngữ) · ${esc(v.epochs)} epoch`)}
    ${stat('Khởi tạo từ', esc((v.init || '').split('/').pop()), `Thời gian train ${sec(v.train_seconds)}`)}
  </div>
  <div class="grid g2 space">
    ${card('Theo ngôn ngữ', 'languages', 'Code sau vá là nhãn xấp xỉ “đã sửa”, không phải an toàn tuyệt đối.', `<div class="table-wrap"><table class="t"><thead><tr><th>Ngôn ngữ</th><th class="num">Cặp</th><th>ROC-AUC</th><th>Đúng thứ tự cặp</th></tr></thead><tbody>${LANGS.filter(l => bl[l]).map(l => `<tr><td class="strong">${l}</td><td class="num">${int(bl[l].n_pairs)}</td><td style="min-width:170px">${barCell(bl[l].roc_auc, 1, S1, num(bl[l].roc_auc, 3))}</td><td style="min-width:170px">${barCell(bl[l].pairwise_acc, 1, S3, pct(bl[l].pairwise_acc))}</td></tr>`).join('')}</tbody></table></div>`, src(v.dir))}
    ${card('Đường học (ROC-AUC val theo epoch)', 'trending-up', '', (v.curve || []).length ? lineChart(v.curve.map(p => p.epoch), [{name:'ROC-AUC', color:S1, values:v.curve.map(p => p.value)}], {xLabel:'epoch', xFmt:x => num(x, 0), valueFmt:x => num(x, 3), yFmt:x => num(x, 2), height:230}) : '<p class="muted">Không có log_history.</p>')}
  </div>`;
}

function gateTab(ev) {
  const g = ev.gate;
  if (!g) return missing('gate_eval_val_*.json');
  const cfgT = g.config_threshold ?? g.threshold, ac = g.at_config || g.at_threshold || {}, as = g.at_threshold || {};
  const differ = g.threshold != null && cfgT != null && Math.abs(g.threshold - cfgT) > 1e-9;
  const cats = g.comparison.map(c => c.name);
  const chart = groupedHBar(cats, [{name:'Code có lỗ hổng', color:S1, values:g.comparison.map(c => c.all?.flag_vuln)}, {name:'Code sau vá', color:S2, values:g.comparison.map(c => c.all?.flag_patched)}], {labelWidth:170});
  const langRows = g.comparison.map(c => `<tr${/Gate BLOCK$/.test(c.name) ? ' class="hl"' : ''}><td class="strong">${esc(c.name)}</td>${LANGS.map(l => `<td class="num">${c[l] ? `${pct(c[l].flag_vuln, 0)} / ${pct(c[l].flag_patched, 0)}` : '—'}</td>`).join('')}<td class="num">${c.all ? num(c.all.flag_vuln - c.all.flag_patched, 3) : '—'}</td></tr>`).join('');
  const sw = g.sweep;
  const first = g.comparison[0]?.all, ai = g.comparison.find(c => c.name.startsWith('AI'))?.all;
  const sastGap = first ? first.flag_vuln - first.flag_patched : null;
  return `<div class="notice" style="margin-bottom:16px">${icon('info')}<span>Đo trên <b>${int(g.n_vulnerable)}</b> hàm có lỗ hổng và <b>${int(g.n_patched)}</b> hàm sau vá của tập val (cặp trước/sau vá, 4 ngôn ngữ). Tỉ lệ cảnh báo trên code sau vá là cận trên của báo nhầm vì code sau vá là nhãn xấp xỉ. Tập test chưa dùng.</span></div>
  ${differ ? `<div class="notice warn" style="margin-bottom:16px">${icon('scale')}<span>Lần chạy <code>${esc(g.file)}</code> chọn lại ngưỡng J lớn nhất là <b>${num(g.threshold, 3)}</b> (J ${num(as.J, 3)}), gần bằng J tại ngưỡng đang dùng <b>${num(cfgT, 3)}</b> (${num(ac.J, 3)}). Cấu hình giữ ${num(cfgT, 3)} theo <code>models/gate_config.json</code>. Các ô số bên dưới tính tại ${num(cfgT, 3)}; riêng biểu đồ so sánh và bảng theo ngôn ngữ là số của script tại ${num(g.threshold, 3)}.</span></div>` : ''}
  <div class="grid g4">
    ${stat('Ngưỡng verifier đang dùng', num(cfgT, 3), differ ? `script chọn lại ${num(g.threshold, 3)} trên ruleset mới; nhóm giữ ${num(cfgT, 3)}` : 'J lớn nhất trên val (không chỉnh theo ứng dụng mục tiêu)')}
    ${stat('Gate BLOCK', `${pct(ac.block_vuln)} <small style="font-size:14px;color:var(--muted)">/ ${pct(ac.block_patched)}</small>`, 'trên code có lỗ hổng / sau vá')}
    ${stat('Gate BLOCK + REVIEW', `${pct(ac.flag_vuln)} <small style="font-size:14px;color:var(--muted)">/ ${pct(ac.flag_patched)}</small>`, `J = ${num(ac.J, 3)}`)}
    ${stat('Gọi đúng lớp khi cảnh báo', pct(as.class_correct_when_flagged), `${differ ? `tại ${num(g.threshold, 3)}. ` : ''}Trước vá bị xử nặng hơn sau vá ở ${pct(as.pairwise?.before_higher)} cặp`)}
  </div>
  <div class="grid g-2-1 space">
    ${card(`Semgrep đơn lẻ so với Semgrep + AI${differ ? ` (ngưỡng ${num(g.threshold, 3)})` : ''}`, 'bar-chart-3', 'Tỉ lệ bị cảnh báo. Thanh xanh dài = bắt được nhiều; thanh cam ngắn = ít báo trên code đã vá.', chart + legend([[S1, 'Code có lỗ hổng'], [S2, 'Code sau vá']]), src(g.file))}
    ${card('Đọc nhanh', 'lightbulb', '', `<ul style="margin:0;padding-left:18px;line-height:1.8;color:var(--text-2)">
      <li>Semgrep (mọi finding): ${pct(first?.flag_vuln)} trên code có lỗ hổng so với ${pct(first?.flag_patched)} trên code sau vá — chênh ${num(sastGap, 3)}${sastGap != null && sastGap < 0.05 ? ', gần như không phân biệt trước/sau vá' : ''}.</li>
      <li>Verifier CodeBERT đơn lẻ: ${pct(ai?.flag_vuln)} so với ${pct(ai?.flag_patched)} (chênh ${num(ai ? ai.flag_vuln - ai.flag_patched : null, 3)}).</li>
      <li>Gate chỉ BLOCK khi có bằng chứng mạnh (${pct(ac.block_patched)} code sau vá bị chặn); phần còn lại chuyển REVIEW cho người xem.</li></ul>`)}
  </div>
  <div class="space">${card('Quét ngưỡng verifier', 'chart-spline', 'Mỗi điểm là một ngưỡng p_vulnerable; vạch tím là ngưỡng đang dùng. Rê chuột để xem số.', lineChart(sw.map(s => s.threshold), [
      {name:'Cảnh báo, có lỗ hổng', color:S1, values:sw.map(s => s.flag_vuln)}, {name:'Cảnh báo, sau vá', color:S2, values:sw.map(s => s.flag_patched)}, {name:'J', color:S3, values:sw.map(s => s.J), fmt:v => num(v, 3)}],
      {xLabel:'ngưỡng', marker:{x:cfgT, label:`đang dùng ${num(cfgT, 3)}`}, width:1100, height:300}) + legend([[S1, 'BLOCK + REVIEW trên code có lỗ hổng'], [S2, 'BLOCK + REVIEW trên code sau vá'], [S3, 'J = chênh lệch hai đường']]))}</div>
  <div class="space">${card(`Theo ngôn ngữ (có lỗ hổng / sau vá)${differ ? ` · ngưỡng ${num(g.threshold, 3)}` : ''}`, 'languages', '', `<div class="table-wrap"><table class="t"><thead><tr><th>Cấu hình</th>${LANGS.map(l => `<th class="num">${l}</th>`).join('')}<th class="num">J (tất cả)</th></tr></thead><tbody>${langRows}</tbody></table></div>`)}</div>`;
}

function targetsTab(data, state) {
  const configs = data.configs.filter(c => (c.targets_summary || []).length);
  if (!configs.length) return missing('kết quả 09_eval_targets.py');
  const cfg = configs.find(c => c.id === state.config) || configs[0];
  const runs = data.runs.filter(r => r.config_id === cfg.id && r.eval && !r.superseded);
  const tot = methodTotals(runs);
  const ms = Object.values(tot);
  const chart = groupedHBar(ms.map(m => method(m.method)), [{name:'Lỗ hổng phát hiện đúng lớp', color:S1, values:ms.map(m => m.gt ? m.tp / m.gt : null)}, {name:'Hàm an toàn bị cảnh báo', color:S2, values:ms.map(m => m.safe ? m.flagged_safe / m.safe : null)}], {labelWidth:190});
  const appRows = ms.map(m => `<tr${m.method === 'Gate_BLOCK' ? ' class="hl"' : ''}><td class="strong">${esc(method(m.method))}</td>${runs.map(r => { const x = r.eval.methods.find(y => y.method === m.method); return `<td class="num">${x ? `${x.tp}/${x.gt}` : '—'}<span class="sub">${x ? `${x.flagged_safe}/${x.safe} an toàn` : ''}</span></td>`; }).join('')}</tr>`).join('');
  const evo = configs.map(c => ({c, m:Object.fromEntries(c.targets_summary.map(x => [x.method, x]))}));
  return `<div class="notice" style="margin-bottom:16px">${icon('info')}<span>4 ứng dụng mục tiêu (Flask Vuln App, DVWA, WebGoat, Juice Shop) có ground truth viết tay, <b>không</b> dùng để train hay chỉnh rule. Ngưỡng verifier giữ nguyên giá trị chọn trên val. CodeBERT 6 lớp không có lớp “an toàn” nên khi đứng một mình nó cảnh báo mọi hàm.</span></div>
  <div class="grid g2">
    ${card(`Tổng 4 ứng dụng · ${cfg.label}`, 'target', `Đổi cấu hình ở ô “Cấu hình pipeline” phía trên để xem cấu hình khác.`, chart + legend([[S1, 'Lỗ hổng phát hiện đúng lớp (recall)'], [S2, 'Hàm an toàn bị cảnh báo']]))}
    ${card('Bảng số', 'table', '', `<div class="table-wrap"><table class="t"><thead><tr><th>Phương pháp</th><th class="num">Đúng lớp</th><th class="num">An toàn bị báo</th><th class="num">Precision</th></tr></thead><tbody>${ms.map(m => `<tr${m.method === 'Gate_BLOCK' ? ' class="hl"' : ''}><td class="strong">${esc(method(m.method))}</td><td class="num">${ratio(m.tp, m.gt)}</td><td class="num">${ratio(m.flagged_safe, m.safe)}</td><td class="num">${m.pred ? num(m.tp / m.pred, 2) : '—'}</td></tr>`).join('')}</tbody></table></div>`)}
  </div>
  <div class="space">${card('Theo ứng dụng (đúng lớp · hàm an toàn bị cảnh báo)', 'layout-list', 'DVWA, WebGoat, Juice Shop có ground truth mức file nên được đếm theo file.', `<div class="table-wrap"><table class="t"><thead><tr><th>Phương pháp</th>${runs.map(r => `<th class="num">${esc(appName(data, r))}</th>`).join('')}</tr></thead><tbody>${appRows}</tbody></table></div>`)}</div>
  <div class="space">${card('Tiến trình các cấu hình', 'history', 'Cùng 4 ứng dụng, cùng ground truth; mỗi hàng là một cấu hình đã chạy.', `<div class="table-wrap"><table class="t"><thead><tr><th>Cấu hình</th><th class="num">Semgrep đúng lớp</th><th class="num">Semgrep báo nhầm</th><th class="num">Gate BLOCK đúng lớp</th><th class="num">Gate BLOCK chặn nhầm</th><th class="num">BLOCK + REVIEW đúng lớp</th></tr></thead><tbody>${evo.map(({c, m}) => `<tr${c.current ? ' class="hl"' : ''}><td><span class="strong">${c.current ? '★ ' : ''}${esc(c.label)}</span></td><td class="num">${m.SAST_B ? ratio(m.SAST_B.tp, m.SAST_B.gt) : '—'}</td><td class="num">${m.SAST_B ? ratio(m.SAST_B.flagged_safe, m.SAST_B.safe) : '—'}</td><td class="num">${m.Gate_BLOCK ? ratio(m.Gate_BLOCK.tp, m.Gate_BLOCK.gt) : '—'}</td><td class="num">${m.Gate_BLOCK ? ratio(m.Gate_BLOCK.flagged_safe, m.Gate_BLOCK.safe) : '—'}</td><td class="num">${m.Gate_BLOCK_or_REVIEW ? ratio(m.Gate_BLOCK_or_REVIEW.tp, m.Gate_BLOCK_or_REVIEW.gt) : '—'}</td></tr>`).join('')}</tbody></table></div>`)}</div>`;
}

function rulesTab(ev, data) {
  const r = ev.rules;
  if (!r) return missing('rule_metrics_v*_val.json');
  const vs = Object.keys(r.cells);
  const cur = vs[vs.length - 1], prev = vs.length > 1 ? vs[0] : null;
  const cells = r.cells[cur] || {}, pcells = prev ? r.cells[prev] || {} : {};
  const classes = data.project.classes;
  const mk = key => heatmap(LANGS.map(l => ({label:l, l})), classes.map(c => ({label:CLASS_SHORT[c], c})), (row, col) => {
    const x = cells[`${row.l}|${col.c}`];
    if (!x || !x.n) return null;
    const v = x[key] / x.n, p = pcells[`${row.l}|${col.c}`];
    const pv = p && p.n ? p[key] / p.n : null;
    return {t:v, text:pct(v, 0), sub:`${x[key]}/${x.n}`, tip:tip(`${row.l} · ${CLASS_LABEL[col.c]}`, [[S2, `Semgrep ${cur}`, `${x[key]}/${x.n} (${pct(v)})`], ...(pv != null ? [['', `Semgrep ${prev}`, pct(pv)]] : [])])};
  }, {rowW:'110px', corner:'Ngôn ngữ × lớp'});
  const n = data.project.ruleset;
  return `<div class="grid g3">
    ${stat('Ruleset đang dùng', `v${esc(n.version)}`, `${int(n.n_rules)} rule trong security-config/semgrep/semgrep.yml`)}
    ${stat('Công cụ SAST', 'Semgrep CE', 'Bandit đã bỏ khỏi luồng chính (quyết định nhóm 21/10)')}
    ${stat('Bộ so sánh', esc(prev ? `${prev} → ${cur}` : cur), `${esc(r.file)} (tập val, mẫu có lỗ hổng)`)}
  </div>
  <div class="grid g2 space">
    ${card(`Semgrep báo đúng lớp (mọi tầng) · ${cur}`, 'scan-search', 'Tỉ lệ mẫu có lỗ hổng trong val có ít nhất một finding đúng lớp. Rê chuột để so với bản trước.', mk('any'))}
    ${card(`Chỉ tầng high · ${cur}`, 'flame', 'Tầng high là finding đủ mạnh để Gate BLOCK một mình.', mk('high'))}
  </div>`;
}

const ciText = (ci, what) => !ci ? '' : ci[0] > 0 ? `${what}: KTC 95% nằm hẳn trên 0, khác biệt có ý nghĩa.` : ci[1] < 0 ? `${what}: KTC 95% nằm hẳn dưới 0, thấp hơn có ý nghĩa.` : `${what}: KTC 95% chứa 0, chưa đủ bằng chứng là khác nhau.`;
function c06Tab(ev) {
  const c = ev.c06;
  if (!c) return missing('pretrain_vs_finetune_<model>_val.json (C06)');
  const order = [['random_head', 'CodeBERT gốc + đầu ngẫu nhiên'], ['tfidf_lr', 'TF-IDF + Logistic Regression'], ['linear_probe', 'CodeBERT gốc đóng băng + LR'], ['finetuned', 'CodeBERT fine-tune (C03)']].filter(([k]) => c.results[k]);
  const chart = groupedHBar(order.map(([, n]) => n), [{name:'Macro-F1', color:S1, values:order.map(([k]) => c.results[k].macro_f1)}], {labelWidth:210, barH:14, ci:[order.map(([k]) => c.results[k].macro_f1_ci95)], fmt:v => num(v, 3)});
  const d = c.diff_ci95 || {};
  return `<div class="grid g-2-1">
    ${card('Fine-tune mang lại bao nhiêu', 'git-branch', `Cùng ${int(c.n_eval)} mẫu val, cùng tiền xử lý. Vạch trắng là khoảng tin cậy 95% bootstrap.`, chart, src(c.file))}
    ${card('Kết luận có kiểm định', 'sigma', '', `<div class="kv">
      <div><span>Fine-tune − linear probe</span><strong>${d.finetuned_minus_linear_probe ? `+${num(d.finetuned_minus_linear_probe[0], 3)} … +${num(d.finetuned_minus_linear_probe[1], 3)}` : '—'}</strong></div>
      <div><span>Linear probe − TF-IDF</span><strong>${d.linear_probe_minus_tfidf ? `${num(d.linear_probe_minus_tfidf[0], 3)} … ${num(d.linear_probe_minus_tfidf[1], 3)}` : '—'}</strong></div>
      <div><span>Silhouette [CLS] trước → sau</span><strong>${num(c.silhouette?.before_cls, 2)} → ${num(c.silhouette?.after_cls, 2)}</strong></div></div>
      <p class="muted space" style="line-height:1.7">${ciText(d.finetuned_minus_linear_probe, 'Fine-tune so với linear probe')} ${ciText(d.linear_probe_minus_tfidf, 'Linear probe (CodeBERT gốc không fine-tune) so với TF-IDF')}</p>`)}
  </div>
  <div class="grid g2 space">
    ${card('Theo ngôn ngữ (macro-F1)', 'languages', '', `<div class="table-wrap"><table class="t"><thead><tr><th>Phương pháp</th>${LANGS.map(l => `<th class="num">${l}</th>`).join('')}</tr></thead><tbody>${order.map(([k, n]) => `<tr${k === 'finetuned' ? ' class="hl"' : ''}><td class="strong">${esc(n)}</td>${LANGS.map(l => `<td class="num">${num(c.results[k].per_language_macro_f1?.[l], 3)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`)}
    ${c.tsne ? card('t-SNE vector [CLS] trước và sau fine-tune', 'scatter-chart', 'Ảnh do 29_pretrain_vs_finetune.py vẽ.', `<img class="fig" src="/api/figure?path=${encodeURIComponent(c.tsne)}" alt="t-SNE vector CLS trước và sau fine-tune" loading="lazy">`) : ''}
  </div>`;
}

export function renderEvaluation(data, state) {
  const ev = data.evaluation;
  const tab = TABS.some(([id]) => id === state.tab) ? state.tab : 'model';
  const body = {model:() => modelTab(ev), verifier:() => verifierTab(ev), gate:() => gateTab(ev), targets:() => targetsTab(data, state), rules:() => rulesTab(ev, data), c06:() => c06Tab(ev)}[tab]();
  return `<div class="page-head"><div><h1 class="page-title">Đánh giá mô hình</h1>
      <p class="page-desc">Số liệu thực nghiệm trên tập val và 4 ứng dụng mục tiêu, đọc từ run_info và báo cáo trong <code>reports/</code>. Tập test được giữ cho lần chạy J01 cuối (chỉ một lần).</p></div>
    <div class="actions">${badge('Chưa dùng tập test', 'b-accent', 'lock')}</div></div>
  <div class="tabs" role="tablist">${TABS.map(([id, label, ic]) => `<button role="tab" aria-selected="${id === tab}" class="${id === tab ? 'active' : ''}" data-action="set" data-replace="1" data-patch="${esc(JSON.stringify({tab:id}))}">${icon(ic)}${label}</button>`).join('')}</div>
  ${body}`;
}
