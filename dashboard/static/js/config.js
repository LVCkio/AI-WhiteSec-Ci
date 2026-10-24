// Màn hình "Cấu hình & Rule": phiên bản, kiểm thử, ngưỡng, chính sách Gate, toàn bộ rule Semgrep của nhóm,
// tiêu chí chọn rule, dữ liệu và ground truth. Chỉ đọc data.config_info (dashboard/project_info.py).
import { esc, icon, int, num, pct, fmtDate, badge, decisionBadge, CLASS_LABEL, CLASS_SHORT, tierBadge } from './ui.js';
import { heatmap, tip } from './charts.js';

const TABS = [['versions', 'Phiên bản & kiểm thử', 'tags'], ['thresholds', 'Ngưỡng & chính sách', 'sliders-horizontal'],
  ['rules', 'Rule Semgrep', 'scroll-text'], ['criteria', 'Tiêu chí chọn rule', 'list-checks'], ['data', 'Dữ liệu & ground truth', 'database']];
const LANGS = ['Python', 'Java', 'JavaScript', 'PHP'];
const LANG_OF = {python:'Python', java:'Java', javascript:'JavaScript', js:'JavaScript', typescript:'JavaScript', php:'PHP', regex:'regex'};
const patch = o => esc(JSON.stringify(o));
const md = s => esc(s).replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`([^`]+)`/g, '<code>$1</code>');
const card = (title, ic, body, desc='', right='') => `<div class="card"><div class="card-head"><div><h2>${icon(ic)}${esc(title)}</h2>${desc ? `<p>${desc}</p>` : ''}</div>${right ? `<div class="right">${right}</div>` : ''}</div><div class="card-body">${body}</div></div>`;
const kv = items => `<div class="kv">${items.filter(Boolean).map(([k, v, mono]) => `<div><span>${esc(k)}</span><strong class="${mono ? 'mono' : ''}"${mono ? ` title="${esc(v)}"` : ''}>${mono && String(v).length > 20 ? esc(String(v).slice(0, 16)) + '…' : esc(v ?? '—')}</strong></div>`).join('')}</div>`;
const sha = v => v ? `<span class="mono" title="${esc(v)}">${esc(v.slice(0, 12))}…</span>` : '—';
const ruleLang = r => [...new Set((r.languages || []).map(l => LANG_OF[String(l).toLowerCase()] || l))].join(', ');
const ruleLangKey = r => { const l = (r.languages || []).map(x => LANG_OF[String(x).toLowerCase()] || x); return l.includes('regex') ? (r.id.includes('.php.') ? 'PHP' : 'regex') : l[0]; };
const kind = r => r.regex ? 'regex' : r.mode === 'taint' ? 'taint' : 'pattern';

function versionsTab(ci) {
  const v = ci.versions, rs = v.ruleset, m = v.model, ds = v.dataset, rt = v.rule_tests, ut = v.unit_tests;
  const status = s => s === 'used' ? badge('đã dùng cho J01', 'b-review', 'lock-open') : s === 'frozen' ? badge('đóng băng, chưa dùng', 'b-pass', 'lock') : badge('đã dựng, chưa đánh giá', 'b-info', 'package-check');
  return `<div class="grid g4">
    <div class="card stat"><div class="s-label">Công cụ</div><div class="s-value">v${esc(v.tool.version || '—')}</div><div class="s-note">${esc(v.tool.name)} · kiến trúc ${esc(v.gate.architecture || '')}</div></div>
    <div class="card stat"><div class="s-label">Ruleset Semgrep</div><div class="s-value">v${esc(rs.version || '—')}</div><div class="s-note">${int(rs.n_rules)} rule đang dùng · ${int(rs.n_disabled)} rule đã tắt · Semgrep ${esc(rs.semgrep_pinned || '')}</div></div>
    <div class="card stat"><div class="s-label">Test rule (positive + negative)</div><div class="s-value">${int(rt.passed)}/${int(rt.total)}</div><div class="s-note">${int(rt.positive)} ca phải báo · ${int(rt.negative)} ca không được báo · ${rs.regression_passed ? 'regression đạt' : 'regression CHƯA đạt'}</div></div>
    <div class="card stat"><div class="s-label">Unit test pipeline</div><div class="s-value">${ut ? `${int(ut.ran)} ${ut.ok ? '✓' : '✗'}` : '—'}</div><div class="s-note">${ut ? `${ut.ok ? 'tất cả đạt' : `lỗi: ${esc(ut.failed || '')}`} · lần chạy ${fmtDate(ut.time)}` : 'chưa có reports/unittest_log.txt (chạy run_tests.bat)'}</div></div>
  </div>
  <div class="card space"><div class="card-head"><div><h2>${icon('flask-conical')}Phiên bản các tập test</h2><p>Tập test chỉ dùng một lần ở bước đánh giá cuối; mọi lựa chọn cấu hình, ngưỡng và rule đều làm trên train/val.</p></div></div>
    <div class="card-body table-wrap"><table class="t"><thead><tr><th>Tập test</th><th>Phiên bản</th><th class="num">Số mẫu</th><th>SHA-256</th><th>Ngày tạo</th><th>Trạng thái</th></tr></thead><tbody>
    ${v.test_sets.map(t => `<tr><td><span class="strong">${esc(t.name)}</span><span class="sub">${esc(t.note || '')}</span></td><td class="mono">${esc(t.version || '—')}</td><td class="num">${int(t.n)}</td><td>${sha(t.sha256)}</td><td>${esc(t.created || '—')}</td><td>${status(t.status)}</td></tr>`).join('')}
    <tr><td><span class="strong">Bộ test của ruleset Semgrep</span><span class="sub">tests/positive (ruleid:) và tests/negative (ok:) cho từng rule; khóa cùng manifest.</span></td><td class="mono">v${esc(rs.version)}</td><td class="num">${int(rt.total)}</td><td>${sha(rs.sha256)}</td><td>${fmtDate(rt.time)}</td><td>${rs.regression_passed ? badge(`${rt.passed}/${rt.total} đạt`, 'b-pass', 'circle-check') : badge('chưa đạt', 'b-block')}</td></tr>
    ${ut ? `<tr><td><span class="strong">Unit test của pipeline</span><span class="sub">tests/ (scan.py, compare_gate.py, dữ liệu, dashboard)</span></td><td class="mono">${esc(ut.file)}</td><td class="num">${int(ut.ran)}</td><td>—</td><td>${fmtDate(ut.time)}</td><td>${ut.ok ? badge('tất cả đạt', 'b-pass', 'circle-check') : badge(`lỗi ${ut.failed || ''}`, 'b-block')}</td></tr>` : ''}
    </tbody></table></div></div>
  <div class="grid g2 space">
    ${card('Ruleset Semgrep', 'scan-search', kv([['Phiên bản', `v${rs.version}`], ['SHA-256 bundle', rs.sha256, true], ['Semgrep (ghim)', rs.semgrep_pinned], ['Tạo lúc', fmtDate(rs.generated_at)], ['Python khi kiểm tra', rs.python], ['Bản chụp registry', (rs.registry_snapshot || []).join(', ')]]), 'security-config/semgrep/ruleset-manifest.json')}
    ${card('Mô hình CodeBERT', 'brain-circuit', kv([['Thư mục', m.dir], ['Mô hình gốc', m.base], ['Dữ liệu train', m.data_version], ['SHA-256 train.csv', m.train_sha256, true], ['SHA-256 val.csv', m.val_sha256, true], ['Checkpoint tốt nhất', m.best_checkpoint], ['Seed / thiết bị', `${m.seed ?? '—'} / ${m.device ?? '—'}`], ['Thư viện', m.versions ? Object.entries(m.versions).map(([k, x]) => `${k} ${x}`).join(' · ') : '—']]), `${m.dir}/run_info.json`)}
    ${card('Verifier và Security Gate', 'shield-check', kv([['Verifier', v.verifier.dir], ['Ngưỡng p_vulnerable', num(v.verifier.threshold, 3)], ['Chọn ngày', v.verifier.selected], ['Gate config', `v${v.gate.version}`], ['Kiến trúc', v.gate.architecture]]), 'models/gate_config.json')}
    ${card('Phiên bản dữ liệu', 'database', kv([['Phiên bản', ds.version], ['Thư mục', ds.dir], ['Ngày tạo', ds.created], ['Train / val / test', ds.counts ? `${int(ds.counts.train)} / ${int(ds.counts.val)} / ${int(ds.counts.test)}` : '—'], ['Ánh xạ CWE', ds.cwe_map], ['Loại trùng', `${int(ds.exact_duplicates_dropped)} trùng hẳn · ${int(ds.near_duplicate_pairs)} cặp gần giống`], ['Tối đa / repo × ngôn ngữ × lớp', ds.max_per_repo_language_class]]), `${ds.dir || ''}/manifest.json`)}
  </div>`;
}

const POLICY_ROWS = [['agree', null, 'Hai luồng cùng báo một lớp'], ['sast_only', 'high', 'Chỉ Semgrep báo, finding tầng high'], ['sast_only', 'audit', 'Chỉ Semgrep báo, finding tầng audit'],
  ['codebert_only', null, 'Chỉ CodeBERT báo (verifier vượt ngưỡng)'], ['conflict', null, 'Hai luồng báo hai lớp khác nhau'], ['pass', null, 'Không luồng nào báo']];
function thresholdsTab(ci) {
  const p = ci.policy.policy || {}, d = ci.policy.degraded || {};
  const val = (rule, tier) => typeof rule === 'object' && rule ? rule[tier] : rule;
  return `${card('Các ngưỡng đang dùng', 'gauge', `<div class="table-wrap"><table class="t"><thead><tr><th>Ngưỡng</th><th>Giá trị</th><th>Cách chọn</th><th>Tác dụng</th></tr></thead><tbody>${ci.thresholds.map(t => `<tr><td><span class="strong">${esc(t.name)}</span><span class="sub mono">${esc(t.where)}</span></td><td class="nowrap"><b style="color:var(--text);font-size:14px">${esc(typeof t.value === 'number' ? num(t.value, 3) : t.value ?? '—')}</b> <span class="muted">${esc(t.unit)}</span></td><td style="white-space:normal;min-width:260px">${esc(t.how)}</td><td style="white-space:normal;min-width:200px">${esc(t.effect)}</td></tr>`).join('')}</tbody></table></div>`, 'Mọi ngưỡng được chọn trên tập train/val, không chỉnh theo 4 ứng dụng mục tiêu và không dùng tập test.')}
  <div class="grid g2 space">
    ${card('Chính sách Security Gate (song song đầy đủ)', 'shield-check', `<div class="table-wrap"><table class="t"><thead><tr><th>Trạng thái Compare</th><th>Điều kiện</th><th>Quyết định</th></tr></thead><tbody>${POLICY_ROWS.map(([st, tier, text]) => `<tr><td class="mono">${esc(st)}${tier ? `.${tier}` : ''}</td><td>${esc(text)}</td><td>${decisionBadge(val(p[st], tier))}</td></tr>`).join('')}</tbody></table></div>`, 'models/gate_config.json → policy. Kết luận cả lượt quét: có BLOCK thì BLOCK; có REVIEW thì REVIEW.')}
    ${card('Khi một luồng bị lỗi (chế độ suy giảm)', 'triangle-alert', `<div class="table-wrap"><table class="t"><thead><tr><th>Chế độ</th><th>Điều kiện</th><th>Quyết định</th></tr></thead><tbody>
      <tr><td class="mono">degraded_sast_only</td><td>CodeBERT lỗi, finding high</td><td>${decisionBadge(val(d.degraded_sast_only, 'high'))}</td></tr>
      <tr><td class="mono">degraded_sast_only</td><td>CodeBERT lỗi, finding audit</td><td>${decisionBadge(val(d.degraded_sast_only, 'audit'))}</td></tr>
      <tr><td class="mono">degraded_codebert_only</td><td>Semgrep lỗi, CodeBERT báo</td><td>${decisionBadge(val(d.degraded_codebert_only))}</td></tr></tbody></table></div>
      <p class="muted space" style="line-height:1.7">Ở chế độ suy giảm, kết luận của lượt quét tối thiểu là REVIEW (không bao giờ PASS) vì chỉ còn một nguồn bằng chứng.</p>`)}
  </div>`;
}

function filterRules(rules, s) {
  const q = (s.rq || '').trim().toLowerCase();
  return rules.filter(r => (s.rlang === 'all' || ruleLangKey(r) === s.rlang) && (s.rcls === 'all' || r.vuln_class === s.rcls)
    && (s.rtier === 'all' || r.confidence === s.rtier) && (s.rkind === 'all' || kind(r) === s.rkind)
    && (!q || `${r.id} ${r.message} ${r.cwe} ${r.scope}`.toLowerCase().includes(q)));
}
const sel = (bind, value, options, label) => `<label class="field"><span>${label}</span><select data-bind="${bind}">${options.map(([v, t]) => `<option value="${esc(v)}"${v === value ? ' selected' : ''}>${esc(t)}</option>`).join('')}</select></label>`;
const prec = m => m ? `${int(m.correct)}/${int(m.hits)}${m.hits ? ` (${pct(m.precision ?? m.correct / m.hits, 0)})` : ''}` : '—';
function rulesTab(ci, state) {
  const rules = ci.rules, shown = filterRules(rules, state);
  const counts = {};
  rules.forEach(r => { const k = `${ruleLangKey(r)}|${r.vuln_class}`; (counts[k] ||= {high:0, audit:0}); counts[k][r.confidence === 'high' ? 'high' : 'audit'] += 1; });
  const grid = heatmap(LANGS.map(l => ({label:l, l})), Object.keys(CLASS_LABEL).map(c => ({label:CLASS_SHORT[c], c})), (row, col) => {
    const x = counts[`${row.l}|${col.c}`];
    if (!x) return null;
    const n = x.high + x.audit;
    return {t:Math.min(1, n / 8), text:`${n}`, sub:`${x.high} high · ${x.audit} audit`, tip:tip(`${row.l} · ${CLASS_LABEL[col.c]}`, [['', 'Tầng high', String(x.high)], ['', 'Tầng audit', String(x.audit)]])};
  }, {rowW:'110px', corner:'Số rule'});
  return `<div class="grid g-2-1">
    ${card(`Phân bố ${rules.length} rule theo ngôn ngữ × lớp`, 'grid-3x3', grid, 'Toàn bộ là rule do nhóm viết (tiền tố <code>team.</code>), kèm bản chụp registry Semgrep cố định để quét lại được.')}
    ${card('Đọc nhanh', 'info', `<ul style="margin:0;padding-left:18px;line-height:1.8;color:var(--text-2)">
      <li><b>high</b>: đủ mạnh để Gate BLOCK một mình (luồng taint không qua sanitizer, hoặc mẫu gần như chắc chắn sai).</li>
      <li><b>audit</b>: dùng API nguy hiểm với giá trị không phải hằng; chỉ REVIEW nếu CodeBERT không cùng báo.</li>
      <li><b>taint</b>: theo dõi dữ liệu từ nguồn (request) tới sink; <b>pattern</b>: khớp mẫu cú pháp; <b>regex</b>: chỉ cho template PHP mà parser không đọc được.</li>
      <li>Số “đúng lớp / lần báo” đo trên mẫu có lỗ hổng (${esc(ci.metrics_tag || '')}); a/b là tỉ lệ bản đã vá bị báo so với bản lỗi báo đúng (TC5).</li></ul>`)}
  </div>
  <div class="filters space">
    ${sel('rlang', state.rlang, [['all', 'Mọi ngôn ngữ'], ...LANGS.map(l => [l, l]), ['regex', 'regex']], 'Ngôn ngữ')}
    ${sel('rcls', state.rcls, [['all', 'Mọi lớp'], ...Object.entries(CLASS_LABEL)], 'Lớp')}
    ${sel('rtier', state.rtier, [['all', 'Mọi tầng'], ['high', 'high'], ['audit', 'audit']], 'Tầng')}
    ${sel('rkind', state.rkind, [['all', 'Mọi kiểu'], ['taint', 'taint'], ['pattern', 'pattern'], ['regex', 'regex']], 'Kiểu rule')}
    <label class="field grow"><span>Tìm</span><input class="input" data-input="rq" value="${esc(state.rq || '')}" placeholder="id rule, nội dung, CWE" autocomplete="off"></label>
  </div>
  <div class="card"><div class="card-head"><div><h2>${icon('scroll-text')}Rule đang dùng</h2><p>Bấm một rule để xem nội dung YAML đầy đủ, metadata, test và số liệu.</p></div><div class="right"><span class="muted">${shown.length} / ${rules.length}</span></div></div>
    <div class="card-body table-wrap"><table class="t"><thead><tr><th>Rule</th><th>Ngôn ngữ</th><th>Lớp</th><th>CWE</th><th>Tầng</th><th>Kiểu</th><th class="num">Test</th><th class="num">Train: đúng lớp / báo</th><th class="num">Val: đúng lớp / báo</th></tr></thead><tbody>
    ${shown.map(r => `<tr class="clickable" data-action="rule" data-id="${esc(r.id)}"><td><span class="strong mono">${esc(r.id)}</span><span class="sub">${esc(r.message)}</span></td><td>${esc(ruleLang(r))}</td><td>${esc(CLASS_SHORT[r.vuln_class] || r.vuln_class || '—')}</td><td class="mono nowrap">${esc(r.cwe || "—")}</td><td>${tierBadge(r.confidence)}</td><td>${badge(kind(r), 'b-outline')}</td>
      <td class="num">${r.tests.total ? `${r.tests.passed}/${r.tests.total}` : '—'}<span class="sub">${r.tests.positive}+ / ${r.tests.negative}−</span></td><td class="num">${prec(r.metrics.train)}</td><td class="num">${prec(r.metrics.val)}</td></tr>`).join('')}
    </tbody></table></div></div>
  ${ci.disabled_rules.length ? `<div class="card space"><div class="card-head"><div><h2>${icon('ban')}Rule đã tắt (${ci.disabled_rules.length})</h2><p>Không nằm trong bundle semgrep.yml; giữ lại trong <code>rules_disabled/</code> cùng lý do để tái lập.</p></div></div>
    <div class="card-body table-wrap"><table class="t"><thead><tr><th>Rule</th><th>Lớp</th><th>Tầng</th><th>Lý do tắt</th></tr></thead><tbody>${ci.disabled_rules.map(r => `<tr class="clickable" data-action="rule" data-id="${esc(r.id)}" data-disabled="1"><td><span class="strong mono">${esc(r.id)}</span><span class="sub">${esc(r.file || '')}</span></td><td>${esc(CLASS_SHORT[r.vuln_class] || r.vuln_class || '—')}</td><td>${tierBadge(r.confidence)}</td><td style="white-space:normal;min-width:320px">${esc(r.disabled_reason || '—')}</td></tr>`).join('')}</tbody></table></div></div>` : ''}`;
}

export function openRule(data, id, disabled=false) {
  const ci = data.config_info;
  const r = (disabled ? ci.disabled_rules : ci.rules).find(x => x.id === id) || ci.rules.concat(ci.disabled_rules).find(x => x.id === id);
  if (!r) return;
  const m = r.metrics || {};
  const pairs = m.pairs || {};
  const body = `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px">${tierBadge(r.confidence)}${badge(kind(r), 'b-outline')}${badge(CLASS_LABEL[r.vuln_class] || r.vuln_class || '—', 'b-muted')}${r.cwe ? badge(r.cwe, 'b-info') : ''}${r.owasp ? badge(r.owasp, 'b-muted') : ''}${r.disabled_reason ? badge('đã tắt', 'b-block', 'ban') : ''}</div>
    <p style="line-height:1.7;margin-bottom:14px">${esc(r.message)}</p>
    ${kv([['Ngôn ngữ', ruleLang(r)], ['Phạm vi', r.scope], ['Phiên bản rule', r.rule_version], ['Thuộc ruleset', r.ruleset_version], ['Severity Semgrep', r.severity], ['Mức rủi ro', r.risk],
      ['Test', r.tests ? `${r.tests.passed}/${r.tests.total} đạt (${r.tests.positive} phải báo, ${r.tests.negative} không được báo)` : '—'],
      ['Train: đúng lớp / báo', prec(m.train)], ['Val: đúng lớp / báo', prec(m.val)],
      ['Cặp train (bản lỗi đúng / bản vá bị báo)', pairs.train ? `${pairs.train.b_right} / ${pairs.train.a_fixed}${pairs.train.ratio != null ? ` (a/b ${num(pairs.train.ratio, 2)})` : ''}` : '—']])}
    ${r.change ? `<div class="notice space">${icon('history')}<span><b>Thay đổi:</b> ${esc(r.change)}</span></div>` : ''}
    ${r.disabled_reason ? `<div class="notice warn space">${icon('ban')}<span><b>Lý do tắt:</b> ${esc(r.disabled_reason)}</span></div>` : ''}
    <h3 style="font-size:13px;margin:18px 0 8px">Nội dung rule (YAML)</h3><pre class="code" style="padding:12px 14px;margin:0;white-space:pre">${esc(r.source)}</pre>`;
  document.querySelector('#overlay').innerHTML = `<div class="modal-backdrop"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="rule-title" style="width:min(900px,100%)"><header class="modal-head"><h2 id="rule-title" class="mono">${esc(r.id)}</h2><button class="btn small ghost" data-action="close-modal" aria-label="Đóng">${icon('x')}</button></header><div class="modal-body">${body}</div></section></div>`;
  window.lucide?.createIcons({attrs:{'stroke-width':1.75}});
  document.querySelector('#overlay .modal-head button')?.focus();
}

function criteriaTab(ci) {
  const c = ci.criteria;
  if (!c) return `<div class="card empty">${icon('file-question')}<strong>Chưa có security-config/semgrep/TIEU_CHI_CHON_RULE.md</strong></div>`;
  return card(c.title || 'Tiêu chí chọn rule', 'list-checks', `<div class="table-wrap"><table class="t"><thead><tr><th>Mã</th><th>Tiêu chí</th><th>Cách kiểm</th></tr></thead><tbody>${c.rows.map(r => `<tr><td class="strong mono" style="vertical-align:top">${esc(r.code)}</td><td style="white-space:normal;line-height:1.65;min-width:380px">${md(r.name)}</td><td style="white-space:normal;line-height:1.6;min-width:180px">${md(r.check)}</td></tr>`).join('')}</tbody></table></div>`,
    `Áp dụng từ ruleset v4.2.0. Một rule được giữ hoặc thêm khi đạt TC1–TC7; được xếp tầng high/audit theo TC8. Nguồn: <code>${esc(c.file)}</code>.`);
}

function dataTab(ci, state) {
  const d = ci.dataset.counts;
  const split = ['train', 'val', 'test'].includes(state.dsplit) ? state.dsplit : 'train';
  const cells = d?.[split]?.cells || {};
  const max = Math.max(1, ...Object.values(cells));
  const grid = d ? heatmap(LANGS.map(l => ({label:l, l})), Object.keys(CLASS_LABEL).map(c => ({label:CLASS_SHORT[c], c})), (row, col) => {
    const n = cells[`${row.l}|${col.c}`];
    if (!n) return null;
    return {t:Math.sqrt(n / max), text:int(n), tip:tip(`${row.l} · ${CLASS_LABEL[col.c]}`, [['', `Số mẫu (${split})`, int(n)]])};
  }, {rowW:'110px', corner:`Tập ${split}`}) : '<p class="muted">Không có số liệu dữ liệu.</p>';
  const srcs = d ? [...new Set(['train', 'val', 'test'].flatMap(s => Object.keys(d[s]?.sources || {})))] : [];
  const SRC = {pyvul:'PyVul (Python)', crossvul:'CrossVul', cvefixes:'CVEfixes', synthetic:'Synthetic (HARDCODED, tự sinh)'};
  const apps = Object.keys(ci.ground_truth || {});
  const app = apps.includes(state.gtapp) ? state.gtapp : apps[0];
  const g = ci.ground_truth?.[app];
  const APPN = {flask_vuln_app:'Flask Vuln App', dvwa:'DVWA', webgoat:'WebGoat', 'juice-shop':'OWASP Juice Shop'};
  return `<div class="grid g-2-1">
    ${card('Thành phần dữ liệu theo ngôn ngữ × lớp', 'grid-3x3', `<div class="chips" style="margin-bottom:12px">${['train', 'val', 'test'].map(s => `<button class="chip${s === split ? ' active' : ''}" data-action="set" data-replace="1" data-patch="${patch({dsplit:s})}">${s} <b>${int(d?.[s]?.n)}</b></button>`).join('')}</div>${grid}`,
      'Chỉ đếm số mẫu; ô “—” là chưa có mẫu thật. Tập test được đếm để mô tả, chưa dùng để đánh giá.')}
    ${card('Nguồn dữ liệu', 'git-branch', `<div class="table-wrap"><table class="t"><thead><tr><th>Nguồn</th><th class="num">train</th><th class="num">val</th><th class="num">test</th></tr></thead><tbody>${srcs.map(s => `<tr><td class="strong">${esc(SRC[s] || s)}</td>${['train', 'val', 'test'].map(sp => `<td class="num">${int(d[sp]?.sources?.[s] || 0)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`)}
  </div>
  <div class="space">${card('Ánh xạ lớp lỗ hổng ↔ CWE / OWASP (của nhóm)', 'link-2', `<div class="table-wrap"><table class="t"><thead><tr><th>Lớp</th><th>CWE chính</th><th>OWASP 2021</th><th>Mức nghiêm trọng</th></tr></thead><tbody>${ci.cwe_map.map(c => `<tr><td class="strong">${esc(CLASS_LABEL[c.class] || c.class)}</td><td><span class="mono">CWE-${esc(c.cwe)}</span><span class="sub">${esc(c.cwe_name || '')}</span></td><td class="mono">${esc(c.owasp || '—')}</td><td>${badge(c.severity || '—', c.severity === 'critical' ? 'b-crit' : 'b-high')}</td></tr>`).join('')}</tbody></table></div>`,
    'rules/vuln_metadata.json. Ánh xạ CWE mở rộng của dữ liệu (E03) và tiêu chí TC1 dùng cùng 6 lớp này.')}</div>
  ${g ? `<div class="space">${card(`Ground truth viết tay · ${APPN[app] || app} (${int(g.n)} lỗ hổng)`, 'target', `<div class="chips" style="margin-bottom:12px">${apps.map(a => `<button class="chip${a === app ? ' active' : ''}" data-action="set" data-replace="1" data-patch="${patch({gtapp:a})}">${esc(APPN[a] || a)} <b>${int(ci.ground_truth[a].n)}</b></button>`).join('')}</div>
    <div class="table-wrap"><table class="t"><thead><tr><th>Mã</th><th>Lớp</th><th>File / hàm</th><th>Ghi chú</th></tr></thead><tbody>${g.items.map(i => `<tr><td class="mono strong">${esc(i.id)}</td><td>${esc(CLASS_SHORT[i.class] || i.class)}<span class="sub mono">${esc(i.cwe || '')}</span></td><td><span class="mono">${esc(i.file)}</span><span class="sub mono">${esc(i.function === '<file>' ? 'mức file' : i.function)}${i.line ? ` · dòng ${esc(i.line)}` : ''}</span></td><td style="white-space:normal;min-width:240px">${esc(i.note || '')}</td></tr>`).join('')}</tbody></table></div>`,
    `Nguồn: ${esc(g.source || 'targets/' + app + '/ground_truth.json')}. Ứng dụng mục tiêu không dùng để train hay chỉnh rule.`)}</div>` : ''}`;
}

export function renderConfig(data, state) {
  const ci = data.config_info;
  if (!ci) return `<div class="card empty">${icon('file-question')}<strong>Chưa có thông tin cấu hình</strong></div>`;
  const tab = TABS.some(([id]) => id === state.ctab) ? state.ctab : 'versions';
  const body = {versions:() => versionsTab(ci), thresholds:() => thresholdsTab(ci), rules:() => rulesTab(ci, state), criteria:() => criteriaTab(ci), data:() => dataTab(ci, state)}[tab]();
  return `<div class="page-head"><div><h1 class="page-title">Cấu hình &amp; Rule</h1>
      <p class="page-desc">Những gì làm nên kết quả của nhóm: phiên bản từng thành phần và các tập test, ngưỡng và chính sách quyết định, toàn bộ rule Semgrep tự viết cùng tiêu chí chọn, dữ liệu và ground truth. Đọc trực tiếp từ manifest và file cấu hình trong dự án.</p></div>
    <div class="actions">${badge(`ruleset v${ci.versions.ruleset.version}`, 'b-accent', 'scan-search')}${badge(`Gate v${ci.versions.gate.version}`, 'b-accent', 'shield-check')}</div></div>
  <div class="tabs" role="tablist">${TABS.map(([id, label, ic]) => `<button role="tab" aria-selected="${id === tab}" class="${id === tab ? 'active' : ''}" data-action="set" data-replace="1" data-patch="${patch({ctab:id})}">${icon(ic)}${label}${id === 'rules' ? ` <span class="badge b-muted">${ci.rules.length}</span>` : ''}</button>`).join('')}</div>
  ${body}`;
}
