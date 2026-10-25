import { esc, icon, int, num, pct, decisionBadge, gtBadge, tierBadge, severityBadge, badge, cls, CLASS_LABEL, STATE_LABEL, unitName, unitLoc, appName, sourceLabel, download, csv } from './ui.js';
import { allUnits, flagged, unitLang, gateReason, DEC } from './agg.js';

const patch = o => esc(JSON.stringify(o));
const GT_FILTERS = [['all', 'Mọi trạng thái GT'], ['tp', 'Đúng lớp (GT)'], ['wrong', 'Sai lớp (GT)'], ['fp', 'Báo nhầm hàm an toàn'], ['miss', 'Bỏ sót (PASS nhưng có lỗ hổng)'], ['nogt', 'Không có GT']];

function gtState(u) {
  const g = u.gt;
  if (!g) return 'nogt';
  if (g.status === 'safe') return u.decision === 'PASS' ? 'safe' : 'fp';
  if (u.decision === 'PASS') return 'miss';
  return g.class_match ? 'tp' : 'wrong';
}

export function filterUnits(runs, state) {
  const base = state.gt === 'miss' ? allUnits(runs).filter(u => u.decision === 'PASS')
    : state.decision === 'flagged' ? flagged(runs)
    : state.decision === 'all' ? allUnits(runs) : allUnits(runs).filter(u => u.decision === state.decision);
  const q = state.q.trim().toLowerCase();
  return base.filter(u => (state.cls === 'all' || u.vuln_class === state.cls || (u.related_classes || []).includes(state.cls))
    && (state.lang === 'all' || unitLang(u) === state.lang)
    && (state.state === 'all' || u.compare_state === state.state)
    && (state.gt === 'all' || gtState(u) === state.gt)
    && (!q || `${u.file} ${u.function} ${u.cwe || ''} ${(u.findings || []).map(f => f.rule).join(' ')}`.toLowerCase().includes(q)))
    .sort((a, b) => (DEC[a.decision] - DEC[b.decision]) || ((b.priority?.score ?? 0) - (a.priority?.score ?? 0)) || a.key.localeCompare(b.key));
}

const select = (bind, value, options, label) => `<label class="field"><span>${label}</span><select data-bind="${bind}">${options.map(([v, t]) => `<option value="${esc(v)}"${v === value ? ' selected' : ''}>${esc(t)}</option>`).join('')}</select></label>`;

const refLabel = h => { try { const u = new URL(h); const last = u.pathname.split('/').filter(Boolean).pop() || ''; return `${u.hostname.replace(/^www\./, '')} · ${decodeURIComponent(last).replace(/\.html?$/, '').replace(/_/g, ' ')}`; } catch { return h; } };
function streams(u, run) {
  const thr = run.config?.verifier_threshold;
  const cb = u.codebert || {};
  const probs = Object.entries(u.probabilities || {}).sort((a, b) => b[1] - a[1]);
  const pv = u.p_vulnerable;
  const verOn = !!run.config?.verifier;
  const sem = (u.findings || []);
  return `<div class="streams">
    <div class="card"><div class="card-body"><div class="stream-head"><h3>${icon('scan-search')}Luồng Semgrep CE</h3>${sem.length ? badge(`${sem.length} finding`, 'b-info') : badge('không báo', 'b-outline')}</div>
      ${sem.length ? sem.map(f => `<div class="finding"><div class="f-top"><span class="f-rule">${esc(f.rule)}</span>${tierBadge(f.confidence)}${u.severity ? severityBadge(u.severity) : ''}</div>
        <div class="f-msg">${esc(f.message || '')}</div>
        <div class="f-msg">Dòng ${esc(f.line ?? '—')} · ${esc((f.classes || []).map(c => CLASS_LABEL[c] || c).join(', ') || 'ngoài 6 lớp')}${(f.cwes || []).length ? ` · CWE-${esc(f.cwes.join(', CWE-'))}` : ''}</div></div>`).join('')
        : `<div class="empty" style="padding:18px">${icon('circle-dashed')}Không có finding Semgrep thuộc 6 lớp cho đơn vị này.</div>`}
    </div></div>
    <div class="card"><div class="card-body"><div class="stream-head"><h3>${icon('brain-circuit')}Luồng CodeBERT</h3>${cb.flagged ? badge('vượt ngưỡng', 'b-review', 'flag') : badge('không báo', 'b-outline')}</div>
      ${probs.length ? probs.map(([c, p], i) => `<div class="prob-row${i === 0 ? ' top' : ''}"><span class="name">${esc(CLASS_LABEL[c] || c)}</span><div class="bar"><span style="width:${100 * p}%;background:${i === 0 ? 'var(--s1)' : '#33456f'}"></span></div><b>${pct(p)}</b></div>`).join('')
        : `<p class="muted">Đơn vị PASS: chỉ lưu lớp dự đoán <b>${esc(cls(u.codebert_class))}</b>.</p>`}
      ${verOn && pv != null ? `<div class="gauge"><div style="display:flex;justify-content:space-between;font-size:12px"><span class="muted">Verifier p_vulnerable</span><b>${num(pv, 3)} ${pv >= thr ? '≥' : '<'} ngưỡng ${num(thr, 3)}</b></div>
        <div class="gauge-track"><span style="width:${100 * pv}%;background:${pv >= thr ? 'var(--warn)' : 'var(--s3)'}"></span><i style="left:${100 * thr}%"></i></div>
        <div class="gauge-scale"><span>0</span><span>ngưỡng chọn trên val cặp trước/sau vá</span><span>1</span></div></div>` : ''}
      <p class="muted" style="font-size:11.5px;margin-top:10px">Lớp 6-lớp chỉ dùng để gọi tên lỗ hổng; việc luồng AI có báo hay không do ${verOn ? 'verifier quyết định' : 'xác suất lớp cao nhất quyết định'}.</p>
    </div></div></div>`;
}

function detail(data, u) {
  if (!u) return `<div class="card empty">${icon('mouse-pointer-click')}<strong>Chọn một cảnh báo</strong>Danh sách bên trái đã lọc theo phạm vi và bộ lọc.</div>`;
  const run = u.run, r = gateReason(u, run);
  const tone = u.decision === 'BLOCK' ? 'block' : u.decision === 'REVIEW' ? 'review' : 'pass';
  const downgraded = run.config?.policy && (() => {
    const pol = run.config.policy[u.compare_state];
    const expect = typeof pol === 'object' && pol ? pol[r.rule.split('.')[1]] : pol;
    return expect === 'BLOCK' && u.decision === 'REVIEW';
  })();
  const g = u.gt, rem = u.remediation;
  const gtBox = g ? (() => {
    const st = gtState(u);
    const map = {tp:['gt-ok', 'badge-check', 'Đúng: có lỗ hổng và một lớp Gate báo (related_classes) khớp ground truth'], wrong:['gt-mid', 'shuffle', 'Có lỗ hổng nhưng Gate gọi sai lớp'],
      fp:['gt-bad', 'circle-alert', 'Báo nhầm: ground truth không ghi lỗ hổng ở đơn vị này'], miss:['gt-bad', 'circle-off', 'Bỏ sót: có lỗ hổng nhưng Gate PASS'], safe:['gt-ok', 'circle-check', 'An toàn và không bị cảnh báo']};
    const [c, ic, t] = map[st];
    return `<div class="gt-box ${c}">${icon(ic)}<div><strong>${esc(t)}</strong>${g.status === 'vulnerable_file' ? '<div class="muted" style="font-size:12px">Ground truth của ứng dụng này ở mức file: mọi hàm trong file được tính theo file.</div>' : ''}
      ${g.items.length ? `<ul>${g.items.map(i => `<li><b>${esc(i.id)}</b> — ${esc(CLASS_LABEL[i.class] || i.class)}${i.line ? ` (dòng ${esc(i.line)})` : ''}${i.description ? `: ${esc(i.description)}` : ''}</li>`).join('')}</ul>` : ''}</div></div>`;
  })() : '';
  return `<div class="detail">
    <div class="card"><div class="card-body"><div class="detail-head"><span class="prio ${esc(u.priority?.level || 'none')}">${esc(u.priority?.level || '—')}</span><div style="min-width:0">
      <h2>${esc(cls(u.vuln_class))} · ${esc(unitName(u))}</h2><div class="loc">${esc(appName(data, run))} · ${esc(unitLoc(u))}</div>
      <div class="badges">${decisionBadge(u.decision)}${badge(STATE_LABEL[u.compare_state] || u.compare_state, 'b-accent')}${u.severity ? badge(`mức ${u.severity}`, u.severity === 'critical' ? 'b-crit' : 'b-high') : ''}${u.cwe ? `<a class="badge b-info" href="${esc(u.cwe_url)}" target="_blank" rel="noopener noreferrer">${esc(u.cwe)}</a>` : ''}${u.owasp ? `<a class="badge b-muted" href="${esc(u.owasp_url)}" target="_blank" rel="noopener noreferrer">${esc(u.owasp)}</a>` : ''}${gtBadge(u)}</div></div></div>
    <div class="reason ${tone}" style="margin-top:16px"><span class="sym">${icon(tone === 'block' ? 'octagon-x' : tone === 'review' ? 'eye' : 'circle-check')}</span><div>
      <h3>Vì sao Security Gate quyết định ${esc(u.decision)}</h3><p>${esc(r.text)} Quy tắc áp dụng: <code>policy.${esc(r.rule)}</code> → <b>${esc(u.decision)}</b>.${downgraded ? ` Hạ từ BLOCK xuống REVIEW vì mức nghiêm trọng dưới <code>block_min_severity</code>.` : ''}</p>
      ${u.priority ? `<p>Điểm ưu tiên ${esc(u.priority.score)} (${esc(u.priority.level)} — ${esc(u.priority.meaning || '')}).</p>` : ''}</div></div>
    </div></div>
    ${streams(u, run)}
    ${gtBox}
    <div class="card"><div class="card-head"><div><h3>${icon('file-code-2')}Mã nguồn</h3><p>Đọc trực tiếp từ thư mục đã quét; dòng có finding được tô đỏ.</p></div></div><div class="card-body" id="code-slot"><div class="muted">Đang đọc mã nguồn…</div></div></div>
    ${rem ? `<div class="card"><div class="card-head"><div><h3>${icon('wrench')}Gợi ý khắc phục (${esc(cls(u.vuln_class))})</h3></div></div><div class="card-body">
      <p style="line-height:1.7">${esc(rem.summary)}</p>${rem.language_specific ? `<p class="muted" style="margin-top:8px;line-height:1.7"><b>Ví dụ:</b> <span class="mono">${esc(rem.language_specific)}</span></p>` : ''}
      ${(rem.references || []).length ? `<div class="chips space">${rem.references.map(h => `<a class="chip" href="${esc(h)}" target="_blank" rel="noopener noreferrer">${icon('external-link')}${esc(refLabel(h))}</a>`).join('')}</div>` : ''}</div></div>` : ''}
  </div>`;
}

export function renderAlerts(data, state, {scopeRuns}) {
  const runs = scopeRuns();
  const items = filterUnits(runs, state);
  const sel = items.find(u => u.key === state.unit) || (state.unit ? allUnits(runs).find(u => u.key === state.unit) : null) || items[0];
  const langs = [...new Set(allUnits(runs).map(unitLang))].sort();
  return `<div class="page-head"><div><h1 class="page-title">Cảnh báo bảo mật</h1>
      <p class="page-desc">Mỗi dòng là một đơn vị code mà Security Gate cho BLOCK hoặc REVIEW, kèm bằng chứng của từng luồng. Với 4 ứng dụng mục tiêu, nhãn ground truth cho biết cảnh báo đúng, sai lớp hay báo nhầm.</p></div>
    <div class="actions"><button class="btn" data-action="export-alerts">${icon('download')}Xuất CSV (${int(items.length)})</button></div></div>
  <div class="filters">
    ${select('decision', state.decision, [['flagged', 'BLOCK + REVIEW'], ['BLOCK', 'Chỉ BLOCK'], ['REVIEW', 'Chỉ REVIEW'], ['PASS', 'PASS'], ['all', 'Mọi đơn vị']], 'Quyết định')}
    ${select('cls', state.cls, [['all', 'Mọi lớp'], ...Object.entries(CLASS_LABEL)], 'Lớp lỗ hổng')}
    ${select('lang', state.lang, [['all', 'Mọi ngôn ngữ'], ...langs.map(l => [l, l])], 'Ngôn ngữ')}
    ${select('state', state.state, [['all', 'Mọi trạng thái'], ...Object.entries(STATE_LABEL)], 'Compare')}
    ${select('gt', state.gt, GT_FILTERS, 'Ground truth')}
    <label class="field grow"><span>Tìm</span><input class="input" data-input="q" value="${esc(state.q)}" placeholder="File, hàm, CWE hoặc rule Semgrep" autocomplete="off"></label>
  </div>
  <div class="alerts-layout">
    <div class="card alert-detail">${detail(data, sel)}</div>
    <div class="card alert-list"><div class="list-head"><span>${int(items.length)} đơn vị</span><span class="muted">${runs.length} lượt quét</span></div>
      <div class="alert-scroll">${items.length ? items.slice(0, 500).map(u => `<button class="alert-item${sel && u.key === sel.key ? ' selected' : ''}" data-action="set" data-replace="1" data-patch="${patch({unit:u.key})}">
        <span class="prio ${esc(u.priority?.level || 'none')}">${esc(u.priority?.level || '—')}</span>
        <span class="ai-body"><span class="ai-title"><strong>${esc(unitName(u))}</strong>${decisionBadge(u.decision)}</span>
        <span class="ai-meta" style="display:block">${esc(appName(data, u.run))} · ${esc(unitLoc(u))}</span>
        <span class="ai-tags">${badge(cls(u.vuln_class || u.codebert_class), 'b-muted')}${badge(sourceLabel(u), 'b-outline')}${gtBadge(u)}</span></span></button>`).join('')
        + (items.length > 500 ? `<div class="empty">Hiển thị 500/${int(items.length)}; thu hẹp bộ lọc để xem thêm.</div>` : '')
        : `<div class="empty">${icon('filter-x')}<strong>Không có đơn vị khớp bộ lọc</strong></div>`}</div></div>
  </div>`;
}

export async function alertsAfter(data, state) {
  const slot = document.querySelector('#code-slot');
  if (!slot) return;
  const runs = data.runs;
  const [runId, unitId] = (document.querySelector('.alert-item.selected')?.dataset.patch ? JSON.parse(document.querySelector('.alert-item.selected').dataset.patch).unit : state.unit || '').split('|');
  const run = runs.find(r => r.id === runId);
  const u = run?.units.find(x => x.id === unitId);
  if (!u) { slot.innerHTML = '<div class="muted">Không xác định được đơn vị.</div>'; return; }
  const hits = new Set((u.findings || []).map(f => f.line).filter(Boolean));
  let [a, b] = u.lines || [];
  if (!a) { const ls = [...hits]; a = ls.length ? Math.min(...ls) - 6 : 1; b = ls.length ? Math.max(...ls) + 6 : 40; }
  a = Math.max(1, a - 2); b = Math.min(b + 2, a + 220);
  try {
    const res = await fetch(`/api/source?${new URLSearchParams({run:run.id, file:u.file, start:a, end:b})}`, {cache:'no-store'});
    const js = await res.json();
    if (!res.ok) throw new Error(js.error || `HTTP ${res.status}`);
    if (!document.body.contains(slot)) return;
    const [ua, ub] = u.lines || [0, 0];
    slot.innerHTML = `<div class="code">${js.lines.map((t, i) => { const n = js.start + i; return `<div class="ln${hits.has(n) ? ' hit' : n >= ua && n <= ub ? ' in' : ''}"><span>${n}</span><span>${esc(t) || ' '}</span></div>`; }).join('')}</div>
      <p class="muted" style="font-size:11.5px;margin-top:8px">${esc(js.file)} · dòng ${js.start}–${js.end} / ${js.total}${js.end - js.start + 1 >= 220 ? ' (đã cắt bớt)' : ''}</p>`;
  } catch (err) {
    if (document.body.contains(slot)) slot.innerHTML = `<div class="notice">${icon('file-x')}<span>Không hiển thị được mã nguồn: ${esc(err.message)}. (Chỉ đọc được khi thư mục đã quét còn trên máy.)</span></div>`;
    window.lucide?.createIcons({attrs:{'stroke-width':1.75}});
  }
}

export function exportAlerts(data, state, runs) {
  const items = filterUnits(runs, state);
  const rows = [['ung_dung', 'cau_hinh', 'file', 'ham', 'dong', 'quyet_dinh', 'compare', 'lop', 'cwe', 'uu_tien', 'diem', 'semgrep_rules', 'codebert_lop', 'p_vulnerable', 'ground_truth']];
  items.forEach(u => rows.push([appName(data, u.run), u.run.config_id, u.file, u.function, u.lines ? u.lines.join('-') : '', u.decision, u.compare_state,
    u.vuln_class || '', u.cwe || '', u.priority?.level || '', u.priority?.score ?? '', (u.findings || []).map(f => `${f.rule}[${f.confidence}]`).join(' '),
    u.codebert?.class || u.codebert_class || '', u.p_vulnerable ?? '', gtState(u)]));
  download(`aiws_canh_bao_${state.config}_${new Date().toISOString().slice(0, 10)}.csv`, '﻿' + csv(rows), 'text/csv;charset=utf-8');
}
