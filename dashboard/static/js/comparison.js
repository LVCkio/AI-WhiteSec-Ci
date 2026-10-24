import { esc, icon, int, num, ratio, fmtDate, decisionBadge, badge, cls, method, appName, unitName, unitLoc, download } from './ui.js';

const patch = o => esc(JSON.stringify(o));
const appKey = r => r.app || `repo:${r.repo_name}`;
const isFlag = d => d === 'BLOCK' || d === 'REVIEW';
const FILTERS = [['changed', 'Mọi thay đổi'], ['new', 'Mới cảnh báo'], ['resolved', 'Không còn cảnh báo'], ['level', 'Đổi mức BLOCK ↔ REVIEW'], ['class', 'Đổi lớp'], ['same', 'Giữ nguyên cảnh báo']];

function pick(data, state) {
  const keys = [...new Set(data.runs.map(appKey))];
  const want = state.repo || state.app;
  const repo = keys.includes(want) ? want : keys[0];
  const runs = data.runs.filter(r => appKey(r) === repo).sort((a, b) => b.created.localeCompare(a.created));
  const cur = data.configs.find(c => c.current);
  let target = runs.find(r => r.id === state.target) || runs.find(r => r.config_id === cur?.id) || runs[0];
  let base = runs.find(r => r.id === state.base && r.id !== target?.id) || runs.find(r => r.id !== target?.id);
  return {repo, runs, base, target};
}

export function diffRuns(base, target) {
  const B = new Map(base.units.map(u => [u.id, u])), T = new Map(target.units.map(u => [u.id, u]));
  const ids = [...new Set([...B.keys(), ...T.keys()])].sort();
  const rows = [];
  for (const id of ids) {
    const b = B.get(id), t = T.get(id);
    const bd = b?.decision || 'PASS', td = t?.decision || 'PASS';
    let kind = null;
    if (!isFlag(bd) && isFlag(td)) kind = 'new';
    else if (isFlag(bd) && !isFlag(td)) kind = 'resolved';
    else if (isFlag(bd) && isFlag(td)) kind = bd !== td ? 'level' : (b?.vuln_class !== t?.vuln_class ? 'class' : 'same');
    if (!kind) continue;
    const gt = (t || b).gt;
    let impact = '';
    if (gt) {
      const vuln = gt.status !== 'safe';
      if (kind === 'new') impact = vuln ? 'good:Bắt thêm lỗ hổng' : 'bad:Thêm báo nhầm';
      else if (kind === 'resolved') impact = vuln ? 'bad:Bỏ sót mới' : 'good:Bớt báo nhầm';
      else if (kind === 'class' && vuln) { const ok = c => c && (gt.classes || []).includes(c); impact = ok(t?.vuln_class) && !ok(b?.vuln_class) ? 'good:Đổi sang đúng lớp' : !ok(t?.vuln_class) && ok(b?.vuln_class) ? 'bad:Đổi sang sai lớp' : ''; }
      else if (kind === 'level') impact = td === 'BLOCK' ? (vuln ? 'good:Chặn thêm lỗ hổng thật' : 'bad:Chặn nhầm thêm') : (vuln ? 'bad:Lỗ hổng thật hạ xuống REVIEW' : 'good:Bớt chặn nhầm');
    }
    rows.push({id, kind, base:b, target:t, bd, td, impact, unit:t || b, missing:!b ? 'base' : !t ? 'target' : null});
  }
  return rows;
}

function sigDiff(a, b) {
  const f = [['ruleset', 'Ruleset Semgrep', v => v ? `v${v}` : '—'], ['sast_tools', 'Công cụ SAST', v => (v || []).join(' + ')], ['model_dir', 'Mô hình 6 lớp', v => (v || '').split('/').pop()],
    ['verifier', 'Verifier', v => v ? v.split('/').pop() : 'không'], ['verifier_threshold', 'Ngưỡng verifier', v => v ?? '—']];
  return f.filter(([k]) => JSON.stringify(a[k]) !== JSON.stringify(b[k])).map(([, n, fmt]) => ({name:n, from:fmt(a[f.find(x => x[1] === n)[0]]), to:fmt(b[f.find(x => x[1] === n)[0]])}));
}

const runCard = (data, r, label) => {
  const c = data.configs.find(x => x.id === r.config_id);
  const d = r.summary?.decisions || {};
  return `<div class="card run-card"><div class="rc-top"><span>${icon('git-commit-horizontal')} ${esc(label)}</span>${c?.current ? badge('hiện tại', 'b-accent', 'star') : badge(r.tag || 'scan', 'b-outline')}</div>
    <h3>${esc(appName(data, r))}</h3><div class="rc-cfg">${esc(c?.label || r.config_id)}</div>
    <div style="display:flex;gap:6px;flex-wrap:wrap">${decisionBadge(r.verdict)}${badge(`${d.BLOCK || 0} BLOCK`, 'b-block')}${badge(`${d.REVIEW || 0} REVIEW`, 'b-review')}</div>
    <div class="muted" style="font-size:11.5px">${fmtDate(r.created)} · ${esc(r.source_file)}</div></div>`;
};

export function renderComparison(data, state) {
  const {repo, runs, base, target} = pick(data, state);
  const keys = [...new Map(data.runs.map(r => [appKey(r), appName(data, r)])).entries()];
  if (!base || !target) return `<div class="page-head"><div><h1 class="page-title">So sánh lượt quét</h1></div></div>
    <div class="card"><div class="card-body"><label class="field" style="max-width:320px"><span>Ứng dụng / repo</span><select data-bind="repo">${keys.map(([k, n]) => `<option value="${esc(k)}"${k === repo ? ' selected' : ''}>${esc(n)}</option>`).join('')}</select></label></div></div>
    <div class="card empty space">${icon('git-compare-arrows')}<strong>Cần ít nhất hai lượt quét cùng ứng dụng / repo</strong>Ứng dụng này mới có ${runs.length} lượt.</div>`;
  const rows = diffRuns(base, target);
  const count = k => rows.filter(r => r.kind === k).length;
  const shown = rows.filter(r => state.cmp === 'changed' ? r.kind !== 'same' : r.kind === state.cmp);
  const diffs = sigDiff(base.config, target.config);
  const gtDelta = base.eval && target.eval ? ['Gate_BLOCK', 'Gate_BLOCK_or_REVIEW', 'SAST_B'].map(m => {
    const a = base.eval.methods.find(x => x.method === m), b = target.eval.methods.find(x => x.method === m);
    return a && b ? {m, tp:[a.tp, b.tp, a.gt], fp:[a.flagged_safe, b.flagged_safe, a.safe]} : null; }).filter(Boolean) : [];
  const delta = (a, b, goodUp) => { const d = b - a; if (!d) return `<span class="delta-neutral">không đổi</span>`;
    const good = goodUp ? d > 0 : d < 0; return `<span class="${good ? 'delta-up' : 'delta-down'}">${d > 0 ? '+' : ''}${d}</span>`; };
  const opt = (r, sel) => `<option value="${esc(r.id)}"${r.id === sel ? ' selected' : ''}>${esc(r.tag || r.id)} · ${esc(data.configs.find(c => c.id === r.config_id)?.label || '')}</option>`;
  return `<div class="page-head"><div><h1 class="page-title">So sánh lượt quét</h1>
      <p class="page-desc">Đối chiếu hai lượt quét của cùng một ứng dụng / repo theo từng đơn vị code (file + hàm): cấu hình mới bắt thêm, bỏ sót hay bớt báo nhầm ở đâu. “Không còn cảnh báo” chỉ mô tả kết quả của lượt sau, không chứng minh lỗi đã được sửa.</p></div>
    <div class="actions"><button class="btn" data-action="export-compare">${icon('download')}Xuất JSON</button></div></div>
  <div class="card"><div class="card-body">
    <div class="compare-top">
      <label class="field"><span>Ứng dụng / repo</span><select data-bind="repo">${keys.map(([k, n]) => `<option value="${esc(k)}"${k === repo ? ' selected' : ''}>${esc(n)}</option>`).join('')}</select></label>
      <div class="compare-pick">
        <label class="field"><span>Lượt gốc (trước)</span><select data-bind="base">${runs.filter(r => r.id !== target.id).map(r => opt(r, base.id)).join('')}</select></label>
        <button class="swap" title="Đổi chiều" aria-label="Đổi chiều so sánh" data-action="set" data-patch="${patch({base:target.id, target:base.id})}">${icon('arrow-left-right')}</button>
        <label class="field"><span>Lượt đối chiếu (sau)</span><select data-bind="target">${runs.filter(r => r.id !== base.id).map(r => opt(r, target.id)).join('')}</select></label>
      </div>
    </div></div></div>
  <div class="grid g2 space">${runCard(data, base, 'Lượt gốc')}${runCard(data, target, 'Lượt đối chiếu')}</div>
  <div class="notice ${diffs.length ? '' : 'ok'} space">${icon(diffs.length ? 'settings-2' : 'check-check')}<span>${diffs.length ? `Hai lượt khác nhau ở: ${diffs.map(d => `<b>${esc(d.name)}</b> ${esc(d.from)} → ${esc(d.to)}`).join(' · ')}. Mọi thay đổi bên dưới đến từ những khác biệt cấu hình này (cùng mã nguồn ứng dụng).` : 'Hai lượt cùng cấu hình pipeline.'}</span></div>
  <div class="grid g4 space">
    ${[['new', 'Mới cảnh báo', 'plus-circle', 'amber'], ['resolved', 'Không còn cảnh báo', 'minus-circle', 'green'], ['level', 'Đổi mức BLOCK ↔ REVIEW', 'arrow-up-down', 'violet'], ['same', 'Giữ nguyên cảnh báo', 'equal', '']].map(([k, l, ic, tone]) =>
      `<button class="card kpi clickable" data-action="set" data-replace="1" data-patch="${patch({cmp:k})}"><div class="kpi-top"><span>${l}</span><span class="kpi-icon ${tone}">${icon(ic)}</span></div><div class="kpi-value">${int(count(k))}</div><div class="kpi-note">${k === 'same' ? `${int(count('class'))} đơn vị đổi lớp` : 'đơn vị code'}</div></button>`).join('')}
  </div>
  ${gtDelta.length ? `<div class="card space"><div class="card-head"><div><h3>${icon('target')}Thay đổi theo ground truth</h3><p>Từ bảng 09_eval_targets.py của hai lượt.</p></div></div><div class="card-body table-wrap"><table class="t"><thead><tr><th>Phương pháp</th><th class="num">Đúng lớp: trước → sau</th><th class="num">Thay đổi</th><th class="num">Hàm an toàn bị báo: trước → sau</th><th class="num">Thay đổi</th></tr></thead><tbody>
    ${gtDelta.map(g => `<tr><td class="strong">${esc(method(g.m))}</td><td class="num">${g.tp[0]} → ${g.tp[1]} / ${g.tp[2]}</td><td class="num">${delta(g.tp[0], g.tp[1], true)}</td><td class="num">${g.fp[0]} → ${g.fp[1]} / ${g.fp[2]}</td><td class="num">${delta(g.fp[0], g.fp[1], false)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
  <div class="card space"><div class="card-head"><div><h3>${icon('list-tree')}Đơn vị thay đổi</h3></div><div class="right"><span class="muted">${int(shown.length)} / ${int(rows.length)}</span></div></div>
    <div class="card-body"><div class="chips" style="margin-bottom:14px">${FILTERS.map(([k, l]) => `<button class="chip${state.cmp === k ? ' active' : ''}" data-action="set" data-replace="1" data-patch="${patch({cmp:k})}">${l} <b>${k === 'changed' ? rows.filter(r => r.kind !== 'same').length : count(k)}</b></button>`).join('')}</div>
    ${shown.length ? `<div class="table-wrap"><table class="t"><thead><tr><th>Đơn vị</th><th>Trước</th><th></th><th>Sau</th><th>Lớp</th><th>Ý nghĩa (ground truth)</th></tr></thead><tbody>${shown.slice(0, 400).map(r => {
      const [tone, text] = r.impact ? r.impact.split(':') : ['', ''];
      const cb = r.base?.vuln_class, ct = r.target?.vuln_class;
      return `<tr class="clickable" data-action="screen" data-screen="alerts" data-patch="${patch({unit:`${(r.target ? target : base).id}|${r.id}`, config:(r.target ? target : base).config_id, decision:'all', app:repo, gt:'all', state:'all', cls:'all', lang:'all', q:''})}">
        <td><span class="strong">${esc(unitName(r.unit))}</span><span class="sub mono">${esc(unitLoc(r.unit))}${r.missing ? ` · chỉ có ở lượt ${r.missing === 'base' ? 'sau' : 'trước'}` : ''}</span></td>
        <td>${decisionBadge(r.bd)}</td><td class="arrow">${icon('arrow-right')}</td><td>${decisionBadge(r.td)}</td>
        <td>${cb && ct && cb !== ct ? `${esc(cls(cb))} → ${esc(cls(ct))}` : esc(cls(ct || cb))}</td>
        <td>${text ? badge(text, tone === 'good' ? 'b-pass' : 'b-crit', tone === 'good' ? 'trending-up' : 'trending-down') : '<span class="muted">—</span>'}</td></tr>`; }).join('')}</tbody></table></div>`
      : `<div class="empty">${icon('equal')}<strong>Không có đơn vị nào trong nhóm này</strong></div>`}
    </div></div>`;
}

export function exportComparison(data, state) {
  const {base, target} = pick(data, state);
  if (!base || !target) return;
  const rows = diffRuns(base, target).map(r => ({unit:r.id, kind:r.kind, before:r.bd, after:r.td,
    class_before:r.base?.vuln_class || null, class_after:r.target?.vuln_class || null, ground_truth:r.unit.gt?.status || null, impact:r.impact || null}));
  download(`aiws_so_sanh_${base.id}_vs_${target.id}.json`.replace(/[:]/g, '-'), JSON.stringify({base:base.id, target:target.id, base_config:base.config, target_config:target.config, changes:rows}, null, 2));
}
