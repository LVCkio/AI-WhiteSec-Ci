import { esc, icon, int, num, pct, ratio, sec, fmtDate, decisionBadge, badge, method, appName, APP_LANG, STATE_LABEL, STATE_COLOR, unitName, unitLoc, cls } from './ui.js';
import { stackBar, legend } from './charts.js';
import { pipelineCard } from './overview.js';
import { flagged } from './agg.js';

const patch = o => esc(JSON.stringify(o));

function timing(run) {
  const t = run.timing || {};
  const serial = (t.sast_s || 0) + (t.codebert_s || 0);
  const max = Math.max(serial, t.total_s || 0, 0.001);
  const row = (label, v, color, note='') => `<div class="timing-row"><span>${esc(label)}${note ? `<span class="sub" style="display:block;color:var(--subtle);font-size:11px">${esc(note)}</span>` : ''}</span><div class="bar"><span style="width:${100 * (v || 0) / max}%;background:${color}"></span></div><b>${sec(v)}</b></div>`;
  const saved = serial && t.parallel_wall_s ? 1 - t.parallel_wall_s / serial : null;
  return `${row('Trích đơn vị', t.extract_s, '#5f7299')}
    ${row('Semgrep CE', t.sast_s, 'var(--s2)', 'luồng SAST')}
    ${row('CodeBERT + verifier', t.codebert_s, 'var(--s1)', `gồm nạp mô hình ${sec(t.model_load_s)}`)}
    ${row('Hai luồng song song', t.parallel_wall_s, 'var(--accent)', 'thời gian thực của bước phân tích')}
    ${row('Nếu chạy nối tiếp', serial, '#3a4a70', 'Semgrep + CodeBERT')}
    <p class="muted" style="font-size:12px;margin-top:6px">${saved != null ? `Chạy song song tiết kiệm <b style="color:var(--text)">${pct(saved, 0)}</b> so với nối tiếp; luồng chậm nhất (CodeBERT trên ${esc(run.device || 'CPU')}) quyết định tổng thời gian.` : ''} Tổng ${sec(t.total_s)}.</p>`;
}

export function renderMonitoring(data, state, {scopeRuns}) {
  const runs = [...scopeRuns(undefined, undefined, {includeOld:true})].sort((a, b) => b.created.localeCompare(a.created) || a.id.localeCompare(b.id));
  if (!runs.length) return `<div class="card empty">${icon('inbox')}<strong>Chưa có lượt quét trong phạm vi này</strong></div>`;
  const run = runs.find(r => r.id === state.run) || runs[0];
  const s = run.summary || {}, d = s.decisions || {}, cs = s.compare_states || {};
  const cfg = data.configs.find(c => c.id === run.config_id);
  const rs = run.ruleset || {};
  const top = flagged([run]).slice(0, 6);
  const stParts = Object.entries(cs).map(([k, v]) => ({name:STATE_LABEL[k], value:v, color:STATE_COLOR[k]}));
  const ev = run.eval;
  return `<div class="page-head"><div><h1 class="page-title">Giám sát lượt quét</h1>
      <p class="page-desc">Mỗi lượt là một lần chạy <code>scan.py</code> (ứng dụng mục tiêu qua <code>09_eval_targets.py</code>, hoặc commit đặt trong <code>reports/scans/</code>). Thời gian đo trên máy đã chạy, không dùng làm số đo hiệu năng tuyệt đối.</p></div></div>
  <div class="monitor">
    <div class="card run-list"><div class="list-head" style="display:flex;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);background:#0f162e;font-size:12px"><span>${icon('list')} ${runs.length} lượt quét</span></div>
      <div class="run-scroll">${runs.map(r => `<button class="run-item${r.id === run.id ? ' selected' : ''}" data-action="set" data-replace="1" data-patch="${patch({run:r.id})}">
        <span class="r1"><strong>${esc(appName(data, r))}</strong>${decisionBadge(r.verdict)}</span>
        <span class="r2"><span class="mono">${esc(r.tag || r.id)}</span><span>${int(r.summary?.units)} đơn vị</span></span>
        <span class="r2"><span>${r.superseded ? 'đã có lượt mới hơn' : esc(data.configs.find(c => c.id === r.config_id)?.current ? '★ cấu hình hiện tại' : 'cấu hình cũ')}</span><span>${fmtDate(r.created)}</span></span></button>`).join('')}</div></div>
    <div class="detail">
      <div class="card"><div class="card-body">
        <div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:flex-start">
          <div><h2 style="font-size:18px;font-weight:700">${esc(appName(data, run))}</h2><div class="muted" style="margin-top:4px">${esc(cfg?.label || run.config_id)}</div></div>
          <div style="display:flex;gap:6px;flex-wrap:wrap">${decisionBadge(run.verdict)}${badge(run.mode === 'parallel' ? 'song song đầy đủ' : run.mode, run.mode === 'parallel' ? 'b-pass' : 'b-review', run.mode === 'parallel' ? 'git-fork' : 'triangle-alert')}${cfg?.current ? badge('cấu hình hiện tại', 'b-accent', 'star') : ''}</div>
        </div>
        ${run.degraded_reason ? `<div class="notice warn space">${icon('triangle-alert')}<span>Chế độ suy giảm: ${esc(JSON.stringify(run.degraded_reason))}. Kết luận tối thiểu REVIEW.</span></div>` : ''}
        <div class="kv space">
          <div><span>Ngôn ngữ</span><strong>${esc(run.app ? APP_LANG[run.app] : run.languages.join(', ') || '—')}</strong></div>
          <div><span>Đơn vị / file</span><strong>${int(s.units)} / ${int(s.files)}</strong></div>
          <div><span>Ruleset</span><strong>v${esc(rs.ruleset_version || '—')} ${rs.regression_passed ? '· regression đạt' : ''}</strong></div>
          <div><span>SHA-256 ruleset</span><strong class="mono">${esc((rs.ruleset_sha256 || '').slice(0, 16))}…</strong></div>
          <div><span>Mô hình / verifier</span><strong>${esc((run.config.model_dir || '').split('/').pop())} / ${esc(run.config.verifier ? `${run.config.verifier.split('/').pop()} ≥ ${run.config.verifier_threshold}` : 'không verifier')}</strong></div>
          <div><span>Lần gọi mô hình</span><strong>${int(s.model_calls)} · ${esc(run.device || '—')}</strong></div>
          <div><span>Commit</span><strong class="mono">${esc(run.commit ? run.commit.slice(0, 12) : 'quét theo file (--files)')}</strong></div>
          <div><span>File kết quả</span><strong class="mono">${esc(run.source_file)}</strong></div>
        </div></div></div>
      ${pipelineCard(data, run.config, 'Luồng của lượt quét này')}
      <div class="grid g2">
        <div class="card"><div class="card-head"><div><h3>${icon('timer')}Thời gian từng bước</h3><p>Từ <code>timing_seconds</code> trong JSON của scan.py.</p></div></div><div class="card-body">${timing(run)}</div></div>
        <div class="card"><div class="card-head"><div><h3>${icon('shield-check')}Quyết định và trạng thái Compare</h3></div></div><div class="card-body">
          ${stackBar([{name:'BLOCK', value:d.BLOCK || 0, color:'var(--crit)'}, {name:'REVIEW', value:d.REVIEW || 0, color:'var(--warn)'}, {name:'PASS', value:d.PASS || 0, color:'#2a3656'}], s.units, 'Quyết định Gate')}
          ${legend([['var(--crit)', `BLOCK ${int(d.BLOCK || 0)}`], ['var(--warn)', `REVIEW ${int(d.REVIEW || 0)}`], ['#2a3656', `PASS ${int(d.PASS || 0)}`]])}
          <div style="height:18px"></div>
          ${stackBar(stParts, s.units, 'Trạng thái Compare')}${legend(stParts.map(p => [p.color, `${p.name}: ${int(p.value)}`]))}
        </div></div>
      </div>
      ${ev ? `<div class="card"><div class="card-head"><div><h3>${icon('target')}Đối chiếu ground truth (${int(ev.n_vulnerabilities)} lỗ hổng, ${int(ev.n_vulnerable_units)} đơn vị có lỗ hổng${run.gt_file_level ? ', mức file' : ''})</h3><p>Từ <code>${esc(run.source_file.replace('_scan', '_eval'))}</code>.</p></div></div>
        <div class="card-body table-wrap"><table class="t"><thead><tr><th>Phương pháp</th><th class="num">Đúng lớp</th><th class="num">Đơn vị có lỗ hổng được báo</th><th class="num">Hàm an toàn bị báo</th><th class="num">Sai lớp</th></tr></thead><tbody>
        ${ev.methods.map(m => `<tr${m.method === 'Gate_BLOCK' ? ' class="hl"' : ''}><td class="strong">${esc(method(m.method))}</td><td class="num">${ratio(m.tp, m.gt)}</td><td class="num">${ratio(m.vuln_units_flagged, m.vuln_units)}</td><td class="num">${ratio(m.flagged_safe, m.safe)}</td><td class="num">${int(m.wrong_class)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
      <div class="card"><div class="card-head"><div><h3>${icon('siren')}Cảnh báo ưu tiên của lượt này</h3></div><div class="right"><button class="link" data-action="screen" data-screen="alerts" data-patch="${patch({app:run.app || `repo:${run.repo_name}`, config:run.config_id})}">Mở trong Cảnh báo ${icon('arrow-up-right')}</button></div></div>
        <div class="card-body table-wrap">${top.length ? `<table class="t"><tbody>${top.map(u => `<tr class="clickable" data-action="screen" data-screen="alerts" data-patch="${patch({unit:u.key, config:run.config_id})}"><td><span class="prio ${esc(u.priority?.level || 'none')}">${esc(u.priority?.level || '—')}</span></td><td><span class="strong">${esc(unitName(u))}</span><span class="sub mono">${esc(unitLoc(u))}</span></td><td>${esc(cls(u.vuln_class))}</td><td>${decisionBadge(u.decision)}</td></tr>`).join('')}</tbody></table>` : `<div class="empty">${icon('shield-check')}Không có cảnh báo.</div>`}</div></div>
    </div>
  </div>`;
}
