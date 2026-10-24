import { esc, icon, int, num, pct, ratio, sec, kpi, decisionBadge, gtBadge, cls, unitName, unitLoc, appName, STATE_LABEL, STATE_COLOR, APP_LANG, badge, sourceLabel } from './ui.js';
import { flagged, decisionCounts, stateCounts, methodTotals } from './agg.js';
import { stackBar, legend } from './charts.js';

const patch = o => esc(JSON.stringify(o));

export function pipelineCard(data, sig, title='Luồng xử lý của cấu hình này') {
  const tools = (sig.sast_tools || []).map(t => t === 'semgrep' ? 'Semgrep CE' : t.charAt(0).toUpperCase() + t.slice(1)).join(' + ');
  const model = (sig.model_dir || '').split('/').pop();
  const ver = sig.verifier ? `${sig.verifier_kind === 'codebert' ? 'CodeBERT' : 'TF-IDF'} nhị phân, p_vulnerable ≥ ${num(sig.verifier_threshold, 3)}` : 'không dùng verifier (xác suất lớp cao nhất)';
  const pol = sig.policy || {};
  return `<div class="card"><div class="card-head"><div><h2>${icon('workflow')}${esc(title)}</h2>
    <p>Hai luồng chạy song song, độc lập trên cùng đơn vị code (hàm); chỉ gộp ở bước Compare. Không luồng nào dùng kết quả của luồng kia.</p></div></div>
    <div class="card-body"><div class="pipeline">
      <div class="pipe-node"><div class="t">${icon('git-commit-horizontal')}Trích đơn vị code</div><div class="d">Hàm bị sửa trong commit (Python: ast; Java/JS/PHP: bộ trích M02). Không tách được thì lấy cả file.</div><div class="v">scan.py</div></div>
      <div class="pipe-arrow">${icon('arrow-right')}</div>
      <div class="pipe-parallel">
        <div class="pipe-node"><div class="t">${icon('scan-search')}${esc(tools)}</div><div class="d">Ruleset v${esc(sig.ruleset || '?')} + bản chụp registry; finding gắn tầng <b>high</b> / <b>audit</b>.</div></div>
        <div class="pipe-tag">song song</div>
        <div class="pipe-node"><div class="t">${icon('brain-circuit')}CodeBERT ${esc(model)}</div><div class="d">Phân loại 6 lớp mọi đơn vị; verifier: ${esc(ver)}.</div></div>
      </div>
      <div class="pipe-arrow">${icon('arrow-right')}</div>
      <div class="pipe-node"><div class="t">${icon('git-merge')}Normalize &amp; Compare</div><div class="d">agree · sast_only · codebert_only · conflict · pass</div><div class="v">compare_gate.py</div></div>
      <div class="pipe-arrow">${icon('arrow-right')}</div>
      <div class="pipe-node"><div class="t">${icon('shield-check')}Security Gate v${esc(sig.gate_version || '?')}</div>
        <div class="d">agree → ${esc(pol.agree || '?')}; chỉ Semgrep: high → ${esc(pol.sast_only?.high || '?')}, audit → ${esc(pol.sast_only?.audit || '?')}; chỉ CodeBERT / khác lớp → ${esc(pol.codebert_only || '?')}.</div>
        <div class="v">BLOCK / REVIEW / PASS</div></div>
    </div></div></div>`;
}

export function renderOverview(data, state, {scopeRuns}) {
  const runs = scopeRuns();
  if (!runs.length) return `<div class="card empty">${icon('inbox')}<strong>Chưa có lượt quét trong phạm vi này</strong>Chạy <code>09_eval_targets.py</code> hoặc <code>scan.py --json reports/scans/&lt;tên&gt;.json</code> rồi bấm Làm mới.</div>`;
  const cfg = data.configs.find(c => c.id === state.config);
  const sig = cfg?.signature || runs[0].config;
  const dc = decisionCounts(runs), sc = stateCounts(runs), units = dc.BLOCK + dc.REVIEW + dc.PASS;
  const tot = methodTotals(runs);
  const gb = tot.Gate_BLOCK, gbr = tot.Gate_BLOCK_or_REVIEW, sb = tot.SAST_B;
  const verdicts = runs.reduce((m, r) => (m[r.verdict] = (m[r.verdict] || 0) + 1, m), {});
  const top = flagged(runs).slice(0, 8);
  const ev = data.evaluation;
  const go = (screen, p={}) => `data-action="screen" data-screen="${screen}" data-patch="${patch(p)}"`;

  const kpis = [
    kpi({label:'Đơn vị bị chặn (BLOCK)', value:int(dc.BLOCK), unit:`/ ${int(units)}`, iconName:'octagon-x', tone:'red',
      note:`${int(verdicts.BLOCK || 0)}/${runs.length} lượt quét có kết luận BLOCK`, action:go('alerts', {decision:'BLOCK'}), link:'Xem đơn vị bị chặn'}),
    kpi({label:'Cần người xem (REVIEW)', value:int(dc.REVIEW), unit:`/ ${int(units)}`, iconName:'eye', tone:'amber',
      note:'Chỉ một luồng báo (audit), CodeBERT báo riêng hoặc hai luồng khác lớp', action:go('alerts', {decision:'REVIEW'}), link:'Xem danh sách REVIEW'}),
  ];
  if (gb) {
    kpis.push(kpi({label:'Lỗ hổng thật bị chặn đúng lớp', value:int(gb.tp), unit:`/ ${int(gb.gt)}`, iconName:'badge-check', tone:'green',
      note:`Gate BLOCK theo ground truth (${pct(gb.tp / gb.gt, 0)}). BLOCK + REVIEW: ${ratio(gbr.tp, gbr.gt)}; Semgrep đơn lẻ: ${ratio(sb.tp, sb.gt)}`,
      action:go('evaluation', {tab:'targets'}), link:'Bảng đối chiếu ground truth'}));
    kpis.push(kpi({label:'Hàm an toàn bị chặn nhầm', value:int(gb.flagged_safe), unit:`/ ${int(gb.safe)}`, iconName:'circle-alert', tone:'violet',
      note:`${pct(gb.flagged_safe / gb.safe)} hàm an toàn bị BLOCK. Semgrep đơn lẻ báo ${ratio(sb.flagged_safe, sb.safe)}; BLOCK + REVIEW: ${ratio(gbr.flagged_safe, gbr.safe)}`,
      action:go('alerts', {decision:'flagged', gt:'fp'}), link:'Xem báo nhầm'}));
  } else {
    kpis.push(kpi({label:'Không cảnh báo (PASS)', value:int(dc.PASS), unit:`/ ${int(units)}`, iconName:'circle-check', tone:'green', note:'Không luồng nào báo'}));
    kpis.push(kpi({label:'Lượt quét', value:int(runs.length), iconName:'activity', note:'Chưa có ground truth cho phạm vi này'}));
  }

  const appRows = runs.map(r => {
    const d = r.summary?.decisions || {}, total = r.summary?.units || 0;
    const m = r.eval ? Object.fromEntries(r.eval.methods.map(x => [x.method, x])) : null;
    return `<tr class="clickable" data-action="screen" data-screen="monitoring" data-patch="${patch({run:r.id})}">
      <td><span class="strong">${esc(appName(data, r))}</span><span class="sub">${esc(r.app ? APP_LANG[r.app] || r.languages.join(', ') : r.languages.join(', '))}${state.config === 'all' ? ` · ${esc(r.tag || r.config_id)}` : ''}</span></td>
      <td>${decisionBadge(r.verdict)}</td>
      <td class="num">${int(total)}</td>
      <td style="min-width:140px">${stackBar([{name:'BLOCK', value:d.BLOCK || 0, color:'var(--crit)'}, {name:'REVIEW', value:d.REVIEW || 0, color:'var(--warn)'}, {name:'PASS', value:d.PASS || 0, color:'#2a3656'}], total, appName(data, r))}
        <span class="sub">${int(d.BLOCK || 0)} BLOCK · ${int(d.REVIEW || 0)} REVIEW · ${int(d.PASS || 0)} PASS</span></td>
      <td class="num">${m ? `${int(m.Gate_BLOCK.tp)}/${int(m.Gate_BLOCK.gt)}` : '—'}<span class="sub">${m ? `${int(m.Gate_BLOCK.flagged_safe)}/${int(m.Gate_BLOCK.safe)} an toàn bị chặn` : 'không có GT'}</span></td>
      <td class="num">${sec(r.timing?.total_s)}</td></tr>`;
  }).join('');

  const stParts = Object.entries(sc).map(([k, v]) => ({name:STATE_LABEL[k], value:v, color:STATE_COLOR[k]}));
  const model = ev.model, ver = ev.verifier, gate = ev.gate;

  return `<div class="page-head"><div><h1 class="page-title">Tổng quan bảo mật</h1>
      <p class="page-desc">${cfg ? esc(cfg.label) : 'Tất cả cấu hình'} · ${runs.length} lượt quét · ${int(units)} đơn vị code. Số liệu lấy trực tiếp từ JSON của <code>scan.py</code> và <code>09_eval_targets.py</code>.</p></div>
    <div class="actions"><button class="btn" ${go('comparison')}>${icon('git-compare-arrows')}So sánh lượt quét</button><button class="btn primary" ${go('alerts')}>${icon('shield-alert')}Mở cảnh báo</button></div></div>
  <div class="grid g4">${kpis.join('')}</div>
  <div class="space">${pipelineCard(data, sig)}</div>
  <div class="grid g-2-1 space">
    <div class="card"><div class="card-head"><div><h2>${icon('layout-list')}Kết quả từng ứng dụng</h2><p>Bấm một dòng để xem chi tiết lượt quét. Ground truth là nhãn viết tay của ứng dụng mục tiêu (không dùng để train hay chỉnh rule).</p></div></div>
      <div class="card-body table-wrap"><table class="t"><thead><tr><th>Ứng dụng</th><th>Kết luận</th><th class="num">Đơn vị</th><th>Quyết định Gate</th><th class="num">Gate BLOCK đúng lớp</th><th class="num">Thời gian</th></tr></thead><tbody>${appRows}</tbody></table></div></div>
    <div class="card"><div class="card-head"><div><h2>${icon('git-merge')}Hai luồng gặp nhau thế nào</h2><p>Trạng thái Compare của mọi đơn vị trong phạm vi.</p></div></div>
      <div class="card-body">${stackBar(stParts, units, 'Trạng thái Compare')}${legend(stParts.map(p => [p.color, `${p.name}: ${int(p.value)}`]))}
      <div class="divider" style="height:1px;background:var(--border);margin:16px 0"></div>
      <h3 style="font-size:13px;font-weight:650;margin-bottom:10px;display:flex;gap:8px;align-items:center">${icon('brain-circuit')}Mô hình trên tập val</h3>
      <div class="kv">
        <div><span>CodeBERT macro-F1</span><strong>${num(model?.val?.macro_f1, 3)}</strong></div>
        <div><span>Verifier ROC-AUC</span><strong>${num(ver?.val?.roc_auc, 3)}</strong></div>
        <div><span>Gate BLOCK (có lỗ hổng / sau vá)</span><strong>${pct((gate?.at_config || gate?.at_threshold)?.block_vuln)} / ${pct((gate?.at_config || gate?.at_threshold)?.block_patched)}</strong></div>
      </div>
      <button class="link space" ${go('evaluation', {tab:'model'})}>Xem đánh giá mô hình ${icon('arrow-up-right')}</button></div></div>
  </div>
  <div class="card space"><div class="card-head"><div><h2>${icon('siren')}Cảnh báo ưu tiên</h2><p>BLOCK trước, rồi theo điểm ưu tiên (mức nghiêm trọng × bằng chứng của hai luồng).</p></div>
    <div class="right"><button class="link" ${go('alerts')}>Tất cả ${int(dc.BLOCK + dc.REVIEW)} cảnh báo ${icon('arrow-up-right')}</button></div></div>
    <div class="card-body table-wrap">${top.length ? `<table class="t"><thead><tr><th>Ưu tiên</th><th>Đơn vị</th><th>Lớp</th><th>Nguồn</th><th>Gate</th><th>Ground truth</th></tr></thead><tbody>${top.map(u => `
      <tr class="clickable" data-action="screen" data-screen="alerts" data-patch="${patch({unit:u.key})}">
        <td><span class="prio ${esc(u.priority?.level || 'none')}">${esc(u.priority?.level || '—')}</span></td>
        <td><span class="strong">${esc(unitName(u))}</span><span class="sub mono">${esc(appName(data, u.run))} · ${esc(unitLoc(u))}</span></td>
        <td>${esc(cls(u.vuln_class))}<span class="sub">${esc(u.cwe || '')}</span></td>
        <td>${esc(sourceLabel(u))}</td><td>${decisionBadge(u.decision)}</td><td>${gtBadge(u) || badge('—', 'b-outline')}</td></tr>`).join('')}</tbody></table>`
      : `<div class="empty">${icon('shield-check')}<strong>Không có cảnh báo</strong></div>`}</div></div>`;
}
