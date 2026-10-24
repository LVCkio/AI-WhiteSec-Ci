// Tiện ích hiển thị dùng chung. Mọi chuỗi từ dữ liệu đều đi qua esc() trước khi vào innerHTML.
export const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const icon = (name, cls='') => `<i data-lucide="${name}"${cls?` class="${cls}"`:''}></i>`;

const nf = new Intl.NumberFormat('vi-VN');
export const num = (v, d=0) => v==null || Number.isNaN(v) ? '—' : new Intl.NumberFormat('vi-VN',{minimumFractionDigits:d,maximumFractionDigits:d}).format(v);
export const int = v => v==null ? '—' : nf.format(v);
export const pct = (v, d=1) => v==null || Number.isNaN(v) ? '—' : `${num(v*100, d)}%`;
export const ratio = (a, b, d=0) => b ? `${int(a)}/${int(b)} (${num(100*a/b, d)}%)` : '—';
export const sec = v => v==null ? '—' : v < 1 ? `${num(v*1000,0)} ms` : v < 90 ? `${num(v, 1)} giây` : `${num(v/60, 1)} phút`;
export const fmtDate = iso => {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString('vi-VN',{hour:'2-digit',minute:'2-digit',day:'2-digit',month:'2-digit',year:'numeric'});
};

export const CLASS_LABEL = {
  SQL_INJECTION:'SQL Injection', XSS:'Cross-site Scripting (XSS)', OS_COMMAND_INJECTION:'OS Command Injection',
  PATH_TRAVERSAL:'Path Traversal', AUTHENTICATION_WEAKNESS:'Xác thực yếu', HARDCODED_CREDENTIALS:'Thông tin xác thực gắn cứng',
};
export const CLASS_SHORT = {
  SQL_INJECTION:'SQLi', XSS:'XSS', OS_COMMAND_INJECTION:'OS cmd', PATH_TRAVERSAL:'Path', AUTHENTICATION_WEAKNESS:'Auth', HARDCODED_CREDENTIALS:'Hardcoded',
};
export const cls = c => CLASS_LABEL[c] || c || '—';
export const STATE_LABEL = {
  agree:'Hai luồng cùng lớp', sast_only:'Chỉ Semgrep báo', codebert_only:'Chỉ CodeBERT báo', conflict:'Hai luồng khác lớp', pass:'Không luồng nào báo',
};
export const STATE_COLOR = {agree:'var(--s1)', sast_only:'var(--s2)', codebert_only:'var(--s3)', conflict:'#c98500', pass:'#2a3656'};
export const METHOD_LABEL = {
  SAST_B:'Semgrep (mọi finding)', SAST_high_only:'Semgrep tầng high', AI_verifier:'AI đơn lẻ (verifier)',
  CodeBERT_all_functions:'CodeBERT 6 lớp (mọi hàm)', Gate_BLOCK:'Gate BLOCK', Gate_BLOCK_or_REVIEW:'Gate BLOCK + REVIEW',
};
export const method = m => METHOD_LABEL[m] || m;
export const APP_LANG = {flask_vuln_app:'Python', dvwa:'PHP', webgoat:'Java', 'juice-shop':'JavaScript/TypeScript'};

export function decisionBadge(d) {
  if (d === 'BLOCK') return `<span class="badge b-block">${icon('octagon-x')}BLOCK</span>`;
  if (d === 'REVIEW') return `<span class="badge b-review">${icon('eye')}REVIEW</span>`;
  if (d === 'PASS') return `<span class="badge b-pass">${icon('circle-check')}PASS</span>`;
  return `<span class="badge b-muted">${esc(d || '—')}</span>`;
}
export const badge = (text, kind='b-muted', ic='') => `<span class="badge ${kind}">${ic?icon(ic):''}${esc(text)}</span>`;
export const tierBadge = t => t === 'high' ? badge('high', 'b-high', 'flame') : badge(t || 'audit', 'b-audit');
export function gtBadge(u) {
  const g = u.gt;
  if (!g) return '';
  if (g.status === 'safe') return u.decision === 'PASS' ? badge('An toàn (GT)', 'b-outline') : badge('Báo nhầm (GT)', 'b-crit', 'circle-alert');
  if (u.decision === 'PASS') return badge('Bỏ sót (GT)', 'b-crit', 'circle-off');
  return g.class_match ? badge('Đúng lớp (GT)', 'b-pass', 'badge-check') : badge('Sai lớp (GT)', 'b-review', 'shuffle');
}
export const sourceLabel = u => u.compare_state === 'agree' || u.compare_state === 'conflict' ? 'Semgrep + CodeBERT'
  : u.compare_state === 'sast_only' ? 'Semgrep' : u.compare_state === 'codebert_only' ? 'CodeBERT' : '—';

export function kpi({label, value, unit='', note='', iconName='activity', tone='', action='', link=''}) {
  const tag = action ? 'button' : 'div';
  return `<${tag} class="card kpi${action?' clickable':''}"${action?` ${action}`:''}>
    <div class="kpi-top"><span>${esc(label)}</span><span class="kpi-icon ${tone}">${icon(iconName)}</span></div>
    <div class="kpi-value">${value}${unit?`<small>${esc(unit)}</small>`:''}</div>
    ${note?`<div class="kpi-note">${note}</div>`:''}${link?`<div class="kpi-link">${esc(link)}${icon('arrow-up-right')}</div>`:''}
  </${tag}>`;
}
export const barCell = (v, max=1, color='var(--s1)', text=null) => {
  const w = v==null || !max ? 0 : Math.max(0, Math.min(100, 100*v/max));
  return `<div class="bar-cell"><div class="bar"><span style="width:${w}%;background:${color}"></span></div><b>${text ?? pct(v)}</b></div>`;
};
export function download(name, text, type='application/json') {
  const url = URL.createObjectURL(new Blob([text], {type}));
  const a = Object.assign(document.createElement('a'), {href:url, download:name});
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const csv = rows => rows.map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\r\n');
export const unitName = u => u.function === '<file>' ? u.file.split('/').pop() : u.function === '<module>' ? `${u.file.split('/').pop()} (mức module)` : u.function;
export const unitLoc = u => `${u.file}${u.lines ? `:${u.lines[0]}–${u.lines[1]}` : ''}`;
export const appName = (data, run) => run?.repo_name || data.project.apps?.[run?.app] || run?.app || '—';
export const runShort = (data, run) => {
  const c = data.configs.find(x => x.id === run.config_id);
  return `${appName(data, run)} · ${c?.current ? 'cấu hình hiện tại' : (run.tag || run.id)}`;
};
