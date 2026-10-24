// Điều phối: tải dữ liệu thật từ /api/data, trạng thái trên URL (#màn-hình?...), vẽ khung và màn hình.
import { esc, icon, fmtDate, appName } from './ui.js';
import { renderOverview } from './overview.js';
import { renderAlerts, alertsAfter, exportAlerts } from './alerts.js';
import { flagged as flaggedUnits } from './agg.js';
import { renderEvaluation } from './evaluation.js';
import { renderMonitoring } from './monitoring.js';
import { renderComparison, exportComparison } from './comparison.js';
import { renderConfig, openRule } from './config.js';

const SCREENS = [
  ['overview', 'Tổng quan', 'layout-dashboard', renderOverview],
  ['alerts', 'Cảnh báo bảo mật', 'shield-alert', renderAlerts],
  ['evaluation', 'Đánh giá mô hình', 'brain-circuit', renderEvaluation],
  ['monitoring', 'Giám sát lượt quét', 'activity', renderMonitoring],
  ['comparison', 'So sánh lượt quét', 'git-compare-arrows', renderComparison],
  ['config', 'Cấu hình & Rule', 'settings-2', renderConfig],
];
const DEFAULT = {screen:'overview', config:'', app:'all', unit:'', run:'', repo:'', base:'', target:'', cmp:'changed', tab:'model',
  decision:'flagged', cls:'all', lang:'all', state:'all', gt:'all', q:'',
  ctab:'versions', rlang:'all', rcls:'all', rtier:'all', rkind:'all', rq:'', dsplit:'train', gtapp:''};
const app = document.querySelector('#app');
const tooltip = document.querySelector('#tooltip');
let data = null, dataVersion = '', state = {...DEFAULT}, loadError = '', loading = false;

// ------------------------------------------------------------------ trạng thái URL
function readHash() {
  const [screen, query=''] = location.hash.replace(/^#\/?/, '').split('?');
  const p = new URLSearchParams(query);
  const s = {...DEFAULT};
  if (SCREENS.some(([id]) => id === screen)) s.screen = screen;
  for (const k of Object.keys(DEFAULT)) if (k !== 'screen' && p.has(k)) s[k] = p.get(k);
  return s;
}
function writeHash(replace=false) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(state)) if (k !== 'screen' && v !== DEFAULT[k] && v !== '') p.set(k, v);
  const h = `#/${state.screen}${p.toString() ? '?' + p : ''}`;
  if (h !== location.hash) (replace ? history.replaceState(null, '', h) : history.pushState(null, '', h));
}
export function setState(patch, {replace=false, scroll=false} = {}) {
  state = {...state, ...patch};
  writeHash(replace);
  render();
  if (scroll) window.scrollTo({top:0});
}

// ------------------------------------------------------------------ phạm vi
const appKey = r => r.app || `repo:${r.repo_name}`;
export function scopeRuns(d=data, s=state, {includeOld=false} = {}) {
  return d.runs.filter(r => (includeOld || !r.superseded) && (s.config === 'all' || r.config_id === s.config) && (s.app === 'all' || appKey(r) === s.app));
}
function ensureScope() {
  if (!data) return;
  const cur = data.configs.find(c => c.current) || data.configs[0];
  if (state.config !== 'all' && !data.configs.some(c => c.id === state.config)) state.config = cur ? cur.id : 'all';
  const apps = new Set(data.runs.filter(r => state.config === 'all' || r.config_id === state.config).map(appKey));
  if (state.app !== 'all' && !apps.has(state.app)) state.app = 'all';
}

// ------------------------------------------------------------------ khung
function shell(content) {
  const cfg = data.configs.find(c => c.id === state.config);
  const runsInCfg = data.runs.filter(r => state.config === 'all' || r.config_id === state.config);
  const apps = [...new Map(runsInCfg.map(r => [appKey(r), appName(data, r)])).entries()];
  const alerts = flaggedUnits(scopeRuns()).length;
  const title = SCREENS.find(([id]) => id === state.screen)[1];
  const p = data.project, sig = p.current_signature;
  return `<div class="shell">
  <aside class="sidebar" aria-label="Điều hướng">
    <a class="brand" href="#/overview" data-action="screen" data-screen="overview"><span class="brand-mark">${icon('shield-check')}</span>
      <span class="brand-copy"><span class="brand-name">AI-WhiteSec-CI</span><span class="brand-sub">Semgrep ∥ CodeBERT</span></span></a>
    <div class="nav-label">KẾT QUẢ</div>
    <nav class="nav">${SCREENS.map(([id, label, ic]) => `<button class="nav-item${state.screen === id ? ' active' : ''}" data-action="screen" data-screen="${id}" title="${label}"${state.screen === id ? ' aria-current="page"' : ''}>${icon(ic)}<span class="nav-text">${label}</span>${id === 'alerts' && alerts ? `<span class="badge b-review count">${alerts}</span>` : ''}</button>`).join('')}</nav>
    <div class="sidebar-stack" data-action="screen" data-screen="config" role="button" tabindex="0" title="Xem phiên bản, ngưỡng và rule" style="cursor:pointer"><strong>Cấu hình đã chốt</strong>
      <div class="row"><span class="dot" style="background:var(--s2)"></span>Semgrep CE v${esc(p.ruleset.version)} · ${esc(p.ruleset.n_rules)} rule</div>
      <div class="row"><span class="dot" style="background:var(--s1)"></span>${esc((sig.model_dir || '').split('/').pop())} + verifier ≥ ${esc(sig.verifier_threshold ?? '—')}</div>
      <div class="row"><span class="dot" style="background:var(--accent)"></span>Security Gate v${esc(p.gate.version)}</div>
    </div>
  </aside>
  <div class="workspace">
    <header class="topbar">
      <div class="crumb">AI-WhiteSec-CI ${icon('chevron-right')}<strong>${title}</strong></div>
      <div class="scope">
        <label class="field"><span>Cấu hình pipeline</span><select data-bind="config" aria-label="Cấu hình pipeline">
          ${data.configs.map(c => `<option value="${esc(c.id)}"${c.id === state.config ? ' selected' : ''}>${c.current ? '★ ' : ''}${esc(c.label)}</option>`).join('')}
          <option value="all"${state.config === 'all' ? ' selected' : ''}>Tất cả cấu hình</option></select></label>
        <label class="field"><span>Ứng dụng / repo</span><select data-bind="app" aria-label="Ứng dụng">
          <option value="all">Tất cả (${apps.length})</option>${apps.map(([k, n]) => `<option value="${esc(k)}"${k === state.app ? ' selected' : ''}>${esc(n)}</option>`).join('')}</select></label>
        <button class="btn small ghost" data-action="refresh" title="Đọc lại file kết quả"${loading ? ' disabled' : ''}>${icon('refresh-cw')}Làm mới</button>
      </div>
    </header>
    <main class="main" id="main" tabindex="-1">
      ${cfg && !cfg.current ? `<div class="notice warn" style="margin-bottom:16px">${icon('history')}<span>Đang xem <b>cấu hình cũ</b>: ${esc(cfg.label)}. Cấu hình hiện tại: ${esc(p.current_label)}.</span></div>` : ''}
      ${loadError ? `<div class="notice warn" style="margin-bottom:16px">${icon('wifi-off')}<span>${esc(loadError)} Đang hiển thị lần đọc gần nhất.</span></div>` : ''}
      ${content}
    </main>
    <footer class="footer"><span>Semgrep CE ∥ CodeBERT (+ verifier) → Compare → Security Gate · chỉ kết quả thực nghiệm, tập test chưa dùng (J01)</span>
      <span>Đọc lúc ${fmtDate(data.generated_at)} · ${data.runs.length} lượt quét</span></footer>
  </div></div>`;
}

function render() {
  if (!data) {
    app.innerHTML = loadError ? `<div class="empty" style="padding-top:20vh">${icon('server-off')}<strong>Không đọc được kết quả</strong>${esc(loadError)}<br><button class="btn space" data-action="refresh">${icon('refresh-cw')}Thử lại</button></div>` : app.innerHTML;
    window.lucide?.createIcons({attrs:{'stroke-width':1.75}});
    return;
  }
  ensureScope();
  const renderer = SCREENS.find(([id]) => id === state.screen)[3];
  let content;
  try {
    content = renderer(data, state, {scopeRuns, setState});
  } catch (err) {
    console.error(err);
    content = `<div class="card empty">${icon('bug')}<strong>Lỗi hiển thị màn hình</strong>${esc(err.message)}</div>`;
  }
  app.innerHTML = shell(content);
  window.lucide?.createIcons({attrs:{'stroke-width':1.75}});
  if (state.screen === 'alerts') alertsAfter(data, state);
  document.title = `${SCREENS.find(([id]) => id === state.screen)[1]} · AI-WhiteSec-CI`;
}

async function load() {
  loading = true;
  try {
    const res = await fetch('/api/data', {cache:'no-store'});
    if (!res.ok) throw new Error(`Server trả HTTP ${res.status}.`);
    const json = await res.json();
    if (json.schema !== 'aiws-dashboard/1.0') throw new Error('Dữ liệu không đúng schema dashboard.');
    data = json; dataVersion = res.headers.get('X-Data-Version') || ''; loadError = '';
  } catch (err) {
    loadError = err.message === 'Failed to fetch' ? 'Không kết nối được server dashboard (đã tắt cửa sổ chạy server?).' : err.message;
  } finally {
    loading = false;
  }
  render();
}

// ------------------------------------------------------------------ sự kiện
document.addEventListener('click', e => {
  if (e.target.classList?.contains('modal-backdrop')) { document.querySelector('#overlay').innerHTML = ''; return; }
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const a = el.dataset.action;
  if (el.tagName === 'A') e.preventDefault();
  if (a === 'screen') setState({screen:el.dataset.screen, ...(el.dataset.patch ? JSON.parse(el.dataset.patch) : {})}, {scroll:true});
  else if (a === 'set') setState(JSON.parse(el.dataset.patch), {replace:el.dataset.replace === '1'});
  else if (a === 'refresh') { load(); toast('Đang đọc lại file kết quả…'); }
  else if (a === 'export-alerts') exportAlerts(data, state, scopeRuns());
  else if (a === 'export-compare') exportComparison(data, state);
  else if (a === 'close-modal') document.querySelector('#overlay').innerHTML = '';
  else if (a === 'rule') openRule(data, el.dataset.id, el.dataset.disabled === '1');
});
document.addEventListener('change', e => {
  const el = e.target.closest('[data-bind]');
  if (!el) return;
  const patch = {[el.dataset.bind]: el.value};
  if (el.dataset.bind === 'config') Object.assign(patch, {unit:'', run:''});
  if (el.dataset.bind === 'repo') Object.assign(patch, {base:'', target:''});
  setState(patch);
});
let qTimer;
document.addEventListener('input', e => {
  const el = e.target.closest('[data-input]');
  if (!el) return;
  clearTimeout(qTimer);
  qTimer = setTimeout(() => {
    const pos = el.selectionStart;
    setState({[el.dataset.input]: el.value}, {replace:true});
    const again = document.querySelector(`[data-input="${el.dataset.input}"]`);
    if (again) { again.focus(); again.setSelectionRange(pos, pos); }
  }, 250);
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { document.querySelector('#overlay').innerHTML = ''; tooltip.hidden = true; }
});
function showTip(el, x, y) {
  tooltip.innerHTML = el.dataset.tip;
  tooltip.hidden = false;
  const r = tooltip.getBoundingClientRect();
  tooltip.style.left = `${Math.min(window.innerWidth - r.width - 12, x + 14)}px`;
  tooltip.style.top = `${Math.max(8, Math.min(window.innerHeight - r.height - 12, y + 14))}px`;
}
document.addEventListener('mousemove', e => {
  const el = e.target.closest?.('[data-tip]');
  if (el && el.dataset.tip) showTip(el, e.clientX, e.clientY); else tooltip.hidden = true;
});
document.addEventListener('focusin', e => {
  const el = e.target.closest?.('[data-tip]');
  if (el && el.dataset.tip) { const r = el.getBoundingClientRect(); showTip(el, r.left, r.bottom); }
});
document.addEventListener('scroll', () => { tooltip.hidden = true; }, {passive:true});
window.addEventListener('popstate', () => { state = readHash(); render(); });
window.addEventListener('hashchange', () => { state = readHash(); render(); });
window.addEventListener('focus', async () => {
  if (!data || loading) return;
  try {
    const v = await (await fetch('/api/version', {cache:'no-store'})).json();
    if (v.version !== dataVersion) { await load(); toast('Đã cập nhật kết quả mới.'); }
  } catch { /* server đã tắt: giữ dữ liệu cũ */ }
});

function toast(msg) {
  const t = document.querySelector('#toast');
  t.textContent = msg; t.classList.add('visible');
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove('visible'), 2600);
}

state = readHash();
load();
