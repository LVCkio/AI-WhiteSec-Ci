import { esc, icon, badge, fmtDate, timeAgo, runStatus } from './ui.js';
import { createDemo } from './demo.js';
import { adaptAudit } from './adapter.js';
import { renderOverview } from './overview.js';
import { renderAlerts } from './alerts.js';
import { renderEvaluation } from './evaluation.js';
import { renderMonitoring } from './monitoring.js';
import { renderComparison, ensureComparisonSelection, compareRuns } from './comparison.js';

const screens = [
  ['overview','Tổng quan','layout-dashboard'], ['alerts','Cảnh báo bảo mật','shield-alert'],
  ['evaluation','Đánh giá mô hình','brain-circuit'], ['monitoring','Giám sát CI/CD','workflow'],
  ['comparison','So sánh lượt quét','git-compare-arrows'],
];
let data = createDemo();
let rawAudit = null;
let apiKey = ''; // Intentionally memory only: no URL, cookie or browser storage.
let requestVersion = 0;
let updating = false;
let connectionError = '';
let lastFocus = null;
const state = {screen:'overview',project:'all',runId:'M-105',period:'24h',runStatus:'all',
  taskId:'codebert',findingId:'F-001',alertTab:'overview',
  compareBaseId:null,compareTargetId:null,compareFilter:'all',focusSince:null,
  filters:{project:'all',severity:'all',cwe:'all',source:'all',verification:'all'}};
const app = document.querySelector('#app');
const overlay = document.querySelector('#overlay');

function icons() { window.lucide?.createIcons({attrs:{'stroke-width':1.7}}); }
function selectedRun() { return data.runs.find(run=>run.id===state.runId); }
function ensureSelection() {
  if (!data.projects.some(project=>project.id===state.project)) state.project='all';
  const scoped=data.runs.filter(run=>(state.project==='all'||run.projectId===state.project)
    && (state.screen!=='monitoring'||state.runStatus==='all'||runStatus(run).code===state.runStatus||run.decision===state.runStatus)
    && (state.screen!=='monitoring'||!state.focusSince||!Number.isFinite(Date.parse(run.createdAt))||Date.parse(run.createdAt)>=Date.parse(state.focusSince)));
  if (!scoped.some(run=>run.id===state.runId)) state.runId=scoped[0]?.id || null;
  if (!data.findings.some(finding=>finding.id===state.findingId)) state.findingId=data.findings[0]?.id || null;
  if (state.screen==='alerts') {
    const filters=state.filters;
    const rank={critical:0,high:1,medium:2,low:3,info:4,unknown:5};
    const visible=data.findings.filter(finding=>(state.project==='all'||finding.projectId===state.project)
      && (filters.project==='all'||finding.projectId===filters.project)
      && (filters.severity==='all'||finding.severity===filters.severity||filters.severity==='critical-high'&&['critical','high'].includes(finding.severity))
      && (filters.cwe==='all'||finding.cwes.includes(filters.cwe))
      && (filters.source==='all'||finding.source===filters.source)
      && (filters.verification==='all'||finding.verification===filters.verification||filters.verification==='actionable'&&!['false-positive','refuted'].includes(finding.verification))
      && (!state.focusSince||!Number.isFinite(Date.parse(data.runs.find(run=>run.id===finding.runId)?.createdAt))||Date.parse(data.runs.find(run=>run.id===finding.runId)?.createdAt)>=Date.parse(state.focusSince)))
      .sort((a,b)=>(rank[a.severity]??5)-(rank[b.severity]??5));
    const selected=visible.find(finding=>finding.id===state.findingId)||visible[0];
    if(selected){state.findingId=selected.id;state.runId=selected.runId;}
  }
}
function render() {
  ensureSelection();
  if(state.screen==='comparison'){const selection=ensureComparisonSelection(data,state);if(selection.target)state.runId=selection.target.id;}
  const run=selectedRun();
  const demo=data.source==='demo';
  const title=screens.find(([id])=>id===state.screen)?.[1] || 'Tổng quan';
  const renderScreen={overview:renderOverview,alerts:renderAlerts,evaluation:renderEvaluation,monitoring:renderMonitoring,comparison:renderComparison}[state.screen];
  app.innerHTML=`<div class="app-shell">
    <aside class="sidebar" aria-label="Điều hướng dashboard">
      <a class="brand" href="#overview" data-action="screen" data-screen="overview" aria-label="AI WhiteSec CI Tổng quan"><span class="brand-mark">${icon('shield-check')}</span><span class="brand-copy">AI WhiteSec<span class="brand-subtitle">CI SECURITY PLATFORM</span></span></a>
      <div class="nav-label">WORKSPACE</div><nav class="sidebar-nav">${screens.map(([id,label,symbol])=>`<button class="nav-item${state.screen===id?' active':''}" data-action="screen" data-screen="${id}" aria-label="${label}"${state.screen===id?' aria-current="page"':''}>${icon(symbol)}<span class="nav-text">${label}</span>${id==='alerts'&&data.findings.length?`<span class="badge badge-warning nav-count">${data.findings.length}</span>`:''}</button>`).join('')}</nav>
      <div class="sidebar-caption"><span class="sidebar-system-dot"></span>Gateway Security Gate<br><span>Hai detector · một quyết định</span></div>
      <div class="sidebar-spacer"></div><div class="sidebar-footer"><span class="avatar">OP</span><span class="user-copy"><strong>Operator</strong><small>Nhóm vận hành</small></span></div>
    </aside>
    <div class="workspace">
      <div class="demo-banner${demo?'':' live-banner'}">${icon(demo?'triangle-alert':'database')}<strong>${demo?'DỮ LIỆU MINH HỌA':'AUDIT TỪ GATEWAY LOCAL'}</strong><span>— ${demo?'Không phải kết quả thực nghiệm':'Mode của từng run được ghi riêng · kết quả demo không cho phép deploy'}</span></div>
      <header class="header"><div class="breadcrumb"><span class="header-product">AI WhiteSec CI</span>${icon('chevron-right')}<strong>${title}</strong></div><div class="header-meta"><span class="header-trace optional mono" title="${esc(run?.repo || '')}">${icon('folder-git-2')}${esc(run?.repo || 'Chưa có repository')}</span><span class="optional mono">${icon('git-branch')}${esc(run?.branch || 'Chưa ghi nhận')}</span><span class="optional mono">${icon('git-commit-horizontal')}${esc(run?.commit?.slice(0,7) || '—')}</span><button class="header-run mono" data-action="run" data-run="${esc(run?.id || '')}">${esc(run?.id || '—')}</button><span class="last-updated optional">${icon('clock-3')}${timeAgo(data.generatedAt)}</span><button class="btn small source-button" data-action="connection">${icon(demo?'database':'plug-zap')}<span>${demo?'Dữ liệu minh họa':'API local'}</span></button><button class="btn icon-only" data-action="refresh" aria-label="Làm mới dữ liệu" title="Làm mới dữ liệu"${updating?' disabled':''}>${icon('refresh-cw')}</button></div></header>
      <main class="main-content" id="main" tabindex="-1">${connectionError?`<div class="notice connection-error" role="alert">${icon('wifi-off')}<span>${esc(connectionError)} Dữ liệu hiển thị là lần tải thành công gần nhất.</span><button class="btn small" data-action="connection">Kết nối lại</button></div>`:''}${data.warnings.length?`<div class="notice audit-warning">${icon('info')}<span>${data.warnings.map(esc).join(' · ')}</span></div>`:''}${renderScreen(data,state)}</main>
      <footer class="app-footer"><span>Checkmarx ∥ CodeBERT → Gateway → Security Gate</span><span>${demo?'UI fixture · local preview':`Audit cập nhật ${fmtDate(data.generatedAt)}`}</span></footer>
    </div></div>`;
  icons();
}
function toast(message) {
  const element=document.querySelector('#toast');
  element.textContent=message;element.classList.add('visible');
  clearTimeout(toast.timer);toast.timer=setTimeout(()=>element.classList.remove('visible'),4000);
}
function closeModal() {overlay.innerHTML='';lastFocus?.focus();}
function modal(title,body) {
  lastFocus=document.activeElement;
  overlay.innerHTML=`<div class="modal-backdrop" data-backdrop="true"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="dialog-title"><header class="modal-header"><h2 id="dialog-title">${esc(title)}</h2><button class="btn icon-only" data-action="close-modal" aria-label="Đóng">${icon('x')}</button></header><div class="modal-body">${body}</div></section></div>`;
  icons();overlay.querySelector('input,button')?.focus();
}
function connectionModal() {
  modal('Nguồn dữ liệu dashboard',`<div class="source-options"><div class="source-option"><span class="source-symbol">${icon('flask-conical')}</span><div><h3>Dữ liệu minh họa</h3><p>Fixture riêng để xem đủ màn hình; mọi run đều không cho phép deploy.</p></div><button class="btn" data-action="demo">${data.source==='demo'?'Đang sử dụng':'Dùng minh họa'}</button></div><div class="source-option"><span class="source-symbol">${icon('server')}</span><div><h3>Gateway local</h3><p>Đọc audit trên cùng máy và cùng origin với dashboard.</p></div>${data.source==='live'?badge('Đã kết nối','success'):badge('Chưa kết nối','muted')}</div></div>
    <form id="connect-form" autocomplete="off"><label class="key-label" for="gateway-key">Gateway API key</label><input class="key-input" id="gateway-key" name="gateway-key" type="password" autocomplete="off" spellcheck="false" required placeholder="Nhập GATEWAY_API_KEY của phiên local"><p class="form-note">Key chỉ giữ trong bộ nhớ tab; tải lại trang cần nhập lại. Request gửi đến ${esc(location.origin)}.</p><div class="notice">${icon('info')}<span>Lấy key từ biến <code>GATEWAY_API_KEY</code> trong PowerShell đã chạy hệ thống. Nếu Gateway vừa đổi code, khởi động lại hai service trước khi kết nối.</span></div><p class="form-error" role="alert" id="connect-error"></p><div class="modal-actions"><button class="btn" type="button" data-action="close-modal">Đóng</button><button class="btn primary" type="submit">${icon('plug-zap')}Kết nối API local</button></div></form>`);
}
async function fetchAudit(key) {
  const controller=new AbortController();
  const timer=setTimeout(()=>controller.abort(),15000);
  try {
    const response=await fetch('/v1/dashboard/export',{headers:{'X-API-Key':key},cache:'no-store',credentials:'omit',signal:controller.signal});
    if (!response.ok) {
      if(response.status===401||response.status===403)throw new Error('Gateway API key chưa đúng.');
      if(response.status===404)throw new Error('Gateway chưa có dashboard API. Hãy khởi động lại service với code mới.');
      throw new Error(`Gateway trả HTTP ${response.status}.`);
    }
    const payload=await response.json();
    if(payload.schema_version!=='1.0'||!Array.isArray(payload.runs)||!Array.isArray(payload.details))throw new Error('Dashboard API trả dữ liệu không đúng schema.');
    return payload;
  } catch(error) {if(error.name==='AbortError')throw new Error('Gateway chưa phản hồi trong 15 giây.');throw error;}
  finally {clearTimeout(timer);}
}
async function connect(event) {
  event.preventDefault();
  const form=event.target;
  const key=form.elements['gateway-key'].value.trim();
  if(!key)return;
  const button=form.querySelector('[type="submit"]');
  const error=form.querySelector('#connect-error');
  button.disabled=true;error.textContent='';
  const version=++requestVersion;
  try {
    const payload=await fetchAudit(key);
    if(version!==requestVersion)return;
    apiKey=key;rawAudit=payload;data=adaptAudit(payload);connectionError='';
    form.reset();closeModal();render();toast(`Đã đọc ${data.runs.length} run từ Gateway local.`);
  } catch(problem) {if(version===requestVersion&&error.isConnected)error.textContent=problem.message;}
  finally {if(button.isConnected)button.disabled=false;}
}
async function refresh(silent=false) {
  if(updating)return;
  if(data.source==='demo') {if(!silent)toast('Đang xem fixture minh họa. Chọn API local để đọc run của hệ thống.');return;}
  if(!apiKey){if(!silent)connectionModal();return;}
  updating=true;
  const version=++requestVersion;
  try {
    const payload=await fetchAudit(apiKey);
    if(version!==requestVersion)return;
    rawAudit=payload;data=adaptAudit(payload);connectionError='';render();
    if(!silent)toast('Đã làm mới audit local.');
  }catch(error){if(version===requestVersion){connectionError=error.message;render();}}
  finally {updating=false;}
}
function navigate(screen) {
  if(!screens.some(([id])=>id===screen))return;
  state.screen=screen;render();window.scrollTo({top:0});
}
function exportAudit(target) {
  const finding=data.findings.find(item=>item.id===target.dataset.finding);
  const payload=target.dataset.export==='evidence'&&finding?{
    source:data.source,generated_at:data.generatedAt,finding,
    run:data.runs.find(run=>run.id===finding.runId),detail:data.details[finding.runId],
  }:rawAudit||{source:'demo',note:'UI fixture, không phải kết quả thực nghiệm',...data};
  const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;
  link.download=finding?'whitesec-evidence.json':`whitesec-${data.source}-audit.json`;
  document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast('Đã xuất JSON audit của nguồn dữ liệu đang chọn.');
}
function exportComparison() {
  const comparison=compareRuns(data,state.compareBaseId,state.compareTargetId);
  if(!comparison.valid){toast('Chọn hai lượt quét cùng dự án để xuất so sánh.');return;}
  const payload={source:data.source,generated_at:new Date().toISOString(),
    note:'So sánh theo metadata và vị trí được ghi nhận. Không còn ghi nhận không chứng minh đã sửa lỗi.',comparison};
  const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;link.download='whitesec-comparison.json';
  document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  toast('Đã xuất báo cáo so sánh hai lượt quét.');
}
function focusOverview(value) {
  const reference=Date.parse(data.generatedAt)||Date.now();
  state.focusSince=new Date(reference-({'24h':1,'7d':7,'30d':30}[state.period]||1)*86400000).toISOString();
  if(value==='risk'){
    state.filters={project:'all',severity:'critical-high',cwe:'all',source:'all',verification:'actionable'};
    state.alertTab='overview';navigate('alerts');
  }else if(['BLOCK','REVIEW','pending'].includes(value)){
    state.runStatus=value;navigate('monitoring');
  }
}
function profile(id) {
  const project=data.projects.find(item=>item.id===id);if(!project)return;
  const runs=data.runs.filter(run=>run.projectId===id);
  modal('Hồ sơ dự án',`<div class="profile-head">${icon('folder-git-2')}<h3>${esc(project.name)}</h3>${badge(data.source==='demo'?'DEMO':'AUDIT LOCAL',data.source==='demo'?'warning':'info')}</div><dl class="profile-grid">${[['Repository',project.repo],['Framework',project.framework],['Phụ trách',project.owner],['Môi trường',project.environment],['Số run',runs.length],['Branch gần nhất',runs[0]?.branch||'Chưa ghi nhận']].map(([label,value])=>`<div><dt>${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl><div class="notice">${icon('workflow')}<span>Checkmarx và CodeBERT phân tích cùng snapshot song song. Gateway hợp nhất hai nhánh và Security Gate quyết định.</span></div><div class="modal-actions"><button class="btn primary" data-action="monitor" data-project="${esc(id)}" data-run="${esc(runs[0]?.id||'')}">Xem giám sát</button></div>`);
}
function modelInfo() {
  modal('Metadata mô hình',`<p class="form-note">Metadata lấy từ audit đã ghi nhận; chưa xác nhận readiness hiện tại hoặc hiệu năng trên tập held-out.</p><pre class="code-block">${esc(JSON.stringify(data.model,null,2))}</pre><div class="modal-actions"><button class="btn" data-action="screen" data-screen="evaluation">Đánh giá mô hình</button></div>`);
}
async function action(target) {
  const {action:kind,value,run:runId,project,finding}=target.dataset;
  if(kind==='screen'){state.focusSince=null;closeModal();navigate(target.dataset.screen);}
  else if(kind==='connection')connectionModal();
  else if(kind==='close-modal')closeModal();
  else if(kind==='demo'){requestVersion++;apiKey='';rawAudit=null;connectionError='';updating=false;data=createDemo();state.project='all';state.runId='M-105';state.findingId='F-001';state.compareBaseId=null;state.compareTargetId=null;state.focusSince=null;closeModal();render();}
  else if(kind==='refresh')await refresh();
  else if(kind==='period'){state.period=value;render();}
  else if(kind==='overview-focus')focusOverview(target.dataset.focus);
  else if(kind==='clear-overview-focus'){state.focusSince=null;render();}
  else if(kind==='compare'){state.focusSince=null;if(project)state.project=project;if(runId){state.compareTargetId=runId;state.compareBaseId=null;const selected=data.runs.find(run=>run.id===runId);if(selected)state.project=selected.projectId;}state.compareFilter='all';navigate('comparison');}
  else if(kind==='compare-filter'){state.compareFilter=value;render();}
  else if(kind==='compare-swap'){[state.compareBaseId,state.compareTargetId]=[state.compareTargetId,state.compareBaseId];render();}
  else if(kind==='compare-export')exportComparison();
  else if(kind==='run'||kind==='monitor'){state.focusSince=null;if(project)state.project=project;if(runId)state.runId=runId;const chosen=data.runs.find(run=>run.id===runId);if(kind==='monitor'||state.screen!=='monitoring'||chosen&&state.runStatus!=='all'&&chosen.decision!==state.runStatus&&runStatus(chosen).code!==state.runStatus)state.runStatus='all';state.taskId='codebert';closeModal();navigate('monitoring');}
  else if(kind==='profile')profile(project);
  else if(kind==='task'){state.taskId=target.dataset.task;render();}
  else if(kind==='event'){state.eventId=target.dataset.event;render();}
  else if(kind==='finding'){const selected=data.findings.find(item=>item.id===finding);if(selected){state.findingId=finding;state.runId=selected.runId;if(state.screen!=='alerts'||target.dataset.evidenceLink==='true'){state.focusSince=null;state.project='all';state.filters={project:'all',severity:'all',cwe:'all',source:'all',verification:'all'};}state.alertTab='overview';navigate('alerts');}}
  else if(kind==='alert-tab'){state.alertTab=value;render();}
  else if(kind==='reset-filters'){state.focusSince=null;state.filters={project:'all',severity:'all',cwe:'all',source:'all',verification:'all'};render();}
  else if(kind==='review-demo'&&data.source==='demo'){const item=data.findings.find(item=>item.id===finding);if(item&&['confirmed','false-positive','unreviewed'].includes(value)){item.verification=value;render();toast('Đã đổi trạng thái fixture. Đây chỉ là thao tác minh họa.');}}
  else if(kind==='export')exportAudit(target);
  else if(kind==='model-info')modelInfo();
}
document.addEventListener('click',event=>{
  if(event.target.matches('[data-backdrop]')){closeModal();return;}
  const target=event.target.closest('[data-action]');
  if(!target||target.disabled||['alert-filter','project-filter','run-status-filter','compare-base','compare-target'].includes(target.dataset.action))return;
  event.preventDefault();action(target).catch(()=>toast('Thao tác chưa hoàn tất. Hãy thử lại.'));
});
document.addEventListener('change',event=>{
  const target=event.target;const kind=target.dataset.action;
  if(kind==='project-filter'){state.project=target.value;if(state.screen==='comparison'){state.compareBaseId=null;state.compareTargetId=null;state.compareFilter='all';}ensureSelection();render();}
  else if(kind==='run-status-filter'){state.runStatus=target.value;render();}
  else if(kind==='alert-filter'){state.filters[target.dataset.filter]=target.value;render();}
  else if(kind==='compare-base'){state.compareBaseId=target.value;state.compareFilter='all';render();}
  else if(kind==='compare-target'){state.compareTargetId=target.value;state.compareFilter='all';render();}
});
document.addEventListener('submit',event=>{if(event.target.id==='connect-form')connect(event);});
document.addEventListener('keydown',event=>{
  if(event.key==='Escape'&&overlay.children.length)closeModal();
  if(event.key==='Enter'&&event.target.matches('tr[data-action]')){event.preventDefault();action(event.target);}
  if(event.key==='Tab'&&overlay.children.length){const controls=[...overlay.querySelectorAll('button:not(:disabled),input,a[href]')];const first=controls[0],last=controls.at(-1);if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}}
});
setInterval(()=>{if(apiKey&&!document.hidden&&!overlay.children.length&&!document.activeElement?.matches('select,input'))refresh(true);},15000);
render();
