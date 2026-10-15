import { esc, icon, timeAgo, runStatus } from './ui.js';

const safe = value => esc(value == null || value === '' ? '—' : value);
const asNumber = value => typeof value === 'number' && Number.isFinite(value) ? value : null;
const deployAllowed = run => run?.mode==='real'&&run?.status==='decided'&&run?.decision==='PASS'&&run?.allowDeploy===true;
const toneFor = decision => ({ PASS:'green', BLOCK:'red', REVIEW:'amber', ERROR:'red' }[decision] || 'blue');
const tag = (text,tone='neutral') => `<span class="badge ${tone}">${esc(text)}</span>`;
const heading = (title, symbol, right='') => `<div class="section-heading"><h2>${icon(symbol)}${esc(title)}</h2>${right}</div>`;
const empty = (title,description) => `<div class="empty-state">${icon('inbox')}<strong>${esc(title)}</strong>${esc(description)}</div>`;
const fmtDuration = seconds => seconds == null ? '—' : seconds >= 60 ? `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s` : `${Math.round(seconds)}s`;
const severityName = value => ({critical:'Nghiêm trọng',high:'Cao',medium:'Trung bình',low:'Thấp',info:'Thông tin',unknown:'Chưa rõ'}[value]||value||'Chưa rõ');
const sourceName = value => ({'Combined':'Hai bộ phân tích','Checkmarx only':'Chỉ Checkmarx','CodeBERT only':'Chỉ CodeBERT'}[value]||value);

function periodRuns(data,state){
  const runs = Array.isArray(data.runs) ? data.runs : [];
  const dates = runs.map(run => Date.parse(run.createdAt)).filter(Number.isFinite);
  const reference = Date.parse(data.generatedAt) || (dates.length ? Math.max(...dates) : Date.now());
  const days = { '24h':1,'7d':7,'30d':30 }[state.period] || 1;
  return runs.filter(run => {
    const time=Date.parse(run.createdAt);
    return (!state.project || state.project==='all' || run.projectId===state.project)
      && (!Number.isFinite(time) || time >= reference-days*86400000);
  });
}

function kpis(runs,findings,projects){
  const risk=findings.filter(finding=>['critical','high'].includes(finding.severity)
    && !['false-positive','refuted'].includes(finding.verification)).length;
  const values = [
    ['Cảnh báo rủi ro cao',risk,'Critical / High · chưa loại trừ','shield-alert','red','risk','Xem cảnh báo'],
    ['Lượt bị chặn',runs.filter(run=>run.decision==='BLOCK').length,'Gate BLOCK · cần kiểm tra','shield-x','red','BLOCK','Xem lượt bị chặn'],
    ['Cần xem xét',runs.filter(run=>run.decision==='REVIEW').length,'Gate REVIEW · cần đối chiếu','file-search','amber','REVIEW','Xem lượt cần review'],
    ['Đang chờ kết quả',runs.filter(run=>runStatus(run).code==='pending').length,'Chưa có quyết định cuối','clock-3','blue','pending','Theo dõi phân tích'],
  ];
  const summary=[
    ['Dự án trong phạm vi',projects.length,'folder-kanban'],
    ['Lượt quét trong kỳ',runs.length,'git-branch'],
    ['Lỗi phân tích',runs.filter(run=>runStatus(run).code==='error').length,'circle-x'],
    ['Cho phép deploy',runs.filter(deployAllowed).length,'shield-check'],
  ];
  return `<div class="overview-kpis" aria-label="Các mục cần chú ý">${values.map(([title,value,caption,symbol,tone,focus,cta])=>`<button class="card kpi-card ${tone}" data-action="overview-focus" data-focus="${focus}" aria-label="${esc(`${cta}: ${value}`)}"><span class="kpi-top"><span>${esc(title)}</span><span class="kpi-icon ${tone}">${icon(symbol)}</span></span><strong class="kpi-value">${esc(value)}</strong><span class="kpi-caption">${esc(caption)}</span><span class="kpi-link">${esc(cta)}${icon('arrow-up-right')}</span></button>`).join('')}</div><dl class="overview-summary">${summary.map(([label,value,symbol])=>`<div><dt>${icon(symbol)}${esc(label)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>`;
}

function projectCard(project,runs,findings,index,demo){
  const projectRuns = runs.filter(run => run.projectId===project.id || run.repo===project.repo);
  const latest = [...projectRuns].sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt))[0];
  const projectFindings = findings.filter(finding=>finding.projectId===project.id || projectRuns.some(run=>run.id===finding.runId));
  const phase = demo && project.phase ? project.phase : null;
  const completed = phase ? Math.max(0,Math.min(11,asNumber(phase.completed)||0)) : null;
  const progress = phase ? Math.round(completed/11*100) : null;
  const status = latest ? runStatus(latest) : null;
  const tones = ['blue','purple','cyan'];
  return `<article class="card project-card"><div class="project-card-head"><div class="project-symbol ${tones[index%3]}">${icon(['globe','layers','server'][index%3])}</div><div class="project-card-title"><h3>${safe(project.name)}</h3><span class="mono">${safe(project.repo)}</span></div>${demo ? tag('DỮ LIỆU MẪU','demo') : tag(project.environment||'Chưa rõ','neutral')}</div><div class="project-tags">${tag(project.framework||'Chưa rõ công nghệ','neutral')}${tag(project.environment||'Chưa rõ môi trường','outline')}</div><div class="project-meta"><span>${icon('user-round')} ${safe(project.owner)}</span><span>${icon('git-branch')} ${safe(latest?.branch)}</span></div><div class="project-phase"><div><span>${phase ? 'Tiến độ giai đoạn · mẫu' : 'Tiến độ giai đoạn'}</span><strong>${phase ? `${completed}/11` : 'Chưa báo cáo'}</strong></div><div class="progress-track ${completed===11?'green':''}"><span style="width:${progress||0}%"></span></div><p>${phase ? `P${Math.min(10,asNumber(phase.current)??completed)} · ${progress}% hoàn thành (mẫu)` : 'Chưa có tiến độ giai đoạn từ hệ thống thật'}</p></div><div class="project-numbers"><div><strong>${projectRuns.length}</strong><span>lượt chạy</span></div><div><strong class="${projectFindings.length?'text-red':''}">${projectFindings.length}</strong><span>phát hiện</span></div><div><strong>${projectRuns.filter(run=>run.decision==='PASS').length}</strong><span>Gate PASS</span></div></div><div class="project-latest"><span>Lượt gần nhất</span>${latest ? tag(status.label,toneFor(latest.decision)) : tag('Chưa có lượt chạy','neutral')}<span class="project-last-time">${latest ? esc(timeAgo(latest.createdAt)) : '—'}</span></div><div class="project-buttons"><button class="btn primary" data-action="monitor" data-project="${esc(project.id)}" ${latest?`data-run="${esc(latest.id)}"`:''}>${icon('workflow')} Giám sát CI/CD</button><button class="btn ghost" data-action="profile" data-project="${esc(project.id)}">${icon('external-link')} Hồ sơ dự án</button></div></article>`;
}

function incidents(data,findings,runs){
  const priorities = {critical:0,high:1,medium:2,low:3,info:4,unknown:5};
  const visible = [...findings].filter(finding=>!['false-positive','refuted'].includes(finding.verification)).sort((a,b)=>(priorities[a.severity]??5)-(priorities[b.severity]??5)).slice(0,4);
  return `<section class="overview-incidents section-space">${heading('Cảnh báo ưu tiên','shield-alert',`<button class="btn text" data-action="screen" data-screen="alerts">Tất cả cảnh báo ${icon('arrow-up-right')}</button>`)}<div class="card">${visible.length ? visible.map(finding=>{ const run=runs.find(run=>run.id===finding.runId); const project=(data.projects||[]).find(project=>project.id===finding.projectId); return `<button class="incident-row" data-action="finding" data-finding="${esc(finding.id)}"><span class="incident-symbol ${esc(finding.severity||'unknown')}">${icon('triangle-alert')}</span><span class="incident-content"><strong>${safe(finding.title)}</strong><span>${safe(project?.name||run?.projectName||finding.projectId)} <b>·</b> <span class="mono">${safe(finding.path)}${finding.line?`:${esc(finding.line)}`:''}</span></span></span>${tag(severityName(finding.severity),finding.severity||'neutral')}<span class="incident-source">${safe(sourceName(finding.source))}</span><span class="incident-time">${run?esc(timeAgo(run.createdAt)):'—'}</span>${icon('chevron-right')}</button>`;}).join('') : empty('Chưa có cảnh báo cần xem xét','Không có phát hiện phù hợp trong phạm vi dự án và thời gian đã chọn.')}</div></section>`;
}

function health(data,runs){
  const demo = data.source==='demo';
  const scanner = runs.some(run=>(run.checkmarx?.status||run.checkmarx)==='completed');
  const modelResult = runs.some(run=>(run.codebert?.status||run.codebert)==='completed');
  const modelError = runs.some(run=>(run.codebert?.status||run.codebert)==='error');
  const items = [
    ['Gateway','router',demo?'Dữ liệu mẫu':'Audit đã tải','blue'],
    ['CodeBERT','brain-circuit',demo?'Suy luận mẫu':modelResult?'Đã nhận kết quả':modelError?'Có lỗi đã báo cáo':'Chưa có kết quả trong kỳ',modelResult?'green':'amber'],
    ['Checkmarx','scan-line',demo?'SARIF mẫu':scanner?'Đã nhận bằng chứng':'Chờ quét','amber'],
    ['Security Gate','shield-check',runs.some(run=>run.status==='decided')?'Đã có quyết định':'Chờ bằng chứng','blue'],
    ['Lưu trữ audit','database',demo?'Audit mẫu':'Chưa báo cáo trạng thái','neutral'],
  ];
  return `<section class="section-space">${heading('Bằng chứng vận hành','activity',`<span class="section-count">${demo?'TRẠNG THÁI MẪU':'BẰNG CHỨNG ĐÃ BÁO CÁO'}</span>`)}<div class="card health-strip">${items.map(([name,symbol,status,tone])=>`<div class="health-item"><span class="health-icon">${icon(symbol)}</span><div><strong>${esc(name)}</strong><span class="health-state ${tone}"><b></b>${esc(status)}</span></div></div>`).join('')}</div></section>`;
}

function runsTable(runs){
  return `<section class="section-space">${heading('Lượt chạy pipeline gần đây','git-pull-request',`<button class="btn text" data-action="screen" data-screen="monitoring">Xem pipeline ${icon('arrow-up-right')}</button>`)}<div class="card table-wrap">${runs.length ? `<table class="table overview-runs"><thead><tr><th>Mã lượt chạy</th><th>Dự án / nhánh</th><th>Commit</th><th>Quyết định Gateway</th><th>Phát hiện</th><th>Thời gian</th><th>Bắt đầu</th></tr></thead><tbody>${[...runs].sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt)).slice(0,5).map(run=>`<tr tabindex="0" data-action="run" data-run="${esc(run.id)}"><td><span class="mono text-blue">${safe(run.id)}</span>${run.mode==='demo'?`<span class="subline">LƯỢT CHẠY MẪU</span>`:''}</td><td><span class="project-cell">${safe(run.projectName||run.projectId)}</span><span class="subline">${icon('git-branch')} ${safe(run.branch)}</span></td><td><span class="mono">${esc((run.commit||'').slice(0,8)||'—')}</span></td><td>${tag(run.decision||'PENDING',toneFor(run.decision))}${deployAllowed(run)?tag('Cho phép deploy','green'):''}</td><td>${safe(run.findingsCount??0)}</td><td class="mono">${esc(fmtDuration(asNumber(run.duration)))}</td><td>${esc(timeAgo(run.createdAt))}</td></tr>`).join('')}</tbody></table>` : empty('Chưa có lượt chạy pipeline','Đăng ký snapshot để khởi chạy hai nhánh phân tích độc lập.')}</div></section>`;
}

function severityChart(findings){
  const severities=['critical','high','medium','low','info','unknown'];
  const colors=['#f06276','#ec9755','#efc65a','#638bf9','#6882a8','#8c85bc'];
  const values=severities.map(severity=>findings.filter(finding=>finding.severity===severity).length);
  const maximum=Math.max(1,...values);
  const bars=values.map((value,index)=>{const height=value/maximum*93;const x=50+index*64;return `<rect x="${x}" y="${130-height}" width="31" height="${height}" rx="4" fill="${colors[index]}" opacity=".88"/><text x="${x+15.5}" y="${120-height}" text-anchor="middle" fill="#d3dff2" font-size="11">${value}</text><text x="${x+15.5}" y="153" text-anchor="middle" fill="#9eafcc" font-size="9">${severityName(severities[index])}</text>`;}).join('');
  return `<div class="overview-chart-svg"><svg viewBox="0 0 450 166" role="img" aria-label="Phát hiện theo mức độ nghiêm trọng">${[37,68,99,130].map(y=>`<line x1="34" y1="${y}" x2="434" y2="${y}" stroke="#1c2847" stroke-dasharray="3 5"/>`).join('')}${bars}</svg></div>`;
}

function activityChart(data,runs,period){
  const days={'24h':1,'7d':7,'30d':30}[period]||1;
  const bins=period==='24h'?8:period==='7d'?7:10;
  const dates=runs.map(run=>Date.parse(run.createdAt)).filter(Number.isFinite);
  const now=Date.parse(data.generatedAt)||(dates.length?Math.max(...dates):Date.now());
  const width=days*86400000/bins;
  const counts=Array.from({length:bins},(_,index)=>runs.filter(run=>{const time=Date.parse(run.createdAt);return time>=now-(bins-index)*width&&time<=now-(bins-index-1)*width;}).length);
  const max=Math.max(1,...counts);
  const points=counts.map((count,index)=>[34+index*(395/(bins-1)),130-count/max*91]);
  const path=points.map(([x,y],index)=>`${index?'L':'M'} ${x.toFixed(1)} ${y.toFixed(1)}`).join(' ');
  const labels=period==='24h'?['24h trước','18h','12h','6h','Hiện tại']:period==='7d'?['7 ngày trước','5 ngày','3 ngày','1 ngày','Hiện tại']:['30 ngày trước','23 ngày','15 ngày','8 ngày','Hiện tại'];
  return `<div class="overview-chart-svg"><svg viewBox="0 0 450 166" role="img" aria-label="Hoạt động pipeline trong khoảng thời gian đã chọn"><defs><linearGradient id="activity-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="#6187ff" stop-opacity=".3"/><stop offset="1" stop-color="#6187ff" stop-opacity="0"/></linearGradient></defs>${[37,68,99,130].map(y=>`<line x1="34" y1="${y}" x2="434" y2="${y}" stroke="#1c2847" stroke-dasharray="3 5"/>`).join('')}<path d="${path} L 429 130 L 34 130 Z" fill="url(#activity-fill)"/><path d="${path}" fill="none" stroke="#7294ff" stroke-width="2"/>${points.map(([x,y])=>`<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2.5" fill="#95afff"/>`).join('')}${labels.map((label,index)=>`<text x="${34+index*98.75}" y="153" text-anchor="middle" fill="#9eafcc" font-size="9">${label}</text>`).join('')}</svg></div>`;
}

export function renderOverview(data,state={}){
  const runs=periodRuns(data,state);
  const runIds=new Set(runs.map(run=>run.id));
  const findings=(data.findings||[]).filter(finding=>runIds.has(finding.runId));
  const allProjects=data.projects||[];
  const projects=allProjects.filter(project=>!state.project||state.project==='all'||project.id===state.project);
  const selected=state.period||'24h';
  return `<div class="overview-screen"><div class="page-title-row"><div><h1 class="page-title">Tổng quan bảo mật</h1><p class="page-description">Ưu tiên cảnh báo cần xử lý và theo dõi quyết định bảo mật của Gateway.</p></div><div class="page-actions"><button class="btn primary" data-action="screen" data-screen="comparison">${icon('git-compare-arrows')} So sánh lượt quét</button><button class="btn ghost" data-action="screen" data-screen="monitoring">${icon('workflow')} Giám sát CI/CD</button></div></div><div class="overview-scope"><div class="field"><label for="overview-project-filter">Dự án</label><select id="overview-project-filter" data-action="project-filter" aria-label="Lọc tổng quan theo dự án"><option value="all">Tất cả dự án</option>${allProjects.map(project=>`<option value="${esc(project.id)}" ${state.project===project.id?'selected':''}>${safe(project.name||project.repo||project.id)}</option>`).join('')}</select></div><div class="segmented" aria-label="Khoảng thời gian báo cáo">${[['24h','24 giờ'],['7d','7 ngày'],['30d','30 ngày']].map(([value,label])=>`<button class="${selected===value?'active':''}" data-action="period" data-value="${value}" aria-pressed="${selected===value}">${label}</button>`).join('')}</div><span class="overview-scope-note">${icon('list-filter')}Chỉ số theo phạm vi đã chọn</span></div>${kpis(runs,findings,projects)}${incidents(data,findings,runs)}<section class="section-space">${heading('Danh mục dự án','folder-kanban',`<span class="section-count">${projects.length} DỰ ÁN</span>`)}<div class="overview-projects">${projects.length ? projects.map((project,index)=>projectCard(project,runs,findings,index,data.source==='demo')).join('') : `<div class="card">${empty('Chưa đăng ký repository','Dự án sẽ xuất hiện sau khi Gateway nhận một snapshot bất biến.')}</div>`}</div></section>${runsTable(runs)}${health(data,runs)}<div class="overview-analytics section-space"><section class="card card-body">${heading('Phát hiện theo mức độ','chart-no-axes-column')}<p class="section-description">Phát hiện đã báo cáo trong phạm vi dự án và thời gian đã chọn</p>${severityChart(findings)}<div class="chart-legend">${['Nghiêm trọng','Cao','Trung bình','Thấp','Thông tin','Chưa rõ'].map((name,index)=>`<span><b style="background:${['#f06276','#ec9755','#efc65a','#638bf9','#6882a8','#8c85bc'][index]}"></b>${name}</span>`).join('')}</div></section><section class="card card-body">${heading('Hoạt động pipeline','chart-no-axes-combined')}<p class="section-description">Đăng ký lượt chạy · ${esc(selected)} · ${data.source==='demo'?'bản ghi mẫu':'lượt chạy đã báo cáo'}</p>${activityChart(data,runs,selected)}<div class="chart-legend"><span><b style="background:#7294ff"></b>Số lượt chạy theo khoảng</span><span>${runs.length} lượt trong kỳ</span></div></section></div><p class="overview-footnote">${icon('info')}Điểm mô hình là bằng chứng; policy của Gateway quyết định bảo mật cuối.${data.source==='demo'?' PASS mẫu luôn giữ deploy bị vô hiệu hóa.':''}</p></div>`;
}
