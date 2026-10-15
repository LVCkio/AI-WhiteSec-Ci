import { esc, icon, fmtDate, timeAgo, runStatus, tasksFor } from './ui.js';
import { renderGateEvidence } from './gate-evidence.js';

const safe=value=>esc(value==null||value===''?'—':value);
const number=value=>typeof value==='number'&&Number.isFinite(value)?value:null;
const deployAllowed=run=>run?.mode==='real'&&run?.status==='decided'&&run?.decision==='PASS'&&run?.allowDeploy===true;
const tag=(label,tone='neutral')=>`<span class="badge ${tone}">${esc(label)}</span>`;
const decisionTone=decision=>({PASS:'green',BLOCK:'red',REVIEW:'amber',ERROR:'red'}[decision]||'blue');
const statusTone=status=>({completed:'green',running:'blue',pending:'amber',blocked:'red',error:'red',review:'amber'}[status]||'neutral');
const heading=(title,symbol,right='')=>`<div class="section-heading"><h2>${icon(symbol)}${esc(title)}</h2>${right}</div>`;
const empty=(title,description)=>`<div class="empty-state">${icon('inbox')}<strong>${esc(title)}</strong>${esc(description)}</div>`;
const duration=value=>number(value)===null?'Chưa báo cáo':value>=60?`${Math.floor(value/60)}m ${Math.round(value%60)}s`:`${Math.round(value)}s`;
const branchStatus=value=>typeof value==='string'?value:value?.status||'pending';
const statusName=value=>({completed:'Hoàn tất',running:'Đang chạy',pending:'Đang chờ',blocked:'Bị chặn',error:'Lỗi',review:'Cần xem xét',incomplete:'Chưa đầy đủ'}[value]||value||'Chưa rõ');
const severityName=value=>({critical:'Nghiêm trọng',high:'Cao',medium:'Trung bình',low:'Thấp',info:'Thông tin',unknown:'Chưa rõ'}[value]||value||'Chưa rõ');
const sourceName=value=>({'Combined':'Hai bộ phân tích','Checkmarx only':'Chỉ Checkmarx','CodeBERT only':'Chỉ CodeBERT'}[value]||value);

function scopedRuns(data,state){
  return [...(data.runs||[])].filter(run=>{
    if(state.project&&state.project!=='all'&&run.projectId!==state.project&&run.repo!==state.project)return false;
    const cutoff=Date.parse(state.focusSince),created=Date.parse(run.createdAt);
    if(Number.isFinite(cutoff)&&Number.isFinite(created)&&created<cutoff)return false;
    if(['BLOCK','REVIEW'].includes(state.runStatus))return run.decision===state.runStatus;
    const code=runStatus(run).code;
    return !state.runStatus||state.runStatus==='all'||code===state.runStatus;
  }).sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt));
}

function runList(runs,selected){
  return `<aside class="card monitor-run-list"><div class="monitor-list-heading"><span>${icon('list-filter')} Lượt chạy pipeline</span><span class="mono">${runs.length}</span></div>${runs.length?`<div class="monitor-list-scroll">${runs.map(run=>`<button class="monitor-run ${selected?.id===run.id?'selected':''}" data-action="run" data-run="${esc(run.id)}"><div class="monitor-run-title"><span class="mono">${safe(run.id)}</span>${icon('chevron-right')}</div><div class="monitor-run-project">${safe(run.projectName||run.projectId)}</div><div class="monitor-run-branch">${icon('git-branch')} ${safe(run.branch)} <span class="mono">${esc((run.commit||'').slice(0,7))}</span></div><div class="monitor-run-footer">${tag(run.decision||'PENDING',decisionTone(run.decision))}<span>${esc(timeAgo(run.createdAt))}</span></div></button>`).join('')}</div>`:empty('Không có lượt chạy phù hợp','Đổi bộ lọc hoặc đăng ký một snapshot bất biến mới.')}</aside>`;
}

function projectSummary(data,run,tasks){
  const project=(data.projects||[]).find(project=>project.id===run.projectId||project.repo===run.repo)||{};
  const completed=tasks.filter(task=>['completed','blocked','review','error'].includes(task.status)).length;
  const progress=tasks.length?Math.round(completed/tasks.length*100):0;
  return `<section class="card monitor-project-summary"><div class="monitor-project-heading"><div class="monitor-project-logo">${icon('layers')}</div><div><h2>${safe(project.name||run.projectName||run.projectId)}</h2><span class="mono">${safe(run.repo)}</span></div><div class="monitor-project-badges">${tag(run.mode==='demo'?'LƯỢT CHẠY MẪU':'BẰNG CHỨNG THẬT',run.mode==='demo'?'demo':'blue')}${tag(run.decision||'PENDING',decisionTone(run.decision))}</div></div><div class="monitor-project-meta"><span>${icon('git-branch')}<b>${safe(run.branch)}</b></span><span>${icon('git-commit-horizontal')}<b class="mono">${esc((run.commit||'').slice(0,10)||'—')}</b></span><span>${icon('box')}<b>${safe(project.framework)}</b></span><span>${icon('user-round')}<b>${safe(run.actor||project.owner)}</b></span><span>${icon('clock-3')}<b>${esc(fmtDate(run.createdAt))}</b></span></div><div class="monitor-project-progress"><div><span>Các bước đã có kết quả</span><strong>${completed}/${tasks.length} <span>${progress}%</span></strong></div><div class="progress-track"><span style="width:${progress}%"></span></div></div></section>`;
}

const stageDefinitions=[
  {id:'snapshot',label:'Khóa snapshot',symbol:'git-branch',slot:'source'},
  {id:'register',label:'Đăng ký run',symbol:'fingerprint',slot:'register'},
  {id:'codebert',label:'CodeBERT',symbol:'brain-circuit',slot:'model'},
  {id:'checkmarx',label:'Checkmarx',symbol:'scan-line',slot:'scanner'},
  {id:'combine',label:'Gateway hợp nhất',symbol:'merge',slot:'combine'},
  {id:'gate',label:'Security Gate',symbol:'shield-check',slot:'gate'},
];

function pipeline(run,tasks,state){
  const stageNodes=stageDefinitions.map(definition=>{
    const task=tasks.find(task=>task.id===definition.id);
    const status=task?.status||'pending';
    const selected=(state.taskId||'codebert')===definition.id;
    return `<button class="pipeline-node ${definition.slot} ${esc(status)} ${selected?'selected':''}" data-action="task" data-task="${definition.id}"><span class="pipeline-node-icon">${icon(definition.symbol)}</span><strong>${definition.label}</strong><span class="pipeline-node-status"><b></b>${esc(statusName(status))}</span></button>`;
  }).join('');
  return `<section class="card card-body monitor-pipeline">${heading('Pipeline phân tích song song','workflow',tag('CÙNG SNAPSHOT','outline'))}<div class="pipeline-architecture"><svg class="pipeline-connectors" viewBox="0 0 700 190" preserveAspectRatio="none" aria-hidden="true"><defs><marker id="pipe-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#385478"/></marker></defs><path d="M120 95 H147 M267 95 H285 V44 H303 M285 95 V146 H303 M426 44 H446 V95 H464 M426 146 H446 V95 M583 95 H602" stroke="#385478" stroke-width="1.6" fill="none" marker-end="url(#pipe-arrow)"/></svg>${stageNodes}<span class="pipeline-parallel-label">SONG SONG</span></div><div class="pipeline-footnote"><span>${icon('git-fork')}CodeBERT và Checkmarx phân tích độc lập.</span><span>${icon('merge')}Gateway chờ đủ hai nhánh để quyết định.</span></div></section>`;
}

function eventMarkup(event){
  if(typeof event==='string')return `<li><span class="event-dot"></span><p>${esc(event)}</p></li>`;
  const timestamp=event.timestamp||event.at||event.createdAt||event.time;
  return `<li><span class="event-dot ${event.level==='error'?'error':''}"></span>${timestamp?`<time class="mono">${esc(fmtDate(timestamp))}</time>`:''}<p>${safe(event.message||event.description||event.type||event.name)}</p></li>`;
}

function taskDetail(data,run,tasks,state){
  const selected=tasks.find(task=>task.id===(state.taskId||'codebert'))||tasks.find(task=>task.id==='codebert')||tasks[0];
  const definition=stageDefinitions.find(stage=>stage.id===selected?.id)||stageDefinitions[2];
  if(!selected)return `<section class="card card-body monitor-task-detail">${heading('Chi tiết tác vụ','terminal')}${empty('Chưa có bằng chứng tác vụ','Gateway audit chưa báo cáo chi tiết bước phân tích của lượt này.')}</section>`;
  const detail=data.details?.[run.id]||{};
  const raw=selected.id==='codebert'?detail.codebert:selected.id==='checkmarx'?detail.checkmarx:null;
  const evidence=detail.record?.evidence||detail.record||detail.evidence||detail;
  const sourceDigest=evidence.source_manifest_sha256||evidence.identity?.source_manifest_sha256;
  const artifactDigest=evidence.identity?.artifact_digest||detail.identity?.artifact_digest;
  const events=Array.isArray(selected.events)&&selected.events.length?selected.events:(run.events||[]).filter(event=>event.taskId===selected.id||event.stage===selected.id);
  const metadata=[
    ['Trạng thái',statusName(selected.status||'pending')],
    ['Bắt đầu',selected.startedAt?fmtDate(selected.startedAt):'Chưa báo cáo'],
    ['Thời gian',duration(selected.duration)],
    ['Chế độ bằng chứng',run.mode==='demo'?'Dữ liệu mẫu':'Hệ thống thật'],
  ];
  if(selected.id==='codebert'){
    metadata.push(['Phiên bản mô hình',typeof raw==='object'?(raw?.model_version||raw?.modelVersion||'Chưa báo cáo'):'Chưa báo cáo']);
    metadata.push(['Đơn vị mã nguồn',run.unitsCount??'Chưa báo cáo']);
  }else if(selected.id==='checkmarx'){
    metadata.push(['Mã scan',typeof raw==='object'?raw?.scan_id||raw?.scanId||'Chưa báo cáo':'Chưa báo cáo']);
    metadata.push(['Cấu hình quét',typeof raw==='object'?raw?.preset||'Chưa báo cáo':'Chưa báo cáo']);
  }else if(selected.id==='snapshot'||selected.id==='register'){
    metadata.push(['Source manifest',sourceDigest?String(sourceDigest).slice(0,18)+'…':'Chưa báo cáo']);
    metadata.push(['Artifact digest',artifactDigest?String(artifactDigest).slice(0,22)+'…':'Chưa báo cáo']);
  }
  const description=selected.description||({snapshot:'Bằng chứng nguồn bất biến được đăng ký cho lượt chạy này.',register:'Identity của run ràng buộc mã nguồn, repository, commit và artifact.',codebert:'Weights cố định tạo điểm cho sáu nhóm lỗ hổng. Predictions không cấp quyền deploy.',checkmarx:'Phát hiện SAST là bằng chứng độc lập cho policy của Gateway.',combine:'Gateway đối chiếu hai nhánh với cùng identity bất biến.',gate:'Gateway áp dụng policy có phiên bản và quyết định bảo mật cuối.'}[selected.id]||'Đang chờ bằng chứng tác vụ được báo cáo.');
  return `<section class="card card-body monitor-task-detail"><div class="section-heading"><h2>${icon(definition.symbol)}${safe(selected.name||definition.label)}<span class="task-detail-caption">Chi tiết tác vụ</span></h2>${tag(statusName(selected.status||'pending'),statusTone(selected.status))}</div><p class="task-description">${esc(description)}</p><div class="task-metadata">${metadata.map(([label,value])=>`<div><span>${esc(label)}</span><strong class="${['Mã scan','Phiên bản mô hình','Source manifest','Artifact digest'].includes(label)?'mono':''}">${safe(value)}</strong></div>`).join('')}</div><div class="task-events-heading"><span>${icon('terminal')} Nhật ký tác vụ</span><span>${events.length} sự kiện</span></div>${events.length?`<ol class="task-events">${events.slice(-5).map(eventMarkup).join('')}</ol>`:`<div class="task-no-events">${icon('clock-3')}Chưa có nhật ký tác vụ. Thiếu log không có nghĩa phân tích thành công.</div>`}</section>`;
}

function finalGate(data,run){
  const scannerStatus=branchStatus(run.checkmarx);
  const modelStatus=branchStatus(run.codebert);
  const missing=[];
  if(!run.decision&&scannerStatus!=='completed'&&scannerStatus!=='error')missing.push('Checkmarx');
  if(!run.decision&&modelStatus!=='completed'&&modelStatus!=='error')missing.push('CodeBERT');
  const status=run.decision||'PENDING';
  const detail=data.details?.[run.id]||{};
  const decision=detail.final_decision||detail.record?.decision||detail.decision||{};
  const policyVersion=detail.policy?.version||decision.policy_version||detail.policy_version||'Chưa báo cáo';
  const predicates=[
    ['Bằng chứng Checkmarx',statusName(scannerStatus),statusTone(scannerStatus)],
    ['Bằng chứng CodeBERT',statusName(modelStatus),statusTone(modelStatus)],
    ['Ràng buộc run / commit',run.commit?'Đã ghi commit':'Chưa báo cáo',run.commit?'blue':'neutral'],
    ['Phiên bản policy',policyVersion,'neutral'],
  ];
  return `<section class="card card-body monitor-gate"><div class="section-heading"><h2>${icon('shield-check')}Gateway Security Gate</h2>${tag(status,decisionTone(run.decision))}</div><div class="gate-result"><div class="gate-result-symbol ${decisionTone(run.decision)}">${icon(run.decision==='PASS'?'shield-check':run.decision==='BLOCK'||run.decision==='ERROR'?'shield-alert':'clock-3')}</div><div><strong>${status==='PENDING'?'Đang chờ đủ bằng chứng':`${esc(status)} · Quyết định policy của Gateway`}</strong><p>${deployAllowed(run)?'PASS thật cho phép chuyển sang kiểm tra điều kiện phát hành.':'Deploy bị vô hiệu hóa cho lượt chạy này.'}</p></div><span class="gate-deploy ${deployAllowed(run)?'allowed':'denied'}"><span>allow_deploy</span><strong class="mono">${deployAllowed(run)?'true':'false'}</strong></span></div><div class="gate-predicates">${predicates.map(([label,value,tone])=>`<div><span>${esc(label)}</span>${tag(value,tone)}</div>`).join('')}</div>${missing.length?`<div class="notice amber gate-missing">${icon('hourglass')}<span>Thiếu bằng chứng hoàn tất: <strong>${esc(missing.join(' + '))}</strong>. Lượt đang chờ không được PASS.</span></div>`:''}${renderGateEvidence(data,run)}</section>`;
}

function findings(data,run){
  const values=(data.findings||[]).filter(finding=>finding.runId===run.id);
  const related=(data.findings||[]).filter(finding=>finding.runId!==run.id&&finding.projectId===run.projectId&&['critical','high'].includes(finding.severity)).slice(0,2);
  return `<section class="card card-body monitor-findings">${heading('Phát hiện bảo mật','shield-alert',`<span class="section-count">${values.length} PHÁT HIỆN</span>`)}${values.length?`<div class="monitor-finding-list">${values.slice(0,5).map(finding=>`<button class="monitor-finding" data-action="finding" data-finding="${esc(finding.id)}"><div><strong>${safe(finding.title)}</strong><span class="mono">${safe(finding.path)}${finding.line?`:${esc(finding.line)}`:''}</span><span class="monitor-finding-cwes">${(finding.cwes||[]).map(cwe=>esc(cwe)).join(' · ')||'Chưa báo cáo CWE'} <b>·</b> ${safe(sourceName(finding.source))}</span></div><div>${tag(severityName(finding.severity),finding.severity||'neutral')}${number(finding.score)!==null?`<span class="finding-score mono">điểm ${finding.score.toFixed(3)}</span>`:''}</div>${icon('chevron-right')}</button>`).join('')}</div>`:`<div class="monitor-no-findings">${icon('file-search')}Chưa nhận phát hiện cho lượt chạy này.${run.status!=='decided'?' Bằng chứng phân tích vẫn đang chờ.':''}</div>`}${related.length?`<div class="related-incidents"><h3>${icon('link')}Phát hiện liên quan trong dự án</h3>${related.map(finding=>`<button data-action="finding" data-finding="${esc(finding.id)}">${tag(severityName(finding.severity),finding.severity)}<span>${safe(finding.title)}</span><span class="mono">${safe(finding.runId)}</span>${icon('arrow-up-right')}</button>`).join('')}</div>`:''}<p class="finding-verification-note">${icon('info')}Cần xem xét phát hiện; sự đồng thuận của bộ phân tích không là ground truth.</p></section>`;
}

function phases(data,run){
  const project=(data.projects||[]).find(project=>project.id===run.projectId||project.repo===run.repo);
  const phase=data.source==='demo'&&run.mode==='demo'?project?.phase:null;
  const completed=phase?Math.max(0,Math.min(11,number(phase.completed)||0)):null;
  const current=phase?Math.max(0,Math.min(10,number(phase.current)??completed)):null;
  const labels=['Phạm vi','Dữ liệu','Mô hình','Suy luận','Gateway','Policy','Container','Nối CI','Thử nghiệm','Đánh giá','Phát hành'];
  return `<section class="card card-body monitor-phases">${heading('Theo dõi giai đoạn dự án','milestone',tag(phase?'METADATA MẪU':'CHƯA BÁO CÁO',phase?'demo':'neutral'))}<p class="section-description">${phase?'Mốc dự án minh họa từ metadata demo; đây không là kết quả CI hay phát hành thật.':'Audit thật chưa báo cáo tiến độ phát triển. Trạng thái các giai đoạn được giữ là chưa rõ.'}</p><div class="phase-grid">${labels.map((label,index)=>{const status=!phase?'unknown':index<completed?'completed':index===current?'current':'upcoming';return `<div class="phase-node ${status}"><span class="phase-mark">${status==='completed'?icon('check'):status==='current'?icon('loader-circle'):icon('minus')}</span><span class="mono">P${index}</span><strong>${label}</strong><small>${status==='unknown'?'Chưa rõ':status==='completed'?'Hoàn tất':status==='current'?'Hiện tại':'Tiếp theo'}</small></div>`;}).join('')}</div></section>`;
}

function auditTable(data,run){
  const runs=(data.runs||[]).filter(item=>item.projectId===run.projectId||item.repo===run.repo).sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt)).slice(0,5);
  return `<section class="monitor-audit section-space">${heading('Lịch sử audit dự án','history',`<span class="section-count">BẢN GHI RUN BẤT BIẾN</span>`)}<div class="card table-wrap"><table class="table"><thead><tr><th>Mã lượt chạy</th><th>Commit</th><th>Trigger / người chạy</th><th>Quyết định</th><th>Deploy</th><th>Thời gian tạo</th></tr></thead><tbody>${runs.map(item=>`<tr tabindex="0" class="${item.id===run.id?'current-run':''}" data-action="run" data-run="${esc(item.id)}"><td><span class="mono text-blue">${safe(item.id)}</span>${item.id===run.id?tag('Đang chọn','blue'):''}</td><td class="mono">${esc((item.commit||'').slice(0,8)||'—')}</td><td>${safe(item.trigger)}<span class="subline">${safe(item.actor)}</span></td><td>${tag(item.decision||'PENDING',decisionTone(item.decision))}</td><td>${tag(deployAllowed(item)?'Cho phép':'Từ chối',deployAllowed(item)?'green':'neutral')}</td><td>${esc(fmtDate(item.createdAt))}</td></tr>`).join('')}</tbody></table></div></section>`;
}

export function renderMonitoring(data,state={}){
  const runs=scopedRuns(data,state);
  const selected=runs.find(run=>run.id===state.runId)||runs[0];
  const tasks=selected?tasksFor(selected)||[]:[];
  const projectOptions=(data.projects||[]).map(project=>`<option value="${esc(project.id)}" ${state.project===project.id?'selected':''}>${safe(project.name||project.repo)}</option>`).join('');
  const cutoff=Date.parse(state.focusSince);
  const statusOptions=[['all','Tất cả trạng thái'],['BLOCK','Bị chặn · BLOCK'],['REVIEW','Cần xem xét · REVIEW'],['pending','Chờ bằng chứng'],['completed','Đã có quyết định'],['error','Lỗi phân tích']];
  return `<div class="monitoring-screen">
    <div class="page-title-row"><div><h1 class="page-title">Giám sát CI/CD</h1><p class="page-description">Theo dõi hai nhánh phân tích, bằng chứng hợp nhất và quyết định cuối của Gateway.</p></div><div class="page-actions">${tag(data.source==='demo'?'DỮ LIỆU MẪU':'API LOCAL',data.source==='demo'?'demo':'blue')}<button class="btn ghost" data-action="screen" data-screen="overview">${icon('layout-dashboard')} Tổng quan</button></div></div>
    ${Number.isFinite(cutoff)?`<div class="gate-focus-notice"><span>${icon('calendar-range')}Giới hạn từ ${esc(fmtDate(state.focusSince))}; giữ các run chưa có thời gian.</span><button class="btn small" data-action="clear-overview-focus">Bỏ giới hạn thời gian</button></div>`:''}
    <div class="filter-bar"><div class="field"><label for="monitor-project-filter">Dự án</label><select id="monitor-project-filter" data-action="project-filter" aria-label="Lọc theo dự án"><option value="all">Tất cả dự án</option>${projectOptions}</select></div><div class="field"><label for="monitor-status-filter">Trạng thái</label><select id="monitor-status-filter" data-action="run-status-filter" aria-label="Lọc theo trạng thái phân tích">${statusOptions.map(([value,label])=>`<option value="${value}" ${state.runStatus===value?'selected':''}>${label}</option>`).join('')}</select></div><span class="filter-spacer"></span><span class="monitor-filter-note">${icon('git-fork')}Checkmarx + CodeBERT chạy song song</span></div>
    <div class="monitor-workspace">${runList(runs,selected)}<div class="monitor-detail">${selected?`${projectSummary(data,selected,tasks)}${pipeline(selected,tasks,state)}${taskDetail(data,selected,tasks,state)}${finalGate(data,selected)}${findings(data,selected)}${phases(data,selected)}`:`<div class="card">${empty('Chọn một lượt chạy pipeline','Chi tiết xuất hiện khi snapshot nguồn được đăng ký với Gateway.')}</div>`}</div></div>${selected?auditTable(data,selected):''}
  </div>`;
}
