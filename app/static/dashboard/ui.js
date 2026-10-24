export const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const icon = name => `<i data-lucide="${esc(name)}" class="icon" aria-hidden="true"></i>`;
export const badge = (label,tone='muted') => `<span class="badge badge-${['success','danger','warning','info','muted'].includes(tone)?tone:'muted'}"><span class="badge-dot"></span>${esc(label)}</span>`;
export const sectionHeading = (title,subtitle='') => `<div class="section-heading"><h3>${esc(title)}</h3>${subtitle?`<span>${esc(subtitle)}</span>`:''}</div>`;
export function fmtDate(value){if(!value)return '—';const d=new Date(value);return Number.isNaN(d.getTime())?'—':d.toLocaleString('vi-VN',{timeZone:'Asia/Saigon',hour:'2-digit',minute:'2-digit',day:'2-digit',month:'2-digit',year:'numeric'});}
export function timeAgo(value){if(!value)return '—';const delta=Math.max(0,(Date.now()-new Date(value).getTime())/1000);if(!Number.isFinite(delta))return '—';return delta<60?'Vừa xong':delta<3600?`${Math.floor(delta/60)} phút trước`:delta<86400?`${Math.floor(delta/3600)} giờ trước`:`${Math.floor(delta/86400)} ngày trước`;}
export function runStatus(run){if(run.status==='pending')return {label:'Đang chạy',tone:'info',code:'pending'};if(run.decision==='ERROR')return {label:'Lỗi phân tích',tone:'danger',code:'error'};return {label:'Hoàn tất phân tích',tone:'success',code:'completed'};}
export function tasksFor(run){if(run.tasks?.length)return run.tasks;const both=run.codebert!=='pending'&&run.checkmarx!=='pending';return [
  {id:'snapshot',name:'Khóa snapshot',status:'completed',description:'Commit, source manifest và artifact digest được gắn với cùng run.'},
  {id:'register',name:'Đăng ký run',status:'completed',description:'Gateway tiếp nhận source và khởi tạo nhánh suy luận độc lập.'},
  {id:'codebert',name:'CodeBERT inference',status:run.codebert==='completed'?'completed':run.codebert==='error'?'error':run.codebert==='incomplete'?'review':'running',description:'Dự đoán sáu nhóm lỗi bằng artifact cố định, song song với Checkmarx.'},
  {id:'checkmarx',name:'Checkmarx SAST',status:run.checkmarx==='completed'?'completed':run.checkmarx==='error'?'error':run.checkmarx==='incomplete'?'review':'pending',description:'Chờ báo cáo scan từ CI/scanner của cùng commit và scope.'},
  {id:'combine',name:'Gateway hợp nhất',status:both?'completed':'pending',description:'Đối chiếu identity, normalize findings và ghép kết quả hai nhánh.'},
  {id:'gate',name:'Security Gate & Report',status:run.decision==='BLOCK'?'blocked':run.decision==='REVIEW'?'review':run.decision==='ERROR'?'error':run.decision?'completed':'pending',description:run.reasons?.join(' · ')||'Chưa đủ hai kết quả để áp dụng policy.'},
].map(task=>({...task,startedAt:task.id==='register'?run.createdAt:null,
  completedAt:task.id==='gate'&&run.decision?run.completedAt:null,duration:null,events:[]}));}
export const groupName = group => ({SQL_INJECTION:'SQL Injection',XSS:'Cross-site Scripting',OS_COMMAND_INJECTION:'OS Command Injection',PATH_TRAVERSAL:'Path Traversal',INSECURE_AUTHENTICATION:'Insecure Authentication',HARDCODED_CREDENTIALS:'Hardcoded Credentials'}[group]||group||'Chưa phân nhóm');
