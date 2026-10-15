import { tasksFor } from './ui.js';

const GROUPS = ['PATH_TRAVERSAL','XSS','OS_COMMAND_INJECTION','SQL_INJECTION','INSECURE_AUTHENTICATION','HARDCODED_CREDENTIALS'];

/** UI fixtures, never submitted to Gateway or treated as experimental results. */
export function createDemo() {
  const now = Date.now();
  const at = minutes => new Date(now - minutes * 60000).toISOString();
  const projects = [
    { id: 'whitesec/flask-lab-a', name: 'Flask Lab A', repo: 'whitesec/flask-lab-a', framework: 'Flask', owner: 'Nhóm Backend', environment: 'Development', phase: { completed: 8, current: 8 } },
    { id: 'whitesec/django-demo-b', name: 'Django Demo B', repo: 'whitesec/django-demo-b', framework: 'Django', owner: 'Nhóm Web', environment: 'Staging', phase: { completed: 6, current: 6 } },
    { id: 'whitesec/python-api-c', name: 'Python API C', repo: 'whitesec/python-api-c', framework: 'FastAPI', owner: 'Nhóm API', environment: 'Development', phase: { completed: 4, current: 4 } },
  ];
  const samples = [
    ['M-106', 0, 4, null, 'pending', 'completed', 1],
    ['M-105', 0, 35, 'BLOCK', 'completed', 'completed', 2],
    ['M-104', 1, 110, 'REVIEW', 'completed', 'completed', 1],
    ['M-103', 2, 200, 'ERROR', 'error', 'completed', 0],
    ['M-102', 1, 440, 'PASS', 'completed', 'completed', 0],
    ['M-101', 2, 950, 'PASS', 'completed', 'completed', 0],
    ['M-100', 0, 1200, 'BLOCK', 'completed', 'completed', 2],
  ];
  const reasons = {
    BLOCK: ['Checkmarx báo cáo finding High thuộc phạm vi policy.', 'Gateway Security Gate chặn run này.', 'Chế độ demo: không cho phép deploy.'],
    REVIEW: ['Bằng chứng cần được người phụ trách thẩm định.', 'Chế độ demo: không cho phép deploy.'],
    ERROR: ['Nhánh Checkmarx trả lỗi; không đủ bằng chứng quét hợp lệ.', 'Security Gate trả ERROR và giữ allow_deploy=false.'],
    PASS: ['Hai nhánh hoàn tất; không có tín hiệu vượt policy trong fixture này.', 'PASS demo không cho phép deploy.'],
  };
  const runs = samples.map(([id,index,minutes,decision,checkmarx,codebert,count], order) => ({
    id, projectId: projects[index].id, projectName: projects[index].name,
    repo: projects[index].repo, branch: index === 1 ? 'develop' : 'main',
    commit: `${'abcdef1234567890'.repeat(3)}`.slice(order,order + 40),
    createdAt: at(minutes), completedAt: decision ? at(minutes - 2) : null,
    status: decision ? 'decided' : 'pending', decision, mode: 'demo', allowDeploy: false,
    checkmarx, codebert, findingsCount: count, unitsCount: 12 + index * 4,
    maxScore: count ? .91 - index * .06 : .21, duration: decision ? 118 + index * 25 : null,
    trigger: 'push (minh họa)', actor: 'demo-operator', reasons: reasons[decision] || [],
  }));
  const findings = [
    { id:'F-001', runId:'M-105', projectId:projects[0].id, title:'SQL Injection trong truy vấn người dùng', severity:'high', source:'Combined', cwes:['CWE-89'], groups:['SQL_INJECTION'], path:'app/routes/users.py', line:42, score:.94, verification:'unreviewed', code:'@app.get("/users")\ndef get_user():\n    name = request.args.get("name", "")\n    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n    return db.execute(query).fetchall()' },
    { id:'F-002', runId:'M-105', projectId:projects[0].id, title:'Path Traversal ở endpoint tải file', severity:'high', source:'Checkmarx only', cwes:['CWE-22'], groups:['PATH_TRAVERSAL'], path:'app/routes/files.py', line:18, score:.43, verification:'unreviewed', code:'@app.get("/download")\ndef download():\n    filename = request.args.get("file")\n    return send_file("uploads/" + filename)' },
    { id:'F-003', runId:'M-104', projectId:projects[1].id, title:'Reflected XSS trong trang tìm kiếm', severity:'medium', source:'Checkmarx only', cwes:['CWE-79'], groups:['XSS'], path:'search/views.py', line:27, score:.68, verification:'unreviewed' },
    { id:'F-004', runId:'M-106', projectId:projects[0].id, title:'Tín hiệu CodeBERT cần đối chiếu Checkmarx', severity:'unknown', source:'CodeBERT only', cwes:[], groups:['OS_COMMAND_INJECTION'], path:'app/jobs/runner.py', line:31, score:.86, verification:'unreviewed' },
    { id:'F-005', runId:'M-100', projectId:projects[0].id, title:'SQL Injection trong truy vấn người dùng', severity:'high', source:'Checkmarx only', cwes:['CWE-89'], groups:['SQL_INJECTION'], path:'app/routes/users.py', line:42, score:.61, verification:'unreviewed' },
    { id:'F-006', runId:'M-100', projectId:projects[0].id, title:'Thông tin xác thực ghi cứng trong cấu hình', severity:'high', source:'Combined', cwes:['CWE-798'], groups:['HARDCODED_CREDENTIALS'], path:'app/config.py', line:12, score:.81, verification:'unreviewed', code:'DB_USER = "demo_user"\nDB_PASSWORD = "demo_only_password"' },
  ];
  for (const run of runs) {
    const scores = findings.filter(finding => finding.runId === run.id).map(finding => finding.score);
    run.maxScore = scores.length ? Math.max(...scores) : .21;
    const stages={snapshot:[0,4],register:[4,6],codebert:[6,42],checkmarx:[6,108],combine:[108,116],gate:[116,118]};
    const timestamp=seconds=>new Date(Date.parse(run.createdAt)+seconds*1000).toISOString();
    const scale=(run.duration || 118)/118;
    if(run.decision)run.completedAt=timestamp(run.duration);
    run.tasks=tasksFor(run).map(task=>{
      const [start,end]=stages[task.id].map(seconds=>seconds*scale);
      const available=!['pending','running'].includes(task.status);
      return {...task,startedAt:available?timestamp(start):null,completedAt:available?timestamp(end):null,
        duration:available?end-start:null,events:available?[
          {timestamp:timestamp(start),message:`[DEMO] ${task.name}: bắt đầu tác vụ minh họa.`},
          {timestamp:timestamp(end),message:`[DEMO] Trạng thái fixture: ${task.status}.`},
        ]:[]};
    });
  }
  const details = {};
  for (const run of runs) {
    const policy = {version:'demo-policy-v1',release_approved:false,block_checkmarx_severities:['critical','high'],review_score_margin:.05};
    const scope = run.projectId === projects[0].id
      ? ['app/config.py','app/routes/files.py','app/routes/users.py','app/jobs/runner.py']
      : run.projectId === projects[1].id ? ['search/views.py'] : ['app/main.py'];
    const units = scope.map((path,index)=>({unit_id:`demo-unit-${index}`,path,start_line:1,end_line:120,sha256:'c'.repeat(64)}));
    const runFindings = findings.filter(finding=>finding.runId===run.id);
    const scannerFindings = runFindings.filter(finding=>finding.source!=='CodeBERT only').map(finding=>{
      finding.detectorId=finding.id;
      finding.ruleId=finding.groups[0];
      return {finding_id:finding.id,rule_id:finding.ruleId,severity:finding.severity,cwes:finding.cwes,groups:finding.groups,path:finding.path,start_line:finding.line,unit_ids:units.filter(unit=>unit.path===finding.path).map(unit=>unit.unit_id)};
    });
    const predictions = units.map(unit=>({unit_id:unit.unit_id,token_count:24,scores:Object.fromEntries(GROUPS.map(group=>[group,Math.max(.1,...runFindings.filter(finding=>finding.path===unit.path&&finding.groups.includes(group)).map(finding=>finding.score??.1))]))}));
    run.unitsCount=units.length;
    details[run.id] = {
      run, identity:{run_id:run.id,repository:run.repo,commit_sha:run.commit,artifact_digest:`sha256:${'a'.repeat(64)}`},
      source_manifest_sha256:'b'.repeat(64),coverage_issues:[],units,policy,
      workflow:{parallel:['checkmarx','codebert'],join:'gateway',final:'security-gate',authority:'gateway-security-gate'},
      checkmarx:run.checkmarx==='pending'?null:{status:run.checkmarx,mode:'demo',preset:'Minh họa SARIF',scan_id:`demo-${run.id}`,source_manifest_sha256:'b'.repeat(64),coverage_issues:[],findings:scannerFindings},
      codebert:{status:'completed',mode:'demo',authority:'codebert-inference',model_version:'demo-fixture-v1',thresholds:Object.fromEntries(GROUPS.map(group=>[group,.7])),coverage_issues:[],predictions,reasons:['Inference mô phỏng để xem giao diện.']},
      final_decision:run.decision?{decision:run.decision,mode:'demo',allow_deploy:false,authority:'gateway-security-gate',created_at:run.completedAt,reasons:run.reasons,missing_branches:[]}:null,
    };
  }
  return { source:'demo',generatedAt:new Date(now).toISOString(),projects,runs,findings,details,
    model:{status:'demo',mode:'demo',version:'demo-fixture-v1',model_version:'demo-fixture-v1',thresholds:Object.fromEntries(GROUPS.map(group=>[group,.7])),performance:null,readiness:'not_checked',observed_run_id:'M-105'},
    warnings:[],workflow:{parallel:['checkmarx','codebert'],join:'gateway',final:'security-gate',authority:'gateway-security-gate'},
  };
}
