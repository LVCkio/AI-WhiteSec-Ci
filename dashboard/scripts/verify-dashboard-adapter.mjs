/** Verify dashboard mapping against an actual authenticated API export.
 * node --experimental-vm-modules scripts/verify-dashboard-adapter.mjs --url http://127.0.0.1:8080
 * Reads GATEWAY_API_KEY from the environment; never prints or persists it.
 * Alternatively use --snapshot <path> for an already exported audit document.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';
import {fileURLToPath, pathToFileURL} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const assets = path.join(root, 'app', 'static', 'dashboard');
const context = vm.createContext({});
const modules = new Map();
let checks = 0;
const equal = (actual, expected, message) => { checks++; assert.equal(actual, expected, message); };
const truth = (value, message) => { checks++; assert.ok(value, message); };
const finite = value => typeof value === 'number' && Number.isFinite(value);
const list = value => Array.isArray(value) ? value : [];

async function loadModule(filename) {
  const resolved = path.resolve(filename);
  const relative = path.relative(assets, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Module is outside dashboard assets');
  if (modules.has(resolved)) return modules.get(resolved);
  const source = await fs.readFile(resolved, 'utf8');
  const module = new vm.SourceTextModule(source, {context, identifier: pathToFileURL(resolved).href});
  modules.set(resolved, module);
  await module.link((specifier, parent) => {
    if (!specifier.startsWith('./')) throw new Error('Only local dashboard imports are supported');
    return loadModule(path.resolve(path.dirname(fileURLToPath(parent.identifier)), specifier));
  });
  await module.evaluate();
  return module;
}

async function readExport() {
  const args = process.argv.slice(2);
  if (args.length !== 2 || !['--url', '--snapshot'].includes(args[0])) {
    throw new Error('Use --url <Gateway origin> with GATEWAY_API_KEY, or --snapshot <export.json>');
  }
  if (args[0] === '--snapshot') return JSON.parse(await fs.readFile(path.resolve(args[1]), 'utf8'));
  const key = process.env.GATEWAY_API_KEY;
  if (!key?.trim()) throw new Error('GATEWAY_API_KEY must be configured for the API request');
  const url = new URL('/v1/dashboard/export', args[1]);
  const response = await fetch(url, {headers: {'X-API-Key': key}, cache: 'no-store',
                                    signal: AbortSignal.timeout(15000)});
  if (!response.ok) throw new Error(`Dashboard export returned HTTP ${response.status}`);
  return response.json();
}

function verifyAudit(payload, adapted) {
  equal(payload.schema_version, '1.0', 'Dashboard export version');
  truth(Array.isArray(payload.runs) && Array.isArray(payload.details), 'Full export has runs and details');
  equal(adapted.runs.length, payload.runs.length, 'Adapter preserves run count');
  equal(adapted.source, 'live', 'Audit observations remain separate from UI demo fixtures');
  equal(adapted.model.performance, null, 'Audit predictions do not invent performance metrics');
  equal(adapted.model.version, payload.model?.model_version, 'Nullable model version stays nullable');
  equal(adapted.model.readiness, payload.model?.readiness, 'Audit metadata does not promote current readiness');
  let expectedFindingCount = 0;
  for (const run of payload.runs) {
    const actual = adapted.runs.find(item => item.id === run.run_id);
    const detail = payload.details.find(item => item.run.run_id === run.run_id);
    truth(actual && detail, 'Every included run keeps its details');
    equal(actual.commit, detail.identity.commit_sha, 'Model/scanner evidence keeps the locked commit');
    equal(actual.repo, detail.identity.repository, 'Evidence keeps the locked repository');
    equal(actual.mode, run.mode, 'Run mode is preserved');
    equal(actual.decision, run.decision, 'Gateway remains the decision authority');
    equal(actual.allowDeploy, run.allow_deploy, 'Adapter never upgrades release permission');
    equal(actual.duration, null, 'Missing runtime telemetry stays unknown');
    equal(actual.branch, null, 'Missing branch metadata stays unknown');
    if (run.status === 'pending') {
      equal(actual.decision, null, 'A pending join is not PASS');
      equal(actual.allowDeploy, false, 'Pending joins cannot release');
    }
    if (run.mode !== 'real') equal(actual.allowDeploy, false, 'Demo/unknown observations cannot release');
    const scanner = list(detail.checkmarx?.findings);
    const predictions = list(detail.codebert?.predictions);
    const thresholds = detail.codebert?.thresholds || {};
    for (const finding of scanner) {
      const candidates = [];
      for (const prediction of predictions) {
        if (!list(finding.unit_ids).includes(prediction.unit_id)) continue;
        for (const group of list(finding.groups)) {
          if (finite(prediction.scores?.[group])) candidates.push({score: prediction.scores[group], threshold: thresholds[group]});
        }
      }
      const hit = candidates.some(item => finite(item.threshold) && item.score >= item.threshold);
      const mapped = adapted.findings.find(item => item.id === `${run.run_id}::${finding.finding_id}`);
      truth(mapped, 'Checkmarx finding identity is retained');
      equal(mapped.runId, run.run_id, 'Finding cannot move to a different run');
      equal(mapped.source, hit ? 'Combined' : 'Checkmarx only', 'Agreement uses same-unit/group calibrated threshold');
      equal(mapped.score, candidates.length ? Math.max(...candidates.map(item => item.score)) : null,
            'Raw below-threshold probabilities remain visible');
      equal(mapped.severity, finding.severity, 'AI agreement does not overwrite scanner severity');
      equal(mapped.path, finding.path, 'Scanner path is preserved');
      expectedFindingCount++;
    }
    for (const prediction of predictions) {
      for (const [group, score] of Object.entries(prediction.scores || {})) {
        if (!finite(score) || !finite(thresholds[group]) || score < thresholds[group]) continue;
        const paired = scanner.some(finding => list(finding.unit_ids).includes(prediction.unit_id)
                                   && list(finding.groups).includes(group));
        const id = `${run.run_id}::AI::${prediction.unit_id}::${group}`;
        const matches = adapted.findings.filter(item => item.id === id);
        equal(matches.length, paired ? 0 : 1, 'Paired AI signals are deduplicated; unpaired signals are retained once');
        if (!paired) {
          const mapped = matches[0];
          equal(mapped.source, 'CodeBERT only', 'Unpaired prediction retains its detector source');
          equal(mapped.severity, 'unknown', 'AI probabilities do not manufacture scanner severity');
          equal(mapped.score, score, 'Unpaired raw probability is preserved');
          const unit = list(detail.units).find(item => item.unit_id === prediction.unit_id);
          equal(mapped.path, unit?.path || null, 'AI location is a source-unit reference');
          expectedFindingCount++;
        }
      }
    }
  }
  equal(adapted.findings.length, expectedFindingCount, 'No fabricated or duplicated mapped findings');
}

function verifyDemo(demo) {
  equal(demo.source, 'demo', 'UI fixtures remain explicitly labelled');
  equal(demo.model.performance, null, 'Demo does not invent trained performance');
  equal(demo.model.readiness, 'not_checked', 'Demo does not claim current model readiness');
  for (const run of demo.runs) {
    const detail = demo.details[run.id];
    equal(run.mode, 'demo', 'All UI fixture runs are demo mode');
    equal(run.allowDeploy, false, 'No UI fixture releases deployment');
    equal(detail.identity.run_id, run.id, 'Fixture run identity matches');
    equal(detail.identity.commit_sha, run.commit, 'Fixture commit identity matches');
    if (run.status === 'pending') {
      equal(run.decision, null, 'Pending fixture keeps its decision unset');
      equal(detail.final_decision, null, 'Pending fixture has no Security Gate result');
    } else {
      equal(detail.final_decision.decision, run.decision, 'Fixture decision matches its detail');
      equal(detail.final_decision.allow_deploy, false, 'Fixture final gate cannot release');
    }
    const scores = demo.findings.filter(item => item.runId === run.id).map(item => item.score).filter(finite);
    if (scores.length) truth(run.maxScore >= Math.max(...scores), 'Run maximum is consistent with illustrated finding scores');
  }
  for (const finding of demo.findings) {
    const run = demo.runs.find(item => item.id === finding.runId);
    truth(run, 'Fixture finding belongs to an existing run');
    const threshold = demo.details[run.id].codebert.thresholds[finding.groups[0]];
    if (finding.source === 'Combined' || finding.source === 'CodeBERT only') {
      truth(finding.score >= threshold, 'Positive fixture signal is above its calibrated threshold');
      if (run.status !== 'pending' && run.checkmarx === 'completed') {
        equal(run.decision, 'BLOCK', 'Completed fixture with an AI threshold hit must be BLOCK');
      }
    } else if (finding.source === 'Checkmarx only' && finite(finding.score)) {
      truth(finding.score < threshold, 'Scanner-only fixture score is below its AI threshold');
    }
  }
}

try {
  if (typeof vm.SourceTextModule !== 'function') throw new Error('Run Node with --experimental-vm-modules');
  const payload = await readExport();
  const adapter = await loadModule(path.join(assets, 'adapter.js'));
  const demoModule = await loadModule(path.join(assets, 'demo.js'));
  const ui = await loadModule(path.join(assets, 'ui.js'));
  const adapted = adapter.namespace.adaptAudit(payload);
  const demo = demoModule.namespace.createDemo();
  verifyAudit(payload, adapted);
  verifyDemo(demo);
  for (const run of adapted.runs) {
    const tasks = ui.namespace.tasksFor(run);
    for (const id of ['snapshot','codebert','checkmarx','combine']) {
      const task = tasks.find(item => item.id === id);
      equal(task.startedAt, null, 'Run registration is not detector start telemetry');
      equal(task.completedAt, null, 'Final gate time is not detector completion telemetry');
      equal(task.duration, null, 'Missing detector runtime remains unknown');
    }
    equal(tasks.find(item=>item.id==='register').startedAt,run.createdAt,'Audited registration time is retained');
    equal(tasks.find(item=>item.id==='gate').completedAt,run.decision?run.completedAt:null,'Final gate event uses only its own audit timestamp');
  }
  for (const run of demo.runs.filter(item=>item.decision)) {
    const model=run.tasks.find(item=>item.id==='codebert');
    const scanner=run.tasks.find(item=>item.id==='checkmarx');
    equal(model.startedAt,scanner.startedAt,'Demo fixtures illustrate two parallel detector starts');
    truth(run.tasks.every(task=>task.events.every(event=>event.message.startsWith('[DEMO]'))),'Fixture task events stay explicitly demo');
  }
  console.log(`Verified ${payload.runs.length} audit runs, ${adapted.findings.length} mapped findings, ${demo.runs.length} UI demo runs; ${checks} checks passed.`);
} catch (error) {
  console.error(`Dashboard adapter verification failed: ${error.message}`);
  process.exitCode = 1;
}
