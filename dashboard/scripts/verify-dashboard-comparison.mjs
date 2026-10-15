/** node --experimental-vm-modules scripts/verify-dashboard-comparison.mjs */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath, pathToFileURL } from 'node:url';

const assets = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../app/static/dashboard');
const context = vm.createContext({});
const modules = new Map();
let checks = 0;
const equal = (actual, expected, message) => { checks++; assert.equal(actual, expected, message); };
const truth = (actual, message) => { checks++; assert.ok(actual, message); };
const clone = value => JSON.parse(JSON.stringify(value));
async function load(filename) {
  const resolved = path.resolve(filename);
  if (modules.has(resolved)) return modules.get(resolved);
  const relative = path.relative(assets, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) throw new Error('Module must be inside dashboard assets');
  const module = new vm.SourceTextModule(await fs.readFile(resolved, 'utf8'), { context, identifier: pathToFileURL(resolved).href });
  modules.set(resolved, module);
  await module.link((specifier, parent) => {
    if (!specifier.startsWith('./')) throw new Error('Only dashboard-local modules are allowed');
    return load(path.resolve(path.dirname(fileURLToPath(parent.identifier)), specifier));
  });
  await module.evaluate();
  return module;
}

try {
  const { createDemo } = (await load(path.join(assets, 'demo.js'))).namespace;
  const { compareRuns, ensureComparisonSelection, renderComparison } = (await load(path.join(assets, 'comparison.js'))).namespace;
  const demo = createDemo();
  const beforeJSON = JSON.stringify(demo);
  const result = compareRuns(demo, 'M-100', 'M-105');
  truth(result.valid && result.comparable, 'Full demo evidence allows a comparable pair');
  equal(result.counts.new, 1, 'Demo illustrates a newly observed scanner finding');
  equal(result.counts.persistent, 1, 'Demo illustrates one persistent scanner finding');
  equal(result.counts['not-observed'], 1, 'Demo illustrates absence without claiming a verified fix');
  equal(result.counts.unknown, 0, 'Complete default example has no ambiguous identities');
  const persistent = result.rows.find(row => row.status === 'persistent');
  equal(persistent.base.id, 'F-005', 'Old run-specific finding ID is retained only as evidence');
  equal(persistent.target.id, 'F-001', 'Matching ignores run-specific finding identifiers');
  equal(persistent.base.source, 'Checkmarx only', 'Old scanner finding has no above-threshold AI agreement');
  equal(persistent.target.source, 'Combined', 'AI agreement transition does not create a new scanner identity');
  equal(JSON.stringify(demo), beforeJSON, 'Calculation does not mutate any audit or fixture data');

  const state = { project: 'all' };
  ensureComparisonSelection(demo, state);
  equal(state.compareBaseId, 'M-100', 'Default base is a completed predecessor');
  equal(state.compareTargetId, 'M-105', 'Default target skips pending latest run');
  state.compareTargetId = 'M-106';
  ensureComparisonSelection(demo, state);
  equal(state.compareTargetId, 'M-106', 'Explicit pending run selection stays visible');
  state.project = 'whitesec/django-demo-b';
  const selected = ensureComparisonSelection(demo, state);
  truth(selected.runs.every(run => run.projectId === state.project), 'Project selection keeps both selectors in one repository');
  equal(state.compareBaseId, 'M-102', 'Changing repository resets stale base selection');
  equal(state.compareTargetId, 'M-104', 'Changing repository resets stale target selection');
  const emptyState = {};
  ensureComparisonSelection({}, emptyState);
  equal(emptyState.compareBaseId, null, 'Empty data has no invented base');
  equal(emptyState.compareTargetId, null, 'Empty data has no invented target');
  truth(!compareRuns(demo, 'M-100', 'M-104').valid, 'Cross-repository comparison is blocked');
  truth(!compareRuns(demo, 'M-105', 'M-105').valid, 'Same run comparison is blocked');
  truth(!compareRuns(demo, 'missing', 'M-105').valid, 'Missing selected run has an actionable empty state');
  const otherMode = clone(demo);
  otherMode.runs.find(run => run.id === 'M-105').mode = 'real';
  truth(!compareRuns(otherMode, 'M-100', 'M-105').valid, 'Demo and real observations cannot be mixed');

  const pending = compareRuns(demo, 'M-105', 'M-106');
  truth(pending.valid && !pending.comparable, 'Pending pair remains viewable with cautions');
  equal(pending.counts.new, 0, 'Pending evidence does not prove new findings');
  equal(pending.counts['not-observed'], 0, 'Pending scanner absence does not prove a finding disappeared');
  truth(pending.counts.unknown > 0, 'Pending unmatched evidence remains uncertain');
  truth(!pending.warnings.some(warning => warning.includes('chế độ của bằng chứng')), 'Absent pending scanner is not mislabeled as a mode mismatch');
  const pendingHTML = renderComparison(demo, { compareBaseId: 'M-105', compareTargetId: 'M-106', compareFilter: 'unknown' });
  truth(pendingHTML.includes('Lượt đối chiếu đang chờ quyết định Gate.'), 'Pending gate is reported as waiting for a decision');
  truth(!pendingHTML.includes('Quyết định Gate đã thay đổi.'), 'Missing decision is never presented as a changed decision');
  truth(pendingHTML.includes('data-value="unknown" class="active"'), 'Unknown evidence has a dedicated active filter');
  for (const [label, mutate] of [
    ['incomplete detector', value => { value.runs.find(run => run.id === 'M-105').checkmarx = 'incomplete'; value.details['M-105'].checkmarx.status = 'incomplete'; }],
    ['error detector', value => { value.details['M-105'].codebert.status = 'error'; }],
    ['missing detail', value => { delete value.details['M-105']; }],
    ['missing coverage metadata', value => { delete value.details['M-105'].codebert.coverage_issues; }],
    ['missing scanner manifest', value => { delete value.details['M-105'].checkmarx.source_manifest_sha256; }],
    ['coverage issue', value => { value.details['M-105'].coverage_issues.push('partial scope'); }],
    ['changed scope', value => { value.details['M-105'].units[0].path = 'different/config.py'; }],
    ['same-file changed unit scope', value => { value.details['M-105'].units[0].start_line = 2; }],
    ['unknown unit range', value => { delete value.details['M-105'].units[0].end_line; }],
    ['changed preset', value => { value.details['M-105'].checkmarx.preset = 'Different preset'; }],
    ['changed model', value => { value.details['M-105'].codebert.model_version = 'different-version'; }],
    ['changed threshold', value => { value.details['M-105'].codebert.thresholds.SQL_INJECTION = .8; }],
    ['missing predictions', value => { value.details['M-105'].codebert.predictions.pop(); }],
    ['wrong unit prediction', value => { value.details['M-105'].codebert.predictions[0].unit_id = 'not-a-declared-unit'; }],
    ['duplicate unit prediction', value => { value.details['M-105'].codebert.predictions[0].unit_id = value.details['M-105'].codebert.predictions[1].unit_id; }],
    ['missing source unit', value => { value.details['M-105'].units.pop(); }],
    ['wrong evidence identity', value => { value.details['M-105'].identity.commit_sha = 'wrong'; }],
    ['omitted finding', value => { value.findings = value.findings.filter(finding => finding.id !== 'F-002'); }],
  ]) {
    const input = clone(demo);
    mutate(input);
    const compared = compareRuns(input, 'M-100', 'M-105');
    truth(compared.valid && !compared.comparable, `${label}: comparison explains uncertainty`);
    equal(compared.counts.new, 0, `${label}: no false claim of a new finding`);
    equal(compared.counts['not-observed'], 0, `${label}: no false claim of absence`);
    truth(compared.warnings.length > 0, `${label}: caution describes the missing condition`);
  }

  const moved = clone(demo);
  moved.findings.find(finding => finding.id === 'F-001').line = 43;
  const movedResult = compareRuns(moved, 'M-100', 'M-105');
  equal(movedResult.counts.persistent, 0, 'Shifted line is not automatically the same vulnerability');
  equal(movedResult.counts.unknown, 2, 'Both sides of a possible line shift require source review');
  equal(movedResult.counts.new, 1, 'Possible line shift does not inflate new findings');
  equal(movedResult.counts['not-observed'], 1, 'Possible line shift does not inflate missing findings');

  const paths = clone(demo);
  paths.findings.find(finding => finding.id === 'F-001').path = '.\\app\\routes\\users.py';
  equal(compareRuns(paths, 'M-100', 'M-105').counts.persistent, 1, 'Relative prefix and slash normalization preserve path identity');
  const noLine = clone(demo);
  noLine.findings.find(finding => finding.id === 'F-001').line = null;
  truth(compareRuns(noLine, 'M-100', 'M-105').rows.some(row => row.target?.id === 'F-001' && row.status === 'unknown'), 'Missing line cannot create a confident new finding');
  equal(compareRuns(noLine, 'M-100', 'M-105').counts['not-observed'], 0, 'An unidentified target finding cannot prove absence of a base finding');

  const liveRules = clone(demo);
  liveRules.source = 'live';
  liveRules.findings.find(finding => finding.id === 'F-001').title = 'Changed display title';
  delete liveRules.findings.find(finding => finding.id === 'F-001').ruleId;
  equal(compareRuns(liveRules, 'M-100', 'M-105').counts.persistent, 1, 'Live raw scanner rule is recovered from detailed evidence');
  liveRules.details['M-105'].checkmarx.findings.find(finding => finding.finding_id === 'F-001').rule_id = 'Different SQL rule';
  equal(compareRuns(liveRules, 'M-100', 'M-105').counts.persistent, 0, 'Different scanner rules at the same location are not conflated');

  const aiSeparate = clone(demo);
  aiSeparate.findings.find(finding => finding.id === 'F-001').source = 'CodeBERT only';
  equal(compareRuns(aiSeparate, 'M-100', 'M-105').counts.persistent, 0, 'AI-only signal cannot impersonate a scanner finding');
  const duplicates = clone(demo);
  duplicates.findings.push({ ...duplicates.findings.find(finding => finding.id === 'F-001'), id: 'duplicate' });
  equal(compareRuns(duplicates, 'M-100', 'M-105').counts.persistent, 0, 'Ambiguous duplicate signature is never matched arbitrarily');
  truth(compareRuns(demo, 'M-105', 'M-100').warnings.some(warning => warning.includes('mới hơn')), 'Reversed direction remains available with a chronological note');

  const hostile = clone(demo);
  const attack = '\"><img src=x onerror=alert(1)>';
  hostile.findings.find(finding => finding.id === 'F-001').title = attack;
  hostile.findings.find(finding => finding.id === 'F-001').path = attack;
  hostile.findings.find(finding => finding.id === 'F-001').id = attack;
  hostile.projects[0].name = attack;
  const html = renderComparison(hostile, { compareBaseId: 'M-100', compareTargetId: 'M-105', project: 'all' });
  truth(!html.includes('<img'), 'Finding, path, project and action attributes escape untrusted strings');
  truth(html.includes('&lt;img'), 'Escaping preserves readable text');
  truth(html.includes('data-action="compare-export"'), 'Comparison offers a reviewable export');
  truth(html.includes('data-action="compare-swap"'), 'Comparison offers explicit direction switching');
  const onlyNew = renderComparison(demo, { compareBaseId: 'M-100', compareTargetId: 'M-105', compareFilter: 'new' });
  truth(onlyNew.includes('data-finding="F-002"') && !onlyNew.includes('data-finding="F-001"'), 'New filter shows only new evidence rows');
  truth(!renderComparison({}, {}).includes('undefined'), 'Empty view has no undefined text');
  truth(!renderComparison(demo, { compareBaseId: 'M-100', compareTargetId: 'M-105' }).includes('Đã sửa'), 'UI never promotes absence into a verified fix');
  console.log(`Dashboard comparison verified: ${checks} checks passed.`);
} catch (error) {
  console.error(`Dashboard comparison verification failed: ${error.message}`);
  process.exitCode = 1;
}
