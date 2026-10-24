import { groupName } from './ui.js';

const list = value => Array.isArray(value) ? value : [];
const finite = value => typeof value === 'number' && Number.isFinite(value);

/** Audit projections only. Missing timestamps, ownership and telemetry stay unknown. */
export function adaptAudit(payload) {
  const details = Object.fromEntries(list(payload.details).map(detail => [detail.run.run_id, detail]));
  const projects = [...new Set(list(payload.runs).map(run => run.repository))].map(repo => ({
    id: repo, repo, name: repo.split('/').filter(Boolean).at(-1) || repo,
    framework: 'Chưa ghi nhận', owner: 'Chưa ghi nhận', environment: 'Local', phase: null,
  }));
  const runs = list(payload.runs).map(run => {
    const detail = details[run.run_id];
    return { id: run.run_id, projectId: run.repository,
      projectName: projects.find(project => project.id === run.repository)?.name,
      repo: run.repository, branch: null, commit: run.commit_sha,
      createdAt: run.created_at, completedAt: detail?.final_decision?.created_at || null,
      status: run.status, decision: run.decision, mode: run.mode,
      allowDeploy: run.allow_deploy === true, checkmarx: run.checkmarx_status,
      codebert: run.codebert_status, findingsCount: run.findings_count,
      unitsCount: run.units_count, maxScore: run.max_score, duration: null,
      trigger: 'Chưa ghi nhận', actor: 'Chưa ghi nhận',
      reasons: list(detail?.final_decision?.reasons),
    };
  });
  const findings = [];
  for (const run of runs) {
    const detail = details[run.id];
    const detector = detail?.codebert;
    const predictions = list(detector?.predictions);
    const thresholds = detector?.thresholds || {};
    const units = list(detail?.units);
    const sast = list(detail?.checkmarx?.findings);
    const scannerFindings = detail ? sast : list(payload.findings).filter(item => item.run_id === run.id);
    for (const item of scannerFindings) {
      const candidates = predictions.flatMap(prediction => list(item.groups)
        .filter(group => list(item.unit_ids).includes(prediction.unit_id) && finite(prediction.scores?.[group]))
        .map(group => ({score:prediction.scores[group],threshold:thresholds[group]})));
      const hits = candidates.filter(item => finite(item.threshold) && item.score >= item.threshold);
      findings.push({ id: `${run.id}::${item.finding_id}`, detectorId: item.finding_id,
        runId: run.id, projectId: run.projectId, projectName: run.projectName,
        title: item.rule_id || 'Finding Checkmarx', severity: item.severity,
        source: hits.length ? 'Combined' : 'Checkmarx only',
        cwes: list(item.cwes), groups: list(item.groups), path: item.path,
        line: item.start_line, score: candidates.length ? Math.max(...candidates.map(item=>item.score)) : null,
        verification: 'unreviewed',
      });
    }
    for (const prediction of predictions) {
      for (const [group, value] of Object.entries(prediction.scores || {})) {
        if (!finite(value) || !finite(thresholds[group]) || value < thresholds[group]) continue;
        if (sast.some(item => list(item.unit_ids).includes(prediction.unit_id) && list(item.groups).includes(group))) continue;
        const unit = units.find(item => item.unit_id === prediction.unit_id);
        findings.push({ id: `${run.id}::AI::${prediction.unit_id}::${group}`,
          runId: run.id, projectId: run.projectId, projectName: run.projectName,
          title: `Tín hiệu CodeBERT · ${groupName(group)}`, severity: 'unknown',
          source: 'CodeBERT only', cwes: [], groups: [group],
          path: unit?.path || null, line: unit?.start_line || null,
          score: value, verification: 'unreviewed',
        });
      }
    }
  }
  for (const run of runs) {
    run.checkmarxFindingsCount=run.findingsCount;
    run.findingsCount=findings.filter(finding=>finding.runId===run.id).length;
  }
  return { source: 'live', generatedAt: payload.generated_at, projects, runs, findings,
    model: { ...payload.model, version: payload.model?.model_version, performance: null },
    details, warnings: list(payload.warnings), window: payload.window,
    workflow: payload.workflow,
  };
}
