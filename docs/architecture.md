# System architecture

## Goal

The skeleton separates detector execution from integration. Checkmarx remains a
standalone SAST detector. The CodeBERT service remains a standalone classifier.
The backend stores their raw outputs before producing a reproducible combined
view. This preserves evidence for research comparisons and error analysis.

## Runtime flow

1. GitHub Actions checks out the exact commit.
2. Checkmarx scans the repository and exports SARIF.
3. The extractor identifies Python functions or module fallbacks.
4. The inference API returns a supported CWE, confidence scores, and model version.
5. The pipeline sends raw AI and Checkmarx findings to the backend.
6. The correlator creates `AGREEMENT`, `AI_ONLY`, and `SAST_ONLY` findings.
7. PostgreSQL stores the run, raw evidence, and combined view.
8. The dashboard reads the same versioned run used by the experiment scripts.

## Trust boundaries

- Do not send private source code to the VPS unless the repository owner has
  approved it and transport authentication is enabled.
- Keep Checkmarx credentials only in CI secrets. Never write them to reports.
- The mock predictor is a contract test and must never be presented as an AI
  vulnerability-detection result.
- A `SAFE` model label means no supported target CWE was detected. It is not a
  statement that the code has no vulnerability.
- Preserve raw detector output. A policy change must create a new combined view
  or experiment version rather than rewriting the original evidence.

## Correlation policy v1

Two findings agree when they have the same normalized path and CWE, and either
their function names match or their line ranges overlap. The policy deliberately
does not suppress detector-only findings. It is suitable for an initial
agreement-first dashboard and can be evaluated before any CI blocking is added.

## Production replacement points

- Replace `MockPredictor` with the fine-tuned checkpoint loader.
- Add an authenticated API gateway or per-repository token before remote CI use.
- Add Alembic migrations before changing database schemas after experiments begin.
- Pin third-party GitHub Actions to reviewed commit SHAs before production use.
- Add object storage if SARIF/model artifacts outgrow the VPS filesystem.

