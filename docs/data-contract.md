# Finding data contract

## Raw finding

Every detector result must preserve `source`, repository commit context, source
location, CWE, severity, detector evidence, and the version that produced it.
Confidence is required for AI findings and may be absent for Checkmarx findings.

The backend generates a stable fingerprint from path, function, CWE, and source
status when the producer does not provide one. SARIF partial fingerprints remain
inside `evidence` for traceability.

## Combined finding

The backend is the only component allowed to create `source=combined`. Current
statuses are:

- `AGREEMENT`: CodeBERT and Checkmarx match under correlation policy v1.
- `AI_ONLY`: only CodeBERT reports the code unit and CWE.
- `SAST_ONLY`: only Checkmarx reports the code unit and CWE.

Raw findings are not deleted after correlation.

## Dataset boundary

The pilot model supports five CWE classes. `CWE-798` is allowed in the general
schema because Checkmarx may report it, but it is not a supported output of the
current CodeBERT pilot. The inference metadata endpoint exposes both supported
and unsupported classes so the dashboard can state this limitation explicitly.

