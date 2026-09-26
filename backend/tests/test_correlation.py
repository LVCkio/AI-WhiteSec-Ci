"""Extended unit tests for the correlation service.

Covers agreement detection, detector-only preservation, path normalisation,
severity escalation, duplicate fingerprint stability, and edge cases.
"""
from __future__ import annotations

import pytest

from app.services.correlation import (
    correlate_findings,
    findings_match,
    lines_overlap,
    make_fingerprint,
    normalize_path,
    stronger_severity,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _finding(
    source: str,
    finding_id: str,
    file_path: str = "app/users.py",
    cwe: str = "CWE-89",
    function_name: str = "find_user",
    start_line: int = 10,
    end_line: int = 20,
    severity: str = "high",
    confidence: float | None = None,
):
    if confidence is None:
        confidence = 0.9 if source == "ai" else None
    return {
        "id": finding_id,
        "run_id": "run-1",
        "source": source,
        "file_path": file_path,
        "function_name": function_name,
        "start_line": start_line,
        "end_line": end_line,
        "cwe": cwe,
        "severity": severity,
        "confidence": confidence,
        "title": f"Finding {finding_id}",
        "description": None,
        "evidence": {},
        "fingerprint": finding_id,
        "combination_status": None,
        "remediation": None,
        "created_at": "2026-01-01T00:00:00Z",
    }


# ── normalize_path ─────────────────────────────────────────────────────────────

class TestNormalizePath:
    def test_backslash_to_forward(self):
        assert normalize_path("app\\users.py") == "app/users.py"

    def test_strip_leading_dot_slash(self):
        assert normalize_path("./app/users.py") == "app/users.py"

    def test_lowercase(self):
        assert normalize_path("App/Users.PY") == "app/users.py"

    def test_combined(self):
        assert normalize_path(".\\App\\Users.PY") == "app/users.py"


# ── lines_overlap ──────────────────────────────────────────────────────────────

class TestLinesOverlap:
    def test_exact_overlap(self):
        assert lines_overlap({"start_line": 10, "end_line": 20}, {"start_line": 10, "end_line": 20})

    def test_partial_overlap(self):
        assert lines_overlap({"start_line": 10, "end_line": 15}, {"start_line": 14, "end_line": 20})

    def test_adjacent_no_overlap(self):
        assert not lines_overlap({"start_line": 10, "end_line": 13}, {"start_line": 14, "end_line": 20})

    def test_missing_line_returns_false(self):
        assert not lines_overlap({"start_line": 10}, {"start_line": 10, "end_line": 20})

    def test_single_line_match(self):
        assert lines_overlap({"start_line": 10, "end_line": 10}, {"start_line": 10, "end_line": 10})


# ── stronger_severity ─────────────────────────────────────────────────────────

class TestStrongerSeverity:
    def test_high_beats_medium(self):
        assert stronger_severity("medium", "high") == "high"

    def test_critical_wins(self):
        assert stronger_severity("critical", "high", "low") == "critical"

    def test_none_ignored(self):
        assert stronger_severity(None, "low") == "low"

    def test_all_none_defaults_medium(self):
        assert stronger_severity(None, None) == "medium"


# ── make_fingerprint ──────────────────────────────────────────────────────────

class TestMakeFingerprint:
    def test_deterministic(self):
        item = {"file_path": "app/users.py", "function_name": "find_user", "cwe": "CWE-89", "combination_status": "AGREEMENT"}
        assert make_fingerprint(item) == make_fingerprint(item)

    def test_different_cwe_different_fingerprint(self):
        base = {"file_path": "app/users.py", "function_name": "find_user", "combination_status": "AGREEMENT"}
        assert make_fingerprint({**base, "cwe": "CWE-89"}) != make_fingerprint({**base, "cwe": "CWE-79"})

    def test_path_normalisation_applied(self):
        a = {"file_path": "app/users.py", "function_name": "f", "cwe": "CWE-89", "combination_status": "AGREEMENT"}
        b = {"file_path": "APP\\users.PY", "function_name": "f", "cwe": "CWE-89", "combination_status": "AGREEMENT"}
        assert make_fingerprint(a) == make_fingerprint(b)


# ── findings_match ─────────────────────────────────────────────────────────────

class TestFindingsMatch:
    def test_function_name_match(self):
        ai = _finding("ai", "a1")
        cx = _finding("checkmarx", "c1")
        assert findings_match(ai, cx)

    def test_different_cwe_no_match(self):
        ai = _finding("ai", "a1", cwe="CWE-89")
        cx = _finding("checkmarx", "c1", cwe="CWE-79")
        assert not findings_match(ai, cx)

    def test_different_file_no_match(self):
        ai = _finding("ai", "a1", file_path="app/a.py")
        cx = _finding("checkmarx", "c1", file_path="app/b.py")
        assert not findings_match(ai, cx)

    def test_line_overlap_match_when_no_function(self):
        ai = _finding("ai", "a1", function_name="", start_line=10, end_line=20)
        cx = _finding("checkmarx", "c1", function_name="", start_line=15, end_line=25)
        assert findings_match(ai, cx)

    def test_case_insensitive_function(self):
        ai = _finding("ai", "a1", function_name="FindUser")
        cx = _finding("checkmarx", "c1", function_name="finduser")
        assert findings_match(ai, cx)


# ── correlate_findings ────────────────────────────────────────────────────────

class TestCorrelateFindings:
    def test_agreement_when_file_function_and_cwe_match(self):
        results = correlate_findings([_finding("ai", "ai-1"), _finding("checkmarx", "cx-1")])
        assert len(results) == 1
        r = results[0]
        assert r["combination_status"] == "AGREEMENT"
        assert r["confidence"] == 0.9
        assert r["source"] == "combined"

    def test_preserves_detector_only_findings(self):
        results = correlate_findings([
            _finding("ai", "ai-1", cwe="CWE-79"),
            _finding("checkmarx", "cx-1", cwe="CWE-89"),
        ])
        statuses = {r["combination_status"] for r in results}
        assert statuses == {"AI_ONLY", "SAST_ONLY"}

    def test_agreement_evidence_contains_ids(self):
        results = correlate_findings([_finding("ai", "ai-1"), _finding("checkmarx", "cx-1")])
        ev = results[0]["evidence"]
        assert "ai-1" in ev["ai_finding_ids"]
        assert "cx-1" in ev["checkmarx_finding_ids"]

    def test_agreement_uses_stronger_severity(self):
        ai = _finding("ai", "ai-1", severity="medium")
        cx = _finding("checkmarx", "cx-1", severity="critical")
        result = correlate_findings([ai, cx])[0]
        assert result["severity"] == "critical"

    def test_multiple_ai_matches_picks_highest_confidence(self):
        ai_low = _finding("ai", "ai-low", confidence=0.71)
        ai_high = _finding("ai", "ai-high", confidence=0.95)
        cx = _finding("checkmarx", "cx-1")
        result = correlate_findings([ai_low, ai_high, cx])[0]
        assert result["confidence"] == 0.95
        assert result["combination_status"] == "AGREEMENT"

    def test_empty_input(self):
        assert correlate_findings([]) == []

    def test_only_ai_findings(self):
        results = correlate_findings([_finding("ai", "ai-1"), _finding("ai", "ai-2", cwe="CWE-79")])
        assert all(r["combination_status"] == "AI_ONLY" for r in results)

    def test_only_checkmarx_findings(self):
        results = correlate_findings([_finding("checkmarx", "cx-1"), _finding("checkmarx", "cx-2", cwe="CWE-79")])
        assert all(r["combination_status"] == "SAST_ONLY" for r in results)

    def test_fingerprint_present_on_all(self):
        findings = [_finding("ai", "ai-1"), _finding("checkmarx", "cx-1")]
        results = correlate_findings(findings)
        for r in results:
            assert r.get("fingerprint"), "fingerprint must be set"

    def test_path_normalisation_allows_agreement(self):
        ai = _finding("ai", "ai-1", file_path="./App/Users.PY")
        cx = _finding("checkmarx", "cx-1", file_path="app\\users.py")
        results = correlate_findings([ai, cx])
        assert results[0]["combination_status"] == "AGREEMENT"

    def test_combined_findings_are_not_processed(self):
        """Findings already marked combined must not appear in input — test that
        correlate_findings ignores them (they have source != ai/checkmarx)."""
        combined = {**_finding("ai", "ai-1"), "source": "combined"}
        results = correlate_findings([combined])
        # combined source is ignored — result list should be empty
        assert results == []
