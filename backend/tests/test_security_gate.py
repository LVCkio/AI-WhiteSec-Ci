"""Tests for the security_gate script."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make scripts/ importable
_scripts_dir = Path(__file__).resolve().parents[2] / "scripts"
if str(_scripts_dir) not in sys.path:
    sys.path.insert(0, str(_scripts_dir))

from security_gate import evaluate


def _finding(status: str, severity: str = "high") -> dict:
    return {
        "combination_status": status,
        "severity": severity,
        "cwe": "CWE-89",
        "file_path": "app/users.py",
        "start_line": 10,
        "title": f"Test finding {status}",
    }


class TestSecurityGateEvaluate:
    def test_agreement_high_blocks(self):
        findings = [_finding("AGREEMENT", "high")]
        should_block, blocking = evaluate(findings, {"AGREEMENT"}, "high")
        assert should_block
        assert len(blocking) == 1

    def test_agreement_medium_does_not_block_on_high_threshold(self):
        findings = [_finding("AGREEMENT", "medium")]
        should_block, _ = evaluate(findings, {"AGREEMENT"}, "high")
        assert not should_block

    def test_ai_only_not_blocked_by_default_gate(self):
        findings = [_finding("AI_ONLY", "critical")]
        should_block, _ = evaluate(findings, {"AGREEMENT"}, "high")
        assert not should_block

    def test_critical_blocked_when_threshold_is_high(self):
        findings = [_finding("AGREEMENT", "critical")]
        should_block, _ = evaluate(findings, {"AGREEMENT"}, "high")
        assert should_block

    def test_empty_findings_passes(self):
        should_block, blocking = evaluate([], {"AGREEMENT"}, "high")
        assert not should_block
        assert blocking == []

    def test_multiple_statuses_in_block_set(self):
        findings = [_finding("AI_ONLY", "critical"), _finding("SAST_ONLY", "high")]
        should_block, blocking = evaluate(findings, {"AI_ONLY", "SAST_ONLY"}, "high")
        assert should_block
        assert len(blocking) == 2

    def test_info_severity_never_blocks_on_high_threshold(self):
        findings = [_finding("AGREEMENT", "info")]
        should_block, _ = evaluate(findings, {"AGREEMENT"}, "high")
        assert not should_block

    def test_all_severities_block_on_info_threshold(self):
        for sev in ("info", "low", "medium", "high", "critical"):
            should_block, _ = evaluate([_finding("AGREEMENT", sev)], {"AGREEMENT"}, "info")
            assert should_block, f"Expected block for severity={sev}"
