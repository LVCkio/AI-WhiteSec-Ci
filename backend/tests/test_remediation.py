"""Tests for the remediation service."""
from __future__ import annotations

import pytest

from app.services.remediation import REMEDIATION_BY_CWE, remediation_for


class TestRemediationFor:
    def test_known_cwes_return_specific_guidance(self):
        for cwe in ["CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-287", "CWE-798"]:
            result = remediation_for(cwe)
            assert result == REMEDIATION_BY_CWE[cwe]
            assert len(result) > 20, f"guidance for {cwe} seems too short"

    def test_unknown_cwe_returns_generic_guidance(self):
        result = remediation_for("CWE-9999")
        assert "Review" in result or "framework" in result.lower()

    def test_none_returns_generic_guidance(self):
        result = remediation_for(None)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_sql_injection_mentions_parameterized(self):
        assert "parameterized" in remediation_for("CWE-89").lower()

    def test_xss_mentions_escaping(self):
        assert "escaping" in remediation_for("CWE-79").lower() or "encoding" in remediation_for("CWE-79").lower()

    def test_path_traversal_mentions_base_directory(self):
        assert "base" in remediation_for("CWE-22").lower()
