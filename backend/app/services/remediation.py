REMEDIATION_BY_CWE = {
    "CWE-22": "Resolve paths against an approved base directory, normalize them, and reject paths that escape the allowed root.",
    "CWE-78": "Avoid shell execution. Pass arguments as a list and validate untrusted values against an allowlist.",
    "CWE-79": "Use context-aware output encoding and keep framework auto-escaping enabled. Avoid marking untrusted HTML as safe.",
    "CWE-89": "Use parameterized queries or the ORM query API. Never concatenate untrusted input into SQL text.",
    "CWE-287": "Enforce authentication at the protected operation and verify credentials, sessions, and tokens server-side.",
    "CWE-798": "Load credentials from a secret manager or environment-specific configuration and rotate exposed values.",
}


def remediation_for(cwe: str | None) -> str:
    if cwe in REMEDIATION_BY_CWE:
        return REMEDIATION_BY_CWE[cwe]
    return "Review the evidence and apply the framework's documented secure coding guidance."

