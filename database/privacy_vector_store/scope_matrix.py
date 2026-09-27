"""
Investigation Scope Enforcement Matrix.

This module defines what information is permitted to enter the
privacy-preserving retrieval layer.

Important:
- Original forensic evidence is never modified.
- This module only produces a scoped representation.
- Scope decisions are explicit and auditable.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


# ============================================================
# DATA CLASSES
# ============================================================

@dataclass(frozen=True)
class ScopeDecision:
    """
    Decision for one field in an investigation-memory record.
    """

    field: str
    allowed: bool
    action: str
    reason: str


# ============================================================
# DEFAULT POLICY
# ============================================================

DEFAULT_SCOPE_POLICY: dict[str, dict[str, Any]] = {
    # Investigation identifiers
    "email_id": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Required to associate retrieval data with the investigation.",
    },
    "case_id": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Required for investigation-level traceability.",
    },

    # Forensic analytical fields
    "ml_analysis": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Relevant to email-forensics investigation.",
    },
    "rule_based_risk": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Relevant forensic risk information.",
    },
    "hybrid_analysis": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Relevant combined analytical result.",
    },
    "phishing_probability": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Relevant model-derived investigation signal.",
    },

    # Threat indicators
    "url_analysis": {
        "allowed": True,
        "action": "KEEP",
        "reason": "URLs are relevant forensic indicators.",
    },
    "attachment_analysis": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Attachments may be relevant forensic indicators.",
    },
    "threat_indicators": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Threat indicators are within investigation scope.",
    },

    # Evidence metadata
    "evidence_authority": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Required to distinguish evidence from analytical output.",
    },
    "status": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Required for investigation workflow state.",
    },

    # Potentially sensitive fields
    "body": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Raw email body should not enter the privacy retrieval layer by default.",
    },
    "body_plain": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Raw email content may contain unrelated sensitive information.",
    },
    "body_html": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Raw HTML email content may contain unrelated sensitive information.",
    },
    "headers": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Raw headers may contain unrelated personal or infrastructure information.",
    },
    "headers_json": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Raw header data is excluded from retrieval by default.",
    },

    # Identity/contact fields
    "sender": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Direct identity information is excluded from semantic retrieval by default.",
    },
    "recipient": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Direct recipient information is excluded from semantic retrieval by default.",
    },
    "sender_raw": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Raw sender identity is excluded from the privacy retrieval layer.",
    },
    "recipient_raw": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Raw recipient identity is excluded from the privacy retrieval layer.",
    },

    # Evidence file paths
    "source_file": {
        "allowed": False,
        "action": "REDACT",
        "reason": "Local filesystem paths should not be exposed through semantic retrieval.",
    },
    "filename": {
        "allowed": True,
        "action": "KEEP",
        "reason": "Filename is useful for investigation traceability.",
    },
}


# ============================================================
# FIELD CLASSIFICATION
# ============================================================

def classify_field(field: str) -> ScopeDecision:
    """
    Return the scope decision for a field.

    Unknown fields are excluded by default. This is deliberate:
    privacy retrieval should fail closed rather than accidentally
    expose newly introduced sensitive fields.
    """

    normalized = str(field).strip().lower()

    policy = DEFAULT_SCOPE_POLICY.get(normalized)

    if policy is None:
        return ScopeDecision(
            field=normalized,
            allowed=False,
            action="REDACT",
            reason="Unknown field; privacy policy defaults to exclusion.",
        )

    return ScopeDecision(
        field=normalized,
        allowed=bool(policy["allowed"]),
        action=str(policy["action"]),
        reason=str(policy["reason"]),
    )


# ============================================================
# RECORD SCOPING
# ============================================================

def apply_scope_policy(
    record: dict[str, Any],
) -> tuple[dict[str, Any], list[ScopeDecision]]:
    """
    Apply the scope matrix to an investigation-memory record.

    Returns:
        scoped_record:
            Only fields allowed into the retrieval layer.

        decisions:
            Complete audit-friendly list of field decisions.

    The input record is never modified.
    """

    if not isinstance(record, dict):
        raise TypeError("Investigation memory record must be a dictionary.")

    scoped_record: dict[str, Any] = {}
    decisions: list[ScopeDecision] = []

    for field, value in record.items():

        decision = classify_field(field)

        decisions.append(decision)

        if decision.allowed:
            scoped_record[field] = value

    return scoped_record, decisions


# ============================================================
# PUBLIC HELPERS
# ============================================================

def scope_record(record: dict[str, Any]) -> dict[str, Any]:
    """
    Return only fields allowed by the scope policy.
    """

    scoped_record, _ = apply_scope_policy(record)

    return scoped_record


def get_scope_decisions(
    record: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Return JSON-serializable scope decisions.
    """

    _, decisions = apply_scope_policy(record)

    return [
        asdict(decision)
        for decision in decisions
    ]


def get_allowed_fields() -> list[str]:
    """
    Return explicitly allowed fields.
    """

    return sorted(
        field
        for field, policy in DEFAULT_SCOPE_POLICY.items()
        if policy["allowed"]
    )


def get_redacted_fields() -> list[str]:
    """
    Return explicitly redacted fields.
    """

    return sorted(
        field
        for field, policy in DEFAULT_SCOPE_POLICY.items()
        if not policy["allowed"]
    )


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    sample_record = {
        "email_id": "email_0009",
        "filename": "email_0009.eml",
        "ml_analysis": {
            "label": "LEGITIMATE",
        },
        "phishing_probability": 0.02,
        "sender": "employee@example.com",
        "recipient": "another@example.com",
        "body": "Sensitive email content",
        "unknown_future_field": "should not enter retrieval",
    }

    scoped, decisions = apply_scope_policy(sample_record)

    print("=" * 70)
    print("SCOPE MATRIX TEST")
    print("=" * 70)

    print("\nOriginal fields:")
    print(sorted(sample_record.keys()))

    print("\nScoped fields:")
    print(sorted(scoped.keys()))

    print("\nDecisions:")

    for decision in decisions:
        print(
            f"{decision.field:30} "
            f"{decision.action:8} "
            f"allowed={decision.allowed}"
        )

    assert "email_id" in scoped
    assert "filename" in scoped
    assert "ml_analysis" in scoped
    assert "phishing_probability" in scoped

    assert "body" not in scoped
    assert "sender" not in scoped
    assert "recipient" not in scoped
    assert "unknown_future_field" not in scoped

    print("\nSCOPE MATRIX TEST: PASS")