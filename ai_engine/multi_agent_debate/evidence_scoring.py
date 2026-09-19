
"""
Deterministic forensic evidence-strength scoring.

This module does NOT make the final phishing decision.

It converts observable forensic indicators into a structured
evidence profile that can be supplied to the LLM debate layer.

Design principles:
- deterministic
- explainable
- read-only
- no network access
- no tool execution
- no automatic malicious verdict
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


SCORING_VERSION = "1.0"


# ------------------------------------------------------------
# Weights
# ------------------------------------------------------------

WEIGHTS = {
    "spf_fail": 12,
    "dkim_fail": 12,
    "dmarc_fail": 12,

    "suspicious_url": 20,
    "multiple_urls": 5,

    "urgent_language": 8,
    "credential_language": 12,
    "payment_language": 10,

    "external_sender": 5,
    "external_routing": 5,

    "forensic_authentication_failure": 10,
    "forensic_suspicious_url": 15,
    "forensic_urgent_language": 8,
    "forensic_impersonation": 15,
    "forensic_credential_request": 15,
    "forensic_payment_request": 10,

    "instruction_injection": 20,
}


URGENCY_TERMS = [
    "urgent",
    "immediately",
    "immediate action",
    "act now",
    "account suspension",
    "verify your account",
    "verification required",
]

CREDENTIAL_TERMS = [
    "password",
    "credential",
    "login",
    "sign in",
    "verify your account",
    "username",
    "authentication",
]

PAYMENT_TERMS = [
    "payment",
    "invoice",
    "bank account",
    "wire transfer",
    "credit card",
    "payment details",
]

INJECTION_TERMS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "system instruction",
    "reveal system prompt",
    "reveal the system instructions",
    "execute tool",
    "execute commands",
]


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def _safe_text(value: Any) -> str:
    if value is None:
        return ""

    return str(value)


def _contains_any(text: str, terms: List[str]) -> bool:
    text_lower = text.lower()

    return any(
        term.lower() in text_lower
        for term in terms
    )


def _status(value: Any) -> str:
    return _safe_text(value).strip().upper()


def _forensic_flags(evidence: Dict[str, Any]) -> List[str]:

    flags = evidence.get(
        "forensic_flags",
        []
    )

    if not isinstance(flags, list):
        return []

    return [
        _safe_text(flag).strip().lower()
        for flag in flags
    ]


def _body_text(evidence: Dict[str, Any]) -> str:

    body = evidence.get(
        "body",
        {}
    )

    if not isinstance(body, dict):
        return ""

    return _safe_text(
        body.get("text", "")
    )


# ------------------------------------------------------------
# Main scorer
# ------------------------------------------------------------

def score_evidence(
    evidence: Dict[str, Any]
) -> Dict[str, Any]:

    if not isinstance(evidence, dict):
        raise TypeError(
            "Evidence must be a dictionary."
        )

    score = 0

    indicators = []

    # --------------------------------------------------------
    # Security headers
    # --------------------------------------------------------

    security_headers = evidence.get(
        "security_headers",
        {}
    )

    if not isinstance(
        security_headers,
        dict
    ):
        security_headers = {}

    spf = _status(
        security_headers.get("spf")
    )

    dkim = _status(
        security_headers.get("dkim")
    )

    dmarc = _status(
        security_headers.get("dmarc")
    )

    if spf == "FAIL":

        score += WEIGHTS["spf_fail"]

        indicators.append({
            "indicator": "SPF_FAIL",
            "category": "authentication",
            "weight": WEIGHTS["spf_fail"],
            "observation": "SPF authentication failed."
        })

    if dkim == "FAIL":

        score += WEIGHTS["dkim_fail"]

        indicators.append({
            "indicator": "DKIM_FAIL",
            "category": "authentication",
            "weight": WEIGHTS["dkim_fail"],
            "observation": "DKIM authentication failed."
        })

    if dmarc == "FAIL":

        score += WEIGHTS["dmarc_fail"]

        indicators.append({
            "indicator": "DMARC_FAIL",
            "category": "authentication",
            "weight": WEIGHTS["dmarc_fail"],
            "observation": "DMARC authentication failed."
        })

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    urls = evidence.get(
        "urls",
        []
    )

    if not isinstance(urls, list):
        urls = []

    suspicious_url_count = 0

    for url_data in urls:

        if not isinstance(
            url_data,
            dict
        ):
            continue

        risk = _status(
            url_data.get("risk")
        )

        if risk in {
            "SUSPICIOUS",
            "HIGH",
            "MALICIOUS",
            "PHISHING"
        }:

            suspicious_url_count += 1

    if suspicious_url_count > 0:

        score += WEIGHTS["suspicious_url"]

        indicators.append({
            "indicator": "SUSPICIOUS_URL",
            "category": "url",
            "weight": WEIGHTS["suspicious_url"],
            "observation": (
                f"{suspicious_url_count} URL(s) "
                "were marked suspicious/high-risk."
            )
        })

    if len(urls) >= 3:

        score += WEIGHTS["multiple_urls"]

        indicators.append({
            "indicator": "MULTIPLE_URLS",
            "category": "url",
            "weight": WEIGHTS["multiple_urls"],
            "observation": (
                f"Email contains {len(urls)} URLs."
            )
        })

    # --------------------------------------------------------
    # Body language
    # --------------------------------------------------------

    body_text = _body_text(
        evidence
    )

    if _contains_any(
        body_text,
        URGENCY_TERMS
    ):

        score += WEIGHTS["urgent_language"]

        indicators.append({
            "indicator": "URGENT_LANGUAGE",
            "category": "language",
            "weight": WEIGHTS["urgent_language"],
            "observation": (
                "Urgency or account-action language "
                "was observed in the body."
            )
        })

    if _contains_any(
        body_text,
        CREDENTIAL_TERMS
    ):

        score += WEIGHTS["credential_language"]

        indicators.append({
            "indicator": "CREDENTIAL_LANGUAGE",
            "category": "language",
            "weight": WEIGHTS["credential_language"],
            "observation": (
                "Credential or login-related language "
                "was observed."
            )
        })

    if _contains_any(
        body_text,
        PAYMENT_TERMS
    ):

        score += WEIGHTS["payment_language"]

        indicators.append({
            "indicator": "PAYMENT_LANGUAGE",
            "category": "language",
            "weight": WEIGHTS["payment_language"],
            "observation": (
                "Payment or financial language "
                "was observed."
            )
        })

    # --------------------------------------------------------
    # Routing
    # --------------------------------------------------------

    routing = evidence.get(
        "routing",
        {}
    )

    if not isinstance(
        routing,
        dict
    ):
        routing = {}

    external_hops = routing.get(
        "external_hops",
        0
    )

    try:
        external_hops = int(
            external_hops
        )
    except (
        TypeError,
        ValueError
    ):
        external_hops = 0

    if external_hops > 0:

        score += WEIGHTS["external_routing"]

        indicators.append({
            "indicator": "EXTERNAL_ROUTING",
            "category": "routing",
            "weight": WEIGHTS["external_routing"],
            "observation": (
                f"{external_hops} external routing hop(s) "
                "were observed."
            )
        })

    # --------------------------------------------------------
    # Sender
    # --------------------------------------------------------

    email = evidence.get(
        "email",
        {}
    )

    if not isinstance(
        email,
        dict
    ):
        email = {}

    sender = _safe_text(
        email.get("from")
    ).lower()

    recipient = _safe_text(
        email.get("to")
    ).lower()

    sender_domain = (
        sender.split("@")[-1]
        if "@" in sender
        else ""
    )

    recipient_domain = (
        recipient.split("@")[-1]
        if "@" in recipient
        else ""
    )

    if (
        sender_domain
        and recipient_domain
        and sender_domain != recipient_domain
    ):

        score += WEIGHTS["external_sender"]

        indicators.append({
            "indicator": "EXTERNAL_SENDER",
            "category": "sender",
            "weight": WEIGHTS["external_sender"],
            "observation": (
                "Sender and recipient domains differ."
            )
        })

    # --------------------------------------------------------
    # Forensic flags
    # --------------------------------------------------------

    flags = _forensic_flags(
        evidence
    )

    flag_map = {

        "authentication_failure":
            (
                "forensic_authentication_failure",
                "AUTHENTICATION_FAILURE"
            ),

        "suspicious_url":
            (
                "forensic_suspicious_url",
                "FORENSIC_SUSPICIOUS_URL"
            ),

        "urgent_language":
            (
                "forensic_urgent_language",
                "FORENSIC_URGENT_LANGUAGE"
            ),

        "impersonation":
            (
                "forensic_impersonation",
                "IMPERSONATION"
            ),

        "credential_request":
            (
                "forensic_credential_request",
                "CREDENTIAL_REQUEST"
            ),

        "payment_request":
            (
                "forensic_payment_request",
                "PAYMENT_REQUEST"
            ),

        "instruction_injection_text":
            (
                "instruction_injection",
                "INSTRUCTION_INJECTION"
            ),

        "role_manipulation_attempt":
            (
                "instruction_injection",
                "ROLE_MANIPULATION"
            ),

        "system_prompt_access_attempt":
            (
                "instruction_injection",
                "SYSTEM_PROMPT_ACCESS"
            ),
    }

    counted_flag_weights = set()

    for flag in flags:

        if flag not in flag_map:
            continue

        weight_key, indicator_name = (
            flag_map[flag]
        )

        # Do not double-count multiple flags belonging
        # to the same deterministic injection category.
        if weight_key == "instruction_injection":

            if weight_key in counted_flag_weights:
                continue

            counted_flag_weights.add(
                weight_key
            )

        weight = WEIGHTS.get(
            weight_key,
            0
        )

        score += weight

        indicators.append({
            "indicator": indicator_name,
            "category": "forensic_flag",
            "weight": weight,
            "observation": (
                f"Forensic flag observed: {flag}"
            )
        })

    # --------------------------------------------------------
    # Score cap
    # --------------------------------------------------------

    score = min(
        int(score),
        100
    )

    # --------------------------------------------------------
    # Evidence strength
    # --------------------------------------------------------

    if score >= 60:

        strength = "STRONG"

    elif score >= 30:

        strength = "MODERATE"

    elif score > 0:

        strength = "WEAK"

    else:

        strength = "NONE"

    # --------------------------------------------------------
    # Indicator categories
    # --------------------------------------------------------

    categories = sorted(
        set(
            item["category"]
            for item in indicators
        )
    )

    return {

        "scoring_version":
            SCORING_VERSION,

        "score":
            score,

        "strength":
            strength,

        "indicator_count":
            len(indicators),

        "indicator_categories":
            categories,

        "indicators":
            indicators,

        "observed_authentication": {
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc
        },

        "url_count":
            len(urls),

        "suspicious_url_count":
            suspicious_url_count,

        "external_hops":
            external_hops,

        "forensic_flags":
            flags,

        "decision_note":
            (
                "This deterministic score is supporting "
                "evidence only. It does not independently "
                "declare an email phishing or malicious."
            )
    }


# ------------------------------------------------------------
# Debate evidence enrichment
# ------------------------------------------------------------

def enrich_evidence(
    evidence: Dict[str, Any]
) -> Dict[str, Any]:

    if not isinstance(evidence, dict):
        raise TypeError(
            "Evidence must be a dictionary."
        )

    score = score_evidence(
        evidence
    )

    # Deep-copy through JSON so the original evidence
    # is not mutated.
    import copy

    enriched = copy.deepcopy(
        evidence
    )

    enriched["_deterministic_evidence_score"] = score

    return enriched
