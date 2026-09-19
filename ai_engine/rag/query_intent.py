
"""
Query Intent Detection
=======================

Deterministic, auditable intent detection for forensic RAG queries.

This module does not classify emails.
It only determines which retrieval signals should receive
greater weight for a particular investigation query.
"""

from __future__ import annotations

import re


INTENT_KEYWORDS = {

    "AUTHENTICATION": [

        "spf",
        "dkim",
        "dmarc",
        "authentication",
        "auth failure",
        "authentication failure",
        "sender policy",
        "domain authentication",

    ],

    "PHISHING": [

        "phishing",
        "credential",
        "password",
        "login",
        "account",
        "credential request",
        "social engineering",
        "impersonation",

    ],

    "URL": [

        "url",
        "urls",
        "link",
        "website",
        "destination",
        "domain",
        "redirect",

    ],

    "ROUTING": [

        "routing",
        "received",
        "header",
        "headers",
        "mail server",
        "server path",
        "relay",
        "route",
        "message path",

    ],

    "LEGITIMATE": [

        "legitimate",
        "legitimate email",
        "normal business",
        "benign",
        "ordinary business",
        "business email",

    ],

}


def normalize_query(query):

    if query is None:

        return ""

    query = str(query).lower()

    query = re.sub(
        r"\s+",
        " ",
        query
    )

    return query.strip()


def detect_query_intent(query):

    normalized = normalize_query(
        query
    )

    matched = {}

    for intent, keywords in (
        INTENT_KEYWORDS.items()
    ):

        matches = []

        for keyword in keywords:

            if keyword in normalized:

                matches.append(
                    keyword
                )

        if matches:

            matched[
                intent
            ] = matches

    # --------------------------------------------------------------
    # Priority handling
    # --------------------------------------------------------------

    priority = [

        "AUTHENTICATION",
        "PHISHING",
        "URL",
        "ROUTING",
        "LEGITIMATE",

    ]

    selected_intent = "GENERAL"

    for intent in priority:

        if intent in matched:

            selected_intent = intent
            break

    return {

        "intent":
            selected_intent,

        "normalized_query":
            normalized,

        "matched_keywords":
            matched.get(
                selected_intent,
                []
            ),

        "all_intent_matches":
            matched,

    }


def get_intent_weights(intent):

    """
    Retrieval weights.

    These weights are retrieval configuration,
    not probability estimates and not classification scores.
    """

    profiles = {

        "AUTHENTICATION": {

            "semantic_weight": 0.60,
            "signal_weight": 0.40,

        },

        "PHISHING": {

            "semantic_weight": 0.65,
            "signal_weight": 0.35,

        },

        "URL": {

            "semantic_weight": 0.60,
            "signal_weight": 0.40,

        },

        "ROUTING": {

            "semantic_weight": 0.75,
            "signal_weight": 0.25,

        },

        "LEGITIMATE": {

            "semantic_weight": 0.85,
            "signal_weight": 0.15,

        },

        "GENERAL": {

            "semantic_weight": 0.70,
            "signal_weight": 0.30,

        },

    }

    return profiles.get(
        intent,
        profiles["GENERAL"]
    )


def get_query_configuration(query):

    detection = detect_query_intent(
        query
    )

    weights = get_intent_weights(
        detection["intent"]
    )

    return {

        **detection,

        "weights":
            weights,

    }
