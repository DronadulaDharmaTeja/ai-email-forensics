
"""
Hybrid Retrieval Engine
=======================

Combines semantic RAG retrieval with existing forensic,
ML, and threat-intelligence signals.

This module performs retrieval ranking only.
It does NOT replace the ML classifier or forensic risk engine.
"""

from __future__ import annotations

import json
import math
import re
from pathlib import Path


PROJECT_ROOT = Path(
    "/content/drive/MyDrive/email forensics  with advance features"
)

ML_DIR = (
    PROJECT_ROOT
    / "reports"
    / "ml_predictions_corrected"
)

FORENSIC_DIR = (
    PROJECT_ROOT
    / "evidence"
    / "enron"
)

THREAT_DIR = (
    PROJECT_ROOT
    / "threat_intel"
)


def _safe_float(value, default=0.0):

    try:
        return float(value)

    except (
        TypeError,
        ValueError
    ):
        return default


def _safe_int(value, default=0):

    try:
        return int(value)

    except (
        TypeError,
        ValueError
    ):
        return default


def _email_id_from_filename(filename):

    name = Path(filename).stem

    for suffix in (
        "_ml_hybrid",
        "_forensic",
        "_threat_intel",
    ):

        if suffix in name:

            return name.split(
                suffix
            )[0]

    return None


def _load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


def load_hybrid_signals():

    """
    Load existing ML, forensic and threat signals.

    Returns:
        dict[email_id, signal_record]
    """

    records = {}

    ml_files = sorted(
        ML_DIR.glob(
            "email_*_ml_hybrid.json"
        )
    )

    forensic_files = sorted(
        FORENSIC_DIR.glob(
            "email_*_forensic.json"
        )
    )

    threat_files = sorted(
        THREAT_DIR.glob(
            "email_*_threat_intel.json"
        )
    )

    for path in ml_files:

        email_id = _email_id_from_filename(
            path.name
        )

        if not email_id:
            continue

        data = _load_json(path)

        ml = data.get(
            "ml_analysis",
            {}
        )

        if not isinstance(
            ml,
            dict
        ):
            ml = {}

        probability = None

        for key in (
            "phishing_probability",
            "spam_probability",
            "probability",
            "prediction_probability",
            "positive_probability",
        ):

            if ml.get(key) is not None:

                probability = _safe_float(
                    ml.get(key)
                )

                break

        records.setdefault(
            email_id,
            {}
        )

        records[email_id][
            "ml_probability"
        ] = probability

        records[email_id][
            "ml_classification"
        ] = ml.get(
            "classification"
        )

    for path in forensic_files:

        email_id = _email_id_from_filename(
            path.name
        )

        if not email_id:
            continue

        data = _load_json(path)

        flags = data.get(
            "forensic_flags",
            {}
        )

        if isinstance(
            flags,
            dict
        ):

            true_flags = [
                str(k)
                for k, v in flags.items()
                if v is True
            ]

        elif isinstance(
            flags,
            list
        ):

            true_flags = [
                str(v)
                for v in flags
            ]

        else:

            true_flags = []

        urls = data.get(
            "urls",
            []
        )

        if not isinstance(
            urls,
            list
        ):

            urls = []

        records.setdefault(
            email_id,
            {}
        )

        records[email_id][
            "forensic_flags"
        ] = true_flags

        records[email_id][
            "forensic_flag_count"
        ] = len(true_flags)

        records[email_id][
            "forensic_url_count"
        ] = len(urls)

    for path in threat_files:

        email_id = _email_id_from_filename(
            path.name
        )

        if not email_id:
            continue

        data = _load_json(path)

        records.setdefault(
            email_id,
            {}
        )

        records[email_id][
            "url_count"
        ] = _safe_int(
            data.get(
                "url_count",
                0
            )
        )

        records[email_id][
            "high_risk_urls"
        ] = _safe_int(
            data.get(
                "high_risk_urls",
                0
            )
        )

        records[email_id][
            "medium_risk_urls"
        ] = _safe_int(
            data.get(
                "medium_risk_urls",
                0
            )
        )

        records[email_id][
            "low_risk_urls"
        ] = _safe_int(
            data.get(
                "low_risk_urls",
                0
            )
        )

        records[email_id][
            "maximum_url_risk"
        ] = _safe_int(
            data.get(
                "maximum_url_risk",
                0
            )
        )

    return records


def normalize_ml_signal(
    probability
):

    if probability is None:

        return 0.0

    probability = _safe_float(
        probability
    )

    return max(
        0.0,
        min(
            1.0,
            probability
        )
    )


def normalize_url_risk(
    maximum_url_risk
):

    """
    Normalize existing 0-100 URL risk
    to 0-1.
    """

    value = _safe_float(
        maximum_url_risk
    )

    return max(
        0.0,
        min(
            1.0,
            value / 100.0
        )
    )


def normalize_forensic_signal(
    forensic_flag_count
):

    """
    Conservative normalization.

    This is a retrieval feature, not a
    forensic risk score.
    """

    value = _safe_float(
        forensic_flag_count
    )

    return min(
        1.0,
        value / 5.0
    )


def normalize_url_presence(
    url_count
):

    return 1.0 if (
        _safe_int(url_count) > 0
    ) else 0.0


def calculate_signal_score(
    signal
):

    """
    Signal score used only for retrieval.

    Components:
        45% ML probability
        25% maximum URL risk
        20% forensic flag density
        10% URL presence
    """

    ml = normalize_ml_signal(
        signal.get(
            "ml_probability"
        )
    )

    url_risk = normalize_url_risk(
        signal.get(
            "maximum_url_risk",
            0
        )
    )

    forensic = normalize_forensic_signal(
        signal.get(
            "forensic_flag_count",
            0
        )
    )

    url_presence = normalize_url_presence(
        signal.get(
            "url_count",
            0
        )
    )

    score = (
        0.45 * ml
        +
        0.25 * url_risk
        +
        0.20 * forensic
        +
        0.10 * url_presence
    )

    return max(
        0.0,
        min(
            1.0,
            score
        )
    )


def hybrid_rank_score(
    semantic_similarity,
    signal_score,
    semantic_weight=0.70,
    signal_weight=0.30
):

    semantic_similarity = _safe_float(
        semantic_similarity
    )

    signal_score = _safe_float(
        signal_score
    )

    return (
        semantic_weight
        * semantic_similarity
        +
        signal_weight
        * signal_score
    )


def hybrid_search_results(
    semantic_results,
    signals,
    top_k=5,
    semantic_weight=0.70,
    signal_weight=0.30
):

    """
    Re-rank existing semantic RAG results.

    Expected semantic result format:

        {
            "email_id": "...",
            "similarity": 0.52,
            ...
        }

    """

    ranked = []

    for result in semantic_results:

        email_id = (
            result.get(
                "email_id"
            )
            or result.get(
                "document_id"
            )
        )

        if not email_id:

            continue

        signal = signals.get(
            email_id,
            {}
        )

        signal_score = (
            calculate_signal_score(
                signal
            )
        )

        semantic_similarity = (
            result.get(
                "similarity",
                result.get(
                    "score",
                    0.0
                )
            )
        )

        final_score = hybrid_rank_score(
            semantic_similarity,
            signal_score,
            semantic_weight,
            signal_weight
        )

        enriched = dict(
            result
        )

        enriched[
            "hybrid_retrieval"
        ] = {

            "semantic_similarity":
                float(
                    semantic_similarity
                ),

            "signal_score":
                float(
                    signal_score
                ),

            "semantic_weight":
                semantic_weight,

            "signal_weight":
                signal_weight,

            "hybrid_score":
                float(
                    final_score
                ),

        }

        ranked.append(
            enriched
        )

    ranked.sort(
        key=lambda x:
            x[
                "hybrid_retrieval"
            ][
                "hybrid_score"
            ],
        reverse=True
    )

    return ranked[:top_k]




def deduplicate_hybrid_results(
    hybrid_results,
    top_k=5
):

    """
    Deduplicate chunk-level hybrid results
    at the email level.

    When multiple chunks belong to the same email,
    keep the chunk with the highest hybrid score.

    This does not modify the underlying RAG results.
    """

    best_by_email = {}

    for result in hybrid_results:

        email_id = (
            result.get(
                "email_id"
            )
            or result.get(
                "document_id"
            )
        )

        if not email_id:

            continue

        metadata = result.get(
            "hybrid_retrieval",
            {}
        )

        hybrid_score = _safe_float(
            metadata.get(
                "hybrid_score",
                0.0
            )
        )

        existing = best_by_email.get(
            email_id
        )

        if existing is None:

            best_by_email[
                email_id
            ] = result

        else:

            existing_score = _safe_float(
                existing.get(
                    "hybrid_retrieval",
                    {}
                ).get(
                    "hybrid_score",
                    0.0
                )
            )

            if hybrid_score > existing_score:

                best_by_email[
                    email_id
                ] = result

    deduplicated = list(
        best_by_email.values()
    )

    deduplicated.sort(
        key=lambda x:
            _safe_float(
                x.get(
                    "hybrid_retrieval",
                    {}
                ).get(
                    "hybrid_score",
                    0.0
                )
            ),
        reverse=True
    )

    return deduplicated[:top_k]




def intent_aware_hybrid_search(
    query,
    semantic_results,
    signals,
    top_k=5
):

    """
    Intent-aware hybrid retrieval.

    Query intent determines the retrieval weights.
    This function performs retrieval ranking only.

    It does not modify:
        - ML predictions
        - forensic risk scores
        - threat intelligence
        - RAG embeddings
        - source evidence
    """

    from ai_engine.rag.query_intent import (
        get_query_configuration
    )

    configuration = (
        get_query_configuration(
            query
        )
    )

    intent = configuration[
        "intent"
    ]

    weights = configuration[
        "weights"
    ]

    semantic_weight = float(
        weights[
            "semantic_weight"
        ]
    )

    signal_weight = float(
        weights[
            "signal_weight"
        ]
    )

    ranked = []

    for result in semantic_results:

        email_id = (
            result.get(
                "email_id"
            )
            or result.get(
                "document_id"
            )
        )

        if not email_id:
            continue

        signal = signals.get(
            email_id,
            {}
        )

        signal_score = (
            calculate_signal_score(
                signal
            )
        )

        semantic_similarity = _safe_float(
            result.get(
                "similarity",
                result.get(
                    "score",
                    0.0
                )
            )
        )

        hybrid_score = (
            semantic_weight
            * semantic_similarity
            +
            signal_weight
            * signal_score
        )

        enriched = dict(
            result
        )

        enriched[
            "hybrid_retrieval"
        ] = {

            "semantic_similarity":
                float(
                    semantic_similarity
                ),

            "signal_score":
                float(
                    signal_score
                ),

            "semantic_weight":
                semantic_weight,

            "signal_weight":
                signal_weight,

            "hybrid_score":
                float(
                    hybrid_score
                ),

            "query_intent":
                intent,

            "matched_keywords":
                configuration[
                    "matched_keywords"
                ],

        }

        ranked.append(
            enriched
        )

    ranked.sort(
        key=lambda x:
            x[
                "hybrid_retrieval"
            ][
                "hybrid_score"
            ],
        reverse=True
    )

    # Email-level deduplication
    # is performed after ranking so
    # the strongest chunk survives.

    return deduplicate_hybrid_results(
        ranked,
        top_k=top_k
    )


def get_statistics():

    signals = load_hybrid_signals()

    return {

        "email_count":
            len(signals),

        "with_ml_probability":
            sum(
                1
                for value in signals.values()
                if value.get(
                    "ml_probability"
                ) is not None
            ),

        "with_urls":
            sum(
                1
                for value in signals.values()
                if value.get(
                    "url_count",
                    0
                ) > 0
            ),

        "with_forensic_flags":
            sum(
                1
                for value in signals.values()
                if value.get(
                    "forensic_flag_count",
                    0
                ) > 0
            ),

    }
