"""
Privacy Vector Store Pipeline

Pipeline:

Investigation Memory
        |
        v
Scope Matrix
        |
        v
Allowed fields only
        |
        v
Privacy Mask
        |
        v
Private numeric vector
        |
        v
Audit metadata

The original forensic evidence is never modified.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from database.privacy_vector_store.scope_matrix import (
    scope_record,
    get_scope_decisions,
)

from database.privacy_vector_store.privacy_mask import (
    PrivacyConfig,
    build_private_vector,
    audit_to_dict,
)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MEMORY_DIR = (
    PROJECT_ROOT
    / "ai_engine"
    / "investigation_memory"
).resolve()


# ============================================================
# MEMORY LOADING
# ============================================================

def load_investigation_memory(
    email_id: str,
) -> dict[str, Any]:
    """
    Load one investigation-memory record.

    Example:
        email_0009

    loads:
        email_0009_investigation_memory.json
    """

    if not isinstance(email_id, str):
        raise TypeError(
            "email_id must be a string."
        )

    email_id = email_id.strip()

    if not email_id:
        raise ValueError(
            "email_id is required."
        )

    # Prevent path traversal.
    safe_email_id = Path(email_id).name

    if safe_email_id != email_id:
        raise ValueError(
            "Invalid email_id."
        )

    memory_file = (
        MEMORY_DIR
        / f"{safe_email_id}_investigation_memory.json"
    ).resolve()

    if MEMORY_DIR not in memory_file.parents:
        raise ValueError(
            "Resolved memory path is outside "
            "the permitted investigation memory directory."
        )

    if not memory_file.is_file():
        raise FileNotFoundError(
            f"Investigation memory not found: "
            f"{memory_file.name}"
        )

    try:

        with memory_file.open(
            "r",
            encoding="utf-8",
        ) as handle:

            data = json.load(handle)

    except json.JSONDecodeError as exc:

        raise ValueError(
            f"Invalid JSON in {memory_file.name}"
        ) from exc

    except OSError as exc:

        raise OSError(
            f"Unable to read {memory_file.name}"
        ) from exc

    if not isinstance(data, dict):
        raise ValueError(
            "Investigation memory must be a JSON object."
        )

    return data


# ============================================================
# PRIVACY PIPELINE
# ============================================================

def build_privacy_vector(
    record: dict[str, Any],
    *,
    epsilon: float = 1.0,
    seed: int | None = 42,
) -> dict[str, Any]:
    """
    Apply the complete privacy pipeline.

    1. Scope Matrix removes disallowed fields.
    2. Privacy Mask transforms remaining fields.
    3. Audit information is returned.
    """

    if not isinstance(record, dict):
        raise TypeError(
            "record must be a dictionary."
        )

    # --------------------------------------------------------
    # PRESERVE ORIGINAL
    # --------------------------------------------------------

    original_record = dict(record)

    # --------------------------------------------------------
    # STEP 1 — SCOPE ENFORCEMENT
    # --------------------------------------------------------

    scoped_record = scope_record(
        record
    )

    # --------------------------------------------------------
    # STEP 2 — SCOPE DECISIONS
    # --------------------------------------------------------

    decisions = get_scope_decisions(
        record
    )

    # --------------------------------------------------------
    # STEP 3 — PRIVACY TRANSFORMATION
    # --------------------------------------------------------

    config = PrivacyConfig(
        epsilon=epsilon,
        seed=seed,
    )

    private_vector, privacy_audit = (
        build_private_vector(
            scoped_record,
            config,
        )
    )

    # --------------------------------------------------------
    # DETERMINE REDACTED FIELDS
    # --------------------------------------------------------

    original_fields = set(
        original_record.keys()
    )

    scoped_fields = set(
        scoped_record.keys()
    )

    redacted_fields = sorted(
        original_fields - scoped_fields
    )

    # --------------------------------------------------------
    # SECURITY ASSERTIONS
    # --------------------------------------------------------

    # Original record must remain unchanged.
    assert original_record == record

    # No redacted field may enter the scoped record.
    assert not (
        set(redacted_fields)
        & scoped_fields
    )

    # Vector length must match scoped field count.
    assert (
        len(private_vector)
        ==
        len(scoped_record)
    )

    # Every vector value must be numeric.
    assert all(
        isinstance(value, float)
        for value in private_vector
    )

    # Privacy mask output must remain bounded.
    assert all(
        0.0 <= value <= 1.0
        for value in private_vector
    )

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    return {

        "privacy_version": "1.0",

        "scope": {

            "original_field_count":
                len(original_record),

            "scoped_field_count":
                len(scoped_record),

            "original_fields":
                sorted(original_fields),

            "scoped_fields":
                sorted(scoped_fields),

            "redacted_fields":
                redacted_fields,

            "decisions":
                decisions,
        },

        "private_vector":
            private_vector,

        "vector_length":
            len(private_vector),

        "privacy":
            audit_to_dict(
                privacy_audit
            ),

        "source_policy": {

            "original_record_modified":
                False,

            "out_of_scope_fields_in_vector":
                False,

            "raw_text_released":
                False,

            "scope_enforced_before_vectorization":
                True,

            "privacy_mask_applied":
                True,
        },
    }


# ============================================================
# REAL INVESTIGATION MEMORY TEST
# ============================================================

def test_real_memory(
    email_id: str = "email_0009",
) -> None:

    print("=" * 70)
    print("PRIVACY VECTOR PIPELINE TEST")
    print("=" * 70)

    print()
    print("Email ID:")
    print(email_id)

    # --------------------------------------------------------
    # LOAD REAL INVESTIGATION MEMORY
    # --------------------------------------------------------

    record = load_investigation_memory(
        email_id
    )

    print()
    print("Original fields:")
    print(
        sorted(
            record.keys()
        )
    )

    # --------------------------------------------------------
    # RUN PRIVACY PIPELINE
    # --------------------------------------------------------

    result = build_privacy_vector(
        record,
        epsilon=1.0,
        seed=42,
    )

    # --------------------------------------------------------
    # DISPLAY SCOPE INFORMATION
    # --------------------------------------------------------

    print()
    print("Original field count:")
    print(
        result["scope"]
        ["original_field_count"]
    )

    print()
    print("Scoped field count:")
    print(
        result["scope"]
        ["scoped_field_count"]
    )

    print()
    print("Scoped fields:")
    print(
        result["scope"]
        ["scoped_fields"]
    )

    print()
    print("Redacted fields:")
    print(
        result["scope"]
        ["redacted_fields"]
    )

    # --------------------------------------------------------
    # DISPLAY PRIVATE VECTOR
    # --------------------------------------------------------

    print()
    print("Private vector:")
    print(
        result["private_vector"]
    )

    print()
    print("Vector length:")
    print(
        result["vector_length"]
    )

    # --------------------------------------------------------
    # DISPLAY PRIVACY AUDIT
    # --------------------------------------------------------

    print()
    print("Privacy audit:")
    print(
        result["privacy"]
    )

    # --------------------------------------------------------
    # DISPLAY SOURCE POLICY
    # --------------------------------------------------------

    print()
    print("Source policy:")
    print(
        result["source_policy"]
    )

    # --------------------------------------------------------
    # DISPLAY DECISIONS
    # --------------------------------------------------------

    print()
    print("Scope decisions:")

    for decision in result[
        "scope"
    ]["decisions"]:

        print(
            decision
        )

    # --------------------------------------------------------
    # FINAL SECURITY VALIDATION
    # --------------------------------------------------------

    assert (
        result["source_policy"]
        ["original_record_modified"]
        is False
    )

    assert (
        result["source_policy"]
        ["out_of_scope_fields_in_vector"]
        is False
    )

    assert (
        result["source_policy"]
        ["raw_text_released"]
        is False
    )

    assert (
        result["source_policy"]
        ["scope_enforced_before_vectorization"]
        is True
    )

    assert (
        result["source_policy"]
        ["privacy_mask_applied"]
        is True
    )

    assert isinstance(
        result["private_vector"],
        list,
    )

    assert (
        result["vector_length"]
        ==
        result["scope"]
        ["scoped_field_count"]
    )

    assert all(
        isinstance(value, float)
        for value
        in result["private_vector"]
    )

    assert all(
        0.0 <= value <= 1.0
        for value
        in result["private_vector"]
    )

    print()
    print("=" * 70)
    print("PRIVACY VECTOR PIPELINE TEST: PASS")
    print("=" * 70)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    test_real_memory(
        "email_0009"
    )