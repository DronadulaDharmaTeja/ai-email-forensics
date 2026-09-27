"""
Privacy Vector Store v1.0
Redaction + vector clipping + Gaussian masking.

Note:
This module does not claim a formal DP guarantee by itself.
Formal DP requires defined sensitivity and privacy accounting.
"""

import hashlib
import re
from datetime import datetime, timezone

import numpy as np


VERSION = "1.0"
DEFAULT_CLIP_NORM = 1.0
DEFAULT_EPSILON = 1.0
DEFAULT_DELTA = 1e-5
DEFAULT_SENSITIVITY = 1.0

ALLOWED_SCOPES = {
    "investigation",
    "case_memory",
    "threat_intel",
    "research",
}


def redact_text(text: str) -> str:
    """Remove common direct identifiers before vectorization."""
    text = re.sub(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',
                  "[EMAIL]", text, flags=re.I)
    text = re.sub(r'\bhttps?://\S+\b', "[URL]", text)
    text = re.sub(r'\b\d{7,}\b', "[NUMBER]", text)
    return text


def clip_vector(vector, max_norm=DEFAULT_CLIP_NORM):
    """Clip vector L2 norm to a fixed bound."""
    v = np.asarray(vector, dtype=float)
    norm = np.linalg.norm(v)

    if norm == 0 or norm <= max_norm:
        return v

    return v * (max_norm / norm)


def mask_vector(
    vector,
    sensitivity=DEFAULT_SENSITIVITY,
    epsilon=DEFAULT_EPSILON,
    delta=DEFAULT_DELTA,
    max_norm=DEFAULT_CLIP_NORM
):
    """Clip then add Gaussian noise calibrated from privacy parameters."""

    if sensitivity < 0:
        raise ValueError("sensitivity must be >= 0")

    if epsilon <= 0:
        raise ValueError("epsilon must be > 0")

    if not 0 < delta < 1:
        raise ValueError("delta must be between 0 and 1")

    clipped = clip_vector(vector, max_norm)

    noise_scale = (
        sensitivity
        * np.sqrt(2 * np.log(1.25 / delta))
        / epsilon
    )

    noise = np.random.normal(
        0,
        noise_scale,
        size=clipped.shape
    )

    return clipped + noise


def create_record(vector, scope="investigation"):
    """Create a privacy-protected vector record."""

    if scope not in ALLOWED_SCOPES:
        raise ValueError(
            f"Invalid privacy scope: {scope}. "
            f"Allowed scopes: {sorted(ALLOWED_SCOPES)}"
        )

    masked = mask_vector(vector)

    return {
        "version": VERSION,
        "scope": scope,
        "vector": masked.tolist(),
        "clip_norm": DEFAULT_CLIP_NORM,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "vector_sha256": hashlib.sha256(
            masked.tobytes()
        ).hexdigest(),
        "privacy_status": "DP_STYLE_MASKED",
        "epsilon": DEFAULT_EPSILON,
        "delta": DEFAULT_DELTA,
        "sensitivity": DEFAULT_SENSITIVITY,
        "noise_scale": (
            DEFAULT_SENSITIVITY
            * np.sqrt(2 * np.log(1.25 / DEFAULT_DELTA))
            / DEFAULT_EPSILON
        ),
    }



# ======================================================================
# STEP 57 — ROLE/SCOPE AUTHORIZATION
# ======================================================================

def authorize_scope(role, scope, policy_path=None):
    """
    Authorize a role against a privacy scope.

    The authorization decision is loaded from the external
    privacy_access_policy.json policy.

    Parameters
    ----------
    role : str
        Role requesting access.

    scope : str
        Privacy scope being requested.

    policy_path : str or pathlib.Path, optional
        Optional explicit access-policy path.

    Returns
    -------
    dict
        Authorization result containing:

        authorized
        role
        scope
        reason
        policy_version
        policy_sha256

    Raises
    ------
    ValueError
        For invalid role/scope input or unknown role/scope.

    FileNotFoundError
        If the access policy cannot be found.
    """

    from pathlib import Path
    import json

    # --------------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------------

    if not isinstance(role, str):
        raise ValueError(
            "role must be a string."
        )

    if not isinstance(scope, str):
        raise ValueError(
            "scope must be a string."
        )

    role = role.strip()
    scope = scope.strip()

    if not role:
        raise ValueError(
            "role must be a non-empty string."
        )

    if not scope:
        raise ValueError(
            "scope must be a non-empty string."
        )

    # --------------------------------------------------------------
    # DEFAULT POLICY LOCATION
    # --------------------------------------------------------------

    if policy_path is None:

        policy_path = (
            Path(__file__).resolve().parent
            / "privacy_access_policy.json"
        )

    policy_path = Path(
        policy_path
    )

    if not policy_path.exists():
        raise FileNotFoundError(
            f"Privacy access policy not found: "
            f"{policy_path}"
        )

    # --------------------------------------------------------------
    # LOAD POLICY
    # --------------------------------------------------------------

    with open(
        policy_path,
        "r",
        encoding="utf-8"
    ) as f:

        policy = json.load(f)

    roles = policy.get(
        "roles",
        {}
    )

    allowed_scopes = set(
        policy.get(
            "allowed_scopes",
            []
        )
    )

    # --------------------------------------------------------------
    # ROLE VALIDATION
    # --------------------------------------------------------------

    if role not in roles:

        raise ValueError(
            f"Unknown role: {role}. "
            f"Allowed roles: "
            f"{sorted(roles.keys())}"
        )

    # --------------------------------------------------------------
    # SCOPE VALIDATION
    # --------------------------------------------------------------

    if scope not in allowed_scopes:

        raise ValueError(
            f"Unknown privacy scope: {scope}. "
            f"Allowed scopes: "
            f"{sorted(allowed_scopes)}"
        )

    # --------------------------------------------------------------
    # ROLE -> SCOPE AUTHORIZATION
    # --------------------------------------------------------------

    authorized_scopes = set(
        roles.get(
            role,
            []
        )
    )

    authorized = (
        scope in authorized_scopes
    )

    if authorized:

        reason = (
            "ROLE_SCOPE_AUTHORIZED"
        )

    else:

        reason = (
            "ROLE_SCOPE_DENIED"
        )

    # --------------------------------------------------------------
    # RETURN DETERMINISTIC DECISION
    # --------------------------------------------------------------

    return {
        "authorized": authorized,
        "role": role,
        "scope": scope,
        "reason": reason,
        "policy_version": policy.get(
            "version",
            "unknown"
        ),
        "policy_sha256": policy.get(
            "policy_sha256",
            ""
        ),
    }



# ======================================================================
# STEP 58 — AUTHORIZED PRIVACY RECORD CREATION
# ======================================================================

def create_authorized_record(
    vector,
    role,
    scope="investigation",
    policy_path=None
):
    """
    Create a privacy-masked vector record only after role/scope
    authorization succeeds.

    Every authorization decision is recorded in the access audit log.
    Raw evidence and raw vector values are not written to the audit log.
    """

    # --------------------------------------------------------------
    # AUTHORIZATION
    # --------------------------------------------------------------

    authorization = authorize_scope(
        role=role,
        scope=scope,
        policy_path=policy_path
    )

    # --------------------------------------------------------------
    # DENIED ACCESS — AUDIT BEFORE RAISING
    # --------------------------------------------------------------

    if authorization["authorized"] is not True:

        write_access_audit_event(
            role=role,
            scope=scope,
            authorized=False,
            reason=authorization["reason"],
            policy_version=authorization[
                "policy_version"
            ],
            policy_sha256=authorization[
                "policy_sha256"
            ],
            record_sha256=None
        )

        raise PermissionError(
            "Privacy record access denied: "
            f"role '{role}' is not authorized for "
            f"scope '{scope}'."
        )

    # --------------------------------------------------------------
    # CREATE PRIVACY RECORD
    # --------------------------------------------------------------

    record = create_record(
        vector=vector,
        scope=scope
    )

    # --------------------------------------------------------------
    # WRITE ALLOW AUDIT EVENT
    # --------------------------------------------------------------

    audit_event = write_access_audit_event(
        role=role,
        scope=scope,
        authorized=True,
        reason=authorization[
            "reason"
        ],
        policy_version=authorization[
            "policy_version"
        ],
        policy_sha256=authorization[
            "policy_sha256"
        ],
        record_sha256=record.get(
            "vector_sha256"
        )
    )

    # --------------------------------------------------------------
    # ATTACH AUTHORIZATION METADATA
    # --------------------------------------------------------------

    record["authorization"] = {
        "authorized": True,
        "role": authorization[
            "role"
        ],
        "scope": authorization[
            "scope"
        ],
        "reason": authorization[
            "reason"
        ],
        "policy_version": authorization[
            "policy_version"
        ],
        "policy_sha256": authorization[
            "policy_sha256"
        ],
    }

    record["audit"] = {
        "event_type": audit_event[
            "event_type"
        ],
        "decision": audit_event[
            "decision"
        ],
        "timestamp": audit_event[
            "timestamp"
        ],
    }

    return record


def write_access_audit_event(
    role,
    scope,
    authorized,
    reason,
    policy_version=None,
    policy_sha256=None,
    record_sha256=None,
    event_type="PRIVACY_SCOPE_ACCESS"
):
    """
    Write a hash-chained privacy access-control audit event.

    Each event references the SHA-256 hash of the preceding event.
    """

    from pathlib import Path
    from datetime import datetime, timezone
    import json

    # --------------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------------

    if not isinstance(
        role,
        str
    ) or not role.strip():

        raise ValueError(
            "role must be a non-empty string."
        )

    if not isinstance(
        scope,
        str
    ) or not scope.strip():

        raise ValueError(
            "scope must be a non-empty string."
        )

    if not isinstance(
        authorized,
        bool
    ):

        raise ValueError(
            "authorized must be a boolean."
        )

    if not isinstance(
        reason,
        str
    ) or not reason.strip():

        raise ValueError(
            "reason must be a non-empty string."
        )

    # --------------------------------------------------------------
    # DETERMINE AUDIT PATH
    # --------------------------------------------------------------

    audit_dir = (
        Path(__file__).resolve().parent
        / "audit"
    )

    audit_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    audit_path = (
        audit_dir
        / "privacy_access_audit.jsonl"
    )

    # --------------------------------------------------------------
    # DETERMINE PREVIOUS EVENT HASH
    # --------------------------------------------------------------

    previous_event_hash = "GENESIS"

    if audit_path.exists():

        existing_lines = (
            audit_path
            .read_text(
                encoding="utf-8"
            )
            .splitlines()
        )

        for line in reversed(
            existing_lines
        ):

            if not line.strip():
                continue

            try:

                previous_event = (
                    json.loads(line)
                )

            except json.JSONDecodeError:

                raise ValueError(
                    "Existing audit log contains "
                    "invalid JSON. Refusing to append."
                )

            previous_event_hash = (
                previous_event.get(
                    "event_hash"
                )
            )

            if not previous_event_hash:

                raise ValueError(
                    "Existing audit log is not hash chained. "
                    "Refusing to append."
                )

            break

    # --------------------------------------------------------------
    # CREATE BASE EVENT
    # --------------------------------------------------------------

    event = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "event_type": event_type,

        "role": role.strip(),

        "scope": scope.strip(),

        "authorized": authorized,

        "decision": (
            "ALLOW"
            if authorized
            else "DENY"
        ),

        "reason": reason.strip(),

        "policy_version": (
            policy_version
            if policy_version is not None
            else "unknown"
        ),

        "policy_sha256": (
            policy_sha256
            if policy_sha256 is not None
            else ""
        ),

        "record_sha256": (
            record_sha256
            if record_sha256 is not None
            else None
        ),

        "previous_event_hash": (
            previous_event_hash
        ),
    }

    # --------------------------------------------------------------
    # CALCULATE EVENT HASH
    # --------------------------------------------------------------

    event_hash = (
        _calculate_audit_event_hash(
            event,
            previous_event_hash
        )
    )

    event[
        "event_hash"
    ] = event_hash

    # --------------------------------------------------------------
    # APPEND EVENT
    # --------------------------------------------------------------

    with open(
        audit_path,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            json.dumps(
                event,
                sort_keys=True,
                ensure_ascii=False
            )
            + "\n"
        )

    return event


def _canonical_audit_event_for_hash(event):
    """
    Return canonical JSON bytes for an audit event.

    event_hash is excluded because it is the value being calculated.
    """

    import json

    event_for_hash = dict(event)

    event_for_hash.pop(
        "event_hash",
        None
    )

    return (
        json.dumps(
            event_for_hash,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":")
        )
        .encode("utf-8")
    )


def _calculate_audit_event_hash(
    event,
    previous_event_hash
):
    """
    Calculate SHA-256 for an audit event.

    The previous event hash becomes part of the cryptographic chain.
    The event_hash field itself is excluded from the calculation.
    """

    import hashlib
    import json

    event_for_hash = dict(
        event
    )

    event_for_hash.pop(
        "event_hash",
        None
    )

    event_for_hash[
        "previous_event_hash"
    ] = previous_event_hash

    canonical = (
        json.dumps(
            event_for_hash,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":")
        )
        .encode("utf-8")
    )

    return hashlib.sha256(
        canonical
    ).hexdigest()


def verify_access_audit_log(
    audit_path=None
):
    """
    Verify the complete privacy access audit hash chain.

    Returns
    -------
    dict
        Verification result.

    The verifier checks:

    1. JSON validity.
    2. Required fields.
    3. previous_event_hash continuity.
    4. event_hash correctness.
    5. ALLOW/DENY decision consistency.
    """

    from pathlib import Path
    import json

    if audit_path is None:

        audit_path = (
            Path(__file__).resolve().parent
            / "audit"
            / "privacy_access_audit.jsonl"
        )

    audit_path = Path(
        audit_path
    )

    if not audit_path.exists():

        raise FileNotFoundError(
            f"Audit log not found: {audit_path}"
        )

    lines = (
        audit_path
        .read_text(
            encoding="utf-8"
        )
        .splitlines()
    )

    previous_hash = "GENESIS"

    verified_events = 0

    for line_number, line in enumerate(
        lines,
        start=1
    ):

        if not line.strip():

            continue

        try:

            event = json.loads(
                line
            )

        except json.JSONDecodeError as e:

            return {
                "valid": False,
                "verified_events": verified_events,
                "failed_line": line_number,
                "failure_reason": (
                    f"INVALID_JSON: {e}"
                ),
            }

        required_fields = {
            "timestamp",
            "event_type",
            "role",
            "scope",
            "authorized",
            "decision",
            "reason",
            "policy_version",
            "policy_sha256",
            "record_sha256",
            "previous_event_hash",
            "event_hash",
        }

        missing_fields = (
            required_fields
            - set(event.keys())
        )

        if missing_fields:

            return {
                "valid": False,
                "verified_events": verified_events,
                "failed_line": line_number,
                "failure_reason": (
                    "MISSING_FIELDS: "
                    f"{sorted(missing_fields)}"
                ),
            }

        # ----------------------------------------------------------
        # VERIFY PREVIOUS HASH
        # ----------------------------------------------------------

        if event[
            "previous_event_hash"
        ] != previous_hash:

            return {
                "valid": False,
                "verified_events": verified_events,
                "failed_line": line_number,
                "failure_reason": (
                    "BROKEN_PREVIOUS_HASH"
                ),
            }

        # ----------------------------------------------------------
        # VERIFY DECISION CONSISTENCY
        # ----------------------------------------------------------

        expected_decision = (
            "ALLOW"
            if event["authorized"]
            else "DENY"
        )

        if event[
            "decision"
        ] != expected_decision:

            return {
                "valid": False,
                "verified_events": verified_events,
                "failed_line": line_number,
                "failure_reason": (
                    "DECISION_MISMATCH"
                ),
            }

        # ----------------------------------------------------------
        # CALCULATE CURRENT EVENT HASH
        # ----------------------------------------------------------

        calculated_hash = (
            _calculate_audit_event_hash(
                event,
                previous_hash
            )
        )

        # ----------------------------------------------------------
        # VERIFY CURRENT HASH
        # ----------------------------------------------------------

        if event[
            "event_hash"
        ] != calculated_hash:

            return {
                "valid": False,
                "verified_events": verified_events,
                "failed_line": line_number,
                "failure_reason": (
                    "EVENT_HASH_MISMATCH"
                ),
                "expected_hash": calculated_hash,
                "stored_hash": event[
                    "event_hash"
                ],
            }

        # ----------------------------------------------------------
        # ADVANCE CHAIN
        # ----------------------------------------------------------

        previous_hash = event[
            "event_hash"
        ]

        verified_events += 1

    return {
        "valid": True,
        "verified_events": verified_events,
        "failed_line": None,
        "failure_reason": None,
        "final_event_hash": previous_hash,
    }

