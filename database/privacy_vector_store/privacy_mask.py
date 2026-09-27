"""
Privacy-preserving representation layer.

This module takes an already scope-filtered investigation record and
creates a privacy-preserving numeric representation.

Important:
- Original forensic evidence is never modified.
- Out-of-scope fields must be removed by scope_matrix.py first.
- This module does not claim that noise alone provides complete privacy.
- The privacy parameters are explicit and auditable.
"""

from __future__ import annotations

import hashlib
import math
import random
from dataclasses import dataclass, asdict
from typing import Any


# ============================================================
# PRIVACY CONFIGURATION
# ============================================================

DEFAULT_EPSILON = 1.0
DEFAULT_SEED = 42


@dataclass(frozen=True)
class PrivacyConfig:
    """
    Explicit privacy configuration.

    epsilon:
        Smaller values introduce stronger perturbation.

    seed:
        Optional deterministic seed for reproducible testing.

    clip_min / clip_max:
        Bounds applied to numeric values before normalization.
    """

    epsilon: float = DEFAULT_EPSILON
    seed: int | None = DEFAULT_SEED
    clip_min: float = 0.0
    clip_max: float = 1.0


@dataclass(frozen=True)
class PrivacyAudit:
    """
    Audit information describing the transformation.
    """

    epsilon: float
    seed: int | None
    input_fields: int
    numeric_fields: int
    categorical_fields: int
    transformed_fields: int
    mechanism: str


# ============================================================
# VALIDATION
# ============================================================

def validate_privacy_config(config: PrivacyConfig) -> None:
    """
    Validate privacy parameters.
    """

    if not math.isfinite(config.epsilon):
        raise ValueError("epsilon must be finite.")

    if config.epsilon <= 0:
        raise ValueError("epsilon must be greater than 0.")

    if not math.isfinite(config.clip_min):
        raise ValueError("clip_min must be finite.")

    if not math.isfinite(config.clip_max):
        raise ValueError("clip_max must be finite.")

    if config.clip_min >= config.clip_max:
        raise ValueError("clip_min must be smaller than clip_max.")


# ============================================================
# NUMERIC NORMALIZATION
# ============================================================

def clip_and_normalize(
    value: float,
    clip_min: float,
    clip_max: float,
) -> float:
    """
    Clip a numeric value and normalize it to [0, 1].
    """

    value = float(value)

    if not math.isfinite(value):
        value = clip_min

    clipped = min(
        max(value, clip_min),
        clip_max,
    )

    return (
        clipped - clip_min
    ) / (
        clip_max - clip_min
    )


# ============================================================
# DIFFERENTIAL-PRIVACY-STYLE PERTURBATION
# ============================================================

def laplace_noise(
    scale: float,
    rng: random.Random,
) -> float:
    """
    Generate Laplace noise using inverse transform sampling.

    This is the standard Laplace mechanism primitive.

    The caller is responsible for ensuring that the sensitivity
    and privacy budget are appropriate for the released statistic.
    """

    if scale <= 0:
        raise ValueError("Laplace scale must be greater than 0.")

    u = rng.random() - 0.5

    if u == 0:
        u = 1e-12

    return -scale * math.copysign(
        math.log(1 - 2 * abs(u)),
        u,
    )


def perturb_numeric(
    value: float,
    config: PrivacyConfig,
    rng: random.Random,
) -> float:
    """
    Apply a bounded Laplace perturbation to a normalized value.

    Sensitivity is treated as 1 because the input has already been
    normalized to [0, 1].
    """

    normalized = clip_and_normalize(
        value,
        config.clip_min,
        config.clip_max,
    )

    sensitivity = 1.0

    scale = sensitivity / config.epsilon

    noisy = normalized + laplace_noise(
        scale,
        rng,
    )

    # Keep released value bounded.
    return min(
        max(noisy, 0.0),
        1.0,
    )


# ============================================================
# STABLE CATEGORICAL REPRESENTATION
# ============================================================

def stable_hash_to_unit_interval(
    value: Any,
) -> float:
    """
    Convert a categorical value into a stable numeric representation.

    This is NOT a privacy guarantee by itself.

    It is only a deterministic feature encoding.
    """

    encoded = str(value).encode(
        "utf-8",
        errors="replace",
    )

    digest = hashlib.sha256(encoded).digest()

    integer_value = int.from_bytes(
        digest[:8],
        byteorder="big",
        signed=False,
    )

    maximum = float(2**64 - 1)

    return integer_value / maximum


def perturb_categorical(
    value: Any,
    config: PrivacyConfig,
    rng: random.Random,
) -> float:
    """
    Convert a categorical value into a stable numeric value and
    apply bounded perturbation.
    """

    base_value = stable_hash_to_unit_interval(
        value
    )

    sensitivity = 1.0

    scale = sensitivity / config.epsilon

    noisy = base_value + laplace_noise(
        scale,
        rng,
    )

    return min(
        max(noisy, 0.0),
        1.0,
    )


# ============================================================
# RECORD TRANSFORMATION
# ============================================================

def build_private_vector(
    scoped_record: dict[str, Any],
    config: PrivacyConfig | None = None,
) -> tuple[list[float], PrivacyAudit]:
    """
    Convert a scope-filtered record into a privacy-preserving
    numeric vector.

    Nested dictionaries and lists are represented using stable
    deterministic summaries rather than raw text.

    The input record is never modified.
    """

    if not isinstance(scoped_record, dict):
        raise TypeError(
            "scoped_record must be a dictionary."
        )

    if config is None:
        config = PrivacyConfig()

    validate_privacy_config(config)

    rng = random.Random(config.seed)

    vector: list[float] = []

    numeric_fields = 0
    categorical_fields = 0

    for field in sorted(scoped_record.keys()):

        value = scoped_record[field]

        # ----------------------------------------------------
        # Numeric
        # ----------------------------------------------------

        if isinstance(value, (int, float)) and not isinstance(value, bool):

            numeric_fields += 1

            vector.append(
                perturb_numeric(
                    float(value),
                    config,
                    rng,
                )
            )

            continue

        # ----------------------------------------------------
        # Boolean
        # ----------------------------------------------------

        if isinstance(value, bool):

            categorical_fields += 1

            vector.append(
                perturb_numeric(
                    1.0 if value else 0.0,
                    config,
                    rng,
                )
            )

            continue

        # ----------------------------------------------------
        # Complex structured values
        # ----------------------------------------------------

        if isinstance(value, (dict, list, tuple)):

            categorical_fields += 1

            summary = repr(value)

            vector.append(
                perturb_categorical(
                    summary,
                    config,
                    rng,
                )
            )

            continue

        # ----------------------------------------------------
        # String / categorical
        # ----------------------------------------------------

        categorical_fields += 1

        vector.append(
            perturb_categorical(
                value,
                config,
                rng,
            )
        )

    audit = PrivacyAudit(
        epsilon=config.epsilon,
        seed=config.seed,
        input_fields=len(scoped_record),
        numeric_fields=numeric_fields,
        categorical_fields=categorical_fields,
        transformed_fields=len(vector),
        mechanism="bounded_laplace_representation",
    )

    return vector, audit


# ============================================================
# SERIALIZATION
# ============================================================

def audit_to_dict(
    audit: PrivacyAudit,
) -> dict[str, Any]:
    """
    Convert audit information to JSON-compatible data.
    """

    return asdict(audit)


# ============================================================
# SELF TEST
# ============================================================

if __name__ == "__main__":

    sample_record = {
        "email_id": "email_0009",
        "filename": "email_0009.eml",
        "ml_analysis": {
            "label": "LEGITIMATE",
            "score": 0.02,
        },
        "phishing_probability": 0.02,
    }

    config = PrivacyConfig(
        epsilon=1.0,
        seed=42,
    )

    vector, audit = build_private_vector(
        sample_record,
        config,
    )

    print("=" * 70)
    print("PRIVACY MASK TEST")
    print("=" * 70)

    print("\nInput fields:")
    print(len(sample_record))

    print("\nPrivate vector:")
    print(vector)

    print("\nVector length:")
    print(len(vector))

    print("\nAudit:")
    print(audit_to_dict(audit))

    assert isinstance(vector, list)
    assert len(vector) == len(sample_record)

    assert all(
        isinstance(value, float)
        for value in vector
    )

    assert all(
        0.0 <= value <= 1.0
        for value in vector
    )

    assert audit.epsilon == 1.0
    assert audit.transformed_fields == len(
        sample_record
    )

    print("\nPRIVACY MASK TEST: PASS")