import math

def _validate_confidence(value):
    """
    Validate agent confidence.

    Accepts numeric values or numeric strings.
    Rejects missing, non-numeric, NaN, and infinite values.
    """
    if value is None:
        raise ValueError("Agent confidence is required")

    try:
        confidence = float(value)
    except (TypeError, ValueError):
        raise ValueError("Agent confidence must be numeric")

    if not math.isfinite(confidence):
        raise ValueError("Agent confidence must be finite")

    if not 0.0 <= confidence <= 1.0:
        raise ValueError("Agent confidence must be between 0.0 and 1.0")

    return confidence