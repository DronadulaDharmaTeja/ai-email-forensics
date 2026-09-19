
"""
Debate Trace Instrumentation
============================

Provides an auditable trace wrapper around the existing
multi-agent debate engine.

This module does NOT replace the existing debate engine.

Trace records contain:
- round number
- agent outputs
- deterministic evidence metadata
- isolation/security metadata
- final triage metadata

Raw forensic evidence is not duplicated into the trace.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import hashlib
import json
import inspect


TRACE_VERSION = "1.0"


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_json(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def compact_agent_output(output: Any) -> Any:
    """
    Preserve structured agent output without modifying its semantics.
    """
    if isinstance(output, dict):
        return dict(output)

    if isinstance(output, list):
        return list(output)

    if isinstance(output, str):
        return output

    return str(output)


def build_agent_trace(
    round_number: int,
    prosecutor_output: Any,
    defender_output: Any,
    judge_output: Any,
    deterministic_evidence: dict | None = None,
    security: dict | None = None,
) -> dict:
    """
    Build one auditable debate-round trace.
    """

    return {
        "round": round_number,
        "timestamp_utc": utc_timestamp(),

        "agents": {
            "prosecutor": compact_agent_output(
                prosecutor_output
            ),
            "defender": compact_agent_output(
                defender_output
            ),
            "judge": compact_agent_output(
                judge_output
            ),
        },

        "deterministic_evidence": (
            deterministic_evidence
            if deterministic_evidence is not None
            else {}
        ),

        "security": (
            security
            if security is not None
            else {}
        ),
    }


def build_trace_artifact(
    *,
    case_id: str,
    debate_version: str,
    rounds: list[dict],
    final_triage: dict | None = None,
    evidence_sha256: str | None = None,
) -> dict:
    """
    Build complete trace artifact.
    """

    artifact = {
        "trace_version": TRACE_VERSION,
        "case_id": case_id,
        "timestamp_utc": utc_timestamp(),
        "debate_engine_version": debate_version,

        "evidence_sha256": evidence_sha256,

        "round_count": len(rounds),

        "rounds": rounds,

        "final_triage": (
            final_triage
            if final_triage is not None
            else {}
        ),
    }

    artifact["trace_sha256"] = sha256_json(artifact)

    return artifact


def save_trace(
    artifact: dict,
    output_path: str | Path,
) -> Path:
    """
    Persist trace artifact as JSON.
    """

    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(
            artifact,
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    return output_path



# ============================================================
# STEP 19.32 — SECURITY-AWARE TRACE SUPPORT
# ============================================================

def build_security_trace(
    security=None,
    isolation=None,
    deterministic_evidence=None,
):
    """
    Persist the security state that was actually used
    for the debate.
    """

    security = (
        security
        if isinstance(
            security,
            dict
        )
        else {}
    )

    isolation = (
        isolation
        if isinstance(
            isolation,
            dict
        )
        else {}
    )

    deterministic_evidence = (
        deterministic_evidence
        if isinstance(
            deterministic_evidence,
            dict
        )
        else {}
    )

    return {
        "evidence_mode":
            security.get(
                "evidence_mode",
                "READ_ONLY"
            ),

        "data_classification":
            security.get(
                "data_classification",
                "UNTRUSTED_FORENSIC_EVIDENCE"
            ),

        "tool_execution":
            security.get(
                "tool_execution",
                False
            ),

        "isolation_status":
            isolation.get(
                "status"
            ),

        "analysis_mode":
            isolation.get(
                "analysis_mode"
            ),

        "injection_findings":
            len(
                isolation.get(
                    "injection_findings",
                    []
                )
            ),

        "deterministic_score":
            deterministic_evidence.get(
                "score"
            ),

        "deterministic_strength":
            deterministic_evidence.get(
                "strength"
            ),
    }
