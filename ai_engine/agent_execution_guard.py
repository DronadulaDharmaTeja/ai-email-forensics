"""
Agent Execution Guard
AI-Based Email Forensics Investigation System

Purpose:
- Keep forensic evidence read-only
- Block command execution
- Block Python/shell execution
- Block arbitrary file modification
- Allow only approved forensic operations
- Log agent security events

NOTE:
This is an application-level security guard.
It is not an OS/container sandbox.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List


# ============================================================
# ALLOWED FORENSIC OPERATIONS
# ============================================================

ALLOWED_OPERATIONS = {
    "read_evidence",
    "analyze_evidence",
    "retrieve_rag",
    "classify_email",
    "calculate_risk",
    "compare_agent_findings",
    "produce_report",
}


# ============================================================
# BLOCKED OPERATIONS
# ============================================================

BLOCKED_OPERATIONS = {
    "execute_command",
    "execute_python",
    "execute_shell",
    "write_file",
    "delete_file",
    "modify_evidence",
    "network_request",
    "install_package",
}


# ============================================================
# SECURITY EVENT
# ============================================================

@dataclass
class AgentSecurityEvent:
    agent: str
    operation: str
    allowed: bool
    reason: str
    timestamp: float = field(default_factory=time.time)


# ============================================================
# AGENT EXECUTION GUARD
# ============================================================

class AgentExecutionGuard:
    """
    Application-level security boundary for AI agents.
    """

    VERSION = "1.0"

    def __init__(self, max_execution_seconds: float = 120.0):
        self.max_execution_seconds = max_execution_seconds
        self.events: List[AgentSecurityEvent] = []

    # --------------------------------------------------------
    # CHECK OPERATION
    # --------------------------------------------------------

    def check_operation(
        self,
        agent: str,
        operation: str,
    ) -> bool:

        operation = operation.strip().lower()

        # Explicitly blocked operation
        if operation in BLOCKED_OPERATIONS:

            self._log(
                agent=agent,
                operation=operation,
                allowed=False,
                reason="Operation explicitly blocked.",
            )

            return False

        # Anything not allowlisted is blocked
        if operation not in ALLOWED_OPERATIONS:

            self._log(
                agent=agent,
                operation=operation,
                allowed=False,
                reason="Operation is not in the allowlist.",
            )

            return False

        # Approved operation
        self._log(
            agent=agent,
            operation=operation,
            allowed=True,
            reason="Operation allowed.",
        )

        return True

    # --------------------------------------------------------
    # PROTECT FORENSIC EVIDENCE
    # --------------------------------------------------------

    def protect_evidence(
        self,
        evidence: Any,
    ) -> Any:
        """
        Provide a copy of evidence for analysis.

        The original forensic evidence must remain unchanged.
        """

        if isinstance(evidence, dict):
            return dict(evidence)

        if isinstance(evidence, list):
            return list(evidence)

        if isinstance(evidence, str):
            return str(evidence)

        return evidence

    # --------------------------------------------------------
    # VALIDATE AGENT REQUEST
    # --------------------------------------------------------

    def validate_agent_request(
        self,
        agent: str,
        operation: str,
        evidence: Any = None,
    ) -> Dict[str, Any]:

        allowed = self.check_operation(
            agent,
            operation,
        )

        return {
            "security_guard": "AgentExecutionGuard",
            "version": self.VERSION,
            "agent": agent,
            "operation": operation,
            "allowed": allowed,

            # Evidence protection
            "evidence_read_only": True,
            "original_evidence_preserved": True,

            # Execution restrictions
            "command_execution": False,
            "python_execution": False,
            "shell_execution": False,

            # File restrictions
            "arbitrary_file_write": False,
            "evidence_modification": False,

            # Network restrictions
            "arbitrary_network_request": False,

            "reason": (
                "Operation allowed."
                if allowed
                else "Operation blocked by security policy."
            ),
        }

    # --------------------------------------------------------
    # EXECUTION TIME CHECK
    # --------------------------------------------------------

    def check_execution_time(
        self,
        start_time: float,
    ) -> bool:

        elapsed = time.time() - start_time

        return elapsed <= self.max_execution_seconds

    # --------------------------------------------------------
    # SECURITY STATUS
    # --------------------------------------------------------

    def security_status(self) -> Dict[str, Any]:

        return {
            "guard": "AgentExecutionGuard",
            "version": self.VERSION,
            "status": "ACTIVE",

            "evidence_mode": "READ_ONLY",

            "command_execution": False,
            "python_execution": False,
            "shell_execution": False,

            "arbitrary_file_write": False,
            "evidence_modification": False,

            "arbitrary_network_request": False,

            "max_execution_seconds": self.max_execution_seconds,

            "allowed_operations": sorted(
                ALLOWED_OPERATIONS
            ),

            "blocked_operations": sorted(
                BLOCKED_OPERATIONS
            ),
        }

    # --------------------------------------------------------
    # SECURITY EVENT LOG
    # --------------------------------------------------------

    def _log(
        self,
        agent: str,
        operation: str,
        allowed: bool,
        reason: str,
    ) -> None:

        self.events.append(
            AgentSecurityEvent(
                agent=agent,
                operation=operation,
                allowed=allowed,
                reason=reason,
            )
        )


# ============================================================
# SHARED SECURITY GUARD
# ============================================================

agent_guard = AgentExecutionGuard(
    max_execution_seconds=120.0
)


# ============================================================
# SECURITY TEST
# ============================================================

def run_security_test() -> Dict[str, Any]:
    """
    Test the Agent Execution Guard.
    """

    tests = {

        # These must PASS
        "read_evidence": agent_guard.check_operation(
            "PROSECUTOR",
            "read_evidence",
        ),

        "analyze_evidence": agent_guard.check_operation(
            "DEFENDER",
            "analyze_evidence",
        ),

        "retrieve_rag": agent_guard.check_operation(
            "JUDGE",
            "retrieve_rag",
        ),

        # These must be BLOCKED
        "execute_command": agent_guard.check_operation(
            "PROSECUTOR",
            "execute_command",
        ),

        "execute_python": agent_guard.check_operation(
            "DEFENDER",
            "execute_python",
        ),

        "modify_evidence": agent_guard.check_operation(
            "JUDGE",
            "modify_evidence",
        ),
    }

    safe = (
        tests["read_evidence"]
        and tests["analyze_evidence"]
        and tests["retrieve_rag"]
        and not tests["execute_command"]
        and not tests["execute_python"]
        and not tests["modify_evidence"]
    )

    return {
        "guard": "AgentExecutionGuard",
        "version": AgentExecutionGuard.VERSION,
        "status": "ACTIVE",
        "tests": tests,
        "safe": safe,
    }


# ============================================================
# RUN DIRECTLY
# ============================================================

if __name__ == "__main__":

    import json

    print(
        json.dumps(
            run_security_test(),
            indent=2,
        )
    )