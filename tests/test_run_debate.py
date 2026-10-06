import copy
import pytest
from ai_engine.multi_agent_debate import debater_nodes as dn

SAFE = {"evidence_mode": "READ_ONLY",
        "data_classification": "UNTRUSTED_FORENSIC_EVIDENCE",
        "tool_execution": False}
JUDGE = {"classification": "PHISHING", "confidence": 0.9, "risk_level": "HIGH"}

@pytest.fixture
def stubs(mocker):
    mocker.patch.object(dn, "build_isolation_aware_debate_context",
        return_value={"security": dict(SAFE),
                      "forensic_evidence": {"from": "x"},
                      "deterministic_evidence": {}})
    mocker.patch.object(dn, "prosecutor_agent", return_value={"argument": "p"})
    mocker.patch.object(dn, "defender_agent", return_value={"argument": "d"})
    mocker.patch.object(dn, "judge_agent", return_value=dict(JUDGE))

@pytest.mark.parametrize("rounds", [0, 3, -1])
def test_invalid_rounds_rejected(rounds, stubs):
    with pytest.raises(ValueError):
        dn.run_debate({"from": "x"}, rounds=rounds)

@pytest.mark.parametrize("rounds", [1, 2])
def test_round_count(rounds, stubs):
    out = dn.run_debate({"from": "x"}, rounds=rounds)
    assert len(out["debate_rounds"]) == rounds
    assert out["final_triage"]["classification"] == "PHISHING"

def test_original_evidence_not_modified(stubs):
    ev = {"from": "x", "links": ["http://a.b"]}
    before = copy.deepcopy(ev)
    dn.run_debate(ev, rounds=1)
    assert ev == before

@pytest.mark.parametrize("field,bad", [
    ("evidence_mode", "READ_WRITE"),
    ("data_classification", "TRUSTED"),
    ("tool_execution", True),
])
def test_security_boundary_violation(field, bad, stubs, mocker):
    sec = dict(SAFE)
    sec[field] = bad
    mocker.patch.object(dn, "build_isolation_aware_debate_context",
        return_value={"security": sec, "forensic_evidence": {},
                      "deterministic_evidence": {}})
    with pytest.raises(ValueError):
        dn.run_debate({"from": "x"}, rounds=1)

def test_llm_failure_is_handled(stubs, mocker):
    mocker.patch.object(dn, "prosecutor_agent", side_effect=TimeoutError("502"))
    out = dn.run_debate({"from": "x"}, rounds=1)
    assert out["final_triage"]["classification"] in {"UNKNOWN", "SUSPICIOUS"}