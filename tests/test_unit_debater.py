import copy
from datetime import datetime, timezone

import pytest

from ai_engine.multi_agent_debate import debater_nodes as dn


# ---------- normalize_classification ----------

@pytest.mark.parametrize("raw,expected", [
    ("PHISHING", "PHISHING"),
    ("phishing", "PHISHING"),
    ("  Legitimate  ", "LEGITIMATE"),
    ("suspicious", "SUSPICIOUS"),
    ("spam", "PHISHING"),
    ("malicious", "PHISHING"),
    ("ham", "LEGITIMATE"),
    ("safe", "LEGITIMATE"),
    ("uncertain", "UNKNOWN"),
    ("banana", "UNKNOWN"),
    (None, "UNKNOWN"),
    (123, "UNKNOWN"),
])
def test_normalize_classification(raw, expected):
    assert dn.normalize_classification(raw) == expected


# ---------- normalize_agent_output ----------

def test_agent_output_must_be_dict():
    with pytest.raises(ValueError):
        dn.normalize_agent_output("not a dict")


def test_missing_agent_is_filled_from_trusted_caller():
    out = dn.normalize_agent_output({"classification": "PHISHING"}, expected_agent="JUDGE")
    assert out["agent"] == "JUDGE"
    assert out["agent_source"] == "trusted_caller_context"
    assert out["raw_agent"] is None


def test_wrong_agent_name_is_not_overwritten():
    out = dn.normalize_agent_output({"agent": "DEFENDER"}, expected_agent="JUDGE")
    assert out["agent"] == "DEFENDER"
    assert out["agent_source"] == "model_mismatch"


def test_risk_falls_back_to_classification():
    out = dn.normalize_agent_output({"classification": "PHISHING"})
    assert out["risk_level"] == "HIGH"
    assert out["risk_source"] == "deterministic_classification_fallback"


def test_valid_model_risk_is_kept_and_uppercased():
    out = dn.normalize_agent_output({"classification": "SUSPICIOUS", "risk_level": "low"})
    assert out["risk_level"] == "LOW"
    assert out["risk_source"] == "model"


def test_unknown_classification_is_not_low_risk():
    out = dn.normalize_agent_output({"classification": "UNKNOWN"})
    assert out["risk_level"] == "MEDIUM"


def test_preliminary_conclusion_used_when_no_classification():
    out = dn.normalize_agent_output({"preliminary_conclusion": "malicious"})
    assert out["classification"] == "PHISHING"


def test_normalize_does_not_modify_input():
    original = {"agent": "JUDGE", "classification": "spam", "risk_level": "high"}
    before = copy.deepcopy(original)
    dn.normalize_agent_output(original, expected_agent="JUDGE")
    assert original == before


@pytest.mark.xfail(reason="CRITICAL is in ALLOWED_RISK_LEVELS but normalize_agent_output drops it")
def test_critical_risk_is_preserved():
    out = dn.normalize_agent_output({"classification": "PHISHING", "risk_level": "CRITICAL"})
    assert out["risk_level"] == "CRITICAL"


# ---------- _validate_confidence ----------

@pytest.mark.parametrize("value,expected", [(0, 0.0), (1, 1.0), (0.5, 0.5), ("0.7", 0.7)])
def test_confidence_accepts_good_values(value, expected):
    assert dn._validate_confidence(value) == expected


@pytest.mark.parametrize("bad", [None, "abc", float("nan"), float("inf"), 1.5, -0.1])
def test_confidence_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        dn._validate_confidence(bad)


# ---------- validate_agent_output ----------

def test_validate_agent_output_accepts_good_output():
    assert dn.validate_agent_output(
        {"classification": "PHISHING", "confidence": 0.8, "risk_level": "HIGH"}) is True


@pytest.mark.parametrize("bad", [
    "text",
    {"classification": "PHISHING", "confidence": "x", "risk_level": "HIGH"},
    {"classification": "PHISHING", "confidence": 2, "risk_level": "HIGH"},
])
def test_validate_agent_output_rejects_bad_output(bad):
    assert dn.validate_agent_output(bad) is False


# ---------- agent validators ----------

def test_prosecutor_validator_fills_agent_and_normalizes():
    out = dn._validate_prosecutor({"preliminary_conclusion": "phish", "confidence": 0.6})
    assert out["agent"] == "PROSECUTOR"
    assert out["preliminary_conclusion"] == "PHISHING"


def test_prosecutor_validator_rejects_wrong_agent():
    with pytest.raises(ValueError):
        dn._validate_prosecutor({"agent": "DEFENDER", "preliminary_conclusion": "PHISHING", "confidence": 0.6})


def test_defender_validator_rejects_missing_confidence():
    with pytest.raises(ValueError):
        dn._validate_defender({"preliminary_conclusion": "LEGITIMATE"})


def test_judge_validator_accepts_good_output():
    out = dn._validate_judge({"classification": "SUSPICIOUS", "confidence": 0.5, "risk_level": "MEDIUM"})
    assert out["agent"] == "JUDGE"
    assert out["classification"] == "SUSPICIOUS"


def test_judge_validator_rejects_bad_confidence():
    with pytest.raises(ValueError):
        dn._validate_judge({"classification": "SUSPICIOUS", "confidence": 5, "risk_level": "MEDIUM"})


# ---------- build_compact_agent_evidence ----------

def test_compact_evidence_requires_dict():
    with pytest.raises(TypeError):
        dn.build_compact_agent_evidence("text")


def test_compact_evidence_has_defaults_for_missing_fields():
    out = dn.build_compact_agent_evidence({})
    assert out["forensic_evidence"]["urls"] == []
    assert out["forensic_evidence"]["forensic_flags"] == []


def test_compact_evidence_drops_unknown_fields():
    out = dn.build_compact_agent_evidence(
        {"forensic_evidence": {"email": {"subject": "hi"}, "extra_field": "drop me"}})
    assert out["forensic_evidence"]["email"] == {"subject": "hi"}
    assert "extra_field" not in out["forensic_evidence"]


# ---------- _json ----------

def test_json_handles_datetime_bytes_and_unicode():
    text = dn._json({
        "when": datetime(2026, 1, 1, tzinfo=timezone.utc),
        "raw": b"hello",
        "name": "caf\u00e9",
    })
    assert "2026-01-01" in text
    assert "hello" in text
    assert "caf\u00e9" in text


# ---------- safe wrapper ----------

def test_unverified_result_is_never_low_risk():
    out = dn._unverified_result(1, TimeoutError("502"))
    assert out["verified"] is False
    assert out["final_triage"]["classification"] == "UNKNOWN"
    assert out["final_triage"]["risk_level"] == "MEDIUM"
    assert "TimeoutError" in out["error"]


def test_wrapper_reraises_isolation_violation(mocker):
    mocker.patch.object(dn, "_run_debate_inner",
                        side_effect=ValueError("Isolation boundary violation: x"))
    with pytest.raises(ValueError):
        dn.run_debate({"a": 1}, rounds=1)


def test_wrapper_turns_other_errors_into_unverified(mocker):
    mocker.patch.object(dn, "_run_debate_inner", side_effect=ValueError("Invalid Judge agent"))
    out = dn.run_debate({"a": 1}, rounds=1)
    assert out["verified"] is False


def test_wrapper_still_rejects_bad_rounds():
    with pytest.raises(ValueError):
        dn.run_debate({"a": 1}, rounds=3)