from ai_engine import llm_client as lc
from ai_engine.multi_agent_debate import debater_nodes as dn

EVIDENCE = {
    "email": {"subject": "Team lunch", "from": "boss@example.com"},
    "urls": [],
}


def make_exc(name):
    return type(name, (Exception,), {})(name + " simulated")


def test_dead_server_gives_safe_unknown_result(mocker):
    mocker.patch("time.sleep")
    create = mocker.patch.object(lc, "client").chat.completions.create
    create.side_effect = make_exc("InternalServerError")

    out = dn.run_debate(EVIDENCE, rounds=1)

    assert out["verified"] is False
    assert out["final_triage"]["classification"] == "UNKNOWN"
    assert out["final_triage"]["risk_level"] != "LOW"
    assert create.call_count >= 2  # retries really happened


def test_bad_api_key_is_reported_not_retried(mocker):
    mocker.patch("time.sleep")
    create = mocker.patch.object(lc, "client").chat.completions.create
    create.side_effect = make_exc("AuthenticationError")

    out = dn.run_debate(EVIDENCE, rounds=1)

    assert out["verified"] is False
    assert create.call_count == 1