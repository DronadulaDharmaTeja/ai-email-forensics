import pytest

from ai_engine import llm_client as lc

REQUEST = {"model": "test", "messages": [{"role": "user", "content": "hi"}]}


def make_exc(name):
    return type(name, (Exception,), {})(name + " simulated")


def test_waits_grow_between_attempts(mocker):
    sleep = mocker.patch("time.sleep")
    create = mocker.patch.object(lc, "client").chat.completions.create
    create.side_effect = [make_exc("InternalServerError")] * 3 + ["OK"]
    assert lc._call_model(dict(REQUEST)) == "OK"
    delays = [c.args[0] for c in sleep.call_args_list]
    assert len(delays) == 3
    assert all(d > 0 for d in delays)
    assert delays == sorted(delays)
    assert len(set(delays)) == 3


def test_maximum_attempts_is_respected(mocker):
    mocker.patch("time.sleep")
    create = mocker.patch.object(lc, "client").chat.completions.create
    create.side_effect = make_exc("InternalServerError")
    with pytest.raises(Exception):
        lc._call_model(dict(REQUEST))
    assert create.call_count == lc._LLM_MAX_ATTEMPTS


@pytest.mark.parametrize("name", [
    "APITimeoutError", "APIConnectionError", "RateLimitError", "InternalServerError",
])
def test_each_transient_error_type_is_retried(mocker, name):
    mocker.patch("time.sleep")
    create = mocker.patch.object(lc, "client").chat.completions.create
    create.side_effect = [make_exc(name), "OK"]
    assert lc._call_model(dict(REQUEST)) == "OK"


@pytest.mark.parametrize("name", ["AuthenticationError", "BadRequestError", "PermissionDeniedError"])
def test_permanent_errors_fail_fast(mocker, name):
    sleep = mocker.patch("time.sleep")
    create = mocker.patch.object(lc, "client").chat.completions.create
    create.side_effect = make_exc(name)
    with pytest.raises(Exception):
        lc._call_model(dict(REQUEST))
    assert create.call_count == 1
    assert sleep.call_count == 0