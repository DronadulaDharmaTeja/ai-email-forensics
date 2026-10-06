import pytest

from ai_engine import llm_client as lc

REQUEST = {"model": "test", "messages": [{"role": "user", "content": "hi"}]}


def make_exc(name):
    # lc matches errors by class name, so a fake class with the right name works
    return type(name, (Exception,), {})(name + " simulated")


@pytest.fixture
def fake_create(mocker):
    mocker.patch("time.sleep")  # no real waiting
    fake = mocker.patch.object(lc, "client")
    return fake.chat.completions.create


def test_success_on_first_try(fake_create):
    fake_create.return_value = "OK"
    assert lc._call_model(dict(REQUEST)) == "OK"
    assert fake_create.call_count == 1


def test_one_502_then_success_is_retried(fake_create):
    fake_create.side_effect = [make_exc("InternalServerError"), "OK"]
    assert lc._call_model(dict(REQUEST)) == "OK"
    assert fake_create.call_count == 2


def test_two_502_then_success_is_retried(fake_create):
    fake_create.side_effect = [
        make_exc("InternalServerError"),
        make_exc("InternalServerError"),
        "OK",
    ]
    assert lc._call_model(dict(REQUEST)) == "OK"


def test_persistent_502_gives_up_instead_of_looping(fake_create):
    fake_create.side_effect = make_exc("InternalServerError")
    with pytest.raises(Exception):
        lc._call_model(dict(REQUEST))
    assert fake_create.call_count <= 5


def test_bad_api_key_is_not_retried(fake_create):
    fake_create.side_effect = make_exc("AuthenticationError")
    with pytest.raises(Exception):
        lc._call_model(dict(REQUEST))
    assert fake_create.call_count == 1