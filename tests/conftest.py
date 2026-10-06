import pytest

@pytest.fixture(autouse=True)
def fake_env(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.setenv("APP_ENV", "test")