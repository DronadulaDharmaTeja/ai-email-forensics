import copy
import inspect
import time

import pytest

from ai_engine import agent_execution_guard as aeg

ALLOWED = sorted(str(x) for x in aeg.ALLOWED_OPERATIONS)
BLOCKED = sorted(str(x) for x in aeg.BLOCKED_OPERATIONS)
AGENT = "PROSECUTOR"


def new_guard():
    return aeg.AgentExecutionGuard()


def _call(method, **wanted):
    """Call a method, passing only the arguments it declares."""
    params = inspect.signature(method).parameters
    kwargs = {k: v for k, v in wanted.items() if k in params}
    missing = [
        n for n, p in params.items()
        if p.default is inspect.Parameter.empty
        and p.kind in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY)
        and n not in kwargs
    ]
    if missing:
        pytest.skip("cannot call " + method.__name__ + ", unknown required args: " + str(missing))
    return method(**kwargs)


def verdict(result):
    if isinstance(result, bool):
        return result
    if isinstance(result, dict) and "allowed" in result:
        return bool(result["allowed"])
    if hasattr(result, "allowed"):
        return bool(result.allowed)
    if isinstance(result, (tuple, list)) and result and isinstance(result[0], bool):
        return result[0]
    pytest.fail("unrecognized result from guard: " + repr(result)[:200])


def is_allowed(op, agent=AGENT, guard=None):
    guard = guard or new_guard()
    try:
        result = _call(guard.check_operation, agent=agent, operation=op)
    except Exception:
        return False  # raising counts as refusing
    return verdict(result)


# ---------- the lists ----------

def test_operation_lists_are_sane():
    assert ALLOWED, "ALLOWED_OPERATIONS is empty"
    assert BLOCKED, "BLOCKED_OPERATIONS is empty"
    overlap = sorted(set(ALLOWED) & set(BLOCKED))
    assert not overlap, "in both lists: " + str(overlap)


def test_list_entries_are_lowercase_and_trimmed():
    # check_operation lowercases input, so an uppercase entry could never match
    bad = [o for o in ALLOWED + BLOCKED if o != o.strip().lower()]
    assert not bad, bad


RISKY = ("delete", "remove", "write", "modify", "edit", "execute", "exec",
         "shell", "send", "download", "upload", "overwrite", "drop")


def test_allowlist_has_no_risky_looking_names():
    # A failure here means "review these names", not necessarily a bug.
    flagged = [o for o in ALLOWED if any(r in o for r in RISKY)]
    assert not flagged, "Review these allowed operations: " + str(flagged)


# ---------- decisions ----------

@pytest.mark.parametrize("op", ALLOWED)
def test_allowed_operation_is_permitted(op):
    assert is_allowed(op), op + " is on the allowlist but was refused"


@pytest.mark.parametrize("op", BLOCKED)
def test_blocked_operation_is_refused(op):
    assert not is_allowed(op), op + " is blocked but was permitted"


VARIANTS = {
    "upper": str.upper,
    "padded": lambda s: "  " + s + "  ",
    "mixed": str.title,
}


@pytest.mark.parametrize("op", BLOCKED)
@pytest.mark.parametrize("variant", list(VARIANTS))
def test_blocked_operation_cannot_be_disguised(op, variant):
    assert not is_allowed(VARIANTS[variant](op))


@pytest.mark.parametrize("op", [
    "totally_unknown_operation", "", "   ", "read_evidence; rm -rf /", "*", "../../etc/passwd",
])
def test_unknown_operation_is_refused(op):
    assert not is_allowed(op)


@pytest.mark.parametrize("op", ALLOWED[:15])
def test_allowed_name_plus_extra_text_is_refused(op):
    assert not is_allowed(op + "_and_delete")
    assert not is_allowed(op + "\u200b")
    assert not is_allowed(op + "\x00")


@pytest.mark.parametrize("bad", [None, 123, [], {}])
def test_non_string_operation_is_never_allowed(bad):
    assert not is_allowed(bad)


@pytest.mark.parametrize("agent", ["PROSECUTOR", "DEFENDER", "JUDGE", "UNKNOWN_AGENT"])
def test_blocked_stays_blocked_for_every_agent(agent):
    for op in BLOCKED:
        assert not is_allowed(op, agent=agent), op + " allowed for " + agent


# ---------- status, time limit, evidence ----------

def test_security_status_is_a_dict():
    g = new_guard()
    is_allowed(BLOCKED[0], guard=g)
    status = g.security_status()
    assert isinstance(status, dict) and status


def _within_time_limit(start):
    guard = new_guard()
    params = inspect.signature(guard.check_execution_time).parameters
    if "start_time" not in params:
        pytest.skip("check_execution_time has no start_time argument: " + str(list(params)))
    try:
        result = _call(guard.check_execution_time, agent=AGENT, start_time=start)
    except Exception:
        return False  # raising counts as "limit exceeded"
    if result is None:
        return True
    return verdict(result)


def test_recent_start_is_within_time_limit():
    assert _within_time_limit(time.time())


def test_very_old_start_exceeds_time_limit():
    assert not _within_time_limit(time.time() - 100000)


def test_protect_evidence_does_not_modify_input():
    guard = new_guard()
    params = inspect.signature(guard.protect_evidence).parameters
    if "evidence" not in params:
        pytest.skip("protect_evidence has no evidence argument: " + str(list(params)))
    ev = {"email": {"subject": "hello"}, "urls": ["http://example.com"]}
    before = copy.deepcopy(ev)
    try:
        _call(guard.protect_evidence, agent=AGENT, evidence=ev)
    except Exception:
        pass
    assert ev == before