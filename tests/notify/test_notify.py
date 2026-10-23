# SPDX-License-Identifier: Apache-2.0
import io
import urllib.error

import pytest

from homelabnext.notify import (
    FakeSender,
    Message,
    Notifier,
    NtfySender,
    RateLimit,
    SendError,
    UnregisteredProblem,
)
from homelabnext.registry import ResolutionError
from homelabnext.state import StateStore

OVERRIDE = (
    "https://n.svc.example.internal:8443"  # no-raw-endpoint: allow override syntax needs a port
)


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    sender = FakeSender()
    clock = Clock()
    n = Notifier(sender, StateStore(tmp_path / "n.json"), clock)
    n.register_pair("Disk almost full", "Disk space recovered")
    return n, sender, clock


def msg(title="Disk almost full", key="disk:app-01", **kw):
    return Message(key=key, title=title, body="95% used", level="warn", **kw)


def test_same_problem_state_twice_is_one_send(env):
    n, sender, _ = env
    assert n.report("disk:app-01", "full", msg()) is True
    assert n.report("disk:app-01", "full", msg()) is False
    assert n.report("disk:app-01", "full", msg()) is False
    assert sender.titles == ["Disk almost full"]


def test_state_change_between_problem_states_sends_again(env):
    n, sender, _ = env
    n.report("k", "warn", msg(key="k"))
    n.report("k", "crit", msg(key="k"))
    assert len(sender.sent) == 2


def test_recovery_sent_once_when_it_clears(env):
    n, sender, _ = env
    n.report("k", "full", msg(key="k", topic="ops", tags=("disk",)))
    assert n.report("k", "ok", Message(key="k", title="x", body="back to 40%")) is True
    assert n.report("k", "ok", Message(key="k", title="x", body="")) is False
    rec = sender.sent[-1]
    assert rec.title == "Disk space recovered" and rec.body == "back to 40%"
    assert rec.topic == "ops" and "recovered" in rec.tags and rec.level == "info"
    assert n.state_of("k") == "ok"


def test_ok_without_prior_problem_sends_nothing(env):
    n, sender, _ = env
    assert n.report("never-red", "ok", msg(key="never-red")) is False
    assert sender.sent == []


def test_new_problem_after_recovery_pages_again(env):
    n, sender, _ = env
    n.report("k", "full", msg(key="k"))
    n.report("k", "ok", msg(key="k"))
    assert n.report("k", "full", msg(key="k")) is True
    assert len(sender.sent) == 3


def test_unregistered_problem_title_is_refused_and_nothing_recorded(env):
    n, sender, _ = env
    with pytest.raises(UnregisteredProblem):
        n.report("k", "bad", msg(title="Mystery alert", key="k"))
    assert sender.sent == [] and n.state_of("k") == "ok"


def test_register_pair_validation(env):
    n, _, _ = env
    with pytest.raises(ValueError):
        n.register_pair("same", "same")
    with pytest.raises(ValueError):
        n.register_pair("", "x")


def test_state_survives_a_new_notifier_on_same_store(tmp_path):
    sender = FakeSender()
    path = tmp_path / "n.json"
    for _ in range(2):  # two "runs" of a cron-style check
        n = Notifier(sender, StateStore(path), Clock())
        n.register_pair("T", "T ok")
        n.report("k", "red", Message("k", "T", "b"))
    assert len(sender.sent) == 1
    n = Notifier(sender, StateStore(path), Clock())
    n.register_pair("T", "T ok")
    assert n.report("k", "ok", Message("k", "T", "b")) is True


def test_failed_send_is_not_recorded_and_retries(env):
    n, sender, _ = env
    sender.fail_next = 1
    with pytest.raises(SendError):
        n.report("k", "full", msg(key="k"))
    assert n.state_of("k") == "ok"
    assert n.report("k", "full", msg(key="k")) is True


def test_global_rate_limit_delays_and_does_not_lose_the_problem(tmp_path):
    sender, clock = FakeSender(), Clock()
    n = Notifier(sender, StateStore(tmp_path / "n.json"), clock, rate_limit=RateLimit(2, 60.0))
    n.register_pair("T", "T ok")
    assert n.report("a", "red", Message("a", "T", "b"))
    assert n.report("b", "red", Message("b", "T", "b"))
    assert n.report("c", "red", Message("c", "T", "b")) is False
    assert n.suppressed_by_rate_limit == 1 and n.state_of("c") == "ok"
    clock.t += 61
    assert n.report("c", "red", Message("c", "T", "b")) is True  # retried after the window
    assert len(sender.sent) == 3


def test_a_scope_has_its_own_budget_and_never_spends_the_global_one(tmp_path):
    """One broker agent looping submit/cancel spent the global budget, and another agent's page
    was then suppressed and never retried."""
    sender = FakeSender()
    n = Notifier(sender, StateStore(tmp_path / "n.json"), Clock(),
                 rate_limit=RateLimit(max_sends=2, window_s=3600))  # fmt: skip
    n.register_pair("Disk almost full", "Disk space recovered")
    for i in range(5):
        n.report(f"loud:{i}", "full", msg(key=f"loud:{i}"), scope="actor-loud")
    assert len(sender.sent) == 2, "the scope's own budget"
    assert n.report("quiet:1", "full", msg(key="quiet:1"), scope="actor-quiet") is True
    assert n.report("host:1", "full", msg(key="host:1")) is True, "the global budget is untouched"


def test_every_scope_together_has_a_loose_backstop(tmp_path):
    sender = FakeSender()
    rl = RateLimit(max_sends=2, window_s=3600, max_sends_all_scopes=3)
    n = Notifier(sender, StateStore(tmp_path / "n.json"), Clock(), rate_limit=rl)
    n.register_pair("Disk almost full", "Disk space recovered")
    for scope in ("a", "b", "c"):
        for i in range(2):
            n.report(f"{scope}:{i}", "full", msg(key=f"{scope}:{i}"), scope=scope)
    assert len(sender.sent) == 3, "three scopes, each under its own budget, still stop at 3"


def test_forget_drops_a_settled_key_and_keeps_an_open_one(env):
    n, _, _ = env
    n.report("disk:app-01", "full", msg())
    assert n.forget("disk:app-01") is False, "still a problem: kept"
    n.clear("disk:app-01")
    assert n.forget("disk:app-01") is True
    assert n.store.get("notify/disk:app-01") is None


def test_clear_marks_a_key_ok_without_a_message(env):
    n, sender, _ = env
    n.report("disk:app-01", "full", msg())
    assert n.clear("disk:app-01") is True and n.state_of("disk:app-01") == "ok"
    assert sender.titles == ["Disk almost full"], "no recovery message"
    assert n.clear("disk:app-01") is False
    assert n.report("disk:app-01", "full", msg()) is True, "a new problem pages again"


def test_per_key_min_interval(tmp_path):
    sender, clock = FakeSender(), Clock()
    n = Notifier(
        sender,
        StateStore(tmp_path / "n.json"),
        clock,
        rate_limit=RateLimit(100, 3600.0, min_interval_per_key_s=300.0),
    )
    n.register_pair("T", "T ok")
    assert n.report("k", "red", Message("k", "T", "b"))
    clock.t += 10
    assert n.report("k", "ok", Message("k", "T", "b")) is False  # flapping: recovery held back
    clock.t += 300
    assert n.report("k", "ok", Message("k", "T", "b")) is True


def test_message_validation():
    with pytest.raises(ValueError):
        Message("k", "t", "b", level="loud")
    with pytest.raises(ValueError):
        Message("k", "t", "b", priority=9)
    with pytest.raises(ValueError):
        Message("", "t", "b")
    assert Message("k", "t", "b", level="crit").effective_priority == 5


# ------------------------------------------------------------------ ntfy sender
class Resp:
    def __init__(self, status=200):
        self.status = status

    def close(self):
        pass


class Opener:
    def __init__(self, resp=None, exc=None):
        self.calls, self.resp, self.exc = [], resp or Resp(), exc

    def __call__(self, req, timeout):
        self.calls.append((req, timeout))
        if self.exc:
            raise self.exc
        return self.resp


def test_ntfy_builds_request_from_resolved_endpoint():
    op = Opener()
    s = NtfySender(lambda: "https://notify.svc.example.internal/", default_topic="ops", opener=op)
    s.send(
        Message(
            "k", "Disk", "95%", level="crit", tags=("disk", "warning"), email="oncall@example.org"
        )
    )
    req, timeout = op.calls[0]
    assert req.full_url == "https://notify.svc.example.internal/ops"
    assert req.get_method() == "POST" and req.data == b"95%" and timeout == 10.0
    h = {k.lower(): v for k, v in req.header_items()}
    assert h["title"] == "Disk" and h["priority"] == "5" and h["tags"] == "disk,warning"
    assert h["email"] == "oncall@example.org"


def test_ntfy_topic_override_and_auth_read_at_send_time():
    op = Opener()
    secret = ["tok-1"]
    s = NtfySender(
        lambda: "https://n.svc.example.internal",
        default_topic="ops",
        auth=lambda: secret[0],
        opener=op,
    )
    secret[0] = "tok-2"
    s.send(Message("k", "t", "b", topic="alerts"))
    req = op.calls[0][0]
    assert req.full_url.endswith("/alerts") and req.get_header("Authorization") == "tok-2"
    assert "tok" not in repr(s)


def test_ntfy_header_injection_is_neutralised():
    op = Opener()
    s = NtfySender(lambda: "http://n.svc.example.internal", default_topic="ops", opener=op)
    s.send(Message("k", "line1\r\nX-Evil: 1", "b"))
    title = op.calls[0][0].get_header("Title")
    assert "\n" not in title and "\r" not in title


@pytest.mark.parametrize("topic", ["../x", "a b", "", "x" * 65])
def test_ntfy_rejects_bad_topic(topic):
    s = NtfySender(
        lambda: "https://n.svc.example.internal", default_topic=topic or None, opener=Opener()
    )
    with pytest.raises(SendError):
        s.send(Message("k", "t", "b"))


def test_ntfy_rejects_bad_email_and_non_http_endpoint():
    s = NtfySender(lambda: "https://n.svc.example.internal", default_topic="ops", opener=Opener())
    with pytest.raises(SendError):
        s.send(Message("k", "t", "b", email="not an email"))
    with pytest.raises(SendError):
        NtfySender(lambda: "ftp://x", default_topic="ops", opener=Opener()).send(
            Message("k", "t", "b")
        )


def test_ntfy_wraps_network_and_http_errors():
    err = urllib.error.HTTPError("u", 503, "x", {}, io.BytesIO())
    for exc in (err, urllib.error.URLError("down"), TimeoutError()):
        s = NtfySender(
            lambda: "https://n.svc.example.internal",
            default_topic="ops",
            opener=Opener(exc=exc),
        )
        with pytest.raises(SendError):
            s.send(Message("k", "t", "b"))
    s = NtfySender(
        lambda: "https://n.svc.example.internal", default_topic="ops", opener=Opener(Resp(500))
    )
    with pytest.raises(SendError):
        s.send(Message("k", "t", "b"))


def test_ntfy_without_endpoint_resolves_through_registry_and_never_defaults(monkeypatch):
    for var in list(__import__("os").environ):
        if var.startswith("HNX_ENDPOINT"):
            monkeypatch.delenv(var)
    s = NtfySender(default_topic="ops", opener=Opener())
    with pytest.raises(
        ResolutionError
    ):  # no registry, no override, no DNS: raises, no literal fallback
        s.base_url()


def test_ntfy_endpoint_via_env_override(monkeypatch):
    monkeypatch.setenv("HNX_ENDPOINT_NOTIFY", OVERRIDE)
    op = Opener()
    NtfySender(default_topic="ops", opener=op).send(Message("k", "t", "b"))
    assert op.calls[0][0].full_url == OVERRIDE + "/ops"


def test_end_to_end_notifier_with_ntfy_sender(tmp_path):
    op = Opener()
    sender = NtfySender(lambda: "https://n.svc.example.internal", default_topic="ops", opener=op)
    n = Notifier(sender, StateStore(tmp_path / "n.json"), Clock())
    n.register_pair("Backup stale", "Backup fresh")
    m = Message("bk", "Backup stale", "no recovery point in 30h", level="warn")
    n.report("bk", "stale", m)
    n.report("bk", "stale", m)
    n.report("bk", "ok", m)
    assert [c[0].get_header("Title") for c in op.calls] == ["Backup stale", "Backup fresh"]


def test_ntfy_endpoint_via_resolver_and_fake_dns():
    from homelabnext.registry import FakeDNS, Resolver

    reg = Resolver(
        domain="example.internal",
        dns=FakeDNS({}),
        environ={"HNX_ENDPOINT_NOTIFY": OVERRIDE},
    )
    op = Opener()
    NtfySender(default_topic="ops", resolver=reg, opener=op).send(Message("k", "t", "b"))
    assert op.calls[0][0].full_url == OVERRIDE + "/ops"
