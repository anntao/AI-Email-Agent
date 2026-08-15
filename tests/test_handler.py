"""Tests for the orchestration: claim ordering, booking guards, and what gets marked read."""

from datetime import datetime, time as dtime, timedelta
from zoneinfo import ZoneInfo

import pytest

from agent import calendar_ops, handler, mailbox, scheduling
from agent.config import Settings
from agent.handler import Context, RetryableError
from agent.intent import Intent, IntentResult
from agent.mailbox import ParsedMessage
from agent.scheduling import Interval, Slot

ET = ZoneInfo("America/New_York")
AGENT = "assistant@example.com"
OWNER = "owner@example.com"
GUEST = "sam@guest.com"
NOW = datetime(2026, 3, 2, 9, 0, tzinfo=ET)  # a Monday


class FakeStore:
    def __init__(self, claimable=True):
        self.claimable = claimable
        self.claims: dict[str, str] = {}
        self.released: list[str] = []
        self.cursor = None
        self.watch = None
        self.rate_ok = True
        self.rate_calls = []

    def claim_message(self, message_id):
        if not self.claimable or message_id in self.claims:
            return False
        self.claims[message_id] = "processing"
        return True

    def complete_message(self, message_id, outcome):
        self.claims[message_id] = f"done:{outcome}"

    def fail_message(self, message_id, error):
        self.claims[message_id] = f"failed:{error}"

    def release_message(self, message_id):
        self.released.append(message_id)
        self.claims.pop(message_id, None)

    def get_cursor(self):
        return self.cursor

    def set_cursor(self, history_id):
        self.cursor = str(history_id)

    def advance_cursor(self, history_id):
        self.cursor = str(history_id)

    def get_watch_expiration(self):
        return self.watch

    def set_watch_expiration(self, ms):
        self.watch = ms

    def check_rate_limit(self, sender, limit, message_id=None):
        self.rate_calls.append((sender, message_id))
        return self.rate_ok


def make_settings(**overrides) -> Settings:
    base = dict(
        project_id="p",
        agent_email=AGENT,
        owner_email=OWNER,
        owner_name="Alex",
        gemini_api_key="key",
        timezone=ET,
        work_start=dtime(9, 30),
        work_end=dtime(18, 0),
    )
    base.update(overrides)
    return Settings(**base)


def make_message(**overrides) -> ParsedMessage:
    headers = {
        "from": f"Sam <{GUEST}>",
        "to": f"{AGENT}, {OWNER}",
        "cc": "",
        "subject": "Re: Intro chat",
        "message-id": "<m1@guest>",
        "references": "",
    }
    headers.update(overrides.pop("headers", {}))
    return ParsedMessage(
        id=overrides.pop("id", "msg1"),
        thread_id=overrides.pop("thread_id", "thread1"),
        headers=headers,
        text=overrides.pop("text", "Can we meet?"),
        html=overrides.pop("html", ""),
    )


@pytest.fixture
def ctx():
    context = Context(settings=make_settings(), store=FakeStore(), gmail=object(), calendar=object())
    context.now = lambda: NOW  # type: ignore[method-assign]
    return context


@pytest.fixture
def wired(monkeypatch, ctx):
    """Patch out every network call; record what the handler tried to do."""
    calls = {"sent": [], "events": [], "read": [], "free": True, "busy": []}

    monkeypatch.setattr(mailbox, "get_message", lambda g, mid: calls["message"])
    monkeypatch.setattr(mailbox, "get_thread", lambda g, tid: [calls["message"]])
    monkeypatch.setattr(mailbox, "mark_read", lambda g, mid: calls["read"].append(mid))
    monkeypatch.setattr(mailbox, "send", lambda g, body, thread_id=None: calls["sent"].append(body))
    monkeypatch.setattr(
        mailbox, "build_reply", lambda **kw: {"raw": kw["html_body"], "subject": kw["subject"]}
    )
    monkeypatch.setattr(calendar_ops, "get_busy", lambda c, cid, s, e: calls["busy"])
    monkeypatch.setattr(calendar_ops, "is_slot_free", lambda c, cid, slot: calls["free"])
    monkeypatch.setattr(
        calendar_ops,
        "create_event",
        lambda c, cid, **kw: calls["events"].append(kw) or {"id": "evt"},
    )
    calls["message"] = make_message()
    calls["ctx"] = ctx
    return calls


def set_intent(monkeypatch, intent, data=None):
    monkeypatch.setattr(
        handler, "classify", lambda *a, **k: IntentResult(intent, data or {})
    )


# ---------- claim ordering (F-02) ----------


def test_retryable_failure_releases_the_claim(monkeypatch, wired):
    ctx = wired["ctx"]
    monkeypatch.setattr(handler, "_process", lambda c, m: (_ for _ in ()).throw(RetryableError("boom")))

    with pytest.raises(RetryableError):
        handler.process_message(ctx, "msg1")

    assert ctx.store.released == ["msg1"]
    assert "msg1" not in ctx.store.claims  # a redelivery can pick it up again


def test_permanent_failure_records_and_does_not_mark_read(monkeypatch, wired):
    ctx = wired["ctx"]
    monkeypatch.setattr(handler, "_process", lambda c, m: (_ for _ in ()).throw(ValueError("bad")))

    outcome = handler.process_message(ctx, "msg1")

    assert "failed" in outcome
    assert ctx.store.claims["msg1"].startswith("failed:")
    assert wired["read"] == []


def test_a_message_is_marked_read_only_after_success(monkeypatch, wired):
    ctx = wired["ctx"]
    set_intent(monkeypatch, Intent.IGNORE)

    handler.process_message(ctx, "msg1")

    assert wired["read"] == ["msg1"]
    assert ctx.store.claims["msg1"].startswith("done:")


def test_an_already_claimed_message_is_skipped(wired):
    ctx = wired["ctx"]
    ctx.store.claims["msg1"] = "processing"
    assert "already handled" in handler.process_message(ctx, "msg1")


# ---------- authorisation side effects (F-01) ----------


def test_unauthorised_mail_is_left_untouched(monkeypatch, wired):
    """Unrelated mail must not be marked read just because it arrived."""
    ctx = wired["ctx"]
    wired["message"] = make_message(headers={"to": "someone@else.com", "cc": ""})

    outcome = handler.process_message(ctx, "msg1")

    assert "ignored" in outcome
    assert wired["read"] == []
    assert wired["sent"] == []


def test_the_agents_own_message_is_skipped(monkeypatch, wired):
    ctx = wired["ctx"]
    wired["message"] = make_message(headers={"x-agent-processed": "true"})
    assert "own message" in handler.process_message(ctx, "msg1")
    assert wired["read"] == []


def test_rate_limited_sender_gets_no_reply(monkeypatch, wired):
    ctx = wired["ctx"]
    ctx.store.rate_ok = False
    set_intent(monkeypatch, Intent.INITIAL_REQUEST)

    outcome = handler.process_message(ctx, "msg1")

    assert "rate limit" in outcome
    assert wired["sent"] == []
    assert wired["read"] == []  # a rate-limited message is left unread


# ---------- proposing ----------


def test_initial_request_offers_slots(monkeypatch, wired):
    ctx = wired["ctx"]
    set_intent(monkeypatch, Intent.INITIAL_REQUEST, {"duration": 45})

    outcome = handler.process_message(ctx, "msg1")

    assert "offered" in outcome
    assert len(wired["sent"]) == 1
    assert "45-minute" in wired["sent"][0]["raw"]


def test_a_full_calendar_produces_an_honest_reply_not_a_made_up_slot(monkeypatch, wired):
    """The old fallback invented "tomorrow at 10am" without checking the calendar."""
    ctx = wired["ctx"]
    wired["busy"] = [Interval(NOW - timedelta(days=1), NOW + timedelta(days=30))]
    set_intent(monkeypatch, Intent.INITIAL_REQUEST)

    outcome = handler.process_message(ctx, "msg1")

    assert "no matching availability" in outcome
    assert "couldn't find an open slot" in wired["sent"][0]["raw"]
    assert wired["events"] == []


# ---------- booking (F-09, F-10) ----------


def offered_html(start: datetime, duration=30) -> str:
    payload = Slot(start, duration).to_payload()
    return f"<!-- data: {payload} -->"


def test_confirmation_books_the_offered_time_not_the_models_reading(monkeypatch, wired):
    ctx = wired["ctx"]
    offered_at = NOW.replace(hour=14, minute=0)
    wired["message"] = make_message(html=offered_html(offered_at, 45))
    set_intent(
        monkeypatch,
        Intent.CONFIRMATION,
        {"confirmed_start_time_iso": offered_at.replace(minute=4).isoformat()},
    )

    outcome = handler.process_message(ctx, "msg1")

    assert "booked" in outcome
    assert len(wired["events"]) == 1
    booked = wired["events"][0]["slot"]
    assert booked.start == offered_at  # 14:00, not the 14:04 the model returned
    assert booked.duration_minutes == 45


def test_booking_rechecks_availability_first(monkeypatch, wired):
    ctx = wired["ctx"]
    offered_at = NOW.replace(hour=14, minute=0)
    wired["message"] = make_message(html=offered_html(offered_at))
    wired["free"] = False
    set_intent(
        monkeypatch, Intent.CONFIRMATION,
        {"confirmed_start_time_iso": offered_at.isoformat()},
    )

    outcome = handler.process_message(ctx, "msg1")

    assert "taken" in outcome
    assert wired["events"] == []
    assert "was taken" in wired["sent"][0]["raw"]


def test_event_attendees_exclude_the_agent_and_include_the_owner(monkeypatch, wired):
    ctx = wired["ctx"]
    offered_at = NOW.replace(hour=14, minute=0)
    wired["message"] = make_message(html=offered_html(offered_at))
    set_intent(
        monkeypatch, Intent.CONFIRMATION,
        {"confirmed_start_time_iso": offered_at.isoformat()},
    )

    handler.process_message(ctx, "msg1")

    attendees = set(wired["events"][0]["attendees"])
    assert OWNER in attendees
    assert GUEST in attendees
    assert AGENT not in attendees


# ---------- free-text proposals are not authorisations (F-04) ----------


def test_a_time_written_in_prose_cannot_book_outside_working_hours(monkeypatch, wired):
    ctx = wired["ctx"]
    wired["message"] = make_message(text="Let's do Tuesday at 7:00 AM")
    proposed = NOW.replace(day=3, hour=7, minute=0)
    set_intent(
        monkeypatch, Intent.CONFIRMATION,
        {"confirmed_start_time_iso": proposed.isoformat()},
    )

    outcome = handler.process_message(ctx, "msg1")

    assert wired["events"] == []
    assert "offered" in outcome  # falls back to proposing real slots


def test_a_time_written_in_prose_still_books_when_it_is_valid_and_free(monkeypatch, wired):
    ctx = wired["ctx"]
    wired["message"] = make_message(text="Tuesday at 2:30 PM works for our side")
    proposed = NOW.replace(day=3, hour=14, minute=30)
    set_intent(
        monkeypatch, Intent.CONFIRMATION,
        {"confirmed_start_time_iso": proposed.isoformat()},
    )

    outcome = handler.process_message(ctx, "msg1")

    assert "booked" in outcome
    assert wired["events"][0]["slot"].source == "text"


def test_prose_booking_is_blocked_when_the_calendar_is_busy(monkeypatch, wired):
    ctx = wired["ctx"]
    wired["message"] = make_message(text="Tuesday at 2:30 PM works")
    wired["free"] = False
    proposed = NOW.replace(day=3, hour=14, minute=30)
    set_intent(
        monkeypatch, Intent.CONFIRMATION,
        {"confirmed_start_time_iso": proposed.isoformat()},
    )

    handler.process_message(ctx, "msg1")
    assert wired["events"] == []


# ---------- day confirmation (F-13) ----------


def test_day_confirmation_books_the_earliest_offered_slot_that_day(monkeypatch, wired):
    ctx = wired["ctx"]
    tuesday_pm = NOW.replace(day=3, hour=15, minute=0)
    tuesday_am = NOW.replace(day=3, hour=10, minute=0)
    wired["message"] = make_message(html=offered_html(tuesday_am) + offered_html(tuesday_pm))
    set_intent(monkeypatch, Intent.DAY_CONFIRMATION, {"day_name": "tuesday"})

    handler.process_message(ctx, "msg1")

    assert wired["events"][0]["slot"].start == tuesday_am


def test_unknown_day_name_proposes_instead_of_returning_an_error(monkeypatch, wired):
    """The old code returned HTTP 400, which Pub/Sub retried into oblivion."""
    ctx = wired["ctx"]
    set_intent(monkeypatch, Intent.DAY_CONFIRMATION, {"day_name": "someday"})

    outcome = handler.process_message(ctx, "msg1")

    assert "offered" in outcome
    assert len(wired["sent"]) == 1


def test_day_with_no_offered_slots_searches_that_day(monkeypatch, wired):
    ctx = wired["ctx"]
    set_intent(monkeypatch, Intent.DAY_CONFIRMATION, {"day_name": "wednesday"})

    handler.process_message(ctx, "msg1")

    assert "Wednesday" in wired["sent"][0]["raw"]


# ---------- model failure (F-14) ----------


def test_a_model_failure_is_retryable_not_a_silent_success(monkeypatch, wired):
    ctx = wired["ctx"]
    monkeypatch.setattr(
        handler, "classify", lambda *a, **k: IntentResult(Intent.ERROR, {}, "503 unavailable", retryable=True)
    )

    with pytest.raises(RetryableError):
        handler.process_message(ctx, "msg1")

    assert ctx.store.released == ["msg1"]
    assert wired["read"] == []


def test_a_permanent_api_error_is_not_retried_forever(monkeypatch, wired):
    ctx = wired["ctx"]
    monkeypatch.setattr(
        handler, "classify",
        lambda *a, **k: IntentResult(Intent.ERROR, {}, "400 INVALID_ARGUMENT: bad schema", retryable=False),
    )

    outcome = handler.process_message(ctx, "msg1")

    assert "failed" in outcome
    assert ctx.store.released == []


# ---------- history cursor ----------


def test_first_notification_seeds_the_cursor_without_processing(monkeypatch, ctx):
    monkeypatch.setattr(handler, "process_message", lambda c, m: pytest.fail("should not process"))
    outcomes = handler.handle_notification(ctx, "12345")
    assert ctx.store.cursor == "12345"
    assert "bootstrapped" in outcomes[0]


def test_expired_cursor_resets_instead_of_processing_random_mail(monkeypatch, ctx):
    ctx.store.cursor = "1"

    def boom(*a, **k):
        raise mailbox.HistoryCursorExpired("1")

    monkeypatch.setattr(mailbox, "list_new_message_ids", boom)
    outcomes = handler.handle_notification(ctx, "999")

    assert ctx.store.cursor == "999"
    assert "expired" in outcomes[0]


def test_every_new_message_is_processed_not_just_the_newest(monkeypatch, ctx):
    ctx.store.cursor = "1"
    monkeypatch.setattr(mailbox, "list_new_message_ids", lambda g, c, limit: (["a", "b", "c"], "9"))
    monkeypatch.setattr(handler, "process_message", lambda c, m: f"{m}: done")

    outcomes = handler.handle_notification(ctx, "9")

    assert outcomes == ["a: done", "b: done", "c: done"]
    assert ctx.store.cursor == "9"


# ---------- proposed-time resolution ----------


def _resolve(specific_time, **kw):
    from agent.handler import _parse_specific_time
    prefs = scheduling.Preferences(specific_time=specific_time, **kw)
    return _parse_specific_time(prefs, ET, None, NOW)


def test_bare_time_with_a_named_day_lands_on_that_day():
    """Regression: "Tuesday at 2pm" resolved to today, a Saturday, and was dropped."""
    got = _resolve("2:00 pm", day_preference="tuesday")
    assert got.weekday() == 1
    assert (got.hour, got.minute) == (14, 0)
    assert got.date() == NOW.date() + timedelta(days=1)  # NOW is a Monday


def test_bare_time_uses_start_date_when_given():
    target = (NOW + timedelta(days=5)).date()
    got = _resolve("9:30 am", start_date=target)
    assert got.date() == target
    assert (got.hour, got.minute) == (9, 30)


def test_explicit_date_in_the_string_wins():
    got = _resolve("2026-03-04T16:00:00-05:00", day_preference="tuesday")
    assert got.date().isoformat() == "2026-03-04"
    assert got.hour == 16


def test_bare_time_already_past_today_moves_forward():
    got = _resolve("8:00 am")  # NOW is 09:00
    assert got > NOW


def test_bare_time_with_no_day_context_stays_today():
    got = _resolve("2:00 pm")
    assert got.date() == NOW.date()
    assert got.hour == 14


def test_seconds_are_never_carried_through():
    got = _resolve("2:00 pm", day_preference="wednesday")
    assert got.second == 0 and got.microsecond == 0


def test_unparsable_time_returns_none():
    assert _resolve("whenever suits you") is None
