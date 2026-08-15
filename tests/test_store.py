"""Tests for the Firestore state layer, against an in-memory fake.

The rate limiter is the reason this file exists. Charging per *attempt* rather
than per *message* meant a transient outage burned the sender's hourly quota
across redeliveries, after which the message was discarded as "rate limited" —
an outage silently converted into a lost email.
"""

from datetime import datetime, timedelta, timezone

import pytest

from agent import store as store_module
from agent.store import STATUS_DONE, STATUS_PROCESSING, Store


class FakeSnapshot:
    def __init__(self, data):
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return dict(self._data) if self._data is not None else {}


class FakeDocRef:
    def __init__(self, docs, key):
        self._docs, self._key = docs, key

    def get(self, transaction=None):
        return FakeSnapshot(self._docs.get(self._key))

    def set(self, data):
        self._docs[self._key] = dict(data)

    def delete(self):
        self._docs.pop(self._key, None)


class FakeCollection:
    def __init__(self, docs, name):
        self._docs, self._name = docs, name

    def document(self, key):
        return FakeDocRef(self._docs, f"{self._name}/{key}")


class FakeTransaction:
    def set(self, ref, data):
        ref.set(data)


class FakeDB:
    def __init__(self):
        self.docs = {}

    def collection(self, name):
        return FakeCollection(self.docs, name)

    def transaction(self):
        return FakeTransaction()


@pytest.fixture
def store(monkeypatch):
    # The real decorator needs a live client; here it just runs the function.
    monkeypatch.setattr(store_module.firestore, "transactional", lambda fn: fn)
    return Store(FakeDB(), stale_claim_seconds=600)


# ---------- rate limiting ----------


def test_retrying_one_message_is_charged_only_once(store):
    """Regression: 12 redeliveries of one message used to exhaust a limit of 12."""
    for _ in range(50):
        assert store.check_rate_limit("sam@x.com", 12, message_id="msg1") is True


def test_distinct_messages_each_consume_budget(store):
    allowed = [store.check_rate_limit("sam@x.com", 3, message_id=f"m{i}") for i in range(5)]
    assert allowed == [True, True, True, False, False]


def test_a_retry_still_passes_after_the_limit_is_reached(store):
    """An in-flight message must not be dropped because later ones filled the bucket."""
    assert store.check_rate_limit("sam@x.com", 2, message_id="early") is True
    assert store.check_rate_limit("sam@x.com", 2, message_id="other") is True
    assert store.check_rate_limit("sam@x.com", 2, message_id="late") is False
    assert store.check_rate_limit("sam@x.com", 2, message_id="early") is True


def test_senders_have_separate_budgets(store):
    assert store.check_rate_limit("a@x.com", 1, message_id="m1") is True
    assert store.check_rate_limit("b@x.com", 1, message_id="m2") is True
    assert store.check_rate_limit("a@x.com", 1, message_id="m3") is False


def test_zero_limit_disables_the_check(store):
    for i in range(20):
        assert store.check_rate_limit("sam@x.com", 0, message_id=f"m{i}") is True


def test_charged_history_is_bounded(store):
    for i in range(store_module.RATE_HISTORY + 50):
        store.check_rate_limit("sam@x.com", 10_000, message_id=f"m{i}")
    doc = store.db.docs[
        f"sender_rate/sam@x.com|{datetime.now(timezone.utc).strftime('%Y%m%d%H')}"
    ]
    assert len(doc["charged"]) == store_module.RATE_HISTORY


def test_clearing_a_sender_resets_the_bucket(store):
    assert store.check_rate_limit("sam@x.com", 1, message_id="m1") is True
    assert store.check_rate_limit("sam@x.com", 1, message_id="m2") is False
    store.clear_rate_limit("sam@x.com")
    assert store.check_rate_limit("sam@x.com", 1, message_id="m3") is True


def test_limiter_failure_never_blocks_scheduling(store, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("firestore down")

    monkeypatch.setattr(store.db, "transaction", boom)
    assert store.check_rate_limit("sam@x.com", 1, message_id="m1") is True


# ---------- claims ----------


def test_a_message_is_claimed_once(store):
    assert store.claim_message("m1") is True
    assert store.claim_message("m1") is False


def test_a_released_message_can_be_reclaimed(store):
    assert store.claim_message("m1") is True
    store.release_message("m1")
    assert store.claim_message("m1") is True


def test_a_completed_message_is_never_reprocessed(store):
    store.claim_message("m1")
    store.complete_message("m1", "offered 9 slots")
    assert store.claim_message("m1") is False
    assert store.db.docs["message_claims/m1"]["status"] == STATUS_DONE


def test_a_failed_message_is_not_retried(store):
    store.claim_message("m1")
    store.fail_message("m1", "boom")
    assert store.claim_message("m1") is False


def test_a_stale_claim_is_reclaimed(store):
    store.claim_message("m1")
    store.db.docs["message_claims/m1"]["claimed_at"] = datetime.now(timezone.utc) - timedelta(
        seconds=3600
    )
    assert store.claim_message("m1") is True
    assert store.db.docs["message_claims/m1"]["status"] == STATUS_PROCESSING


# ---------- cursor ----------


def test_cursor_round_trips(store):
    assert store.get_cursor() is None
    store.set_cursor("100")
    assert store.get_cursor() == "100"


def test_cursor_only_moves_forward(store):
    store.set_cursor("200")
    store.advance_cursor("150")
    assert store.get_cursor() == "200"
    store.advance_cursor("250")
    assert store.get_cursor() == "250"


def test_non_numeric_cursor_is_still_accepted(store):
    store.set_cursor("abc")
    store.advance_cursor("300")
    assert store.get_cursor() == "300"
