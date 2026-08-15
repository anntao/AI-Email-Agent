"""Tests for intent classification, including the response schema's API validity.

The schema is sent to Gemini on every call, and an invalid one fails the whole
request with a 400 — which the handler correctly treats as retryable, producing
a redelivery loop that never resolves. These checks are structural and offline;
they would have caught the empty enum value that shipped in the first deploy.
"""

import pytest

from agent.intent import RESPONSE_SCHEMA, Intent, IntentResult, classify


def walk(node, path="root"):
    """Yield every (path, subschema) pair in a JSON schema tree."""
    if not isinstance(node, dict):
        return
    yield path, node
    for key, child in (node.get("properties") or {}).items():
        yield from walk(child, f"{path}.{key}")
    if "items" in node:
        yield from walk(node["items"], f"{path}[]")


# ---------- schema validity ----------


def test_no_enum_value_is_empty():
    """Regression: Gemini rejects an empty enum value with 400 INVALID_ARGUMENT."""
    for path, node in walk(RESPONSE_SCHEMA):
        for i, value in enumerate(node.get("enum") or []):
            assert value != "", f"{path}.enum[{i}] is empty"
            assert value.strip() == value, f"{path}.enum[{i}] has surrounding whitespace"


def test_every_enum_belongs_to_a_string_field():
    for path, node in walk(RESPONSE_SCHEMA):
        if "enum" in node:
            assert node.get("type") == "STRING", f"{path} has an enum but is not STRING"


def test_every_node_declares_a_supported_type():
    allowed = {"OBJECT", "STRING", "INTEGER", "NUMBER", "BOOLEAN", "ARRAY"}
    for path, node in walk(RESPONSE_SCHEMA):
        assert node.get("type") in allowed, f"{path} has unsupported type {node.get('type')!r}"


def test_required_fields_exist_in_properties():
    for path, node in walk(RESPONSE_SCHEMA):
        for name in node.get("required") or []:
            assert name in (node.get("properties") or {}), f"{path} requires unknown {name!r}"


def test_only_intent_is_required():
    """Everything else must be optional, so the model can omit what isn't stated."""
    assert RESPONSE_SCHEMA["required"] == ["intent"]


def test_intent_enum_matches_the_enum_type():
    declared = set(RESPONSE_SCHEMA["properties"]["intent"]["enum"])
    handled = {i.value for i in Intent} - {Intent.ERROR.value}
    assert declared == handled, "schema and Intent enum have drifted apart"


def test_time_of_day_values_match_what_scheduling_accepts():
    from agent.scheduling import normalise_preferences

    for value in RESPONSE_SCHEMA["properties"]["time_of_day"]["enum"]:
        assert normalise_preferences({"time_of_day": value}).time_of_day == value


# ---------- failure handling ----------


def test_missing_api_key_returns_error_without_calling_out():
    result = classify("hello", None, api_key=None)
    assert result.intent is Intent.ERROR
    assert "not configured" in result.error


def test_error_result_is_not_ok():
    assert not IntentResult(Intent.ERROR, {}, "boom").ok
    assert IntentResult(Intent.IGNORE, {}).ok


@pytest.mark.parametrize("value", list(Intent))
def test_all_intent_values_round_trip(value):
    assert Intent(value.value) is value


# ---------- retry classification ----------


class FakeAPIError(Exception):
    def __init__(self, code=None, status=""):
        super().__init__(f"{code} {status}")
        if code is not None:
            self.code = code
        self.status = status


@pytest.mark.parametrize("code", [400, 401, 403, 404, 422])
def test_client_errors_are_permanent(code):
    """A bad schema or retired model fails identically forever; retrying loops."""
    from agent.intent import _is_retryable
    assert not _is_retryable(FakeAPIError(code, "INVALID_ARGUMENT"))


@pytest.mark.parametrize("code", [408, 429, 500, 502, 503, 504])
def test_transient_errors_are_retryable(code):
    from agent.intent import _is_retryable
    assert _is_retryable(FakeAPIError(code, "UNAVAILABLE"))


def test_status_string_is_used_when_no_code_is_present():
    from agent.intent import _is_retryable
    assert _is_retryable(FakeAPIError(None, "RESOURCE_EXHAUSTED"))
    assert not _is_retryable(FakeAPIError(None, "INVALID_ARGUMENT"))
    assert not _is_retryable(FakeAPIError(None, "NOT_FOUND"))


def test_unknown_failures_default_to_retryable():
    from agent.intent import _is_retryable
    assert _is_retryable(RuntimeError("connection reset"))


def test_missing_key_is_not_retryable():
    assert classify("hi", None, api_key=None).retryable is False
