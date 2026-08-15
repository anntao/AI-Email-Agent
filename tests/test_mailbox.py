"""Tests for MIME parsing, quote stripping and thread truncation."""

import base64

from agent.mailbox import (
    ParsedMessage,
    _collect_parts,
    build_reply,
    build_thread_text,
    html_to_text,
    message_body_text,
    strip_quoted,
)


def b64(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode()


def make(text="", html=""):
    return ParsedMessage(id="1", thread_id="t", headers={"from": "a@b.com"}, text=text, html=html)


# ---------- MIME walking (F-16) ----------


def test_plain_and_html_alternatives_are_kept_separate():
    """Regression: both alternatives used to be concatenated into one blob."""
    payload = {
        "mimeType": "multipart/alternative",
        "parts": [
            {"mimeType": "text/plain", "body": {"data": b64("hello")}},
            {"mimeType": "text/html", "body": {"data": b64("<p>hello</p>")}},
        ],
    }
    text, html = _collect_parts(payload)
    assert text == "hello"
    assert html == "<p>hello</p>"


def test_nested_multipart_is_walked():
    payload = {
        "mimeType": "multipart/mixed",
        "parts": [{
            "mimeType": "multipart/alternative",
            "parts": [{"mimeType": "text/plain", "body": {"data": b64("deep")}}],
        }],
    }
    assert _collect_parts(payload)[0] == "deep"


def test_attachments_without_data_are_skipped():
    payload = {
        "mimeType": "multipart/mixed",
        "parts": [
            {"mimeType": "text/plain", "body": {"data": b64("body")}},
            {"mimeType": "application/pdf", "body": {"attachmentId": "x"}},
        ],
    }
    assert _collect_parts(payload)[0] == "body"


def test_undecodable_part_does_not_raise():
    payload = {"mimeType": "text/plain", "body": {"data": "!!!not base64!!!"}}
    assert _collect_parts(payload) == ("", "")


# ---------- html to text ----------


def test_html_comments_are_removed_from_readable_text():
    assert "data:" not in html_to_text('<p>hi</p><!-- data: {"start": "x"} -->')


def test_list_items_become_bullets():
    assert "- 9:30 AM" in html_to_text("<ul><li>9:30 AM</li></ul>")


def test_entities_are_unescaped():
    assert html_to_text("<p>Jo &amp; Sam</p>") == "Jo & Sam"


def test_script_and_style_are_dropped():
    assert "alert" not in html_to_text("<script>alert(1)</script><p>hi</p>")


# ---------- quote stripping ----------


def test_quoted_lines_are_dropped():
    assert strip_quoted("New reply\n> old thing\n> older thing") == "New reply"


def test_on_wrote_marker_truncates():
    body = "Sounds good\n\nOn Mon, 2 Mar 2026 at 09:00, Sam <s@x.com> wrote:\nEverything before"
    assert strip_quoted(body) == "Sounds good"


def test_original_message_marker_truncates():
    assert strip_quoted("Yes\n-----Original Message-----\nold") == "Yes"


def test_body_without_quotes_is_unchanged():
    assert strip_quoted("Just a note") == "Just a note"


def test_message_body_prefers_plain_text():
    assert message_body_text(make(text="plain", html="<p>html</p>")) == "plain"


def test_message_body_falls_back_to_html():
    assert message_body_text(make(html="<p>html</p>")) == "html"


# ---------- thread assembly ----------


def test_thread_text_is_bounded():
    messages = [make(text="x" * 5000) for _ in range(10)]
    assert len(build_thread_text(messages, max_chars=2000)) <= 2200


def test_thread_keeps_the_most_recent_messages():
    messages = [make(text="oldest"), make(text="middle"), make(text="newest")]
    assert "newest" in build_thread_text(messages, max_chars=10000)


def test_truncation_drops_the_oldest_first():
    messages = [make(text="OLDEST " * 200), make(text="NEWEST")]
    result = build_thread_text(messages, max_chars=300)
    assert "NEWEST" in result


def test_empty_messages_are_skipped():
    assert build_thread_text([make(), make(text="real")], 1000).count("--- From:") == 1


# ---------- outgoing mail ----------


def test_reply_is_multipart_with_a_plain_alternative():
    raw = build_reply(
        sender="a@b.com", sender_name="Assistant", to="c@d.com", cc="",
        subject="Re: Chat", html_body="<html><body><p>Hi</p></body></html>",
        in_reply_to="<m1@x>", references="<m0@x> <m1@x>",
    )
    decoded = base64.urlsafe_b64decode(raw["raw"]).decode()
    assert "text/plain" in decoded and "text/html" in decoded


def test_reply_carries_threading_headers_and_the_agent_marker():
    raw = build_reply(
        sender="a@b.com", sender_name="Assistant", to="c@d.com", cc="e@f.com",
        subject="Re: Chat", html_body="<p>Hi</p>",
        in_reply_to="<m1@x>", references="<m0@x> <m1@x>",
    )
    decoded = base64.urlsafe_b64decode(raw["raw"]).decode()
    assert "In-Reply-To: <m1@x>" in decoded
    assert "X-Agent-Processed: true" in decoded
    assert "Cc: e@f.com" in decoded


def test_empty_cc_header_is_omitted():
    raw = build_reply(
        sender="a@b.com", sender_name="Assistant", to="c@d.com", cc="",
        subject="Re: Chat", html_body="<p>Hi</p>", in_reply_to=None, references=None,
    )
    assert "Cc:" not in base64.urlsafe_b64decode(raw["raw"]).decode()


def test_agent_sent_flag_is_read_from_headers():
    marked = ParsedMessage(id="1", thread_id="t", headers={"x-agent-processed": "true"},
                           text="", html="")
    assert marked.is_agent_sent
    assert not make().is_agent_sent
