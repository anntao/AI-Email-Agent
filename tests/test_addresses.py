"""Tests for address parsing and the authorisation gate."""

import pytest

from agent.addresses import (
    authorize,
    display_name,
    matches_allowlist,
    parse_addresses,
    reply_recipients,
    sender_address,
)

AGENT = "assistant@example.com"
OWNER = "owner@example.com"


def allow(from_h, to_h, cc_h="", allowlist=()):
    return authorize(
        from_header=from_h,
        to_header=to_h,
        cc_header=cc_h,
        agent_email=AGENT,
        owner_email=OWNER,
        allowlist=allowlist,
    )


# ---------- parsing ----------


def test_display_names_are_stripped():
    assert parse_addresses('"Diaz, Anntao" <a@b.com>, Sam <s@c.com>') == ["a@b.com", "s@c.com"]


def test_addresses_are_lowercased_and_deduplicated():
    assert parse_addresses("A@B.com, a@b.com") == ["a@b.com"]


def test_comma_inside_a_quoted_name_does_not_split_the_address():
    assert parse_addresses('"Smith, Jo" <jo@x.com>') == ["jo@x.com"]


def test_empty_headers_parse_to_nothing():
    assert parse_addresses(None, "", "   ") == []


def test_sender_address_extraction():
    assert sender_address("Sam Jones <sam@x.com>") == "sam@x.com"
    assert sender_address("") == ""


def test_display_name_falls_back_to_local_part():
    assert display_name("Sam Jones <sam@x.com>") == "Sam Jones"
    assert display_name("<sam@x.com>") == "sam"


# ---------- the substring vulnerability (F-03) ----------


def test_lookalike_owner_address_is_rejected():
    """Regression: `owner in (to + cc + from)` accepted xowner@example.com."""
    result = allow(f"Impostor <x{OWNER}>", AGENT)
    assert not result.allowed
    assert "not a participant" in result.reason


def test_owner_as_substring_across_header_boundaries_is_rejected():
    result = allow("a@example.com", f"{AGENT}, someone@owner.example.com")
    assert not result.allowed


def test_genuine_owner_participation_is_accepted():
    assert allow("sam@x.com", f"{AGENT}, {OWNER}").allowed


def test_owner_in_cc_is_accepted():
    assert allow("sam@x.com", AGENT, OWNER).allowed


def test_owner_as_sender_is_accepted():
    assert allow(OWNER, f"{AGENT}, sam@x.com").allowed


# ---------- explicit invocation ----------


def test_agent_must_be_addressed_not_merely_mentioned():
    result = allow("sam@x.com", OWNER)
    assert not result.allowed
    assert "not in To or Cc" in result.reason


def test_agent_in_cc_counts_as_addressed():
    assert allow("sam@x.com", OWNER, AGENT).allowed


def test_agents_own_message_is_rejected():
    result = allow(AGENT, f"{AGENT}, {OWNER}")
    assert not result.allowed
    assert "agent itself" in result.reason


def test_unparsable_sender_is_rejected():
    assert not allow("", f"{AGENT}, {OWNER}").allowed


# ---------- allowlist ----------


def test_no_allowlist_permits_anyone_who_passes_the_other_checks():
    assert allow("stranger@x.com", f"{AGENT}, {OWNER}", allowlist=()).allowed


def test_allowlist_blocks_a_sender_who_is_not_listed():
    result = allow("stranger@x.com", f"{AGENT}, {OWNER}", allowlist={"friend@y.com"})
    assert not result.allowed
    assert "allowlist" in result.reason


def test_allowlist_permits_a_listed_address():
    assert allow("friend@y.com", f"{AGENT}, {OWNER}", allowlist={"friend@y.com"}).allowed


def test_allowlist_supports_whole_domains():
    assert allow("anyone@y.com", f"{AGENT}, {OWNER}", allowlist={"@y.com"}).allowed
    assert not allow("anyone@z.com", f"{AGENT}, {OWNER}", allowlist={"@y.com"}).allowed


@pytest.mark.parametrize("entry", ["FRIEND@Y.COM", "friend@y.com"])
def test_allowlist_is_case_insensitive(entry):
    assert matches_allowlist("Friend@Y.com", {entry.lower()})


def test_domain_lookalike_does_not_match():
    assert not matches_allowlist("bad@evil-y.com", {"@y.com"})


# ---------- reply recipients ----------


def test_reply_puts_everyone_else_in_to_and_ccs_the_owner():
    to, cc = reply_recipients(
        from_header="sam@x.com",
        to_header=f"{AGENT}, {OWNER}",
        cc_header="jo@y.com",
        agent_email=AGENT,
        owner_email=OWNER,
    )
    assert set(to.split(", ")) == {"sam@x.com", "jo@y.com"}
    assert cc == OWNER


def test_agent_never_replies_to_itself():
    to, _ = reply_recipients(
        from_header="sam@x.com",
        to_header=AGENT,
        cc_header="",
        agent_email=AGENT,
        owner_email=OWNER,
    )
    assert AGENT not in to


def test_owner_only_thread_falls_back_to_the_sender():
    to, cc = reply_recipients(
        from_header=OWNER,
        to_header=AGENT,
        cc_header="",
        agent_email=AGENT,
        owner_email=OWNER,
    )
    assert to == OWNER
    assert cc == ""
