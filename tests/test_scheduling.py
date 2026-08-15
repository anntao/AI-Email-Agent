"""Tests for the slot logic, including regressions for every date bug in the audit."""

from datetime import datetime, time as dtime, timedelta
from zoneinfo import ZoneInfo

import pytest

from agent.scheduling import (
    Interval,
    Preferences,
    Slot,
    SlotPolicy,
    base_subject,
    clean_subject,
    day_periods,
    extract_text_slots,
    find_available_slots,
    match_confirmed_slot,
    normalise_preferences,
    parse_offered_slots,
    resolve_timezone,
    within_working_hours,
)

ET = ZoneInfo("America/New_York")
POLICY = SlotPolicy(timezone=ET)

# A Monday.
MONDAY_8AM = datetime(2026, 3, 2, 8, 0, tzinfo=ET)


def at(day_offset: int, hour: int, minute: int = 0) -> datetime:
    return (MONDAY_8AM + timedelta(days=day_offset)).replace(hour=hour, minute=minute)


# ---------- working hours (F-19) ----------


def test_day_periods_start_at_configured_work_start_not_nine():
    periods = day_periods(MONDAY_8AM.date(), POLICY)
    assert periods[0][0].time() == dtime(9, 30)


def test_every_offer_sits_inside_the_working_day():
    slots = find_available_slots([], Preferences(), MONDAY_8AM, POLICY)
    assert slots
    assert all(s.start.time() >= dtime(9, 30) for s in slots)
    assert all(s.end.time() <= dtime(18, 0) for s in slots)


def test_custom_work_hours_are_honoured():
    policy = SlotPolicy(timezone=ET, work_start=dtime(11, 0), work_end=dtime(14, 0))
    slots = find_available_slots([], Preferences(), MONDAY_8AM, policy)
    assert all(dtime(11, 0) <= s.start.time() for s in slots)
    assert all(s.end.time() <= dtime(14, 0) for s in slots)


# ---------- slot search ----------


def test_offers_three_days_of_three_slots_when_calendar_is_empty():
    slots = find_available_slots([], Preferences(), MONDAY_8AM, POLICY)
    assert len(slots) == 9
    assert len({s.start.date() for s in slots}) == 3


def test_busy_intervals_are_skipped():
    busy = [Interval(at(0, 9, 0), at(0, 13, 0))]
    today = [
        s for s in find_available_slots(busy, Preferences(), MONDAY_8AM, POLICY)
        if s.start.date() == MONDAY_8AM.date()
    ]
    assert today
    assert all(s.start >= at(0, 13, 0) for s in today)


# ---------- spreading offers across the day ----------


def test_offers_are_spread_across_the_day_not_clustered():
    """An open calendar used to yield the first slot of each window, every time."""
    today = [
        s for s in find_available_slots([], Preferences(), MONDAY_8AM, POLICY)
        if s.start.date() == MONDAY_8AM.date()
    ]
    hours = [s.start.hour for s in today]
    assert len(set(hours)) == len(hours)
    assert max(hours) - min(hours) >= 4  # genuinely spread, not three near-identical times


def test_the_offered_days_are_not_identical_to_each_other():
    slots = find_available_slots([], Preferences(), MONDAY_8AM, POLICY)
    by_day = {}
    for s in slots:
        by_day.setdefault(s.start.date(), []).append(s.start.strftime("%H:%M"))
    shapes = {tuple(v) for v in by_day.values()}
    assert len(by_day) == 3
    assert len(shapes) > 1, "every day offered exactly the same times"


def test_the_same_calendar_always_produces_the_same_offer():
    a = find_available_slots([], Preferences(), MONDAY_8AM, POLICY)
    b = find_available_slots([], Preferences(), MONDAY_8AM, POLICY)
    assert [s.start for s in a] == [s.start for s in b]


def test_spread_returns_everything_when_there_is_little_to_choose_from():
    from agent.scheduling import spread
    assert spread([1, 2], 3) == [1, 2]
    assert spread([], 3) == []
    assert spread([1, 2, 3], 0) == []


def test_spread_never_repeats_an_item():
    from agent.scheduling import spread
    for phase in (0.0, 0.35, 0.5, 0.65, 0.99):
        picked = spread(list(range(20)), 5, phase)
        assert len(picked) == len(set(picked))


def test_spread_stays_in_range():
    from agent.scheduling import spread
    items = list(range(7))
    for phase in (0.0, 0.5, 0.99):
        assert all(x in items for x in spread(items, 3, phase))


def test_a_long_meeting_may_straddle_a_period_boundary():
    """The union window lets a 60-minute slot cross the 12:00 line."""
    from agent.scheduling import free_starts
    starts = free_starts(MONDAY_8AM.date(), [], 60, MONDAY_8AM, POLICY, None)
    assert any(s.hour == 11 and s.minute == 30 for s in starts)


def test_weekends_are_never_offered():
    slots = find_available_slots([], Preferences(), at(4, 8), POLICY)  # from a Friday
    assert all(s.start.weekday() < 5 for s in slots)


def test_day_preference_restricts_to_that_weekday():
    slots = find_available_slots([], Preferences(day_preference="wednesday"), MONDAY_8AM, POLICY)
    assert slots and all(s.start.weekday() == 2 for s in slots)


def test_morning_preference_only_returns_mornings():
    slots = find_available_slots([], Preferences(time_of_day="morning"), MONDAY_8AM, POLICY)
    assert slots and all(s.start.hour < 12 for s in slots)


def test_afternoon_preference_only_returns_afternoons():
    slots = find_available_slots([], Preferences(time_of_day="afternoon"), MONDAY_8AM, POLICY)
    assert slots and all(s.start.hour >= 12 for s in slots)


def test_slots_never_start_in_the_past():
    midday = MONDAY_8AM.replace(hour=13, minute=7)
    slots = find_available_slots([], Preferences(), midday, POLICY)
    assert all(s.start > midday for s in slots)


def test_offers_land_on_the_step_grid():
    midday = MONDAY_8AM.replace(hour=13, minute=7)
    slots = find_available_slots([], Preferences(), midday, POLICY)
    assert all(s.start.minute in (0, 30) for s in slots)


def test_start_date_moves_the_search_forward():
    prefs = Preferences(start_date=(MONDAY_8AM + timedelta(days=7)).date())
    slots = find_available_slots([], prefs, MONDAY_8AM, POLICY)
    assert slots and all(s.start.date() >= prefs.start_date for s in slots)


def test_fully_busy_calendar_returns_nothing():
    busy = [Interval(MONDAY_8AM, MONDAY_8AM + timedelta(days=20))]
    assert find_available_slots(busy, Preferences(), MONDAY_8AM, POLICY) == []


def test_long_meeting_does_not_overflow_the_working_day():
    slots = find_available_slots([], Preferences(duration_minutes=120), MONDAY_8AM, POLICY)
    assert slots and all(within_working_hours(s, POLICY) for s in slots)


# ---------- free-text parsing (F-08) ----------


def test_timezone_token_is_not_read_as_am_pm():
    """Regression: "Tuesday at 2:30 ET" used to be booked at 02:30."""
    slots = extract_text_slots("Tuesday at 2:30 ET works for me", MONDAY_8AM, ET)
    assert len(slots) == 1
    assert slots[0].start.hour == 14
    assert slots[0].start.minute == 30


def test_explicit_pm_is_respected():
    slots = extract_text_slots("How about Wednesday at 4:00 PM?", MONDAY_8AM, ET)
    assert slots[0].start.hour == 16


def test_explicit_am_is_respected():
    slots = extract_text_slots("Thursday at 10:00 AM suits", MONDAY_8AM, ET)
    assert slots[0].start.hour == 10


def test_midnight_and_noon_convert_correctly():
    assert extract_text_slots("Tuesday at 12:00 PM", MONDAY_8AM, ET)[0].start.hour == 12
    assert extract_text_slots("Tuesday at 12:30 AM", MONDAY_8AM, ET)[0].start.hour == 0


def test_bare_afternoon_hour_is_assumed_pm():
    slots = extract_text_slots("Tuesday at 3 works", MONDAY_8AM, ET)
    assert slots[0].start.hour == 15


def test_pacific_time_is_converted_to_local():
    slots = extract_text_slots("Tuesday at 9:00 AM PT", MONDAY_8AM, ET)
    assert slots[0].start.astimezone(ET).hour == 12


def test_text_slots_are_tagged_as_untrusted():
    slots = extract_text_slots("Tuesday at 2:30 PM", MONDAY_8AM, ET)
    assert slots[0].source == "text"


def test_text_slots_are_always_in_the_future():
    slots = extract_text_slots("Monday at 9:30 AM", MONDAY_8AM.replace(hour=14), ET)
    assert all(s.start > MONDAY_8AM.replace(hour=14) for s in slots)


def test_nonsense_times_are_dropped():
    assert extract_text_slots("Tuesday at 99:99", MONDAY_8AM, ET) == []


# ---------- hidden slot payloads (F-04) ----------


def test_offered_slots_come_only_from_hidden_payloads():
    html = (
        '<p>Tuesday at 4:00 PM would be great</p>'
        '<!-- data: {"start": "2026-03-03T14:00:00-05:00", "duration": 45} -->'
    )
    slots = parse_offered_slots(html, ET)
    assert len(slots) == 1
    assert slots[0].duration_minutes == 45
    assert slots[0].start.hour == 14  # not the 4pm written in prose


def test_span_payloads_are_also_read():
    html = '<span style="display:none;">SLOT_DATA:{"start": "2026-03-03T14:00:00-05:00", "duration": 30}</span>'
    assert len(parse_offered_slots(html, ET)) == 1


def test_duplicate_payloads_are_collapsed():
    payload = '{"start": "2026-03-03T14:00:00-05:00", "duration": 30}'
    html = f"<!-- data: {payload} --><span>SLOT_DATA:{payload}</span>"
    assert len(parse_offered_slots(html, ET)) == 1


def test_malformed_payloads_do_not_raise():
    assert parse_offered_slots("<!-- data: {not json} -->", ET) == []
    assert parse_offered_slots("<!-- data: {\"start\": \"nope\"} -->", ET) == []


# ---------- confirmation matching (F-09) ----------


def test_match_returns_the_offered_slot_not_the_parsed_time():
    offered = [Slot(at(1, 14, 0), 30)]
    match = match_confirmed_slot(offered, at(1, 14, 4), tolerance_minutes=5)
    assert match is not None
    assert match.start == at(1, 14, 0)  # the offered time, not 14:04
    assert match.duration_minutes == 30


def test_match_rejects_times_outside_the_tolerance():
    offered = [Slot(at(1, 14, 0), 30)]
    assert match_confirmed_slot(offered, at(1, 14, 30), tolerance_minutes=5) is None


def test_match_picks_the_closest_of_several_offers():
    offered = [Slot(at(1, 14, 0), 30), Slot(at(1, 14, 8), 60)]
    match = match_confirmed_slot(offered, at(1, 14, 7), tolerance_minutes=10)
    assert match.start == at(1, 14, 8)


def test_match_on_empty_offers_is_none():
    assert match_confirmed_slot([], at(1, 14, 0)) is None


# ---------- working hours guard ----------


def test_slot_outside_working_hours_is_rejected():
    assert not within_working_hours(Slot(at(0, 7, 0), 30), POLICY)
    assert not within_working_hours(Slot(at(0, 17, 45), 30), POLICY)  # would end 18:15


def test_weekend_slot_is_rejected():
    assert not within_working_hours(Slot(at(5, 10, 0), 30), POLICY)


def test_slot_inside_working_hours_is_accepted():
    assert within_working_hours(Slot(at(0, 10, 0), 30), POLICY)


# ---------- preference coercion (F-12) ----------


def test_list_day_preference_is_accepted():
    assert normalise_preferences({"day_preference": ["tuesday"]}).day_preference == "tuesday"


def test_dict_day_preference_does_not_raise():
    """Regression: .lower() on a dict used to raise AttributeError mid-request."""
    assert normalise_preferences({"day_preference": {"day": "monday"}}).day_preference == "monday"


@pytest.mark.parametrize("junk", [42, None, True, [], {}, "", "someday"])
def test_junk_day_preference_becomes_none(junk):
    assert normalise_preferences({"day_preference": junk}).day_preference is None


def test_non_dict_payload_is_survivable():
    assert normalise_preferences("not a dict").duration_minutes == 30
    assert normalise_preferences(None).duration_minutes == 30


@pytest.mark.parametrize("raw,expected", [("45", 45), (45, 45), (45.9, 45), ("45 minutes", 45)])
def test_duration_is_coerced(raw, expected):
    assert normalise_preferences({"duration": raw}).duration_minutes == expected


@pytest.mark.parametrize("raw", [0, -5, 10000, "abc", None])
def test_implausible_duration_falls_back_to_the_default(raw):
    assert normalise_preferences({"duration": raw}, 30).duration_minutes == 30


def test_start_date_is_parsed():
    assert normalise_preferences({"start_date": "2026-08-05"}).start_date.day == 5


def test_invalid_start_date_is_ignored():
    assert normalise_preferences({"start_date": "August 5th"}).start_date is None
    assert normalise_preferences({"start_date": "2026-13-45"}).start_date is None


def test_saturday_preference_is_kept_not_silently_dropped():
    assert normalise_preferences({"day_preference": "saturday"}).day_preference == "saturday"


def test_specific_time_survives_coercion_and_still_parses():
    """Coercion lowercases; an ISO timestamp must still round-trip through dateutil."""
    from dateutil import parser as dtparser

    iso = datetime(2026, 3, 3, 14, 0, tzinfo=ET).isoformat()
    prefs = normalise_preferences({"specific_time": iso})
    assert dtparser.parse(prefs.specific_time) == datetime(2026, 3, 3, 14, 0, tzinfo=ET)


# ---------- timezone resolution ----------


@pytest.mark.parametrize("hint,expected", [
    ("Europe/Paris", "Europe/Paris"),
    ("Paris", "Europe/Paris"),
    ("PT", "America/Los_Angeles"),
    ("london", "Europe/London"),
])
def test_timezone_hints_resolve(hint, expected):
    assert str(resolve_timezone(hint, ET)) == expected


def test_unknown_timezone_falls_back():
    assert str(resolve_timezone("Narnia", ET)) == "America/New_York"
    assert str(resolve_timezone(None, ET)) == "America/New_York"


# ---------- subject handling (F-21) ----------


def test_reply_prefixes_are_stripped_only_from_the_front():
    assert clean_subject("Re: Re: Sync re: Re: budget") == "Re: Sync re: Re: budget"


def test_interior_re_is_preserved():
    assert base_subject("Re: Sync re: budget") == "Sync re: budget"


@pytest.mark.parametrize("subject", ["RE: Chat", "re:Chat", "Fwd: Chat", "FW: Chat", "Chat"])
def test_all_prefix_spellings_normalise(subject):
    assert clean_subject(subject) == "Re: Chat"


def test_empty_subject_gets_a_placeholder():
    assert clean_subject("") == "Re: Meeting"
