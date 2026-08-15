"""Slot arithmetic, kept free of network calls so it can be tested directly.

Everything here takes plain data — busy intervals, preferences, a clock — and
returns plain data. That is deliberate: the date and timezone bugs in the
previous version (a timezone token parsed as AM/PM, working hours that were
configured but never applied) were all cheap to catch with a unit test and
impossible to catch without one.
"""

import json
import re
from dataclasses import dataclass
from datetime import date, datetime, time as dtime, timedelta
from typing import Any, Iterable, Optional
from zoneinfo import ZoneInfo

WEEKDAYS = {
    "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
    "friday": 4, "saturday": 5, "sunday": 6,
    "mon": 0, "tue": 1, "tues": 1, "wed": 2, "thu": 3, "thur": 3,
    "thurs": 3, "fri": 4, "sat": 5, "sun": 6,
}

_TZ_TOKENS = {
    "ET": "America/New_York", "EST": "America/New_York", "EDT": "America/New_York",
    "CT": "America/Chicago", "CST": "America/Chicago", "CDT": "America/Chicago",
    "MT": "America/Denver", "MST": "America/Denver", "MDT": "America/Denver",
    "PT": "America/Los_Angeles", "PST": "America/Los_Angeles", "PDT": "America/Los_Angeles",
    "UTC": "UTC", "GMT": "UTC", "BST": "Europe/London", "CET": "Europe/Paris",
    "CEST": "Europe/Paris",
}

CITY_TIMEZONES = {
    "paris": "Europe/Paris", "london": "Europe/London", "new york": "America/New_York",
    "san francisco": "America/Los_Angeles", "los angeles": "America/Los_Angeles",
    "chicago": "America/Chicago", "denver": "America/Denver", "berlin": "Europe/Berlin",
    "madrid": "Europe/Madrid", "tokyo": "Asia/Tokyo", "singapore": "Asia/Singapore",
    "sydney": "Australia/Sydney", "dublin": "Europe/Dublin", "toronto": "America/Toronto",
    "seattle": "America/Los_Angeles", "boston": "America/New_York", "austin": "America/Chicago",
}

# One pattern with *named* groups. The previous implementation nested four time
# patterns inside two day patterns and read AM/PM from a fixed match.group(4),
# so "Tuesday at 2:30 ET" put the timezone token in the AM/PM slot and booked
# 2:30 in the morning.
_TEXT_SLOT_RE = re.compile(
    r"""\b(?P<day>mon|tue|tues|wed|thu|thur|thurs|fri|sat|sun)[a-z]*\b
        (?:[^\n\r]{0,24}?)
        \b(?P<hour>\d{1,2})(?::(?P<minute>\d{2}))?\s*
        (?P<ampm>[ap]\.?\s?m\.?)?
        \s*(?P<tz>[A-Z]{2,4})?\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

_HIDDEN_COMMENT_RE = re.compile(r"<!--\s*data:\s*(\{.*?\})\s*-->", re.DOTALL)
_HIDDEN_SPAN_RE = re.compile(r"SLOT_DATA:\s*(\{.*?\})\s*<", re.DOTALL)
_SUBJECT_PREFIX_RE = re.compile(r"^(?:\s*(?:re|fwd?|fw)\s*:\s*)+", re.IGNORECASE)


@dataclass(frozen=True)
class Interval:
    start: datetime
    end: datetime

    def overlaps(self, other_start: datetime, other_end: datetime) -> bool:
        return max(self.start, other_start) < min(self.end, other_end)


@dataclass(frozen=True)
class Slot:
    start: datetime
    duration_minutes: int
    source: str = "offered"

    @property
    def end(self) -> datetime:
        return self.start + timedelta(minutes=self.duration_minutes)

    def to_payload(self) -> str:
        return json.dumps({"start": self.start.isoformat(), "duration": self.duration_minutes})


@dataclass(frozen=True)
class Preferences:
    duration_minutes: int = 30
    day_preference: Optional[str] = None
    time_of_day: Optional[str] = None
    start_date: Optional[date] = None
    specific_time: Optional[str] = None
    timezone_hint: Optional[str] = None


@dataclass(frozen=True)
class SlotPolicy:
    timezone: ZoneInfo
    work_start: dtime = dtime(9, 30)
    work_end: dtime = dtime(18, 0)
    horizon_days: int = 14
    max_days: int = 3
    per_day: int = 3
    step_minutes: int = 30
    default_duration: int = 30
    lead_minutes: int = 15

    @classmethod
    def from_settings(cls, settings) -> "SlotPolicy":
        return cls(
            timezone=settings.timezone,
            work_start=settings.work_start,
            work_end=settings.work_end,
            horizon_days=settings.search_horizon_days,
            max_days=settings.max_days_offered,
            per_day=settings.slots_per_day,
            step_minutes=settings.slot_step_minutes,
            default_duration=settings.default_duration_minutes,
        )


# ---------- coercion ----------


def as_text(value: Any) -> Optional[str]:
    """Reduce whatever the model returned to a lowercase string, or None.

    The model has been observed returning a list where a string was expected;
    calling .lower() on anything else used to raise AttributeError mid-request.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (list, tuple)):
        return as_text(value[0]) if value else None
    if isinstance(value, dict):
        for key in ("name", "day", "value"):
            if key in value:
                return as_text(value[key])
        return None
    text = str(value).strip().lower()
    return text or None


def as_int(value: Any) -> Optional[int]:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (list, tuple)):
        return as_int(value[0]) if value else None
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        digits = re.search(r"\d+", str(value))
        return int(digits.group()) if digits else None


def as_date(value: Any) -> Optional[date]:
    text = as_text(value)
    if not text:
        return None
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", text)
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def normalise_preferences(raw: Any, default_duration: int = 30) -> Preferences:
    """Turn arbitrary model output into a Preferences value that cannot explode later."""
    if not isinstance(raw, dict):
        return Preferences(duration_minutes=default_duration)

    duration = as_int(raw.get("duration") or raw.get("duration_minutes"))
    if not duration or duration <= 0 or duration > 8 * 60:
        duration = default_duration

    day = as_text(raw.get("day_preference") or raw.get("day"))
    if day is not None:
        day = day.rstrip("s") if day.rstrip("s") in WEEKDAYS else day
        if day not in WEEKDAYS:
            day = None

    time_of_day = as_text(raw.get("time_of_day"))
    if time_of_day not in {"morning", "afternoon", "evening", None}:
        time_of_day = None

    return Preferences(
        duration_minutes=duration,
        day_preference=day,
        time_of_day=time_of_day,
        start_date=as_date(raw.get("start_date")),
        specific_time=as_text(raw.get("specific_time")),
        timezone_hint=as_text(raw.get("time_zone") or raw.get("timezone")),
    )


def resolve_timezone(hint: Optional[str], fallback: ZoneInfo) -> ZoneInfo:
    """Map an IANA name, a US timezone abbreviation or a city name to a ZoneInfo."""
    if not hint:
        return fallback
    hint = hint.strip()
    for candidate in (hint, _TZ_TOKENS.get(hint.upper(), ""), CITY_TIMEZONES.get(hint.lower(), "")):
        if not candidate:
            continue
        try:
            return ZoneInfo(candidate)
        except Exception:  # noqa: BLE001 - fall through to the next candidate
            continue
    return fallback


# ---------- slot search ----------


def _round_up(moment: datetime, step_minutes: int) -> datetime:
    """Round a time up to the next step boundary so offers land on :00 / :30."""
    moment = moment.replace(second=0, microsecond=0)
    remainder = (moment.minute % step_minutes)
    if remainder:
        moment += timedelta(minutes=step_minutes - remainder)
    return moment


def day_periods(day: date, policy: SlotPolicy) -> list[tuple[datetime, datetime]]:
    """Split one working day into morning / early afternoon / late afternoon.

    Bounds come from policy.work_start and policy.work_end. The previous version
    defined WORK_START_HOUR_ET = 9.5 and then hardcoded 9:00 in the search, so it
    offered slots half an hour before the configured start of the day.
    """
    tz = policy.timezone
    start = datetime.combine(day, policy.work_start, tzinfo=tz)
    end = datetime.combine(day, policy.work_end, tzinfo=tz)
    if start >= end:
        return []

    noon = datetime.combine(day, dtime(12, 0), tzinfo=tz)
    three = datetime.combine(day, dtime(15, 0), tzinfo=tz)

    raw = [
        (start, min(noon, end)),
        (max(noon, start), min(three, end)),
        (max(three, start), end),
    ]
    return [(a, b) for a, b in raw if a < b]


def _select_periods(periods: list[tuple[datetime, datetime]], time_of_day: Optional[str]):
    if not periods:
        return []
    if time_of_day == "morning":
        return periods[:1]
    if time_of_day == "afternoon":
        return periods[1:]
    if time_of_day == "evening":
        return periods[-1:]
    return periods


def conflicts(start: datetime, end: datetime, busy: Iterable[Interval]) -> bool:
    return any(interval.overlaps(start, end) for interval in busy)


def find_available_slots(
    busy: Iterable[Interval],
    preferences: Preferences,
    now: datetime,
    policy: SlotPolicy,
) -> list[Slot]:
    """Return the slots to offer, respecting working hours, weekends and busy time."""
    busy = list(busy)
    duration = preferences.duration_minutes or policy.default_duration
    target_weekday = WEEKDAYS.get(preferences.day_preference or "", None)

    now_local = now.astimezone(policy.timezone)
    earliest = _round_up(now_local + timedelta(minutes=policy.lead_minutes), policy.step_minutes)

    first_day = now_local.date()
    if preferences.start_date and preferences.start_date > first_day:
        first_day = preferences.start_date

    slots: list[Slot] = []
    days_used = 0

    for offset in range(policy.horizon_days):
        if days_used >= policy.max_days:
            break
        day = first_day + timedelta(days=offset)
        if day.weekday() >= 5:
            continue
        if target_weekday is not None and day.weekday() != target_weekday:
            continue

        found_today = 0
        for period_start, period_end in _select_periods(
            day_periods(day, policy), preferences.time_of_day
        ):
            if found_today >= policy.per_day:
                break
            cursor = _round_up(max(period_start, earliest), policy.step_minutes)
            while cursor + timedelta(minutes=duration) <= period_end:
                end = cursor + timedelta(minutes=duration)
                if not conflicts(cursor, end, busy):
                    slots.append(Slot(cursor, duration))
                    found_today += 1
                    break
                cursor += timedelta(minutes=policy.step_minutes)

        if found_today:
            days_used += 1

    return slots


# ---------- reading slots back out of a thread ----------


def parse_offered_slots(html: str, tz: ZoneInfo) -> list[Slot]:
    """Recover the slots the agent itself previously offered, from its hidden payloads.

    Only the agent's own machine-readable data counts here. Times written in prose
    are handled separately by extract_text_slots and must pass a live availability
    check before anything is booked.
    """
    found: dict[str, Slot] = {}
    for pattern in (_HIDDEN_COMMENT_RE, _HIDDEN_SPAN_RE):
        for blob in pattern.findall(html or ""):
            try:
                data = json.loads(blob)
                start = datetime.fromisoformat(data["start"])
            except (ValueError, KeyError, TypeError):
                continue
            if start.tzinfo is None:
                start = start.replace(tzinfo=tz)
            duration = as_int(data.get("duration")) or 30
            key = start.astimezone(tz).isoformat()
            found.setdefault(key, Slot(start.astimezone(tz), duration))
    return sorted(found.values(), key=lambda s: s.start)


def _resolve_hour(hour: int, ampm: Optional[str]) -> Optional[int]:
    """Apply an AM/PM marker, or guess sensibly from business hours when absent."""
    if hour > 24 or hour < 0:
        return None
    if ampm:
        meridiem = ampm.replace(".", "").replace(" ", "").lower()
        if hour > 12:
            return None
        if meridiem.startswith("p"):
            return hour if hour == 12 else hour + 12
        return 0 if hour == 12 else hour
    if hour <= 7:
        return hour + 12  # "Tuesday at 3" in a work thread means the afternoon
    return hour


def extract_text_slots(
    text: str,
    now: datetime,
    tz: ZoneInfo,
    default_duration: int = 30,
) -> list[Slot]:
    """Pull "Tuesday at 2:30 ET"-style proposals out of prose.

    Used for agent-to-agent negotiation. Results are tagged source="text" and are
    never treated as pre-approved; the caller re-checks availability first.
    """
    now_local = now.astimezone(tz)
    found: dict[str, Slot] = {}

    for match in _TEXT_SLOT_RE.finditer(text or ""):
        day_token = match.group("day").lower()
        weekday = WEEKDAYS.get(day_token)
        if weekday is None:
            continue

        hour = _resolve_hour(int(match.group("hour")), match.group("ampm"))
        if hour is None or hour > 23:
            continue
        minute = int(match.group("minute") or 0)
        if minute > 59:
            continue

        slot_tz = tz
        token = (match.group("tz") or "").upper()
        if token in _TZ_TOKENS:
            slot_tz = ZoneInfo(_TZ_TOKENS[token])

        ahead = (weekday - now_local.weekday()) % 7
        for extra in (0, 7):
            candidate_date = now_local.date() + timedelta(days=ahead + extra)
            candidate = datetime.combine(candidate_date, dtime(hour, minute), tzinfo=slot_tz)
            if candidate > now_local:
                local = candidate.astimezone(tz)
                found.setdefault(local.isoformat(), Slot(local, default_duration, source="text"))
                break

    return sorted(found.values(), key=lambda s: s.start)


def match_confirmed_slot(
    offered: Iterable[Slot],
    confirmed: datetime,
    tolerance_minutes: int = 5,
) -> Optional[Slot]:
    """Find the offered slot a confirmation refers to.

    Returns the *offered* slot, not the model's reading of it. Booking used to
    use the model's parsed time directly, so a slot offered at 2:00 could be
    booked at 2:04 and still be considered a match.
    """
    best: Optional[Slot] = None
    best_delta = timedelta(minutes=tolerance_minutes)
    for slot in offered:
        delta = abs(slot.start - confirmed)
        if delta <= best_delta:
            best, best_delta = slot, delta
    return best


def within_working_hours(slot: Slot, policy: SlotPolicy) -> bool:
    local = slot.start.astimezone(policy.timezone)
    end = slot.end.astimezone(policy.timezone)
    if local.weekday() >= 5:
        return False
    day_start = datetime.combine(local.date(), policy.work_start, tzinfo=policy.timezone)
    day_end = datetime.combine(local.date(), policy.work_end, tzinfo=policy.timezone)
    return day_start <= local and end <= day_end


def base_subject(subject: str) -> str:
    """The subject with every Re:/Fwd: prefix removed."""
    return _SUBJECT_PREFIX_RE.sub("", (subject or "").strip()) or "Meeting"


def clean_subject(subject: str) -> str:
    """Normalise a reply subject to exactly one "Re: " prefix.

    subject.replace("Re: ", "") was unanchored and global, so it also stripped
    "Re: " from the middle of a subject line.
    """
    return f"Re: {base_subject(subject)}"


def group_by_day(slots: Iterable[Slot], tz: ZoneInfo) -> "dict[date, list[Slot]]":
    grouped: dict[date, list[Slot]] = {}
    for slot in sorted(slots, key=lambda s: s.start):
        grouped.setdefault(slot.start.astimezone(tz).date(), []).append(slot)
    return grouped
