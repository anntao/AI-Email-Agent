"""Google Calendar reads and writes."""

import logging
from datetime import datetime, timedelta
from typing import Iterable

from .scheduling import Interval, Slot

log = logging.getLogger(__name__)


def get_busy(calendar, calendar_id: str, start: datetime, end: datetime) -> list[Interval]:
    """Return busy intervals via freebusy.

    freebusy is a better fit than events().list: it honours events marked as
    free/transparent and all-day events without the caller having to special-case
    date-only entries, which the previous implementation simply skipped.
    """
    response = (
        calendar.freebusy()
        .query(
            body={
                "timeMin": start.isoformat(),
                "timeMax": end.isoformat(),
                "items": [{"id": calendar_id}],
            }
        )
        .execute()
    )
    calendars = response.get("calendars", {})
    entry = calendars.get(calendar_id) or next(iter(calendars.values()), {})

    for error in entry.get("errors", []):
        log.warning("freebusy error for %s: %s", calendar_id, error)

    intervals: list[Interval] = []
    for period in entry.get("busy", []):
        try:
            intervals.append(
                Interval(
                    datetime.fromisoformat(period["start"].replace("Z", "+00:00")),
                    datetime.fromisoformat(period["end"].replace("Z", "+00:00")),
                )
            )
        except (KeyError, ValueError) as exc:
            log.warning("Skipping unparsable busy period %s: %s", period, exc)
    return intervals


def is_slot_free(calendar, calendar_id: str, slot: Slot) -> bool:
    """Re-check a single slot immediately before booking it.

    Slots are offered and confirmed minutes or days apart, and nothing previously
    re-checked the calendar in between, so a slot the owner had since filled was
    double-booked without complaint.
    """
    padding = timedelta(minutes=1)
    busy = get_busy(calendar, calendar_id, slot.start - padding, slot.end + padding)
    return not any(interval.overlaps(slot.start, slot.end) for interval in busy)


def create_event(
    calendar,
    calendar_id: str,
    *,
    summary: str,
    slot: Slot,
    attendees: Iterable[str],
    timezone_name: str,
    description: str = "",
) -> dict:
    event = {
        "summary": summary,
        "description": description,
        "start": {"dateTime": slot.start.isoformat(), "timeZone": timezone_name},
        "end": {"dateTime": slot.end.isoformat(), "timeZone": timezone_name},
        "attendees": [{"email": email} for email in sorted(set(attendees))],
        "reminders": {"useDefault": True},
    }
    created = calendar.events().insert(
        calendarId=calendar_id, body=event, sendUpdates="all"
    ).execute()
    log.info("Created event %s at %s", created.get("id"), slot.start.isoformat())
    return created
