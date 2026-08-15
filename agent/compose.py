"""Email bodies the agent sends.

These are deterministic templates. The previous version built a prompt, called
Gemini, assigned the result to email_body_text and then sent a hardcoded
template anyway — two paid model calls per email whose output was discarded.
"""

from html import escape
from typing import Iterable, Optional
from zoneinfo import ZoneInfo

from .scheduling import Slot, group_by_day

STYLE_LIST = "margin:10px 0; padding-left:20px;"
STYLE_ITEM = "margin:5px 0;"


def _clock(moment) -> str:
    """12-hour clock without a leading zero, portably (%-I is not on all platforms)."""
    return f"{(moment.hour % 12) or 12}:{moment.minute:02d} {moment.strftime('%p')}"


def _format_time(slot: Slot, tz: ZoneInfo, label: str, alt_tz: Optional[ZoneInfo] = None) -> str:
    text = f"{_clock(slot.start.astimezone(tz))} {label}"
    if alt_tz is not None and str(alt_tz) != str(tz):
        other = slot.start.astimezone(alt_tz)
        city = str(alt_tz).rsplit("/", 1)[-1].replace("_", " ")
        text = f"{_clock(other)} {city} / {text}"
    return text


def _format_day(slot: Slot, tz: ZoneInfo) -> str:
    local = slot.start.astimezone(tz)
    return f"{local.strftime('%A, %B')} {local.day}"


def signature(owner_name: str, agent_name: str) -> str:
    return (
        "<div style='margin-top:32px; margin-bottom:8px; "
        "border-top:1px solid #e0e0e0;'></div>"
        "<div style='color:#222; font-size:13px; font-family:sans-serif; margin-top:8px;'>"
        f"<strong>{escape(agent_name)}</strong><br>"
        f"<span style='color:#888;'>on behalf of {escape(owner_name)}</span>"
        "</div>"
    )


def slots_html(slots: Iterable[Slot], tz: ZoneInfo, label: str, alt_tz: Optional[ZoneInfo] = None) -> str:
    parts: list[str] = []
    for _, day_slots in sorted(group_by_day(slots, tz).items()):
        parts.append(f"<p><strong>{escape(_format_day(day_slots[0], tz))}:</strong></p>")
        parts.append(f"<ul style='{STYLE_LIST}'>")
        for slot in day_slots:
            parts.append(
                f"<li style='{STYLE_ITEM}'>{escape(_format_time(slot, tz, label, alt_tz))}</li>"
            )
        parts.append("</ul>")
    return "".join(parts)


def hidden_slot_data(slots: Iterable[Slot]) -> str:
    """Machine-readable copy of every offered slot, carried in the message body.

    This is what lets a later reply be matched against what was actually offered
    without a database of pending proposals.
    """
    parts: list[str] = []
    for slot in slots:
        payload = slot.to_payload()
        parts.append(f"<!-- data: {payload} -->")
        parts.append(f'<span style="display:none;">SLOT_DATA:{payload}</span>')
    return "\n".join(parts)


def proposal_email(
    *,
    slots: list[Slot],
    duration_minutes: int,
    owner_name: str,
    agent_name: str,
    tz: ZoneInfo,
    tz_label: str,
    alt_tz: Optional[ZoneInfo] = None,
    alternative: bool = False,
) -> str:
    lead = (
        f"Here are some other times that work for a {duration_minutes}-minute meeting:"
        if alternative
        else f"Happy to get this booked. Here are some times for a {duration_minutes}-minute meeting:"
    )
    return (
        "<html><body>"
        f"<p>Hi,<br><br>{escape(lead)}</p>"
        f"{slots_html(slots, tz, tz_label, alt_tz)}"
        "<p>Let me know which one suits and I'll send the invite.</p>"
        f"{hidden_slot_data(slots)}"
        f"{signature(owner_name, agent_name)}"
        "</body></html>"
    )


def confirmation_email(
    *,
    slot: Slot,
    owner_name: str,
    agent_name: str,
    tz: ZoneInfo,
    tz_label: str,
) -> str:
    when = f"{_format_day(slot, tz)} at {_format_time(slot, tz, tz_label)}"
    return (
        "<html><body>"
        f"<p>Hi,<br><br>That's booked — {slot.duration_minutes} minutes on {escape(when)}.<br><br>"
        "A calendar invite is on its way to everyone on this thread.</p>"
        f"{signature(owner_name, agent_name)}"
        "</body></html>"
    )


def no_availability_email(
    *,
    owner_name: str,
    agent_name: str,
    horizon_days: int,
) -> str:
    return (
        "<html><body>"
        f"<p>Hi,<br><br>I couldn't find an open slot in {escape(owner_name)}'s calendar "
        f"in the next {horizon_days} days that matches what you asked for.<br><br>"
        "If you let me know a wider range of days or times, I'll take another look.</p>"
        f"{signature(owner_name, agent_name)}"
        "</body></html>"
    )


def slot_taken_email(
    *,
    slot: Slot,
    owner_name: str,
    agent_name: str,
    tz: ZoneInfo,
    tz_label: str,
    alternatives: list[Slot],
) -> str:
    when = f"{_format_day(slot, tz)} at {_format_time(slot, tz, tz_label)}"
    body = (
        "<html><body>"
        f"<p>Hi,<br><br>Apologies — {escape(when)} was taken before I could book it.</p>"
    )
    if alternatives:
        body += "<p>These are still open:</p>"
        body += slots_html(alternatives, tz, tz_label)
        body += "<p>Let me know which one works and I'll send the invite.</p>"
        body += hidden_slot_data(alternatives)
    else:
        body += "<p>Let me know some times that suit you and I'll check again.</p>"
    return body + signature(owner_name, agent_name) + "</body></html>"
