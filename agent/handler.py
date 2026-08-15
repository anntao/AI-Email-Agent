"""Orchestration: turn one Pub/Sub notification into zero or more handled messages.

The shape that matters here is the ordering. A message is claimed, processed,
and only then recorded as done and marked read. A retryable failure releases the
claim so Pub/Sub redelivery genuinely retries it, instead of hitting a marker
that was written before the work and silently returning success.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from zoneinfo import ZoneInfo

from dateutil import parser as dtparser

from . import addresses, calendar_ops, compose, mailbox, scheduling
from .config import Settings
from .intent import Intent, IntentResult, classify
from .mailbox import HistoryCursorExpired, ParsedMessage
from .scheduling import Preferences, Slot, SlotPolicy
from .store import Store

log = logging.getLogger(__name__)


class RetryableError(Exception):
    """A transient failure. The claim is released and Pub/Sub should redeliver."""


@dataclass
class Context:
    settings: Settings
    store: Store
    gmail: object
    calendar: object

    @property
    def policy(self) -> SlotPolicy:
        return SlotPolicy.from_settings(self.settings)

    @property
    def tz(self) -> ZoneInfo:
        return self.settings.timezone

    def now(self) -> datetime:
        return datetime.now(self.tz)

    @property
    def agent_name(self) -> str:
        return f"{self.settings.owner_name}'s AI Assistant"


# ---------- entry point ----------


def handle_notification(ctx: Context, notified_history_id: str) -> list[str]:
    """Process every message added since the stored cursor. Returns per-message outcomes."""
    cursor = ctx.store.get_cursor()

    if cursor is None:
        ctx.store.set_cursor(notified_history_id)
        log.info("No history cursor stored; seeded at %s", notified_history_id)
        return ["bootstrapped history cursor"]

    try:
        message_ids, new_cursor = mailbox.list_new_message_ids(
            ctx.gmail, cursor, limit=ctx.settings.max_messages_per_notification
        )
    except HistoryCursorExpired:
        log.warning("History cursor %s expired; resetting to %s", cursor, notified_history_id)
        ctx.store.set_cursor(notified_history_id)
        return ["history cursor expired, reset"]

    if not message_ids:
        ctx.store.advance_cursor(new_cursor)
        return ["no new messages"]

    outcomes: list[str] = []
    for message_id in message_ids:
        outcomes.append(process_message(ctx, message_id))

    ctx.store.advance_cursor(new_cursor)
    return outcomes


def process_message(ctx: Context, message_id: str) -> str:
    """Claim, process, then record. Raises RetryableError for transient failures."""
    if not ctx.store.claim_message(message_id):
        return f"{message_id}: already handled"

    try:
        outcome, acted = _process(ctx, message_id)
    except RetryableError:
        ctx.store.release_message(message_id)
        raise
    except Exception as exc:  # noqa: BLE001 - permanent failure, do not spin on it
        log.exception("Permanent failure handling %s", message_id)
        ctx.store.fail_message(message_id, f"{type(exc).__name__}: {exc}")
        return f"{message_id}: failed ({type(exc).__name__})"

    ctx.store.complete_message(message_id, outcome)

    # Only messages the agent was legitimately invoked on get touched. Marking
    # every newest-unread message read is how unrelated mail used to disappear.
    if acted:
        try:
            mailbox.mark_read(ctx.gmail, message_id)
        except Exception as exc:  # noqa: BLE001 - cosmetic; the claim prevents reprocessing
            log.warning("Could not mark %s read: %s", message_id, exc)

    return f"{message_id}: {outcome}"


def _process(ctx: Context, message_id: str) -> tuple[str, bool]:
    settings = ctx.settings
    message = mailbox.get_message(ctx.gmail, message_id)

    if message.is_agent_sent:
        return "skipped, agent's own message", False

    auth = addresses.authorize(
        from_header=message.header("from"),
        to_header=message.header("to"),
        cc_header=message.header("cc"),
        agent_email=settings.agent_email,
        owner_email=settings.owner_email,
        allowlist=settings.allowed_senders,
    )
    if not auth.allowed:
        log.info("Not acting on %s: %s", message_id, auth.reason)
        return f"ignored ({auth.reason})", False

    if not ctx.store.check_rate_limit(
        auth.sender, settings.sender_hourly_limit, message_id=message_id
    ):
        log.warning("Rate limit reached for %s", auth.sender)
        # acted=False: leave the message unread so a human can still see it.
        return "ignored (sender rate limit reached)", False

    thread = mailbox.get_thread(ctx.gmail, message.thread_id) if message.thread_id else []
    if not thread:
        thread = [message]

    thread_text = mailbox.build_thread_text(thread, settings.max_thread_chars)
    offered = scheduling.parse_offered_slots(mailbox.thread_html(thread), ctx.tz)
    log.info("Thread %s: %d chars, %d previously offered slots",
             message.thread_id, len(thread_text), len(offered))

    result = classify(
        thread_text,
        ctx.now(),
        api_key=settings.gemini_api_key,
        model=settings.model,
        timezone_name=settings.tzname,
    )
    if result.intent is Intent.ERROR:
        # A misconfigured request (bad schema, retired model, missing key) fails
        # identically on every redelivery, so it must not be retried.
        if not result.retryable:
            raise RuntimeError(f"Intent classification unavailable: {result.error}")
        raise RetryableError(f"Intent classification failed: {result.error}")

    if result.intent is Intent.IGNORE:
        return "ignored (thread is not about scheduling)", True

    if result.intent in (Intent.INITIAL_REQUEST, Intent.OTHER) and not result.data.get(
        "time_of_day"
    ):
        inferred = scheduling.infer_time_of_day(mailbox.message_body_text(message))
        if inferred:
            log.info("Model omitted time_of_day; inferred %r from the message", inferred)
            result.data["time_of_day"] = inferred

    if result.intent is Intent.CONFIRMATION:
        return _handle_confirmation(ctx, message, thread_text, offered, result), True

    if result.intent is Intent.DAY_CONFIRMATION:
        return _handle_day_confirmation(ctx, message, offered, result), True

    return _propose(ctx, message, result, alternative=result.intent is Intent.OTHER), True


# ---------- intent handlers ----------


def _propose(
    ctx: Context,
    message: ParsedMessage,
    result: IntentResult,
    *,
    alternative: bool,
    override: Optional[Preferences] = None,
) -> str:
    settings = ctx.settings
    policy = ctx.policy
    prefs = override or scheduling.normalise_preferences(
        result.data, settings.default_duration_minutes
    )

    alt_tz: Optional[ZoneInfo] = None
    if prefs.timezone_hint:
        candidate = scheduling.resolve_timezone(prefs.timezone_hint, ctx.tz)
        if str(candidate) != str(ctx.tz):
            alt_tz = candidate

    slots = _slots_for(ctx, prefs, alt_tz)

    if not slots:
        html = compose.no_availability_email(
            owner_name=settings.owner_name,
            agent_name=ctx.agent_name,
            horizon_days=policy.horizon_days,
        )
        _reply(ctx, message, html)
        return "no matching availability, told the sender"

    html = compose.proposal_email(
        slots=slots,
        duration_minutes=prefs.duration_minutes,
        owner_name=settings.owner_name,
        agent_name=ctx.agent_name,
        tz=ctx.tz,
        tz_label=settings.timezone_label,
        alt_tz=alt_tz,
        alternative=alternative,
    )
    _reply(ctx, message, html)
    return f"offered {len(slots)} slot(s)"


def _slots_for(ctx: Context, prefs: Preferences, alt_tz: Optional[ZoneInfo]) -> list[Slot]:
    """Slots to offer: an explicitly requested time if it is genuinely free, else a search."""
    policy = ctx.policy
    now = ctx.now()

    if prefs.specific_time:
        requested = _parse_specific_time(prefs, ctx.tz, alt_tz, now)
        if requested is not None:
            slot = Slot(requested, prefs.duration_minutes)
            if (
                slot.start > now
                and scheduling.within_working_hours(slot, policy)
                and calendar_ops.is_slot_free(ctx.calendar, ctx.settings.owner_email, slot)
            ):
                return [slot]
            log.info("Requested time %s is unavailable; searching instead", requested.isoformat())

    window_start = now
    if prefs.start_date:
        candidate = datetime.combine(
            prefs.start_date, datetime.min.time(), tzinfo=ctx.tz
        )
        window_start = max(now, candidate)

    busy = calendar_ops.get_busy(
        ctx.calendar,
        ctx.settings.owner_email,
        window_start - timedelta(hours=1),
        window_start + timedelta(days=policy.horizon_days + 1),
    )
    return scheduling.find_available_slots(busy, prefs, now, policy)


def _parse_specific_time(
    prefs: Preferences, tz: ZoneInfo, alt_tz: Optional[ZoneInfo], now: datetime
) -> Optional[datetime]:
    """Resolve a proposed time to a real datetime.

    The model often returns a bare clock time ("2:00 PM") even when the message
    said "Tuesday at 2pm", because the day travelled in day_preference instead.
    dateutil then fills the date from its default, so the proposal silently
    became *today* — which on a weekend was rejected as outside working hours
    and the stated preference was lost entirely.
    """
    raw = prefs.specific_time
    if not raw:
        return None

    base = now.astimezone(tz).replace(tzinfo=None, second=0, microsecond=0)
    try:
        parsed = dtparser.parse(raw, default=base)
        # Parsing again against a different default reveals whether the string
        # carried a date of its own: if it did, both results agree.
        probe = dtparser.parse(raw, default=base + timedelta(days=1))
    except (ValueError, OverflowError, TypeError) as exc:
        log.info("Could not parse specific_time %r: %s", raw, exc)
        return None

    if parsed.date() != probe.date():
        parsed = parsed.replace(tzinfo=None)
        target = _target_date(prefs, base)
        if target is not None:
            parsed = datetime.combine(target, parsed.time())

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=alt_tz or tz)
    resolved = parsed.astimezone(tz).replace(second=0, microsecond=0)

    # A bare time that has already passed today means the next occurrence.
    if resolved <= now:
        weekday = scheduling.WEEKDAYS.get(prefs.day_preference or "")
        resolved += timedelta(days=7 if weekday is not None else 1)

    return resolved


def _target_date(prefs: Preferences, base: datetime):
    """The date a dateless time refers to, from start_date or a named weekday."""
    if prefs.start_date and prefs.start_date >= base.date():
        return prefs.start_date
    weekday = scheduling.WEEKDAYS.get(prefs.day_preference or "")
    if weekday is None:
        return None
    ahead = (weekday - base.date().weekday()) % 7
    return base.date() + timedelta(days=ahead)


def _handle_confirmation(
    ctx: Context,
    message: ParsedMessage,
    thread_text: str,
    offered: list[Slot],
    result: IntentResult,
) -> str:
    raw = result.data.get("confirmed_start_time_iso")
    confirmed = _parse_confirmed(raw, ctx.tz, ctx.now())
    if confirmed is None:
        log.info("CONFIRMATION without a usable time (%r); proposing instead", raw)
        return _propose(ctx, message, result, alternative=True)

    slot = scheduling.match_confirmed_slot(
        offered, confirmed, ctx.settings.confirm_tolerance_minutes
    )

    if slot is None:
        # Nothing the agent offered matches. The time may have come from another
        # assistant writing in prose, which is a proposal rather than an
        # authorisation, so it has to clear working hours and a live freebusy
        # check before it can be booked.
        candidates = scheduling.extract_text_slots(
            thread_text, ctx.now(), ctx.tz, ctx.settings.default_duration_minutes
        )
        slot = scheduling.match_confirmed_slot(
            candidates, confirmed, ctx.settings.confirm_tolerance_minutes
        )
        if slot is not None and not scheduling.within_working_hours(slot, ctx.policy):
            log.info("Proposed time %s is outside working hours", slot.start.isoformat())
            slot = None

    if slot is None:
        log.info("Confirmed time %s matches no offered slot; proposing alternatives",
                 confirmed.isoformat())
        prefs = scheduling.normalise_preferences(
            {**result.data, "specific_time": confirmed.isoformat()},
            ctx.settings.default_duration_minutes,
        )
        return _propose(ctx, message, result, alternative=True, override=prefs)

    return _book(ctx, message, slot)


def _handle_day_confirmation(
    ctx: Context, message: ParsedMessage, offered: list[Slot], result: IntentResult
) -> str:
    day_name = scheduling.as_text(result.data.get("day_name"))
    weekday = scheduling.WEEKDAYS.get(day_name or "")
    time_of_day = scheduling.as_text(result.data.get("time_of_day"))

    if weekday is None:
        log.info("DAY_CONFIRMATION without a usable day (%r); proposing instead", day_name)
        return _propose(ctx, message, result, alternative=True)

    matching = []
    for slot in offered:
        local = slot.start.astimezone(ctx.tz)
        if local.weekday() != weekday or local < ctx.now():
            continue
        if time_of_day == "morning" and local.hour >= 12:
            continue
        if time_of_day == "afternoon" and local.hour < 12:
            continue
        matching.append(slot)

    if not matching:
        # The day was accepted but nothing offered covers it, so search that day
        # rather than going silent as the previous version did.
        prefs = scheduling.normalise_preferences(
            {**result.data, "day_preference": day_name, "time_of_day": time_of_day},
            ctx.settings.default_duration_minutes,
        )
        return _propose(ctx, message, result, alternative=True, override=prefs)

    return _book(ctx, message, min(matching, key=lambda s: s.start))


def _book(ctx: Context, message: ParsedMessage, slot: Slot) -> str:
    settings = ctx.settings

    if not calendar_ops.is_slot_free(ctx.calendar, settings.owner_email, slot):
        log.info("Slot %s is no longer free", slot.start.isoformat())
        busy = calendar_ops.get_busy(
            ctx.calendar,
            settings.owner_email,
            ctx.now(),
            ctx.now() + timedelta(days=ctx.policy.horizon_days),
        )
        alternatives = scheduling.find_available_slots(
            busy,
            Preferences(duration_minutes=slot.duration_minutes),
            ctx.now(),
            ctx.policy,
        )
        html = compose.slot_taken_email(
            slot=slot,
            owner_name=settings.owner_name,
            agent_name=ctx.agent_name,
            tz=ctx.tz,
            tz_label=settings.timezone_label,
            alternatives=alternatives,
        )
        _reply(ctx, message, html)
        return "slot was taken, offered alternatives"

    attendees = set(
        addresses.parse_addresses(
            message.header("from"), message.header("to"), message.header("cc")
        )
    )
    attendees.discard(settings.agent_email)
    attendees.add(settings.owner_email)

    summary = f"Meeting: {scheduling.base_subject(message.header('subject'))}"
    calendar_ops.create_event(
        ctx.calendar,
        settings.owner_email,
        summary=summary,
        slot=slot,
        attendees=attendees,
        timezone_name=settings.tzname,
        description=f"Scheduled by {ctx.agent_name} from the email thread.",
    )

    html = compose.confirmation_email(
        slot=slot,
        owner_name=settings.owner_name,
        agent_name=ctx.agent_name,
        tz=ctx.tz,
        tz_label=settings.timezone_label,
    )
    _reply(ctx, message, html)
    return f"booked {slot.start.isoformat()} ({slot.source})"


# ---------- helpers ----------


def _parse_confirmed(raw, tz: ZoneInfo, now: datetime) -> Optional[datetime]:
    if not raw or not isinstance(raw, str):
        return None
    try:
        parsed = dtparser.isoparse(raw)
    except (ValueError, TypeError):
        try:
            parsed = dtparser.parse(raw, default=now.replace(tzinfo=None))
        except (ValueError, OverflowError, TypeError):
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed.astimezone(tz)


def _reply(ctx: Context, message: ParsedMessage, html: str) -> None:
    settings = ctx.settings
    to_field, cc_field = addresses.reply_recipients(
        from_header=message.header("from"),
        to_header=message.header("to"),
        cc_header=message.header("cc"),
        agent_email=settings.agent_email,
        owner_email=settings.owner_email,
    )
    if not to_field:
        log.warning("No reply recipient for %s; not sending", message.id)
        return

    message_id_header = message.header("message-id")
    references = " ".join(
        part for part in (message.header("references"), message_id_header) if part
    ).strip()

    body = mailbox.build_reply(
        sender=settings.agent_email,
        sender_name=ctx.agent_name,
        to=to_field,
        cc=cc_field,
        subject=scheduling.clean_subject(message.header("subject")),
        html_body=html,
        in_reply_to=message_id_header,
        references=references,
    )
    mailbox.send(ctx.gmail, body, thread_id=message.thread_id or None)
    log.info("Replied on thread %s to %s (cc %s)", message.thread_id, to_field, cc_field or "-")


# ---------- gmail watch ----------


def ensure_watch(ctx: Context) -> str:
    """Renew the Gmail push subscription when it is close to expiring."""
    expiration = ctx.store.get_watch_expiration()
    now_ms = int(ctx.now().timestamp() * 1000)

    if expiration and expiration > now_ms + 24 * 60 * 60 * 1000:
        return f"watch valid until {expiration}"

    topic = f"projects/{ctx.settings.project_id}/topics/{ctx.settings.pubsub_topic}"
    response = ctx.gmail.users().watch(
        userId="me", body={"topicName": topic, "labelIds": ["INBOX"]}
    ).execute()

    new_expiration = int(response.get("expiration", 0))
    ctx.store.set_watch_expiration(new_expiration)

    # Seed the cursor alongside the watch so the first real notification has
    # somewhere to start from.
    if ctx.store.get_cursor() is None:
        history_id = str(response.get("historyId") or mailbox.current_history_id(ctx.gmail))
        ctx.store.set_cursor(history_id)
        log.info("Seeded history cursor at %s", history_id)

    return f"watch renewed, expires {new_expiration}"
