"""Runtime settings, assembled once per process from env vars and Secret Manager."""

import os
import threading
from dataclasses import dataclass, field
from datetime import time as dtime
from typing import Optional
from zoneinfo import ZoneInfo

from . import secrets

# gmail.modify covers reading messages and toggling labels; gmail.send covers
# replying. Neither permits permanent deletion, unlike the previous
# https://mail.google.com/ grant. calendar.events + calendar.readonly cover
# freebusy queries and event creation.
SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar.readonly",
]

TOKEN_SECRET_ID = "agent-token-json"


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_time(name: str, default: str) -> dtime:
    raw = (os.environ.get(name) or default).strip()
    hour, _, minute = raw.partition(":")
    return dtime(int(hour), int(minute or 0))


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_allowlist(raw: Optional[str]) -> frozenset[str]:
    """Split an allowlist secret into normalised entries.

    Accepts commas, semicolons or whitespace as separators. Entries are either
    full addresses ("sam@example.com") or domains ("@example.com").
    """
    if not raw:
        return frozenset()
    tokens = raw.replace(",", " ").replace(";", " ").split()
    return frozenset(t.strip().lower() for t in tokens if t.strip())


@dataclass(frozen=True)
class Settings:
    project_id: str
    agent_email: str
    owner_email: str
    owner_name: str
    gemini_api_key: Optional[str]
    allowed_senders: frozenset[str] = field(default_factory=frozenset)

    timezone: ZoneInfo = ZoneInfo("America/New_York")
    timezone_label: str = "ET"
    work_start: dtime = dtime(9, 30)
    work_end: dtime = dtime(18, 0)

    model: str = "gemini-3.7-flash"
    pubsub_topic: str = "gmail-new-email"

    search_horizon_days: int = 14
    max_days_offered: int = 3
    slots_per_day: int = 3
    default_duration_minutes: int = 30
    slot_step_minutes: int = 30
    confirm_tolerance_minutes: int = 5

    max_thread_chars: int = 20000
    max_messages_per_notification: int = 10
    sender_hourly_limit: int = 12
    stale_claim_seconds: int = 600

    @property
    def tzname(self) -> str:
        return str(self.timezone)


_settings: Optional[Settings] = None
_lock = threading.Lock()


def load(project_id: str) -> Settings:
    """Build Settings for the given project, memoised per process."""
    global _settings
    if _settings is not None and _settings.project_id == project_id:
        return _settings

    with _lock:
        if _settings is not None and _settings.project_id == project_id:
            return _settings

        tz_name = os.environ.get("AGENT_TIMEZONE", "America/New_York")
        api_key = os.environ.get("GEMINI_API_KEY") or secrets.get_secret(
            project_id, "gemini-api-key"
        )

        _settings = Settings(
            project_id=project_id,
            agent_email=(secrets.get_secret(project_id, "agent-email", required=True) or "").lower(),
            owner_email=(secrets.get_secret(project_id, "owner-email", required=True) or "").lower(),
            owner_name=secrets.get_secret(project_id, "owner-name") or "the owner",
            gemini_api_key=api_key,
            allowed_senders=parse_allowlist(secrets.get_secret(project_id, "allowed-senders")),
            timezone=ZoneInfo(tz_name),
            timezone_label=os.environ.get("AGENT_TIMEZONE_LABEL", "ET"),
            work_start=_env_time("WORK_START", "09:30"),
            work_end=_env_time("WORK_END", "18:00"),
            model=os.environ.get("GEMINI_MODEL", "gemini-3.7-flash"),
            pubsub_topic=os.environ.get("GMAIL_PUBSUB_TOPIC", "gmail-new-email"),
            search_horizon_days=_env_int("SEARCH_HORIZON_DAYS", 14),
            max_days_offered=_env_int("MAX_DAYS_OFFERED", 3),
            slots_per_day=_env_int("SLOTS_PER_DAY", 3),
            default_duration_minutes=_env_int("DEFAULT_DURATION_MINUTES", 30),
            max_thread_chars=_env_int("MAX_THREAD_CHARS", 20000),
            max_messages_per_notification=_env_int("MAX_MESSAGES_PER_NOTIFICATION", 10),
            sender_hourly_limit=_env_int("SENDER_HOURLY_LIMIT", 12),
        )
        return _settings


def reset() -> None:
    """Drop memoised settings. Used by tests."""
    global _settings
    _settings = None


def debug_enabled() -> bool:
    return _env_flag("FLASK_DEBUG")
