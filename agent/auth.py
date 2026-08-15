"""OAuth credentials, refreshed at most once per process and persisted only on change."""

import json
import logging
import threading
from typing import Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from . import secrets
from .config import SCOPES, TOKEN_SECRET_ID

log = logging.getLogger(__name__)

_creds: Optional[Credentials] = None
_lock = threading.Lock()


def _serialise(creds: Credentials) -> str:
    return json.dumps(
        {
            "token": creds.token,
            "refresh_token": creds.refresh_token,
            "token_uri": creds.token_uri,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "scopes": list(creds.scopes or SCOPES),
        },
        sort_keys=True,
    )


def get_credentials(project_id: str) -> Credentials:
    """Return valid credentials, refreshing and persisting them only when needed.

    The previous implementation authenticated twice per request and wrote a new
    Secret Manager version on every refresh, so versions accumulated under load.
    Credentials are cached for the life of the container and the secret is
    rewritten only when the serialised token actually changes.
    """
    global _creds

    with _lock:
        if _creds is not None and _creds.valid:
            return _creds

        if _creds is None:
            raw = secrets.get_secret(project_id, TOKEN_SECRET_ID, required=True)
            _creds = Credentials.from_authorized_user_info(json.loads(raw), SCOPES)

        if _creds.valid:
            return _creds

        if not _creds.refresh_token:
            raise RuntimeError(
                f"Stored credentials have no refresh token. Re-run generate_token.py "
                f"and add a new version of {TOKEN_SECRET_ID}."
            )

        before = _serialise(_creds)
        _creds.refresh(Request())
        after = _serialise(_creds)

        if after != before:
            try:
                name = secrets.add_secret_version(project_id, TOKEN_SECRET_ID, after)
                log.info("Persisted refreshed token as %s", name)
            except Exception as exc:  # noqa: BLE001 - refresh still valid this run
                log.warning("Refreshed token could not be persisted: %s", exc)

        return _creds


def build_services(project_id: str):
    """Return (gmail, calendar) clients built from a single credential fetch."""
    creds = get_credentials(project_id)
    gmail = build("gmail", "v1", credentials=creds, cache_discovery=False)
    calendar = build("calendar", "v3", credentials=creds, cache_discovery=False)
    return gmail, calendar


def reset() -> None:
    """Drop cached credentials. Used by tests."""
    global _creds
    _creds = None
