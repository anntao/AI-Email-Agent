"""Cached access to Secret Manager.

Secrets are read on nearly every request, so values are memoised per process for
SECRET_TTL_SECONDS. Cloud Run reuses instances, which makes this the difference
between one Secret Manager call per container and several per email.
"""

import logging
import threading
import time
from typing import Optional

from google.cloud import secretmanager

log = logging.getLogger(__name__)

SECRET_TTL_SECONDS = 300

_client: Optional[secretmanager.SecretManagerServiceClient] = None
_client_lock = threading.Lock()
_cache: dict[str, tuple[float, Optional[str]]] = {}
_cache_lock = threading.Lock()


def client() -> secretmanager.SecretManagerServiceClient:
    """Return the process-wide Secret Manager client, building it on first use."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = secretmanager.SecretManagerServiceClient()
    return _client


def get_secret(project_id: str, secret_id: str, *, required: bool = False) -> Optional[str]:
    """Read the latest version of a secret, or None if it is missing.

    Raises RuntimeError when required=True and the secret cannot be read, so a
    misconfigured deployment fails at startup rather than midway through an email.
    """
    key = f"{project_id}/{secret_id}"
    now = time.monotonic()

    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < SECRET_TTL_SECONDS:
            value = hit[1]
            if value is None and required:
                raise RuntimeError(f"Required secret {secret_id!r} is not available")
            return value

    value: Optional[str] = None
    try:
        name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
        response = client().access_secret_version(request={"name": name})
        value = response.payload.data.decode("UTF-8").strip()
    except Exception as exc:  # noqa: BLE001 - surface as None/RuntimeError below
        log.warning("Could not read secret %s: %s", secret_id, exc)

    with _cache_lock:
        _cache[key] = (now, value)

    if value is None and required:
        raise RuntimeError(f"Required secret {secret_id!r} is not available")
    return value


def add_secret_version(project_id: str, secret_id: str, payload: str) -> str:
    """Write a new version of a secret and refresh the local cache."""
    parent = f"projects/{project_id}/secrets/{secret_id}"
    version = client().add_secret_version(
        request={"parent": parent, "payload": {"data": payload.encode("UTF-8")}}
    )
    with _cache_lock:
        _cache[f"{project_id}/{secret_id}"] = (time.monotonic(), payload)
    return version.name


def clear_cache() -> None:
    """Drop memoised secrets. Used by tests."""
    with _cache_lock:
        _cache.clear()
