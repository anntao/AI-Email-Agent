"""Cloud Run entrypoint for the email scheduling agent.

Routes:
  POST /       Pub/Sub push target for Gmail notifications
  POST /ping   Cloud Scheduler target that renews the Gmail watch
  GET  /health unauthenticated liveness probe
"""

import base64
import json
import logging
import os
from typing import Optional

import google.auth
from flask import Flask, request
from google.auth.transport import requests as google_requests
from google.cloud import firestore
from google.oauth2 import id_token

from agent import auth, config, handler
from agent.handler import Context, RetryableError
from agent.store import Store

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("agent.main")

app = Flask(__name__)

_project_id: Optional[str] = None
_db: Optional[firestore.Client] = None


def project_id() -> str:
    global _project_id
    if _project_id is None:
        _project_id = os.environ.get("GOOGLE_CLOUD_PROJECT") or google.auth.default()[1]
        if not _project_id:
            raise RuntimeError("Could not determine the Google Cloud project ID")
    return _project_id


def db() -> firestore.Client:
    global _db
    if _db is None:
        _db = firestore.Client(project=project_id())
    return _db


def build_context() -> Context:
    settings = config.load(project_id())
    gmail, calendar = auth.build_services(settings.project_id)
    return Context(
        settings=settings,
        store=Store(db(), stale_claim_seconds=settings.stale_claim_seconds),
        gmail=gmail,
        calendar=calendar,
    )


# ---------- request authentication ----------


def _allow_unauthenticated() -> bool:
    return os.environ.get("ALLOW_UNAUTHENTICATED_PUSH", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def verify_caller() -> Optional[str]:
    """Verify the OIDC token on a push request. Returns an error string, or None if OK.

    Nothing previously authenticated these endpoints; the handler accepted any
    JSON body with a message.data field. Relying on Cloud Run's --no-allow-
    unauthenticated alone leaves no defence if that flag is ever changed, so the
    token is checked here too.
    """
    if _allow_unauthenticated():
        log.warning("ALLOW_UNAUTHENTICATED_PUSH is set; skipping caller verification")
        return None

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return "missing bearer token"

    audience = os.environ.get("PUSH_AUDIENCE") or None
    try:
        claims = id_token.verify_oauth2_token(
            header.split(" ", 1)[1], google_requests.Request(), audience
        )
    except Exception as exc:  # noqa: BLE001 - any failure is a rejection
        return f"invalid token: {exc}"

    expected = os.environ.get("PUSH_SERVICE_ACCOUNT")
    if expected and claims.get("email", "").lower() != expected.lower():
        return f"unexpected caller {claims.get('email')}"
    if expected and not claims.get("email_verified", False):
        return "caller email not verified"

    return None


def extract_history_id(envelope: dict) -> Optional[str]:
    try:
        raw = envelope["message"]["data"]
        payload = json.loads(base64.b64decode(raw).decode("utf-8"))
        return str(payload["historyId"])
    except (KeyError, TypeError, ValueError) as exc:
        log.warning("Could not read historyId from envelope: %s", exc)
        return None


# ---------- routes ----------


@app.route("/", methods=["POST"])
def process_notification():
    error = verify_caller()
    if error:
        log.warning("Rejected push request: %s", error)
        return "Unauthorized", 401

    envelope = request.get_json(silent=True)
    if not isinstance(envelope, dict) or "message" not in envelope:
        return "Not a Pub/Sub push message", 200

    history_id = extract_history_id(envelope)
    if history_id is None:
        # Malformed and unfixable by retrying; ack it so Pub/Sub stops resending.
        return "Malformed notification", 200

    try:
        ctx = build_context()
        outcomes = handler.handle_notification(ctx, history_id)
    except RetryableError as exc:
        log.warning("Retryable failure for historyId %s: %s", history_id, exc)
        return "Retry", 500
    except Exception as exc:  # noqa: BLE001 - unknown failures are worth a retry
        log.exception("Unhandled failure for historyId %s", history_id)
        return f"Error: {type(exc).__name__}", 500

    for outcome in outcomes:
        log.info("Outcome: %s", outcome)
    return json.dumps({"historyId": history_id, "outcomes": outcomes}), 200


@app.route("/ping", methods=["POST"])
def ping():
    error = verify_caller()
    if error:
        log.warning("Rejected ping request: %s", error)
        return "Unauthorized", 401

    try:
        ctx = build_context()
        status = handler.ensure_watch(ctx)
    except Exception as exc:  # noqa: BLE001 - report the failure to Cloud Scheduler
        log.exception("Watch renewal failed")
        return f"Watch renewal failed: {type(exc).__name__}: {exc}", 500

    log.info("Ping: %s", status)
    return status, 200


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


if __name__ == "__main__":
    # debug is off unless FLASK_DEBUG is set. The Werkzeug debugger is remote
    # code execution for anyone who can reach the port, and this binds 0.0.0.0.
    app.run(
        debug=config.debug_enabled(),
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8080)),
    )
