"""Firestore-backed state: message claims, the history cursor, watch expiry, rate limits.

The critical change from the previous design is *when* a message is recorded as
handled. It used to be written before any work happened, keyed on the Pub/Sub
historyId, so a transient failure during calendar or Gmail calls left a marker
that made every redelivery a no-op — the meeting was never booked and nobody was
told. Here a message is *claimed* first and only *completed* once the work
succeeds; a failed run releases the claim so redelivery retries it.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from google.cloud import firestore

log = logging.getLogger(__name__)

CLAIMS = "message_claims"
CURSOR = "gmail_cursor"
WATCH = "gmail_watch"
RATE = "sender_rate"

STATUS_PROCESSING = "processing"
STATUS_DONE = "done"
STATUS_FAILED = "failed"


@dataclass
class Store:
    db: firestore.Client
    stale_claim_seconds: int = 600

    # ---------- message claims ----------

    def claim_message(self, message_id: str) -> bool:
        """Atomically claim a message for processing.

        Returns False when another run already holds or completed it. A claim
        left in 'processing' longer than stale_claim_seconds is reclaimed, which
        recovers from an instance that died mid-request.
        """
        doc_ref = self.db.collection(CLAIMS).document(message_id)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.stale_claim_seconds)

        @firestore.transactional
        def txn(transaction):
            snapshot = doc_ref.get(transaction=transaction)
            if snapshot.exists:
                data = snapshot.to_dict() or {}
                status = data.get("status")
                if status in (STATUS_DONE, STATUS_FAILED):
                    return False
                claimed_at = data.get("claimed_at")
                if claimed_at and claimed_at > cutoff:
                    return False
                log.warning("Reclaiming stale claim for message %s", message_id)
            transaction.set(
                doc_ref,
                {"status": STATUS_PROCESSING, "claimed_at": datetime.now(timezone.utc)},
            )
            return True

        return txn(self.db.transaction())

    def complete_message(self, message_id: str, outcome: str) -> None:
        self.db.collection(CLAIMS).document(message_id).set(
            {
                "status": STATUS_DONE,
                "outcome": outcome,
                "finished_at": firestore.SERVER_TIMESTAMP,
            }
        )

    def fail_message(self, message_id: str, error: str) -> None:
        """Mark a message as permanently failed so redelivery does not retry it."""
        self.db.collection(CLAIMS).document(message_id).set(
            {
                "status": STATUS_FAILED,
                "error": error[:1500],
                "finished_at": firestore.SERVER_TIMESTAMP,
            }
        )

    def release_message(self, message_id: str) -> None:
        """Drop the claim so a Pub/Sub redelivery can retry this message."""
        try:
            self.db.collection(CLAIMS).document(message_id).delete()
        except Exception as exc:  # noqa: BLE001 - stale claim expiry is the backstop
            log.warning("Could not release claim for %s: %s", message_id, exc)

    # ---------- history cursor ----------

    def get_cursor(self) -> Optional[str]:
        doc = self.db.collection(CURSOR).document("history").get()
        if not doc.exists:
            return None
        value = (doc.to_dict() or {}).get("history_id")
        return str(value) if value is not None else None

    def set_cursor(self, history_id: str) -> None:
        self.db.collection(CURSOR).document("history").set(
            {"history_id": str(history_id), "updated_at": firestore.SERVER_TIMESTAMP}
        )

    def advance_cursor(self, history_id: str) -> None:
        """Move the cursor forward only, so out-of-order deliveries cannot rewind it."""
        current = self.get_cursor()
        try:
            if current is not None and int(history_id) <= int(current):
                return
        except (TypeError, ValueError):
            pass
        self.set_cursor(history_id)

    # ---------- gmail watch ----------

    def get_watch_expiration(self) -> Optional[int]:
        doc = self.db.collection(WATCH).document("expiration").get()
        if not doc.exists:
            return None
        value = (doc.to_dict() or {}).get("expiration")
        return int(value) if value else None

    def set_watch_expiration(self, expiration_ms: int) -> None:
        self.db.collection(WATCH).document("expiration").set(
            {"expiration": int(expiration_ms), "updated_at": firestore.SERVER_TIMESTAMP}
        )

    # ---------- per-sender rate limit ----------

    def check_rate_limit(self, sender: str, limit: int) -> bool:
        """Count one request for this sender in the current hour.

        Returns False once the sender exceeds `limit` requests within the hour,
        which bounds how fast an outsider can probe the owner's availability.
        """
        if limit <= 0:
            return True
        bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H")
        doc_ref = self.db.collection(RATE).document(f"{sender}|{bucket}")

        @firestore.transactional
        def txn(transaction):
            snapshot = doc_ref.get(transaction=transaction)
            count = (snapshot.to_dict() or {}).get("count", 0) if snapshot.exists else 0
            if count >= limit:
                return False
            transaction.set(
                doc_ref,
                {"count": count + 1, "updated_at": datetime.now(timezone.utc)},
            )
            return True

        try:
            return txn(self.db.transaction())
        except Exception as exc:  # noqa: BLE001 - never block scheduling on the limiter
            log.warning("Rate limit check failed for %s: %s", sender, exc)
            return True
