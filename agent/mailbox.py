"""Gmail access: enumerating new messages via the History API, reading them, replying."""

import base64
import html as html_lib
import logging
import re
from dataclasses import dataclass, field
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from googleapiclient.errors import HttpError

log = logging.getLogger(__name__)

AGENT_HEADER = "X-Agent-Processed"

_TAG_RE = re.compile(r"<[^>]+>")
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_SCRIPT_RE = re.compile(r"<(script|style)\b.*?</\1>", re.DOTALL | re.IGNORECASE)
_WS_RE = re.compile(r"[ \t]+")
_BLANKS_RE = re.compile(r"\n{3,}")

# Where a mail client starts quoting the message being replied to.
_QUOTE_MARKERS = (
    re.compile(r"^On .{0,200}\bwrote:\s*$", re.IGNORECASE),
    re.compile(r"^-{2,}\s*Original Message\s*-{2,}\s*$", re.IGNORECASE),
    re.compile(r"^_{5,}\s*$"),
    re.compile(r"^From:\s.+$", re.IGNORECASE),
    re.compile(r"^Sent from my \w+", re.IGNORECASE),
)


class HistoryCursorExpired(Exception):
    """Raised when Gmail no longer has history back to the stored cursor."""


@dataclass
class ParsedMessage:
    id: str
    thread_id: str
    headers: dict[str, str]
    text: str
    html: str
    label_ids: tuple[str, ...] = field(default_factory=tuple)

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    @property
    def is_agent_sent(self) -> bool:
        return self.header(AGENT_HEADER).strip().lower() == "true"


# ---------- reading ----------


def current_history_id(gmail) -> str:
    """Return the mailbox's current historyId, used to seed the cursor."""
    profile = gmail.users().getProfile(userId="me").execute()
    return str(profile["historyId"])


def list_new_message_ids(gmail, start_history_id: str, limit: int = 10) -> tuple[list[str], str]:
    """Return message IDs added since start_history_id, plus the new cursor.

    This replaces the previous `messages().list(q='is:unread', maxResults=1)`,
    which returned whichever message happened to be newest-unread rather than the
    ones the notification was actually about.
    """
    ids: list[str] = []
    latest = str(start_history_id)
    page_token = None

    while True:
        try:
            response = (
                gmail.users()
                .history()
                .list(
                    userId="me",
                    startHistoryId=start_history_id,
                    historyTypes=["messageAdded"],
                    labelId="INBOX",
                    pageToken=page_token,
                    maxResults=500,
                )
                .execute()
            )
        except HttpError as exc:
            if exc.resp.status == 404:
                raise HistoryCursorExpired(str(start_history_id)) from exc
            raise

        for record in response.get("history", []):
            for added in record.get("messagesAdded", []):
                message = added.get("message", {})
                labels = set(message.get("labelIds", []))
                if labels & {"DRAFT", "SENT", "TRASH", "SPAM"}:
                    continue
                message_id = message.get("id")
                if message_id and message_id not in ids:
                    ids.append(message_id)

        latest = str(response.get("historyId", latest))
        page_token = response.get("nextPageToken")
        if not page_token or len(ids) >= limit:
            break

    return ids[:limit], latest


def get_message(gmail, message_id: str) -> ParsedMessage:
    raw = gmail.users().messages().get(userId="me", id=message_id, format="full").execute()
    payload = raw.get("payload", {})
    headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
    text, html = _collect_parts(payload)
    return ParsedMessage(
        id=raw["id"],
        thread_id=raw.get("threadId", ""),
        headers=headers,
        text=text,
        html=html,
        label_ids=tuple(raw.get("labelIds", [])),
    )


def get_thread(gmail, thread_id: str) -> list[ParsedMessage]:
    raw = gmail.users().threads().get(userId="me", id=thread_id, format="full").execute()
    messages = []
    for item in raw.get("messages", []):
        payload = item.get("payload", {})
        headers = {h["name"].lower(): h["value"] for h in payload.get("headers", [])}
        text, html = _collect_parts(payload)
        messages.append(
            ParsedMessage(
                id=item["id"],
                thread_id=item.get("threadId", thread_id),
                headers=headers,
                text=text,
                html=html,
                label_ids=tuple(item.get("labelIds", [])),
            )
        )
    return messages


def _collect_parts(payload: dict) -> tuple[str, str]:
    """Walk a MIME tree and return (plain_text, html) separately.

    The old implementation concatenated both alternatives into one blob, so every
    message was sent to the model twice over.
    """
    text_parts: list[str] = []
    html_parts: list[str] = []

    def walk(part: dict) -> None:
        mime = (part.get("mimeType") or "").lower()
        if part.get("parts"):
            for child in part["parts"]:
                walk(child)
            return
        data = (part.get("body") or {}).get("data")
        if not data:
            return
        try:
            decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001 - a single bad part must not fail the message
            log.warning("Could not decode message part (%s): %s", mime, exc)
            return
        if mime == "text/html":
            html_parts.append(decoded)
        elif mime.startswith("text/"):
            text_parts.append(decoded)

    walk(payload)
    return "\n".join(text_parts), "\n".join(html_parts)


def html_to_text(html: str) -> str:
    """Flatten HTML to readable text, dropping comments, scripts and tags."""
    if not html:
        return ""
    cleaned = _SCRIPT_RE.sub(" ", html)
    cleaned = _COMMENT_RE.sub(" ", cleaned)
    cleaned = re.sub(r"<br\s*/?>", "\n", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"</(p|div|li|tr|h[1-6])>", "\n", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"<li\b[^>]*>", "\n- ", cleaned, flags=re.IGNORECASE)
    cleaned = _TAG_RE.sub(" ", cleaned)
    cleaned = html_lib.unescape(cleaned)
    cleaned = _WS_RE.sub(" ", cleaned)
    return _BLANKS_RE.sub("\n\n", cleaned).strip()


def strip_quoted(text: str) -> str:
    """Remove quoted history so each message contributes only its new content."""
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if any(marker.match(stripped) for marker in _QUOTE_MARKERS):
            break
        if stripped.startswith(">"):
            continue
        lines.append(line.rstrip())
    return _BLANKS_RE.sub("\n\n", "\n".join(lines)).strip()


def message_body_text(message: ParsedMessage) -> str:
    """Best available plain text for one message, without quoted history."""
    body = message.text.strip() or html_to_text(message.html)
    return strip_quoted(body)


def build_thread_text(messages: list[ParsedMessage], max_chars: int) -> str:
    """Join a thread newest-first and truncate, so token cost stays bounded.

    Previously the whole thread — plain and HTML parts, quoted history included —
    was concatenated on every reply, which grew roughly quadratically with the
    length of the negotiation.
    """
    chunks: list[str] = []
    used = 0
    for message in reversed(messages):
        body = message_body_text(message)
        if not body:
            continue
        sender = message.header("from", "unknown")
        date = message.header("date", "")
        chunk = f"--- From: {sender} ({date}) ---\n{body}"
        if used + len(chunk) > max_chars:
            remaining = max_chars - used
            if remaining > 200:
                chunks.append(chunk[:remaining] + "\n[truncated]")
            break
        chunks.append(chunk)
        used += len(chunk)
    return "\n\n".join(reversed(chunks))


def thread_html(messages: list[ParsedMessage]) -> str:
    """Concatenated HTML across a thread, used to recover the agent's own slot data."""
    return "\n".join(m.html for m in messages if m.html)


# ---------- writing ----------


def mark_read(gmail, message_id: str) -> None:
    gmail.users().messages().modify(
        userId="me", id=message_id, body={"removeLabelIds": ["UNREAD"]}
    ).execute()


def build_reply(
    *,
    sender: str,
    sender_name: str,
    to: str,
    cc: str,
    subject: str,
    html_body: str,
    in_reply_to: Optional[str],
    references: Optional[str],
) -> dict:
    message = MIMEMultipart("alternative")
    message["To"] = to
    message["From"] = f"{sender_name} <{sender}>"
    if cc:
        message["Cc"] = cc
    message["Subject"] = subject
    if in_reply_to:
        message["In-Reply-To"] = in_reply_to
    if references:
        message["References"] = references
    message[AGENT_HEADER] = "true"
    message.attach(MIMEText(html_to_text(html_body), "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))
    return {"raw": base64.urlsafe_b64encode(message.as_bytes()).decode()}


def send(gmail, body: dict, thread_id: Optional[str] = None) -> dict:
    if thread_id:
        body = {**body, "threadId": thread_id}
    return gmail.users().messages().send(userId="me", body=body).execute()
