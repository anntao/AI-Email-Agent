# AI Email Agent

An assistant you CC into an email thread. It reads the thread, offers times from
the owner's Google Calendar, and books the meeting once someone picks one.

Runs on Cloud Run, triggered by Gmail push notifications over Pub/Sub.

```
Gmail ──watch──▶ Pub/Sub topic ──push──▶ Cloud Run (this service)
                                              │
                       ┌──────────────────────┼──────────────────────┐
                       ▼                      ▼                      ▼
                 Gmail History API      Gemini (intent)       Calendar freebusy
                       │                      │                      │
                       └──────────────────────┴──────────────────────┘
                                              ▼
                                   reply + calendar invite

Firestore holds: the history cursor, per-message claims, the watch expiry,
and per-sender rate counters.
```

## How it decides to act

A message is acted on only when all of these hold:

1. The agent's address is in **To or Cc** — being named in a forwarded body is not
   an invitation.
2. The owner is a **genuine parsed participant** of the thread.
3. The sender passes the **allowlist**, if the `allowed-senders` secret exists.
4. The sender is under the **hourly rate limit**.

Anything else is left alone entirely — not replied to, not marked read.

## Intents

| Intent | Meaning | What happens |
| --- | --- | --- |
| `INITIAL_REQUEST` | Someone wants to meet | Offers up to 3 slots/day across 3 days |
| `CONFIRMATION` | A specific time is accepted | Re-checks freebusy, then books |
| `DAY_CONFIRMATION` | A day is accepted, no time | Books the earliest offered slot that day |
| `OTHER` | Still negotiating | Offers alternatives |
| `IGNORE` | Thread moved past scheduling | Stays silent |

Offered slots are carried in the message body as hidden JSON, so a later reply can
be matched against what was actually offered without a database of pending
proposals. **Only those hidden payloads authorise a booking.** A time written in
prose (say, by another assistant) is treated as a proposal: it must fall inside
working hours and pass a live freebusy check before anything is created.

## Setup

### 1. Google Cloud

```bash
PROJECT=your-project
gcloud config set project $PROJECT

gcloud services enable \
  run.googleapis.com gmail.googleapis.com calendar-json.googleapis.com \
  pubsub.googleapis.com secretmanager.googleapis.com firestore.googleapis.com \
  generativelanguage.googleapis.com

gcloud firestore databases create --location=nam5
```

### 2. Pub/Sub

```bash
gcloud pubsub topics create gmail-new-email

# Let Gmail publish to the topic
gcloud pubsub topics add-iam-policy-binding gmail-new-email \
  --member=serviceAccount:gmail-api-push@system.gserviceaccount.com \
  --role=roles/pubsub.publisher
```

### 3. Secrets

Four secrets are required, one optional:

| Secret | Required | Contents |
| --- | --- | --- |
| `agent-token-json` | yes | OAuth token JSON from `generate_token.py` |
| `agent-email` | yes | The agent account's address |
| `owner-email` | yes | The calendar owner's address |
| `owner-name` | yes | Display name used in signatures |
| `allowed-senders` | no | Addresses and/or `@domains`, comma or space separated |
| `gemini-api-key` | no | Alternative to the `GEMINI_API_KEY` env var |

```bash
for s in agent-token-json agent-email owner-email owner-name; do
  gcloud secrets create $s --replication-policy=automatic
done
printf 'assistant@example.com' | gcloud secrets versions add agent-email --data-file=-
```

Without `allowed-senders`, anyone who emails the agent and CCs the owner can see
the owner's free/busy times. Set it if that is not what you want:

```bash
printf '@yourcompany.com, trusted@partner.com' | \
  gcloud secrets versions add allowed-senders --data-file=-
```

### 4. OAuth token

Sign in as the **agent** account. The calendar owner must have shared their
calendar with the agent account with "Make changes to events".

```bash
pip install -r requirements.txt
python generate_token.py --project $PROJECT
```

Scopes requested — narrower than the original `https://mail.google.com/`, which
allowed permanent deletion:

- `gmail.modify` — read messages, toggle labels
- `gmail.send` — reply in-thread
- `calendar.events` — create events
- `calendar.readonly` — freebusy queries

### 5. Deploy

```bash
gcloud run deploy email-agent \
  --source . \
  --region us-central1 \
  --no-allow-unauthenticated \
  --set-env-vars GEMINI_API_KEY=...,AGENT_TIMEZONE=America/New_York
```

Grant the runtime service account `roles/secretmanager.secretAccessor`,
`roles/secretmanager.secretVersionAdder` (it writes back refreshed tokens) and
`roles/datastore.user`.

### 6. Authenticated push

The service verifies the OIDC token on every `POST /` and `POST /ping`, so both
callers must send one.

```bash
SA=email-agent-invoker@$PROJECT.iam.gserviceaccount.com
URL=$(gcloud run services describe email-agent --region us-central1 --format='value(status.url)')

gcloud iam service-accounts create email-agent-invoker
gcloud run services add-iam-policy-binding email-agent \
  --region us-central1 --member=serviceAccount:$SA --role=roles/run.invoker

gcloud pubsub subscriptions create gmail-push \
  --topic gmail-new-email \
  --push-endpoint="$URL/" \
  --push-auth-service-account=$SA

gcloud scheduler jobs create http renew-gmail-watch \
  --schedule='0 6 * * *' --uri="$URL/ping" --http-method=POST \
  --oidc-service-account-email=$SA
```

Then set `PUSH_SERVICE_ACCOUNT=$SA` so the service rejects anyone else.

### 7. Start the watch

```bash
curl -X POST -H "Authorization: Bearer $(gcloud auth print-identity-token)" "$URL/ping"
```

This also seeds the Gmail history cursor. The watch expires after seven days;
the daily Cloud Scheduler job renews it.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | — | Gemini API key |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Model for intent classification |
| `AGENT_TIMEZONE` | `America/New_York` | IANA timezone for all scheduling |
| `AGENT_TIMEZONE_LABEL` | `ET` | Label shown in emails |
| `WORK_START` / `WORK_END` | `09:30` / `18:00` | Working day bounds |
| `SEARCH_HORIZON_DAYS` | `14` | How far ahead to look |
| `MAX_DAYS_OFFERED` | `3` | Distinct days per proposal |
| `SLOTS_PER_DAY` | `3` | Slots per day |
| `DEFAULT_DURATION_MINUTES` | `30` | Used when none is stated |
| `MAX_THREAD_CHARS` | `20000` | Cap on text sent to the model |
| `SENDER_HOURLY_LIMIT` | `12` | Requests per sender per hour |
| `PUSH_SERVICE_ACCOUNT` | — | Required caller identity for POST routes |
| `PUSH_AUDIENCE` | — | Expected OIDC audience, if you set one |
| `ALLOW_UNAUTHENTICATED_PUSH` | unset | Escape hatch; logs a warning. Do not leave on |
| `GMAIL_PUBSUB_TOPIC` | `gmail-new-email` | Topic short name |
| `LOG_LEVEL` | `INFO` | Python log level |

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
```

The tests cover slot arithmetic, address parsing, MIME handling and the
orchestration ordering. They make no network calls, so they run offline in well
under a second.

Layout:

| File | Responsibility |
| --- | --- |
| `main.py` | Flask routes, OIDC verification |
| `agent/handler.py` | Orchestration and intent dispatch |
| `agent/scheduling.py` | Slot arithmetic (pure, no I/O) |
| `agent/addresses.py` | Address parsing, authorisation |
| `agent/mailbox.py` | Gmail History API, MIME, sending |
| `agent/calendar_ops.py` | freebusy and event creation |
| `agent/intent.py` | Gemini classification |
| `agent/compose.py` | Email templates |
| `agent/store.py` | Firestore state |
| `agent/auth.py` | OAuth credentials |
| `agent/config.py` | Settings |

## Operational notes

- **Failure handling.** A message is claimed before work starts and recorded as
  done only after it succeeds. A transient failure releases the claim and returns
  500 so Pub/Sub redelivers; a permanent failure is recorded so it is not retried
  forever. A claim stuck in `processing` for over 10 minutes is reclaimed.
- **The history cursor** lives at `gmail_cursor/history` in Firestore. If Gmail
  reports it as too old (over a week), the service resets it to the current
  notification and logs a warning rather than guessing at a backlog.
- **Cost.** One Gemini call per acted-on message. Thread text is capped and
  quoted history is stripped, so a long negotiation does not grow without bound.
- **Firestore cleanup.** `message_claims` and `sender_rate` grow slowly. Add a TTL
  policy on `claimed_at` / `updated_at` if you want them pruned automatically.
