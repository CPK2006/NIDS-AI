# NETRA critical live-state email alerts

NETRA can send an email through Resend when the live detector enters its
critical state. Eligibility is scoped to the trusted UUID of the currently
active live-capture session. PCAP replay, simulation, stale sessions, stored
history, and events received by `POST /api/v1/sensor/events` cannot enqueue an
alert. The policy remains 10 `ATTACK` classifications among the latest 20
successful flow classifications to enter critical; 4 or fewer recovers silently
and re-arms. Recovery never sends an email.

## Configuration

Email is disabled by default. Set these process environment values before
starting NETRA; `.env.example` contains placeholders only:

```dotenv
NETRA_EMAIL_ALERTS_ENABLED=true
RESEND_API_KEY=re_...
RESEND_FROM_EMAIL=NETRA <alerts@your-verified-domain.example>
RESEND_TO_EMAIL=security@example.com
NETRA_EMAIL_TIMEOUT_SECONDS=5
NETRA_EMAIL_MAX_ATTEMPTS=4
# Local SQLite override; empty shares sensor event storage. Hosted roles use
# the explicitly selected shared PostgreSQL backend.
NETRA_DELIVERY_BACKEND=sqlite
NETRA_EMAIL_ALERT_DB_PATH=
```

Resend must permit the sender address/domain. Keep the API key private. Missing
or invalid settings do not stop capture or classification. Eligible incidents
are still durably recorded, and the status reports disabled or not configured;
delivery resumes when a later process starts with valid enabled settings.

## Durable delivery and operator status

The separate `critical_email_outbox` table stores each eligible incident before
it is reported as durably queued. It is logically separate from classification
events and sensor forwarding records. With local SQLite event storage, it
shares the database selected by `NETRA_EVENT_DB_PATH` (default
`data/netra_events.sqlite3`). `NETRA_EMAIL_ALERT_DB_PATH` can select a separate
local file. Set `NETRA_DELIVERY_BACKEND=postgresql` and `DATABASE_URL` to store
delivery state in shared PostgreSQL. The default PostgreSQL connection timeout
is three seconds and is bounded by `NETRA_DATABASE_CONNECT_TIMEOUT_SECONDS`
(1–15 seconds). In shared PostgreSQL sensor mode, incident inserts are staged
on a bounded background worker so the packet callback does not wait on database
I/O. Until an insert commits, status includes `staged_not_persisted`; these
volatile entries are not claimed as durable. The worker makes a bounded number
of attempts per staged entry and keeps a sanitized in-process failure category
visible if persistence exhausts those attempts. An exhausted, unpersisted
entry cannot be recovered after process restart; it was not reported as
durably accepted. Local SQLite persistence retains its existing behavior.

The outbox has `pending`, `retrying`, `delivered`, and `permanently_failed`
states, attempt counters, scheduled retry times, UTC timestamps, and a sanitized
error category or HTTP status. Delivery runs on a daemon worker, outside packet
callbacks, inference, and capture locks. A transaction and expiring lease allow
only one process to claim a record at a time. A restart resumes pending and
retryable records after any active lease expires. The ordinary 30-day event
retention job deletes rows only from `events`; it does not delete email audit
records. Delivery audit cleanup is a separate explicit operation. Weekly report
deliveries use a separate `weekly_report_outbox` table; see
[`WEEKLY_REPORTS.md`](WEEKLY_REPORTS.md).

The authenticated V2 route `GET /api/v2/email-alerts/status` returns aggregate
pending, delivered, and failed counts plus a bounded list of failed alert IDs,
timestamps, attempt counts, and sanitized error codes. It never returns the
recipient address, API key, headers, provider response bodies, or exception
text. `POST /api/v2/email-alerts/retry` accepts an explicit JSON body such as
`{"alert_ids":["<failed-alert-uuid>"]}` and requeues only permanently failed
records. V2's existing loopback/authentication gate protects both routes; remote
access requires configured dashboard credentials. Retrying requires an explicit
operator action.

Retryable network errors and HTTP 408, 429, or 5xx responses use bounded attempts
with timeout and exponential delay. Other non-2xx responses become permanently
failed. Failed records remain inspectable and are never silently dropped.
Logs and API responses expose only safe error categories/status codes.

Each incident UUID is also sent as the Resend `Idempotency-Key` on every attempt.
This protects against the ambiguous case where Resend accepted a request but
NETRA crashed before saving the delivered state, subject to Resend's provider
idempotency support and retention window. Exactly-once external delivery cannot
be guaranteed: if provider idempotency expires or is unavailable, a later retry
could produce a duplicate. Delivery is durable and retried, but successful
delivery cannot be guaranteed during provider outage, permanent rejection,
local storage failure, or disabled/missing configuration.

## Hosted worker, migration, and retention

Run a separate worker with `NETRA_RUNTIME_ROLE=hosted_worker`,
`NETRA_DELIVERY_BACKEND=postgresql`, the shared `DATABASE_URL`, and enabled
Resend settings:

```sh
python -m v2.critical_email_alerts
```

Hosted web processes read shared status and permit authenticated explicit retry;
they never start email workers. Multiple worker processes coordinate through
PostgreSQL row locks with `SKIP LOCKED` and expiring leases. Database
connections have bounded timeouts; storage failures are retried on later
polling cycles, while each alert's provider retries remain finite.

PostgreSQL delivery migrations are idempotent and versioned separately from
event history in `netra_schema_version` (`delivery` component). Existing SQLite
outboxes are never copied, overwritten, or deleted automatically. Rollback
means stopping hosted workers and returning to the retained SQLite
configuration; records created after cutover will not be present in SQLite. A
manual migration requires explicit operator action and must preserve IDs and
Resend idempotency keys.

`NETRA_DELIVERY_AUDIT_RETENTION_DAYS` defaults to 3650 days; `0` disables
cleanup. `prune_delivery_records()` is an explicit bounded operation and only
deletes old delivered critical-alert rows. Pending, retryable, and permanently
failed operator-action-required records are retained. Weekly report outbox
rows are retained because their report IDs are the durable interval
idempotency records. Event-history retention does
not delete delivery audit records; no cleanup scheduler is created here.

## Safe local testing

Unit tests use mocked HTTP sessions and never contact Resend. Keep
`NETRA_EMAIL_ALERTS_ENABLED=false` for ordinary local tests. Simulation and PCAP
replay remain ineligible even if email is enabled. The message contains the
incident ID, capture-session ID, counts, and UTC time; it contains no endpoint
IP addresses, ports, or packet payloads.
