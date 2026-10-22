# NETRA local sensor forwarding and hosted ingestion

This is a backend stage only. The local sensor continues to use the existing V2
Scapy and Random Forest pipeline. Forwarding is disabled unless explicitly
enabled, and this repository does not configure or deploy a Render service.

## Local storage and PostgreSQL

SQLite remains the default. `NETRA_EVENT_BACKEND` accepts `sqlite` (default) or
`postgresql`. PostgreSQL selection requires `DATABASE_URL`; missing credentials
fail during backend selection, and an unavailable `psycopg` package is reported
when the selected repository is first used. Neither case switches to SQLite.
The application initializes the event schema on the first repository operation.
Schema version 2 adds the forwarding outbox; an existing SQLite schema version 1
is upgraded transactionally with `CREATE TABLE IF NOT EXISTS`, preserving all
event rows. PostgreSQL uses a version table and a transaction-scoped advisory
lock for concurrent initialization. There is no destructive migration.

The PostgreSQL adapter uses Psycopg 3 with its packaged binary extra so local
Windows development does not require a separately installed `libpq` client.
The dependency is declared in `requirements.txt`; it was not installed in the
active environment. To install it locally, after review run:

```powershell
.\.venv\Scripts\python.exe -m pip install "psycopg[binary]==3.3.6"
```

For local tests, keep `NETRA_EVENT_BACKEND=sqlite`. Unit tests need no PostgreSQL
server or database credentials.

## Authenticated ingestion API

The receiving endpoint is `POST /api/v1/sensor/events`. The body must be JSON of
the form `{"events": [...]}` and contain 1–100 events. Total request size is
limited to 256 KiB. Every event is validated against event schema version 1,
including UUID, timezone-aware ISO-8601 timestamp, origin, type, classification,
and JSON metadata. Raw packet payloads, client SQL, and file paths are not part
of the accepted contract; metadata keys are restricted to the measurements and
error descriptors emitted by the current sensor. A batch is stored in one transaction; a repeated ID
with identical content is acknowledged as a duplicate, while an ID reused with
different content rejects the whole batch.

Set `NETRA_SENSOR_API_KEY` to the same random value on the receiving backend and
the sensor. Generate a value with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

The endpoint accepts only `Authorization: Bearer <key>` and compares the token
in constant time. It never logs request headers or event data. Missing server
configuration returns 503; missing or incorrect credentials return 401. A
per-process limit of 60 authenticated requests per minute per client address,
along with the body and batch limits, provides basic abuse control. For a
multi-worker or multi-instance deployment, configure a shared rate limit at the
trusted ingress/proxy; the in-process counter is not shared between workers.

The hosted service must be published behind HTTPS with HTTP redirected or
rejected at the Render edge. The sensor refuses non-HTTPS forwarding destinations
except localhost/loopback. Do not put database credentials or the SQLite file on
the sensor; only the ingestion URL and dedicated sensor key are used.

## Optional durable forwarding

Forwarding is disabled by default. On the local sensor, configure:

```dotenv
NETRA_EVENT_BACKEND=sqlite
NETRA_FORWARDING_ENABLED=true
NETRA_INGESTION_URL=https://your-service.example/api/v1/sensor/events
NETRA_SENSOR_API_KEY=<same random key configured by the receiver>
NETRA_FORWARD_TIMEOUT_SECONDS=5
NETRA_FORWARD_BATCH_SIZE=100
NETRA_FORWARD_OUTBOX_MAX_EVENTS=10000
```

The detector's existing bounded writer first commits events into local SQLite.
When forwarding is enabled, that same transaction also inserts an immutable copy
into `forwarding_outbox`. A separate daemon worker claims bounded batches with a
lease, posts them outside detector and packet-processing locks, and deletes rows
only after a 2xx response. Stable event UUIDs make retry after an ambiguous
network timeout safe at the receiver. SQLite leases coordinate multiple local
workers that share the same database file. The outbox is capped at 10,000 rows
by default; configure `NETRA_FORWARD_OUTBOX_MAX_EVENTS` from 1 to 100,000. When
full, the event/outbox transaction fails and the existing writer reports the
failure instead of allowing unbounded disk growth.

Network failures, HTTP 408/429, and server errors are retried with exponential
backoff, capped at 256 seconds, for up to eight attempts. Permanent client errors
(other 4xx), redirects, or exhausted retries leave the outbox rows in a blocked
state for operator review; they are not silently deleted. Logs include only an
exception class or HTTP status, never the key, request body, or response body.
The outbox is deliberately excluded from event retention cleanup. Monitor
`SQLiteEventRepository.outbox_counts()` and inspect blocked IDs/reasons with
`list_blocked_outbox()`. After correcting the receiver/configuration, an operator
can explicitly retry selected IDs with `requeue_blocked_outbox(event_ids)`. This
is at-least-once delivery attempt with server-side
deduplication, not a guarantee that every event will reach the receiver: the
pre-database bounded detector queue may still reject events under saturation,
and a permanently rejected batch requires operator action.

The forwarding client sends every locally persisted event type and origin. The
receiver stores `live`, `pcap`, and `simulation` records as tagged; it does not
convert PCAP or simulation traffic into live events or trigger email alerts.

## Verification without secrets or cloud services

Tests use temporary SQLite databases, fake HTTP sessions, and Flask's test
client. They do not contact a production endpoint and do not need a configured
sensor key, PostgreSQL server, or Render credentials. Do not set forwarding to
true in a normal local `.env` unless you have intentionally configured a test or
development receiver.
