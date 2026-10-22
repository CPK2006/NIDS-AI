# NETRA V2 event history

NETRA records a small, local event history in SQLite. The store is accessed through the `EventRepository` protocol in `v2/event_store.py`; `SQLiteEventRepository` is the local implementation. A future hosted repository can implement the same methods without placing SQL in the detector.

## Event contract, version 1

Each event contains:

| Field | Meaning |
| --- | --- |
| `event_id` | UUID generated before enqueueing; duplicate writes with identical content are idempotent. Reusing an ID for different content is an error. |
| `schema_version` | Event contract version, currently `1`. |
| `occurred_at_utc` | Timezone-aware ISO-8601 time normalized to UTC with a `Z` suffix. |
| `origin` | Exactly one of `live`, `pcap`, or `simulation`, assigned from the capture mode or simulator source. |
| `session_id` | UUID identifying the capture run or simulation batch; may be null for manually constructed flows without a source session. |
| `event_type` | `flow_classification`, `alert`, `capture_error`, or `processing_error`. |
| `classification` | `BENIGN` or `ATTACK` for flow classifications; `ATTACK` for alerts; null for operational errors. |
| `metadata` | JSON object containing only supported measurements or error context. |

Successful flow predictions create one `flow_classification` event with packet count, byte count, protocol, and confidence percentage. ATTACK predictions also create an `alert` event; the first event is the classification record, while the second records the attack alert occurrence. Dashboard alert cooldown aggregation remains in memory and is not a reportable event counter. No event is written per packet: packet counts are measured on the flow and stored with its classification. Raw payloads, IP addresses, and ports are not stored in this initial schema.

Capture and inference failures create separate operational error events with the known origin/session and error phase/type. Error messages, packet contents, and local file paths are omitted from persisted metadata.

## Storage and threading

`SQLiteEventRepository` uses SQLite `PRAGMA user_version` (currently schema version 4), parameterized statements, a transaction per write/prune operation, and a connection per operation. Version 3 adds the isolated critical email outbox; version 4 adds a separate weekly report delivery outbox. Neither migration rewrites event rows or sensor forwarding state. Queries are streamed in batches and use the half-open UTC interval `[start_time, end_time)`. Timestamp, origin/time, and event-type/time indexes support reporting queries.

Detector threads use a bounded, nonblocking `EventWriteQueue` (default capacity 1024). A dedicated daemon worker performs repository I/O. If the queue is full, the event is rejected and the writer failure counter is incremented; if a write fails, the failure count and last error are retained and an error is logged. The detector does not treat either case as successful persistence, and capture continues. No database operation is made while the detector state lock is held.

The default database is `data/netra_events.sqlite3`. `NETRA_EVENT_DB_PATH` can select a different path; a relative path is resolved from the project root. Set it in the process environment or `.env` before the first event is written. `NETRA_EVENT_RETENTION_DAYS` defaults to 30.

## Retention and reporting queries

Call `SQLiteEventRepository.prune_expired()` explicitly; this implementation does not start a scheduler. It deletes only rows whose UTC timestamp is strictly earlier than the calculated `now - retention_days` cutoff. Calling it repeatedly is safe. It only deletes from `events`; it does not delete forwarding outbox rows or critical email audit records. Email alert storage and operator retry are documented in [`EMAIL_ALERTS.md`](EMAIL_ALERTS.md).

Use `iter_events(start_time, end_time, origins=..., event_types=...)` with timezone-aware datetimes. The start is inclusive and the end is exclusive. The first stored event marks the beginning of available history; NETRA does not backfill records from earlier runs or claim that a partial collection period is complete.

The V2 dashboard's Historical Traffic Trends view queries stored events through
`EventRepository.aggregate_events`; it does not derive history from in-memory
dashboard counters. The supported windows are 1h, 6h, 24h, 7d, and 30d, with
bucket sizes from one minute to one hour and a maximum of 1000 returned
buckets. Times are UTC. `origin=live` is the default; PCAP replay and simulation
events are shown only when their origin is selected, or when `origin=all` is
explicitly requested. Flow, benign, attack, packet, and byte counts are based
only on `flow_classification` events; alert and operational event counts are
separate to avoid counting an ATTACK flow twice as a flow.

Top Talkers is currently unavailable by design. The version 1 event contract
does not store endpoint IP addresses or ports, and NETRA does not infer endpoint
identities from protocol or other metadata. Adding that feature would require
an explicit event-schema change and a privacy decision about retaining network
identifiers. No raw packet payloads are stored or needed for these trends.

Critical-state email alerts use a separate live-session policy and are not part
of the ordinary classification or event-history stream. Weekly email reports
summarize persisted event records by origin; their interval, outbox, and limits
are documented in [`WEEKLY_REPORTS.md`](WEEKLY_REPORTS.md). See
[`EMAIL_ALERTS.md`](EMAIL_ALERTS.md) for thresholds, Resend settings, retry
behavior, and delivery limitations.

## Hosted storage and sensor forwarding

`PostgreSQLEventRepository` implements the same event query, append, and retention
contract as SQLite. Select it explicitly with `NETRA_EVENT_BACKEND=postgresql`
and `DATABASE_URL`; missing configuration never falls back to SQLite. The
versioned schema is initialized lazily and transactionally. The ingestion route
and optional durable sensor outbox are documented in
[`LOCAL_SENSOR_INGESTION.md`](LOCAL_SENSOR_INGESTION.md).

SQLite remains the default. Forwarding is disabled by default and the sensor
outbox is stored separately from event rows, so regular event retention never
deletes pending or blocked deliveries. The detector's in-memory handoff remains
bounded; saturation is reported and is not durable until the event is committed
to SQLite.
