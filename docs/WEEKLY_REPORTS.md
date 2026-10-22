# NETRA weekly monitoring report

`v2.weekly_report.WeeklyReportService` builds a concise email from persisted
event history through the `EventRepository` interface. It does not read
dashboard HTML or in-memory status counters, and report generation does not
invoke or alter the critical-state policy.

## Interval and target schedule

The reporting interval is seven full days, start inclusive and end exclusive.
The stable weekly boundary is Monday 09:00 `Asia/Kolkata` (03:30 UTC). The
helper `weekly_reporting_interval(now)` selects the latest such boundary at or
before `now`; the report covers the preceding seven days. Both timestamps in
the report are explicit UTC values. The interval can be supplied directly to
`WeeklyReportService.generate(start_time, end_time, generated_at=...)` for
repeatable tests or other callers.

The target schedule is Monday at 09:00 `Asia/Kolkata` (03:30 UTC). Scheduling
is intentionally external and separate from report-generation logic. NETRA
does not create a cron job, scheduler, hosted service, or cloud resource.

## Content and availability

Events are summarized separately for `live`, `pcap`, and `simulation`. Each
origin includes persisted event counts by type, successful flow classification
counts, and BENIGN/ATTACK classification counts. Persisted packet totals are
included only when every classification in that origin and interval has a
valid `packet_count` field; otherwise the total is marked unavailable. They
describe recorded per-flow values and do not imply capture completeness. No
Top Talkers, IP addresses, ports, payloads, or inferred network-wide packet
totals are included.

Persisted critical email incidents are counted from the dedicated critical
outbox for the same occurrence interval, split by their current delivered,
pending/retrying, or permanently failed state. This diagnostic is disclosed as
unavailable if the critical-alert store cannot be queried. Event history query
failure is separately disclosed; empty persisted history is reported as zero
stored records and is not a completeness guarantee. Reports are limited to
records that NETRA retained. The normal event retention period is 30 days, so
older records are not backfilled. Critical-alert outcomes cover records written
to the durable outbox; incidents from before that outbox existed cannot be
reconstructed and are not represented as a guaranteed zero.

## Configuration and callable entry point

Weekly delivery is disabled by default. Add values to the process environment
or `.env`; placeholders are in `.env.example`:

```dotenv
NETRA_WEEKLY_REPORT_ENABLED=true
NETRA_WEEKLY_REPORT_TO_EMAIL=weekly-security@example.com
RESEND_API_KEY=
RESEND_FROM_EMAIL=
NETRA_EMAIL_TIMEOUT_SECONDS=5
NETRA_EMAIL_MAX_ATTEMPTS=4
NETRA_DELIVERY_BACKEND=sqlite
NETRA_WEEKLY_REPORT_DB_PATH=
```

Weekly reports have their own enable flag and recipient. They reuse the existing
Resend API key and sender but do not depend on `NETRA_EMAIL_ALERTS_ENABLED` or
`RESEND_TO_EMAIL`. If report delivery is disabled or incomplete,
`generate()` and tests still work and no request is sent. A scheduled caller can
invoke `WeeklyReportService.run_previous_week()`; the callable local entry point
is `python -m v2.weekly_report`. That command only sends when weekly reporting
is enabled and configuration is valid.

## Durable delivery and idempotency

Delivery records live in the separate `weekly_report_outbox` table. For local
sensor operation it uses SQLite and by default shares the event/critical-alert
database; `NETRA_WEEKLY_REPORT_DB_PATH` can select a separate file. Hosted
`report_job`, `hosted_worker`, and `hosted_web` roles require
`NETRA_DELIVERY_BACKEND=postgresql` and use the same PostgreSQL database as
event history. `report_job` additionally requires
`NETRA_EVENT_BACKEND=postgresql`. The tables are separate from classification
events, sensor forwarding records, and critical incidents. Local sensor
critical-alert records remain local by default and are not forwarded to
PostgreSQL; hosted reports count only incidents explicitly written to the
shared PostgreSQL outbox.

The report UUID is deterministic for the exact UTC interval. The first rendered
report body and intended recipient are persisted before delivery. Repeated
scheduled calls for the same interval reuse that record and do not regenerate
or resend a delivered report. An SQLite transaction or PostgreSQL `FOR UPDATE SKIP LOCKED` lease prevents
concurrent scheduled callers from sending the same report at once. Every Resend attempt uses the
same report UUID as its `Idempotency-Key`. Retryable network and HTTP 408, 429,
or 5xx errors receive bounded retries and persisted retry timing; other HTTP
errors remain inspectable as permanently failed. Each callable scheduled run
also resumes due pending reports left by an earlier interrupted run. Diagnostics retain only a
safe exception category or HTTP status, never credentials, headers, response
bodies, or exception text.

Provider idempotency reduces duplicates if Resend accepted a report before a
process crash, subject to Resend's idempotency behavior and retention period.
Exactly-once external delivery is not guaranteed. A stored report may remain
pending during outages, missing configuration, or storage failure. The
outbox's report body and recipient are persisted data; protect SQLite files
and restrict hosted database access. `NETRA_DELIVERY_AUDIT_RETENTION_DAYS`
defaults to 3650 days (`0` disables cleanup). The explicit
`prune_delivery_records()` operation deletes only old delivered critical-alert
records in bounded batches. Pending, retryable, and permanently failed records
remain. Weekly report rows remain as interval idempotency records;
event retention does not delete delivery records.

For a hosted report job, set `NETRA_RUNTIME_ROLE=report_job`,
`NETRA_EVENT_BACKEND=postgresql`, `NETRA_DELIVERY_BACKEND=postgresql`, and the
shared `DATABASE_URL`, then invoke `python -m v2.weekly_report`. Scheduling is
external. Operators can explicitly requeue failed report IDs using the
authenticated hosted endpoint `POST /api/v2/weekly-reports/retry`; delivery
occurs on a later scheduled report-job run. Existing SQLite outboxes are not migrated automatically; see
[`EMAIL_ALERTS.md`](EMAIL_ALERTS.md) for migration and rollback details.

## Testing

Weekly report tests use mock HTTP sessions and do not contact Resend. They cover
interval boundaries, origin separation, empty and unavailable history, metric
availability, deterministic IDs, configuration handling, retry outcomes, and
duplicate suppression.
