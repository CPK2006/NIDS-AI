# NetGuard reference review and NETRA changes

The reference reviewed was [AegisNet-Netguard_AI](https://github.com/Hari-Padmesh/AegisNet-Netguard_AI). Its code contains a core SDK, request middleware/integrations, an HTTP rule engine, embedded and separate dashboards, alert managers, and optional email/webhook notifiers. The rules inspect middleware-visible paths and query strings and count request/status patterns; they do not inspect arbitrary Scapy traffic. The separate/embedded Starlette dashboard uses Basic Auth or a bearer key, and the FastAPI integration exposes an authenticated health route. The repository also contains a legacy Flask extension whose dashboard/API routes do not apply that auth helper, despite the README's authenticated-dashboard claim. Rule cooldowns suppress repeated alert dispatch while retaining event records and suppression counts. Tests exist for core rule cooldowns, config authentication, dashboard auth, integrations, and persistent project-scoped storage; these are repository tests, not independent production verification. The repository includes an MIT license. NETRA adapts ideas only and does not copy source code.

| Capability | Decision | Reason |
| --- | --- | --- |
| Dashboard authentication | Implemented | V2 dashboards and `/api/v2/*` endpoints use environment-configured Basic Auth. With no credentials, loopback development remains available and remote access is rejected. NETRA applies the protection consistently to all V2 routes, including capture controls and interface/status reads. |
| Alert cooldown / deduplication | Implemented | Repeated ML alerts with the same endpoints, ports, protocol, and label aggregate within a configurable cooldown. Each flow still contributes to classification counters and rolling threat level; the alert retains first and latest timestamps, occurrence count, and accumulated packet/byte evidence. |
| Operational health | Implemented | V2 status now exposes model availability, capture and inference timestamps, capture/processing error counts, and alert-processing status. The dashboard displays model and recent activity health. |
| Optional HTTP rules | Deferred | NETRA's Scapy capture has no HTTP request integration. Applying HTTP rules to arbitrary packet payloads would be misleading and unsafe. A separate, opt-in HTTP integration can be considered if NETRA later instruments an HTTP application. |
| Central dashboard | Deferred | NetGuard's separate dashboard persists project-scoped events in SQLite and supports authenticated ingestion and telemetry. NETRA currently has a single local engine; central persistence requires a separate deployment and retention design. |
| Email/webhook notifications | Deferred | The reference supports SMTP/Resend, generic/Slack webhooks, and weekly digest scheduling. These need external credentials, delivery/retry behavior, and operational tests beyond this local dashboard update. |
| Automatic blocking | Rejected | NetGuard has opt-in IP block controls in some integrations. NETRA's capture engine has no safe enforcement point, and automatic response would add risk outside this monitoring task. |

## Configuration

Set `NETRA_AUTH_USERNAME` and `NETRA_AUTH_PASSWORD` together to protect the V2 dashboard and API. Keep credentials in the environment or a secret manager. Without both values, only loopback clients can use V2. Remote deployments should terminate TLS at a trusted reverse proxy. Set `NETRA_ALERT_COOLDOWN_SECONDS` to adjust aggregation; `0` disables it. See `.env.example`.

Inference exceptions are now reported as processing errors and do not create a benign alert. This prevents an unavailable or malfunctioning model from appearing to have cleared a flow. Successful predictions and the existing feature schema remain unchanged.

No reference code was reused, so preserving its MIT notices in NETRA was not necessary. The reference was cloned to a temporary directory for read-only source inspection; that checkout is outside the NETRA workspace. NETRA's V2 feature schema, model, and successful prediction behavior remain unchanged.
