# NETRA runtime and deployment roles

`NETRA_RUNTIME_ROLE` selects one of four process roles. Its backward-compatible
default is `local_sensor`.

- `local_sensor` runs on the Windows host that can access the capture device. It
  owns Scapy capture, the existing V1/V2 inference pipelines, PCAP replay,
  simulation, local event history, optional HTTPS forwarding, and configurable
  critical email alerts.
- `hosted_web` serves the authenticated dashboard and APIs, receives forwarded
  sensor events, and reads hosted history from PostgreSQL. It does not import
  Scapy or the local detector and does not start capture, forwarding, or email
  workers. Hosted V1 inference downloads the LightGBM model from the private
  Hugging Face repository configured by `HF_MODEL_REPO` (default
  `CPK2006/nids-ai-model-artifacts`) using `HF_TOKEN`. It verifies the model's
  SHA-256 against `model_artifacts.sha256` before deserialization. This does not
  enable V2 live packet capture or sensor-local inference.
- `hosted_worker` runs the critical email outbox worker against shared
  PostgreSQL; it does not run Flask or packet capture.
- `report_job` runs one weekly report from shared PostgreSQL. An external
  scheduler invokes it; NETRA does not create a schedule.

The roles must be deployed as separate processes. `hosted_web` requires
`NETRA_EVENT_BACKEND=postgresql`, `NETRA_DELIVERY_BACKEND=postgresql`,
`DATABASE_URL`, dashboard username/password, and `NETRA_SENSOR_API_KEY`.
`hosted_worker` requires PostgreSQL delivery settings and enabled Resend
configuration. `report_job` requires PostgreSQL event and delivery settings;
Resend settings are required only to send the report. Set secrets in the
process environment or platform secret store, never source control.
`/healthz` is the unauthenticated process health check. `/readyz` additionally
checks repository readiness and returns only sanitized status. Dashboard and
sensor ingestion authentication remain enabled.

## Local Windows sensor

The existing development startup remains valid:

```powershell
$env:NETRA_RUNTIME_ROLE = "local_sensor"
.\.venv\Scripts\python.exe app\app.py
```

Install the pinned local stack and Scapy from a clean Windows checkout with:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-sensor.txt
```

Model files are deliberately ignored by Git (`*.pkl`, `*.joblib`, and
`results/*`). The hosted V1 deployment is configured to retrieve the LightGBM
artifact from the private Hugging Face repository
`CPK2006/nids-ai-model-artifacts` by default. `HF_TOKEN` must be configured in
the deployment environment with read access to that repository; `HF_MODEL_REPO`
can override the repository ID. The hosted loader verifies the V1 file against
the checked-in manifest before deserialization. A matching checksum establishes
byte integrity relative to that manifest, not model provenance, training-run
identity, or release approval. The repository and deployment configuration
alone do not establish that a model owner has approved these binaries for
release.

The current local `model_artifacts.sha256` lists only the three runtime files:
the V2 Random Forest, V1 LightGBM primary, and V1 CatBoost fallback. The
verifier currently succeeds for those local files. This confirms only that the
file bytes match the listed SHA-256 values; it does not establish provenance,
release approval, training-run identity, or source authenticity, and it does
not distribute or authenticate the artifacts.

A clean checkout needs the reviewed manifest and verifier in source control,
the exact binary files obtained from the owner-approved trusted source at the
manifest paths, and a successful verification before local detection starts.
Preserve the paths in `model_artifacts.sha256`, then verify with:

```powershell
.\.venv\Scripts\python.exe scripts\verify_model_artifacts.py
```

The verifier checks the V2 model, V1 primary model, and V1 fallback model by
SHA-256 without deserializing them. A missing or modified file fails the check.
Update hashes only alongside a separately reviewed model release. Do not
commit model weights to obtain a green check. The approved six-algorithm
evaluation ranking does not authorize replacing V2's Random Forest; V1 remains
LightGBM-primary with CatBoost fallback.

## Hosted Linux web process

The Linux build/start procedure below is a validation procedure, not evidence
that it has passed. Hosted Linux startup has not yet been validated in an
approved Linux environment; treat that deployment check as outstanding.

The hosted runtime has a separate pinned dependency set. It intentionally
excludes Scapy and Windows-only `pywinpty` from the Linux image. It includes
the pinned Hugging Face Hub, joblib, LightGBM, NumPy, pandas, and scikit-learn
dependencies needed for hosted V1 inference. `requirements.txt` remains the
existing development environment; `requirements-sensor.txt` extends it with
Scapy for the local sensor.

Production entrypoints:

- Build command: `python -m pip install -r requirements-hosted.txt`
- Start command: `sh scripts/start_hosted.sh` (also declared in `Procfile`)
- Health check: `/healthz`
- Readiness check: `/readyz`
- Python version: `.python-version` (`3.11.9`); platforms that require an
  environment setting can use `PYTHON_VERSION=3.11.9`.

The start script requires the platform-provided numeric `PORT`, sets
`NETRA_RUNTIME_ROLE=hosted_web`, and execs Gunicorn bound to
`0.0.0.0:$PORT`. Gunicorn debug mode is not enabled. `WEB_CONCURRENCY` may
override its default of two workers. Hosted app initialization does not create
local sensor workers, so importing the WSGI app in multiple worker processes
does not duplicate those threads. Gunicorn's graceful worker shutdown is used.
Hosted email and report outboxes use versioned shared PostgreSQL tables. The
local sensor continues to use SQLite unless it explicitly selects
`NETRA_DELIVERY_BACKEND=postgresql`; records are never copied automatically.


Run the hosted delivery worker separately from Gunicorn:

```sh
NETRA_RUNTIME_ROLE=hosted_worker NETRA_DELIVERY_BACKEND=postgresql \
  python -m v2.critical_email_alerts
```

The weekly scheduler should invoke a one-shot report process with
`NETRA_RUNTIME_ROLE=report_job`, `NETRA_EVENT_BACKEND=postgresql`, and
`NETRA_DELIVERY_BACKEND=postgresql`:

```sh
NETRA_RUNTIME_ROLE=report_job NETRA_EVENT_BACKEND=postgresql \
  NETRA_DELIVERY_BACKEND=postgresql python -m v2.weekly_report
```

All hosted roles use the same `DATABASE_URL`. Set the Resend API key/sender and
alert or weekly-report recipient settings only in roles that deliver mail.

### Local hosted smoke test

With a reachable PostgreSQL repository and the hosted environment variables
configured, the Flask development server can still be used for a local
functional smoke test (not production):

```powershell
$env:NETRA_RUNTIME_ROLE = "hosted_web"
$env:NETRA_EVENT_BACKEND = "postgresql"
$env:DATABASE_URL = "<PostgreSQL connection URL>"
$env:NETRA_AUTH_USERNAME = "<dashboard username>"
$env:NETRA_AUTH_PASSWORD = "<strong dashboard password>"
$env:NETRA_SENSOR_API_KEY = "<shared sensor key>"
$env:HOST = "127.0.0.1"
$env:PORT = "5000"
.\.venv\Scripts\python.exe app\app.py
```

In another PowerShell window, check process health and repository readiness:

```powershell
Invoke-WebRequest http://127.0.0.1:5000/healthz
Invoke-WebRequest http://127.0.0.1:5000/readyz
```

The readiness request is deliberately a dependency check, not a public
diagnostics endpoint. Do not expose database errors or credentials in logs or
responses.

### Reproducible Linux build/start validation

On a clean Linux host or container with the pinned Python version:

```sh
python --version
python -m venv .venv
. .venv/bin/activate
python -m pip install --requirement requirements-hosted.txt
NETRA_EVENT_BACKEND=postgresql \
  DATABASE_URL='postgresql://user:password@host/database' \
  NETRA_AUTH_USERNAME='operator' \
  NETRA_AUTH_PASSWORD='replace-with-a-secret' \
  NETRA_SENSOR_API_KEY='replace-with-a-long-random-key' \
  PORT=10000 sh scripts/start_hosted.sh
```

Probe `/healthz` and `/readyz`, then verify an authenticated dashboard request
and an authenticated sensor-ingestion request. Use a disposable test database
and test credentials. This repository change does not provision either.

## Operational limits

The hosted request limiter is process-local; put a shared ingress/rate limit in
front of multiple Gunicorn workers or instances. Event history uses the
configured PostgreSQL repository, and hosted delivery uses shared PostgreSQL
tables. Local sensor outboxes remain SQLite unless the sensor explicitly opts
into PostgreSQL; they are not forwarded or migrated automatically. Local
sensor model artifacts are also not present in a clean source checkout until
obtained from the approved artifact transfer process.
