#!/bin/sh
set -eu

: "${PORT:?PORT environment variable is required}"
case "$PORT" in
  *[!0-9]*|'') echo "PORT must be a numeric TCP port" >&2; exit 2 ;;
esac

export NETRA_RUNTIME_ROLE=hosted_web
exec gunicorn \
  --bind "0.0.0.0:${PORT}" \
  --workers "${WEB_CONCURRENCY:-2}" \
  --timeout 60 \
  --graceful-timeout 30 \
  --access-logfile - \
  --error-logfile - \
  app.app:app
