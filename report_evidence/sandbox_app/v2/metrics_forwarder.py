"""Forward live detector status to the authenticated hosted metrics endpoint."""
import logging
import os
import threading

import requests

logger = logging.getLogger(__name__)


class MetricsForwarder:
    def __init__(self, engine, endpoint, api_key, interval=5):
        self.engine = engine
        self.endpoint = endpoint
        self.api_key = api_key
        self.interval = max(5, int(interval))
        self._stop = threading.Event()
        self._thread = None

    @classmethod
    def from_environment(cls, engine):
        enabled = os.getenv(
            "NETRA_METRICS_ENABLED",
            os.getenv("NETRA_FORWARDING_ENABLED", "false"),
        ).strip().lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return None

        endpoint = os.getenv("NETRA_METRICS_URL", "").strip()
        if not endpoint:
            event_url = os.getenv("NETRA_INGESTION_URL", "").strip()
            suffix = "/api/v1/sensor/events"
            if event_url.endswith(suffix):
                endpoint = event_url[:-len(suffix)] + "/api/v1/sensor/metrics"

        api_key = os.getenv("NETRA_SENSOR_API_KEY", "").strip()
        if not endpoint.startswith("https://"):
            logger.error("Metrics forwarding disabled: NETRA_METRICS_URL must use HTTPS.")
            return None
        if len(api_key) < 32:
            logger.error("Metrics forwarding disabled: sensor API key is missing or too short.")
            return None
        return cls(engine, endpoint, api_key)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="sensor-metrics-forwarder", daemon=True
        )
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                status = self.engine.get_status()
                response = requests.post(
                    self.endpoint,
                    json={"status": status},
                    headers={
                        "Authorization": "Bearer " + self.api_key,
                        "Content-Type": "application/json",
                    },
                    timeout=4,
                    allow_redirects=False,
                )
                if response.status_code != 200:
                    logger.warning(
                        "Metrics update rejected (HTTP %s)", response.status_code
                    )
            except Exception as exc:
                logger.warning("Metrics update failed (%s)", type(exc).__name__)
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
