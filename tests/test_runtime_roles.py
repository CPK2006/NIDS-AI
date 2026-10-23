import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


def hosted_process(source, extra_env=None):
    env = os.environ.copy()
    env.update({
        "NETRA_RUNTIME_ROLE": "hosted_web",
        "NETRA_EVENT_BACKEND": "postgresql",
        "NETRA_DELIVERY_BACKEND": "postgresql",
        "DATABASE_URL": "postgresql://netra:password@db.example.test/netra",
        "NETRA_AUTH_USERNAME": "operator",
        "NETRA_AUTH_PASSWORD": "hosted-test-password",
        "NETRA_SENSOR_API_KEY": "a-long-test-sensor-key-for-runtime-role",
    })
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        [sys.executable, "-c", source], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode:
        raise AssertionError(f"Hosted process failed: {result.stderr}\n{result.stdout}")
    return result.stdout


class RuntimeRoleTests(unittest.TestCase):
    def test_hosted_import_does_not_import_detector_or_model_and_exposes_role_routes(self):
        source = r'''
import json, sys, types
sys.modules["psycopg"] = types.ModuleType("psycopg")
import app.app as module
class Repository:
    def __init__(self): self.events = []; self.aggregations = 0; self.fail = False; self.delivery_fail = False
    def iter_events(self, *args, **kwargs):
        if self.fail: raise RuntimeError("private database path and password")
        return iter(self.events)
    def aggregate_events(self, *args, **kwargs):
        self.aggregations += 1
        return []
    def append_many(self, events, enqueue_forward=False):
        self.events.extend(events)
        return len(events)
    def critical_email_alert_counts(self):
        if self.delivery_fail: raise RuntimeError("private delivery database URL and password")
        return {"pending": 2, "retrying": 0, "delivered": 1, "failed": 0}
    def list_critical_email_alerts(self, **kwargs): return []
    def retry_failed_critical_alerts(self, ids): return len(ids)
    def retry_failed_weekly_reports(self, ids): return len(ids)
repository = Repository()
module.app.config["EVENT_REPOSITORY"] = repository
module.app.config["DELIVERY_REPOSITORY"] = repository
client = module.app.test_client()
auth = ("operator", "hosted-test-password")
assert module.v2_engine is None
assert "v2.live_detector" not in sys.modules
assert "v2.critical_email_alerts" not in sys.modules
assert "scapy" not in sys.modules
import threading
assert not any(thread.name == "netra-resend-alert-worker" for thread in threading.enumerate())
assert module.model is None and module.MODEL_LOADED is False
assert module.app.config["DEBUG"] is False
assert client.get("/api/v2/status", auth=auth).json["runtime_role"] == "hosted_web"
assert client.get("/api/v2/history/trends?window=24h&origin=live", auth=auth).status_code == 200
assert repository.aggregations == 1
assert client.get("/readyz").status_code == 200
delivery = client.get("/api/v2/email-alerts/status", auth=auth)
assert delivery.status_code == 200 and delivery.json["pending"] == 2
retry = client.post("/api/v2/email-alerts/retry", json={"alert_ids": ["9f8c84fb-450c-4bb4-b792-64ce6a98b6f2"]}, auth=auth)
assert retry.status_code == 200 and retry.json["requeued"] == 1
assert client.post("/api/v2/weekly-reports/retry", json={"report_ids": []}).status_code == 401
weekly_retry = client.post("/api/v2/weekly-reports/retry", json={"report_ids": ["9f8c84fb-450c-4bb4-b792-64ce6a98b6f2"]}, auth=auth)
assert weekly_retry.status_code == 200 and weekly_retry.json["requeued"] == 1
for route, method in [("/api/v2/start", "post"), ("/api/v2/stop", "post"),
                      ("/api/v2/clear", "post"), ("/api/v2/simulate-attack", "post"),
                      ("/api/v2/interfaces", "get")]:
    response = getattr(client, method)(route, auth=auth)
    assert response.status_code == 403, (route, response.status_code)
# Hosted dashboards read persisted events, not local sensor counters.
assert client.get("/api/v2/alerts", auth=auth).json["status"]["stats"]["packets_processed"] is None

from datetime import datetime, timedelta, timezone
repository.events = [{
    "event_id": "9f8c84fb-450c-4bb4-b792-64ce6a98b6f2",
    "schema_version": 1,
    "occurred_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "origin": "live",
    "session_id": None,
    "event_type": "flow_classification",
    "classification": "ATTACK",
    "metadata": {
        "packet_count": 4,
        "byte_count": 240,
        "protocol": "TCP",
        "confidence_percent": 97.5,
    },
}]

feed_response = client.get("/api/v2/alerts", auth=auth)
assert feed_response.status_code == 200
assert feed_response.json["feed_available"] is True
assert len(feed_response.json["feed"]) == 1
assert feed_response.json["feed"][0]["label"] == "ATTACK"
assert feed_response.json["feed"][0]["protocol"] == "TCP"
assert feed_response.json["feed"][0]["confidence"] == 97.5
assert feed_response.json["feed"][0]["src_ip"] == "—"
assert feed_response.json["feed"][0]["dst_ip"] == "—"

assert client.get("/", auth=auth).status_code == 503
# Exercise the hosted inference route without network access or model downloads.
class FakeModel:
    def predict_proba(self, features):
        return [[0.9, 0.1]]

module.model = FakeModel()
module.MODEL_LOADED = True
home = client.get("/", auth=auth)
assert home.status_code == 200, home.status_code

form = {feature: "1" for feature in module.FEATURES}
prediction = client.post("/", data=form, auth=auth)
assert prediction.status_code == 200, prediction.status_code
assert b"BENIGN" in prediction.data

assert client.get("/api/v2/start").status_code == 401
assert client.get("/",).status_code == 401
health = client.get("/healthz").get_data(as_text=True)
assert "ok" in health and "password" not in health and "DATABASE_URL" not in health
repository.fail = True
ready = client.get("/readyz")
assert ready.status_code == 503
assert "private database path" not in ready.get_data(as_text=True)
repository.fail = False
repository.delivery_fail = True
ready = client.get("/readyz")
assert ready.status_code == 503
assert ready.json == {"status": "not_ready", "dependency": "delivery_store"}
assert "private delivery database URL" not in ready.get_data(as_text=True)
print(json.dumps({"role": module.RUNTIME_ROLE, "sensor_imported": "v2.live_detector" in sys.modules}))
'''
        output = hosted_process(source)
        self.assertEqual(json.loads(output.strip().splitlines()[-1]), {
            "role": "hosted_web", "sensor_imported": False,
        })

    def test_hosted_role_rejects_missing_or_invalid_database_configuration(self):
        source = "import app.app"
        missing = hosted_process_failure(source, {"DATABASE_URL": ""})
        self.assertIn("requires DATABASE_URL", missing)
        malformed = hosted_process_failure(source, {"DATABASE_URL": "file:///private/path"})
        self.assertIn("valid PostgreSQL URL", malformed)
        sqlite = hosted_process_failure(source, {"NETRA_EVENT_BACKEND": "sqlite"})
        self.assertIn("refusing local storage", sqlite)

    def test_sensor_ingestion_remains_available_in_hosted_role_with_its_own_key(self):
        source = r'''
import sys, types
sys.modules["psycopg"] = types.ModuleType("psycopg")
import app.app as module
class Repository:
    def append_many(self, events, enqueue_forward=False): return len(events)
    def iter_events(self, *args, **kwargs): return iter([])
    def aggregate_events(self, *args, **kwargs): return []
module.app.config["EVENT_REPOSITORY"] = Repository()
client = module.app.test_client()
event = {"event_id": "9f8c84fb-450c-4bb4-b792-64ce6a98b6f2", "schema_version": 1,
 "occurred_at_utc": "2026-10-22T00:00:00+00:00", "origin": "live",
 "session_id": "69d10a0b-f2f0-45cc-9620-1824b1ea0d74", "event_type": "flow_classification",
 "classification": "BENIGN", "metadata": {"packet_count": 2, "byte_count": 90, "protocol": "TCP"}}
response = client.post("/api/v1/sensor/events", json={"events": [event]},
 headers={"Authorization": "Bearer a-long-test-sensor-key-for-runtime-role"})
assert response.status_code == 200, response.get_data(as_text=True)
assert client.post("/api/v1/sensor/events", json={"events": [event]}).status_code == 401
'''
        hosted_process(source)

    def test_default_local_role_still_initializes_the_detector(self):
        # The suite imports app.app in the default role as part of its existing
        # detector, replay, and dashboard tests; this verifies the public contract.
        import importlib
        app_module = importlib.import_module("app.app")
        self.assertEqual(app_module.RUNTIME_ROLE, "local_sensor")
        self.assertIsNotNone(app_module.v2_engine)


def hosted_process_failure(source, extra_env):
    env = os.environ.copy()
    env.update({
        "NETRA_RUNTIME_ROLE": "hosted_web",
        "NETRA_EVENT_BACKEND": "postgresql",
        "NETRA_DELIVERY_BACKEND": "postgresql",
        "DATABASE_URL": "postgresql://netra:password@db.example.test/netra",
        "NETRA_AUTH_USERNAME": "operator",
        "NETRA_AUTH_PASSWORD": "hosted-test-password",
    })
    env.update(extra_env)
    result = subprocess.run([sys.executable, "-c", source], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        raise AssertionError("Hosted application unexpectedly accepted invalid configuration")
    return result.stderr + result.stdout


if __name__ == "__main__":
    unittest.main()
