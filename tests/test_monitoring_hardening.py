import base64
import unittest
from unittest.mock import patch

from app.app import app, v2_engine
from v2.live_detector import Flow, LiveDetectorEngine


class DashboardSecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.username = app.config["NETRA_AUTH_USERNAME"]
        self.password = app.config["NETRA_AUTH_PASSWORD"]

    def tearDown(self):
        app.config["NETRA_AUTH_USERNAME"] = self.username
        app.config["NETRA_AUTH_PASSWORD"] = self.password

    def test_local_development_without_credentials_is_allowed(self):
        app.config["NETRA_AUTH_USERNAME"] = ""
        app.config["NETRA_AUTH_PASSWORD"] = ""
        response = self.client.get("/api/v2/status", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)

    def test_remote_access_without_credentials_is_rejected(self):
        app.config["NETRA_AUTH_USERNAME"] = ""
        app.config["NETRA_AUTH_PASSWORD"] = ""
        response = self.client.get("/api/v2/status", environ_base={"REMOTE_ADDR": "192.0.2.10"})
        self.assertEqual(response.status_code, 503)

    def test_credentials_protect_monitoring_and_controls(self):
        app.config["NETRA_AUTH_USERNAME"] = "operator"
        app.config["NETRA_AUTH_PASSWORD"] = "a-long-test-password"
        self.assertEqual(self.client.get("/api/v2/status").status_code, 401)
        encoded = base64.b64encode(b"operator:a-long-test-password").decode("ascii")
        headers = {"Authorization": f"Basic {encoded}"}
        self.assertEqual(self.client.get("/api/v2/status", headers=headers).status_code, 200)
        self.assertEqual(self.client.post("/api/v2/clear").status_code, 401)
        self.assertEqual(self.client.get("/v2", headers=headers).status_code, 200)

    def test_status_exposes_health_fields(self):
        response = self.client.get("/api/v2/status", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)
        status = response.get_json()
        self.assertIn("model_available", status)
        self.assertIn("alert_processing_status", status)
        self.assertIn("last_inference_time", status["stats"])
        self.assertIn("capture_errors", status["stats"])

    def test_start_api_reports_service_unavailable_when_v2_model_is_missing(self):
        with patch.object(v2_engine, "model", None):
            response = self.client.post(
                "/api/v2/start", json={"mode": "live"},
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            )
        self.assertEqual(response.status_code, 503)
        payload = response.get_json()
        self.assertFalse(payload["success"])
        self.assertFalse(payload["status"]["is_running"])
        self.assertFalse(payload["status"]["model_available"])
        self.assertIn("restart the local sensor", payload["message"].lower())

    def test_simulation_is_not_reported_successful_without_v2_model(self):
        with patch.object(v2_engine, "model", None), patch("app.app.run_attack_simulation") as simulate:
            response = self.client.post(
                "/api/v2/simulate-attack", json={},
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            )
        self.assertEqual(response.status_code, 503)
        self.assertFalse(response.get_json()["success"])
        self.assertIn("model is unavailable", response.get_json()["message"].lower())
        simulate.assert_not_called()

    def test_status_and_dashboard_payloads_are_not_cached(self):
        status_response = self.client.get("/api/v2/status", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        dashboard_response = self.client.get("/api/v2/alerts", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        expected = "no-store, no-cache, must-revalidate, max-age=0"
        self.assertEqual(status_response.headers["Cache-Control"], expected)
        self.assertEqual(dashboard_response.headers["Cache-Control"], expected)

    def test_dashboard_api_embeds_all_live_stat_fields_and_attack_alerts(self):
        stats = {
            "packets_processed": 14912,
            "active_flows": 524,
            "completed_flows": 2395,
            "benign_count": 2395,
            "attack_count": 0,
            "attacks_flagged": 5,
            "processing_errors": 0,
            "capture_errors": 0,
            "last_packet_time": "12:34:56",
            "last_inference_time": "12:34:55",
        }
        snapshot = {
            "alerts": [{"label": "ATTACK", "occurrence_count": 2}],
            "feed": [{"label": "BENIGN"}, {"label": "ATTACK"}],
            "status": {"is_running": True, "mode": "pcap", "model_available": True, "stats": stats},
        }
        with patch("app.app.v2_engine.get_dashboard_snapshot", return_value=snapshot):
            response = self.client.get("/api/v2/alerts?limit=50", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"]["stats"], stats)
        self.assertEqual(payload["alerts"], snapshot["alerts"])
        self.assertEqual(payload["feed"], snapshot["feed"])

    def test_dashboard_uses_serial_polling_and_clears_values_on_request_failure(self):
        response = self.client.get("/v2", environ_base={"REMOTE_ADDR": "127.0.0.1"})
        page = response.get_data(as_text=True)
        self.assertIn("dashboardRequestInFlight", page)
        self.assertIn("setTimeout(updateDashboard, 1500)", page)
        self.assertNotIn("setInterval(updateDashboard", page)
        self.assertIn("fetch('/api/v2/alerts?limit=100', { cache: 'no-store' })", page)
        self.assertIn("document.getElementById(id).textContent = '—'", page)
        self.assertIn("alert.label === 'ATTACK'", page)
        self.assertIn("item.label === 'ATTACK' || item.label === 'BENIGN'", page)
        self.assertIn("<h2>Live Feed</h2>", page)
        self.assertNotIn("Auto-start PCAP / Live", page)

    def test_v1_page_is_protected_with_v2_routes(self):
        app.config["NETRA_AUTH_USERNAME"] = "operator"
        app.config["NETRA_AUTH_PASSWORD"] = "a-long-test-password"
        self.assertEqual(self.client.get("/").status_code, 401)
        self.assertEqual(self.client.post("/").status_code, 401)
        self.assertEqual(self.client.get("/presentation").status_code, 401)


class AlertAggregationTests(unittest.TestCase):
    class Model:
        def predict(self, dataframe):
            return [1]

        def predict_proba(self, dataframe):
            return [[0.1, 0.9]]

    def make_flow(self, src_ip="198.51.100.2"):
        flow = Flow(src_ip, "203.0.113.8", 45000, 443, "TCP", 100.0)
        flow.fwd_packets = 3
        flow.bwd_packets = 2
        flow.fwd_bytes = 300
        flow.bwd_bytes = 200
        flow.fwd_lengths = [100, 100, 100]
        flow.bwd_lengths = [100, 100]
        flow.packet_lengths = [100] * 5
        flow.last_time = 101.0
        return flow

    def test_duplicate_alerts_are_aggregated_without_losing_flow_counts(self):
        with patch("v2.live_detector.os.path.exists", return_value=False):
            engine = LiveDetectorEngine(model_file="missing-model")
        engine.model = self.Model()
        engine.alert_cooldown_seconds = 60
        engine._classify_and_alert(self.make_flow())
        engine._classify_and_alert(self.make_flow())
        self.assertEqual(engine.stats["completed_flows"], 2)
        self.assertEqual(engine.stats["attack_count"], 2)
        self.assertEqual(engine.stats["attacks_flagged"], 2)
        self.assertEqual(len(engine.get_alerts()), 1)
        alert = engine.get_alerts()[0]
        self.assertEqual(alert["occurrence_count"], 2)
        self.assertEqual(alert["packets"], 10)
        self.assertEqual(alert["detection_source"], "ml")

    def test_distinct_sources_remain_separate_alerts(self):
        with patch("v2.live_detector.os.path.exists", return_value=False):
            engine = LiveDetectorEngine(model_file="missing-model")
        engine.model = self.Model()
        engine._classify_and_alert(self.make_flow("198.51.100.2"))
        engine._classify_and_alert(self.make_flow("198.51.100.3"))
        self.assertEqual(len(engine.get_alerts()), 2)

    def test_inference_failure_is_health_error_not_benign_prediction(self):
        class FailingModel:
            def predict(self, dataframe):
                raise RuntimeError("broken model")

        with patch("v2.live_detector.os.path.exists", return_value=False):
            engine = LiveDetectorEngine(model_file="missing-model")
        engine.model = FailingModel()
        engine._classify_and_alert(self.make_flow())
        self.assertEqual(engine.stats["completed_flows"], 0)
        self.assertEqual(engine.stats["processing_errors"], 1)
        self.assertEqual(engine.get_alerts(), [])
        self.assertIsNone(engine.stats["last_inference_time"])


if __name__ == "__main__":
    unittest.main()
