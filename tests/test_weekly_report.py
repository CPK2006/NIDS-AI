from datetime import datetime, timedelta, timezone
import os
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from v2.event_store import SQLiteEventRepository, create_event
from v2.weekly_report import (
    WeeklyReportConfig, WeeklyReportService, configured_repositories, weekly_reporting_interval,
)


class Response:
    def __init__(self, status):
        self.status_code = status


class MockSession:
    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return Response(self.statuses.pop(0))


class WeeklyReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = SQLiteEventRepository(os.path.join(self.temp.name, "history.sqlite3"))
        self.start = datetime(2026, 10, 12, 3, 30, tzinfo=timezone.utc)
        self.end = self.start + timedelta(days=7)
        self.generated = self.end + timedelta(minutes=1)

    def tearDown(self):
        self.temp.cleanup()

    def config(self, **overrides):
        values = {"enabled": True, "api_key": "test-weekly-secret", "sender": "NETRA <alerts@example.com>",
                  "recipient": "weekly@example.com", "timeout_seconds": 1, "max_attempts": 2}
        values.update(overrides)
        return WeeklyReportConfig(**values)

    def service(self, *, repo=None, critical_repo=None, session=None, config=None, sleeper=None):
        return WeeklyReportService(repo or self.repo, self.repo, critical_repository=critical_repo or self.repo,
                                   config=config or self.config(), session=session,
                                   sleeper=sleeper or time.sleep)

    def add(self, origin, event_type, classification=None, metadata=None, at=None):
        return self.repo.append(create_event(
            origin=origin, session_id=str(uuid.uuid4()), event_type=event_type,
            classification=classification, metadata=metadata or {},
            occurred_at=at or (self.start + timedelta(hours=1)),
        ))

    def test_scheduled_interval_is_previous_full_week_and_uses_utc_boundaries(self):
        monday_0900 = datetime(2026, 10, 19, 3, 30, tzinfo=timezone.utc)
        start, end = weekly_reporting_interval(monday_0900)
        self.assertEqual(end, monday_0900)
        self.assertEqual(start, monday_0900 - timedelta(days=7))
        before = weekly_reporting_interval(monday_0900 - timedelta(seconds=1))
        self.assertEqual(before[1], monday_0900 - timedelta(days=7))
        self.assertEqual(before[0], before[1] - timedelta(days=7))

    def test_origin_classifications_and_event_types_are_separate(self):
        self.add("live", "flow_classification", "ATTACK", {"packet_count": 5, "byte_count": 60})
        self.add("live", "alert", "ATTACK", {"packet_count": 5})
        self.add("live", "flow_classification", "BENIGN", {"packet_count": 2, "byte_count": 30})
        self.add("pcap", "flow_classification", "ATTACK", {"packet_count": 9, "byte_count": 90})
        self.add("simulation", "processing_error")
        report = self.service().generate(self.start, self.end, generated_at=self.generated)
        self.assertEqual(report["origins"]["live"]["classification_count"], 2)
        self.assertEqual(report["origins"]["live"]["attack_classifications"], 1)
        self.assertEqual(report["origins"]["live"]["event_counts_by_type"]["alert"], 1)
        self.assertEqual(report["origins"]["pcap"]["attack_classifications"], 1)
        self.assertEqual(report["origins"]["simulation"]["event_counts_by_type"]["processing_error"], 1)
        self.assertEqual(report["origins"]["live"]["recorded_packet_count"]["value"], 7)
        self.assertIn("not a completeness guarantee", report["report_text"])

    def test_empty_interval_is_zero_and_explicitly_not_a_completeness_claim(self):
        report = self.service().generate(self.start, self.end, generated_at=self.generated)
        self.assertTrue(report["history_available"])
        self.assertEqual(report["origins"]["live"]["event_count"], 0)
        self.assertEqual(report["origins"]["pcap"]["attack_classifications"], 0)
        self.assertIn("persisted records only", report["report_text"])
        self.assertTrue(report["critical_email"]["available"])
        self.assertEqual(report["critical_email"]["incidents"], 0)

    def test_persisted_critical_incident_outcome_is_summarized(self):
        incident = {"alert_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
                    "attack_count": 10, "window_size": 20,
                    "occurred_at_utc": (self.start + timedelta(hours=1)).isoformat()}
        self.repo.enqueue_critical_alert(incident)
        lease, batch = self.repo.claim_critical_alerts()
        self.repo.complete_critical_alert(incident["alert_id"], lease)
        report = self.service().generate(self.start, self.end, generated_at=self.generated)
        self.assertEqual(report["critical_email"]["incidents"], 1)
        self.assertEqual(report["critical_email"]["delivered"], 1)
        self.assertIn("1 total; 1 delivered", report["report_text"])

    def test_interval_boundary_excludes_end_and_prior_events(self):
        self.add("live", "flow_classification", "ATTACK", at=self.start)
        self.add("live", "flow_classification", "BENIGN", at=self.end)
        report = self.service().generate(self.start, self.end, generated_at=self.generated)
        self.assertEqual(report["origins"]["live"]["classification_count"], 1)
        self.assertEqual(report["origins"]["live"]["attack_classifications"], 1)

    def test_partial_packet_metadata_and_unavailable_persistence_are_disclosed(self):
        self.add("live", "flow_classification", "BENIGN", {"packet_count": 3})
        self.add("live", "flow_classification", "ATTACK", {})
        report = self.service().generate(self.start, self.end, generated_at=self.generated)
        self.assertFalse(report["origins"]["live"]["recorded_packet_count"]["available"])
        self.assertIsNone(report["origins"]["live"]["recorded_packet_count"]["value"])

        class UnavailableRepository:
            def iter_events(self, *_args, **_kwargs):
                raise RuntimeError("private database detail")

        unavailable = self.service(repo=UnavailableRepository()).generate(
            self.start, self.end, generated_at=self.generated)
        self.assertFalse(unavailable["history_available"])
        self.assertIn("Historical event data: unavailable", unavailable["report_text"])
        self.assertNotIn("private database detail", unavailable["report_text"])
        self.assertTrue(unavailable["critical_email"]["available"])

        class UnavailableCriticalRepository:
            def summarize_critical_email_alerts(self, *_args):
                raise RuntimeError("private delivery store details")

        diagnostics = self.service(critical_repo=UnavailableCriticalRepository()).generate(
            self.start, self.end, generated_at=self.generated)
        self.assertFalse(diagnostics["critical_email"]["available"])
        self.assertIn("Critical incident and email delivery diagnostics: unavailable", diagnostics["report_text"])

    def test_report_id_is_deterministic_for_interval(self):
        service = self.service()
        first = service.generate(self.start, self.end, generated_at=self.generated)
        second = service.generate(self.start, self.end, generated_at=self.generated + timedelta(hours=1))
        self.assertEqual(first["report_id"], second["report_id"])
        self.assertNotEqual(first["generated_at_utc"], second["generated_at_utc"])

    def test_missing_configuration_still_generates_without_sending(self):
        session = MockSession(200)
        service = self.service(config=self.config(enabled=True, api_key="", recipient=""), session=session)
        result = service.run_previous_week(now=self.generated)
        self.assertIn("origins", result)
        self.assertEqual(result["delivery"]["state"], "not_configured")
        self.assertEqual(session.calls, [])

    def test_resend_retry_and_same_interval_do_not_send_duplicate(self):
        session = MockSession(503, 200)
        service = self.service(session=session, sleeper=lambda delay: time.sleep(delay))
        report = service.generate(self.start, self.end, generated_at=self.generated)
        first = service.deliver(report)
        self.assertEqual(first["state"], "delivered")
        self.assertEqual(len(session.calls), 2)
        keys = [call[1]["headers"]["Idempotency-Key"] for call in session.calls]
        self.assertEqual(keys, [report["report_id"], report["report_id"]])
        later_report = service.generate(self.start, self.end, generated_at=self.generated + timedelta(days=1))
        again = service.deliver(later_report)
        self.assertEqual(again["state"], "delivered")
        self.assertFalse(again["sent"])
        self.assertEqual(len(session.calls), 2)
        self.assertNotIn("test-weekly-secret", str(again))

    def test_restart_resumes_due_report_record_from_previous_run(self):
        report = self.service(config=self.config(enabled=False)).generate(
            self.start, self.end, generated_at=self.generated)
        self.repo.enqueue_weekly_report(dict(report, recipient_email="weekly@example.com"))
        token, claimed = self.repo.claim_weekly_report(report["report_id"])
        self.assertIsNotNone(claimed)
        self.repo.fail_weekly_report(report["report_id"], token, error_code="http_503", delay_seconds=0)
        resumed = self.service(session=MockSession(200))
        outcomes = resumed.deliver_pending(now=datetime.now(timezone.utc) + timedelta(seconds=1))
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0]["state"], "delivered")

    def test_permanent_failure_is_retained_and_not_resent(self):
        session = MockSession(422, 200)
        service = self.service(session=session)
        report = service.generate(self.start, self.end, generated_at=self.generated)
        first = service.deliver(report)
        again = service.deliver(report)
        self.assertEqual(first["state"], "permanently_failed")
        self.assertEqual(again["state"], "permanently_failed")
        self.assertEqual(len(session.calls), 1)
        self.assertEqual(self.repo.get_weekly_report(report["report_id"])["last_error_code"], "http_422")

    def test_explicit_retry_requeues_only_permanently_failed_report(self):
        report = self.service(session=MockSession(422)).generate(
            self.start, self.end, generated_at=self.generated)
        self.service(session=MockSession(422)).deliver(report)
        self.assertEqual(self.repo.retry_failed_weekly_reports([report["report_id"]]), 1)
        record = self.repo.get_weekly_report(report["report_id"])
        self.assertEqual(record["state"], "pending")
        self.assertEqual(record["attempts"], 1, "total delivery attempts remain auditable")
        self.assertEqual(record["attempts_in_cycle"], 0, "explicit retry starts a fresh bounded cycle")

    def test_delivery_retention_only_removes_old_delivered_rows(self):
        report = self.service().generate(self.start, self.end, generated_at=self.generated)
        self.repo.enqueue_weekly_report(dict(report, recipient_email="weekly@example.com"))
        lease, claimed = self.repo.claim_weekly_report(report["report_id"])
        self.assertIsNotNone(claimed)
        self.repo.complete_weekly_report(report["report_id"], lease)
        older = (datetime.now(timezone.utc) - timedelta(days=500)).isoformat()
        with self.repo._connection() as connection:
            connection.execute("UPDATE weekly_report_outbox SET updated_at_utc=? WHERE report_id=?",
                               (older, report["report_id"]))
            connection.commit()
        incident = {"alert_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
                    "attack_count": 10, "window_size": 20,
                    "occurred_at_utc": self.generated.isoformat()}
        self.repo.enqueue_critical_alert(incident)
        alert_lease, _ = self.repo.claim_critical_alerts()
        self.repo.complete_critical_alert(incident["alert_id"], alert_lease)
        pending_incident = {"alert_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
                            "attack_count": 10, "window_size": 20,
                            "occurred_at_utc": self.generated.isoformat()}
        failed_incident = {"alert_id": str(uuid.uuid4()), "session_id": str(uuid.uuid4()),
                           "attack_count": 10, "window_size": 20,
                           "occurred_at_utc": self.generated.isoformat()}
        self.repo.enqueue_critical_alert(pending_incident)
        self.repo.enqueue_critical_alert(failed_incident)
        lease, claimed = self.repo.claim_critical_alerts(limit=2)
        self.assertEqual(len(claimed), 2)
        self.repo.fail_critical_alert(failed_incident["alert_id"], lease,
                                      error_code="http_422", permanent=True)
        with self.repo._connection() as connection:
            connection.execute("UPDATE critical_email_outbox SET updated_at_utc=? WHERE alert_id=?",
                               (older, incident["alert_id"]))
            for item in (pending_incident, failed_incident):
                connection.execute("UPDATE critical_email_outbox SET updated_at_utc=? WHERE alert_id=?",
                                   (older, item["alert_id"]))
            connection.commit()
        self.assertEqual(self.repo.prune_delivery_records(retention_days=365), 1)
        self.assertIsNotNone(self.repo.get_weekly_report(report["report_id"]))
        counts = self.repo.critical_email_alert_counts()
        self.assertEqual(counts["delivered"], 0)
        self.assertEqual(counts["pending"], 1)
        self.assertEqual(counts["failed"], 1)

    def test_delivery_retention_configuration_is_conservative(self):
        with self.assertRaises(ValueError):
            self.repo.prune_delivery_records(retention_days=30)
        self.assertEqual(self.repo.prune_delivery_records(retention_days=0), 0)

    def test_hosted_report_job_rejects_local_event_or_delivery_storage(self):
        with patch.dict(os.environ, {"NETRA_RUNTIME_ROLE": "report_job",
                                     "NETRA_EVENT_BACKEND": "sqlite",
                                     "NETRA_DELIVERY_BACKEND": "sqlite"}):
            with self.assertRaisesRegex(RuntimeError, "requires NETRA_EVENT_BACKEND=postgresql"):
                configured_repositories()


if __name__ == "__main__":
    unittest.main()
