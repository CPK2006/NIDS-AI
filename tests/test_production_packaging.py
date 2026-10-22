from pathlib import Path
import tempfile
import unittest

from scripts.verify_model_artifacts import verify


ROOT = Path(__file__).resolve().parents[1]


class ProductionPackagingTests(unittest.TestCase):
    def test_hosted_requirements_are_pinned_and_exclude_sensor_packages(self):
        lines = (ROOT / "requirements-hosted.txt").read_text(encoding="utf-8").lower()
        self.assertIn("flask==", lines)
        self.assertIn("gunicorn==", lines)
        self.assertIn("psycopg[binary]==", lines)
        self.assertNotIn("pywinpty", lines)
        self.assertNotIn("scapy", lines)
        self.assertNotIn("-r requirements.txt", lines)
        self.assertIn("scapy==", (ROOT / "requirements-sensor.txt").read_text(encoding="utf-8").lower())

    def test_production_entrypoint_uses_platform_port_and_hosted_role(self):
        script = (ROOT / "scripts/start_hosted.sh").read_text(encoding="utf-8")
        procfile = (ROOT / "Procfile").read_text(encoding="utf-8")
        self.assertIn('"${PORT:?', script)
        self.assertIn("NETRA_RUNTIME_ROLE=hosted_web", script)
        self.assertIn('0.0.0.0:${PORT}', script)
        self.assertIn("exec gunicorn", script)
        self.assertIn("--graceful-timeout", script)
        self.assertIn("sh scripts/start_hosted.sh", procfile)
        self.assertEqual((ROOT / ".python-version").read_text(encoding="utf-8").strip(), "3.11.9")

    def test_artifact_verifier_accepts_expected_hash_and_rejects_missing_or_changed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            model = root / "model.pkl"
            model.write_bytes(b"approved model bytes")
            import hashlib
            digest = hashlib.sha256(model.read_bytes()).hexdigest()
            manifest = root / "manifest.sha256"
            manifest.write_text(f"{digest}  model.pkl\n", encoding="utf-8")
            self.assertEqual(verify(manifest, root), [])
            model.write_bytes(b"changed model bytes")
            self.assertTrue(any("checksum mismatch" in error for error in verify(manifest, root)))
            model.unlink()
            self.assertTrue(any("missing" in error for error in verify(manifest, root)))

    def test_artifact_verifier_rejects_paths_outside_artifact_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            root.mkdir()
            manifest = root / "manifest.sha256"
            manifest.write_text("0" * 64 + "  ../outside.pkl\n", encoding="utf-8")
            self.assertTrue(any("unsafe path" in error for error in verify(manifest, root)))


if __name__ == "__main__":
    unittest.main()
