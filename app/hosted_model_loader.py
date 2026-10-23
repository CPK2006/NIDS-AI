"""Download and verify the hosted V1 model before deserialization."""

import hashlib
import os
from pathlib import Path

from huggingface_hub import hf_hub_download


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "model_artifacts.sha256"
REPOSITORY_ID = os.getenv(
    "HF_MODEL_REPO",
    "CPK2006/nids-ai-model-artifacts",
)
CACHE_DIR = Path(
    os.getenv("HF_MODEL_CACHE", "/tmp/netra-model-artifacts")
).resolve()
V1_MODEL = "results/models/lightgbm_top20_model.pkl"


def expected_v1_hash():
    """Get the V1 hash from the application-controlled manifest."""
    for line_number, line in enumerate(
        MANIFEST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(maxsplit=1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise ValueError(
                "Invalid model manifest entry at line {}".format(line_number)
            )

        digest, filename = parts
        filename = filename.replace("\\", "/")

        if any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("Invalid model manifest hash")

        path = Path(filename)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("Unsafe model manifest path")

        if filename == V1_MODEL:
            return digest

    raise ValueError("V1 model is missing from the checked-in manifest")


def download_verified_v1_model():
    """Download the private V1 model and verify its expected SHA-256."""
    token = os.getenv("HF_TOKEN")
    if not token:
        raise RuntimeError("HF_TOKEN is not configured")

    expected_hash = expected_v1_hash()
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    path = Path(
        hf_hub_download(
            repo_id=REPOSITORY_ID,
            filename=V1_MODEL,
            repo_type="model",
            token=token,
            cache_dir=str(CACHE_DIR / "hub"),
        )
    )

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != expected_hash:
        raise RuntimeError("V1 model checksum verification failed")

    return str(path)
