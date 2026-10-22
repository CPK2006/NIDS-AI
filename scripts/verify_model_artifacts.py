"""Verify local model files against the checked-in SHA-256 manifest."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "model_artifacts.sha256"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def verify(manifest: Path = MANIFEST, root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    try:
        entries = manifest.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["artifact manifest is unavailable"]

    found = 0
    for line_number, line in enumerate(entries, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not SHA256_RE.fullmatch(parts[0]):
            errors.append(f"manifest line {line_number} is malformed")
            continue
        relative = Path(parts[1].replace("\\", "/"))
        target = (root / relative).resolve()
        if target != root.resolve() and root.resolve() not in target.parents:
            errors.append(f"manifest line {line_number} has an unsafe path")
            continue
        found += 1
        try:
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError:
            errors.append(f"required model artifact is missing: {relative.as_posix()}")
            continue
        if digest != parts[0]:
            errors.append(f"model artifact checksum mismatch: {relative.as_posix()}")

    if found == 0:
        errors.append("artifact manifest contains no model files")
    return errors


def main() -> int:
    errors = verify()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("All required model artifacts match model_artifacts.sha256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
