"""Valio Aimo Agent Gateway."""

import os
from pathlib import Path


def _load_dotenv(path: Path = Path(__file__).resolve().parents[1] / ".env") -> None:
    """Minimal .env loader (no extra dependency). Real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value:
            os.environ.setdefault(key, value)


_load_dotenv()
