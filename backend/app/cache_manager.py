import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Optional

from app.models import AnalysisResult

logger = logging.getLogger(__name__)

# JSON file used for persistence between restarts (None = memory-only)
_CACHE_FILE = Path("/tmp/email_scorer_cache.json")

_lock = threading.Lock()
_store: dict[str, dict] = {}


def _load() -> None:
    if _CACHE_FILE.exists():
        try:
            _store.update(json.loads(_CACHE_FILE.read_text()))
            logger.info("Cache loaded: %d entries from %s", len(_store), _CACHE_FILE)
        except Exception as exc:
            logger.warning("Could not load cache file: %s", exc)


def _persist() -> None:
    try:
        _CACHE_FILE.write_text(json.dumps(_store))
    except Exception as exc:
        logger.warning("Could not persist cache: %s", exc)


# Load on import
_load()


def make_key(subject: str, body: str) -> str:
    """Return a SHA-256 hex digest of *subject* + *body*.

    Concatenating with a null byte prevents collisions between
    ("ab", "cd") and ("a", "bcd").
    """
    raw = f"{subject}\x00{body}".encode()
    return hashlib.sha256(raw).hexdigest()


def get(key: str) -> Optional[AnalysisResult]:
    with _lock:
        entry = _store.get(key)
    if entry is None:
        return None
    try:
        return AnalysisResult.model_validate(entry)
    except Exception as exc:
        logger.warning("Corrupt cache entry %s: %s", key[:16], exc)
        return None


def set(key: str, result: AnalysisResult) -> None:
    with _lock:
        _store[key] = result.model_dump()
        _persist()
