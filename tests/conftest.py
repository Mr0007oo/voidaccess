"""
tests/conftest.py — shared fixtures for the VoidAccess test suite.

The enrichment-source modules use two kinds of module-level singletons that are
sensitive to the event loop / process state:

  1. An enrichment-cache singleton (``_enrichment_cache_singleton``). Left alone
     it defaults to the SQLite backend at ``~/.voidaccess/cache.db``, which would
     persist between test runs and turn mocked HTTP responses into stale cache
     hits. We force a fresh in-memory cache per test.
  2. Lazy ``asyncio.Semaphore`` singletons bound to the loop they were created
     on. pytest-asyncio uses a fresh loop per test, so a semaphore created in a
     previous test would raise "bound to a different event loop". We reset them.

The ``reset_source_state`` fixture is autouse so every test starts clean.
"""

from __future__ import annotations

import os

# ``config.py`` raises if JWT_SECRET is unset and runs at import time. Some test
# modules import ``sources.enrichment`` (which pulls config), so set a dummy
# secret before any such import. Also ensure no DATABASE_URL so the enrichers'
# DB-write helpers no-op during unit tests.
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-production")
os.environ.pop("DATABASE_URL", None)

import pytest

from utils.enrichment_cache import EnrichmentCache, reset_default_cache


@pytest.fixture(autouse=True)
def reset_source_state(monkeypatch):
    """Give each test a fresh in-memory enrichment cache and reset semaphores."""
    reset_default_cache()

    import sources.breach_lookup as breach_lookup
    import sources.infostealer as infostealer
    import sources.nvd as nvd

    fresh_cache = EnrichmentCache(backend="memory")

    for mod in (breach_lookup, infostealer, nvd):
        monkeypatch.setattr(mod, "_enrichment_cache_singleton", fresh_cache, raising=False)

    # Reset lazy per-loop semaphores so they rebind to the test's event loop.
    monkeypatch.setattr(breach_lookup, "_xon_semaphore", None, raising=False)
    monkeypatch.setattr(breach_lookup, "_leakcheck_semaphore", None, raising=False)
    monkeypatch.setattr(infostealer, "_hr_semaphore", None, raising=False)

    # Neutralise the deliberate rate-limit sleeps so the suite runs fast.
    monkeypatch.setattr(breach_lookup, "_XON_REQUEST_DELAY", 0.0, raising=False)
    monkeypatch.setattr(breach_lookup, "_LEAKCHECK_REQUEST_DELAY", 0.0, raising=False)
    monkeypatch.setattr(infostealer, "_HR_REQUEST_DELAY", 0.0, raising=False)
    monkeypatch.setattr(nvd, "_NVD_DELAY_NO_KEY", 0.0, raising=False)
    monkeypatch.setattr(nvd, "_NVD_DELAY_WITH_KEY", 0.0, raising=False)

    yield

    reset_default_cache()


class FakeEntity:
    """Minimal stand-in for a normalized entity (only the attrs enrichers read)."""

    def __init__(self, entity_type: str, value: str, confidence: float = 1.0):
        self.entity_type = entity_type
        self.value = value
        self.confidence = confidence
        self.canonical_value = value


class FakeExtractionResult:
    """Shape: ExtractionResult — only ``.entities`` is used by the enrichers."""

    def __init__(self, entities):
        self.entities = entities


def make_results(*entities) -> list:
    """Wrap FakeEntity instances into a one-element extraction-results list."""
    return [FakeExtractionResult(list(entities))]
