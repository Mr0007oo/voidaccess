"""Shared search timeout, retry, and backoff configuration."""

# Keep these values in one module so the CLI and API search paths cannot drift.
# The API path's 30-second timeout is the common baseline.
ENGINE_TIMEOUT = 30
SEARCH_TIMEOUT = 30
ENGINE_RETRY_COUNT = 2
RETRY_BACKOFF_BASE = 0.5


def retry_backoff(attempt: int) -> float:
    """Return the delay before retry number *attempt* (zero-based)."""
    return RETRY_BACKOFF_BASE * (attempt + 1)
