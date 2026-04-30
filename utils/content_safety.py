"""
utils/content_safety.py — Mandatory content safety filters for VoidAccess.

Operates at multiple layers: query intake, URL filtering, content scanning,
and post-extraction entity value filtering.
Never logs actual prohibited content — only event metadata.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Optional

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Blocklists
# ---------------------------------------------------------------------------

BLOCKED_TERMS = [
    # CSAM related
    "child porn", "cp porn", "lolita", "pedo",
    "pedophil", "childporn", "child sex", "minor sex",
    "underage sex", "jailbait", "preteen sex",
    "child abuse material", "csam", "child model",
    "hurtcore", "daisy's destruction",
    # Gore related
    "gore site", "gore video", "snuff film",
    "murder video", "execution video", "beheading video",
    "torture video", "bestgore", "livegore",
    "watchpeopledie", "realsnuff",
]

BLOCKED_PATTERNS = [
    r'\bcp\b.{0,20}\bonion\b',      # "cp" near "onion"
    r'\bchild.{0,10}\bnaked\b',
    r'\bminor.{0,10}\bnaked\b',
    r'\bkid.{0,10}\bporn\b',
    r'\bteen.{0,10}\bporn\b',
]

BLOCKED_URL_TERMS = [
    "pedo", "loli", "jailbait", "childporn",
    "hurtcore", "csam", "bestgore", "livegore",
    "watchpeople", "realsnuff", "daisy",
]

CONTENT_BLOCKLIST = [
    "child pornography", "child porn",
    "child sexual abuse", "csam",
    "snuff film", "murder porn",
]

# ---------------------------------------------------------------------------
# Entity value blocklist — applied after extraction, before DB storage
# Only checked against text-based entity types (not technical IOCs)
# ---------------------------------------------------------------------------

ENTITY_VALUE_BLOCKLIST: list[str] = [
    # Adult content categories
    "porn", "blowjob", "bdsm", "hardcore",
    "xxx", "nude", "nudes", "naked", "escort",
    "onlyfans", "cam girl", "sex tape",
    "adult content", "adult site",
    # Gore/violence
    "snuff", "gore", "murder video",
    "execution video", "beheading",
    # Exploitation
    "jailbait", "pedo", "csam",
    "child", "minor",
]

# Entity types where prohibited content can appear as names/labels.
# Technical IOC types (hashes, IPs, CVEs, wallets, onion URLs) are
# intentionally omitted — they cannot contain prohibited content.
_TEXT_ENTITY_TYPES: frozenset[str] = frozenset({
    "ORGANIZATION_NAME",
    "THREAT_ACTOR_HANDLE",
    "PERSON_NAME",
    "MALWARE_FAMILY",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_blocked_query(query: str) -> tuple[bool, str]:
    """
    Check if a query should be blocked.
    Returns (is_blocked, reason).
    Never logs the actual query.
    """
    query_lower = query.lower()

    for term in BLOCKED_TERMS:
        if term in query_lower:
            return True, "Query contains prohibited content"

    for pattern in BLOCKED_PATTERNS:
        if re.search(pattern, query_lower, re.IGNORECASE):
            return True, "Query contains prohibited content"

    return False, ""


def is_blocked_entity_value(entity_type: str, value: str) -> bool:
    """
    Return True if an entity value should be dropped before storage.

    Only applies to text-based entity types where prohibited content can
    appear as organisation/actor names (ORGANIZATION_NAME, THREAT_ACTOR_HANDLE,
    PERSON_NAME, MALWARE_FAMILY).

    Never applies to technical IOC types such as FILE_HASH_*, IP_ADDRESS, CVE,
    ONION_URL, or wallet addresses \u2014 these cannot contain prohibited content
    by definition and are intentionally excluded.

    The check is case-insensitive substring matching against
    ENTITY_VALUE_BLOCKLIST.  The actual value is never logged.
    """
    if entity_type not in _TEXT_ENTITY_TYPES:
        return False

    value_lower = (value or "").lower()
    for term in ENTITY_VALUE_BLOCKLIST:
        if term in value_lower:
            return True

    return False


def is_blocked_url(url: str) -> tuple[bool, str]:
    """
    Check if a URL should be blocked from scraping.
    Returns (is_blocked, reason).
    """
    url_lower = url.lower()
    for term in BLOCKED_URL_TERMS:
        if term in url_lower:
            return True, "URL blocked — prohibited content"
    return False, ""


def sanitize_content(text: str) -> tuple[str, bool]:
    """
    Scan scraped text for CSAM/gore indicators.
    Returns (sanitized_text, was_flagged).
    If flagged, returns empty string — the original text is never stored.
    """
    if not text:
        return text, False

    text_lower = text.lower()
    for term in CONTENT_BLOCKLIST:
        if term in text_lower:
            return "", True

    return text, False


def log_content_safety_event(
    event_type: str,
    content_hash: Optional[str] = None,
    user_id: Optional[int] = None,
) -> None:
    """
    Persist a content safety block event to the DB for operator review.
    Fails silently — never disrupts the calling pipeline.
    event_type: one of "query_blocked", "url_blocked", "content_blocked"
    content_hash: SHA-256 hex prefix (≤16 chars) of the blocked item, for correlation only.
    """
    try:
        import os
        if not os.getenv("DATABASE_URL"):
            return
        from db.session import get_session
        from db.models import ContentSafetyEvent
        from datetime import datetime, timezone

        with get_session() as session:
            event = ContentSafetyEvent(
                event_type=event_type,
                user_id=user_id,
                content_hash=content_hash,
                timestamp=datetime.now(timezone.utc),
            )
            session.add(event)
            session.commit()
    except Exception as exc:
        _logger.debug("content_safety: DB log failed (non-critical): %s", exc)
