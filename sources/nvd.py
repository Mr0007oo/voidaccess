"""
sources/nvd.py — NVD 2.0 (National Vulnerability Database) CVE enrichment.

Fills a real gap in the pipeline. Today, when a CVE is extracted as an entity,
the only enrichment is checking whether it appears in CISA's Known Exploited
Vulnerabilities list (``sources/cisa.py``) — a small subset of all CVEs. NVD
2.0 is NIST's authoritative, complete CVE dataset, so ANY extracted CVE can be
enriched with its severity score, description, weaknesses (CWE), and publication
date, regardless of KEV membership.

Runs alongside CISA (both surface complementary facts) inside the Phase-A
``_enrich_new_sources`` fan-out. Reports into ``sources_used`` under ``nvd``.

Auth: works without a key. An optional free NVD_API_KEY raises the rate limit
(NVD documents 5 requests / 30s without a key, 50 / 30s with one), following the
same optional-key pattern as every other source in this project.

Public interface
----------------
async fetch_nvd_cve(cve_id)          → dict | None
async enrich_nvd(entities)           → list[dict]
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Optional

import aiohttp

from utils.enrichment_cache import DEFAULT_TTL, get_enrichment_cache

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Per-investigation cap and pacing. NVD is strict without a key (5 req / 30s),
# so we pace conservatively and keep a soft time budget so a CVE-heavy query
# never blows the enclosing Phase-A deadline.
MAX_CVES_PER_INVESTIGATION = 15
_NVD_DELAY_NO_KEY = 6.5    # seconds between requests (≈5 per 30s window)
_NVD_DELAY_WITH_KEY = 0.7  # seconds between requests (≈50 per 30s window)
_NVD_SOFT_BUDGET = 45.0    # stop issuing new requests after this many seconds

DEFAULT_TTL.setdefault("nvd", 259200)  # 72 h — CVE metadata is fairly stable

_enrichment_cache_singleton: Optional[Any] = None

# Loose CVE-id shape guard; the extractor emits canonical CVE-YYYY-NNNN+ strings.
import re as _re
_CVE_RE = _re.compile(r"^CVE-\d{4}-\d{4,}$", _re.I)


async def _get_enrichment_cache():
    global _enrichment_cache_singleton
    if _enrichment_cache_singleton is None:
        _enrichment_cache_singleton = await get_enrichment_cache()
    return _enrichment_cache_singleton


def _api_key() -> str:
    return (os.getenv("NVD_API_KEY") or "").strip()


def _request_delay() -> float:
    return _NVD_DELAY_WITH_KEY if _api_key() else _NVD_DELAY_NO_KEY


def _parse_cve(cve: dict) -> dict[str, Any]:
    """Extract the fields we care about from an NVD 2.0 ``cve`` object."""
    cve_id = cve.get("id", "")

    # Description — prefer English.
    description = ""
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en":
            description = d.get("value", "")
            break

    # CVSS — prefer v3.1, then v3.0, then v2.
    base_score: Optional[float] = None
    base_severity = ""
    vector = ""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr and isinstance(arr, list):
            cdata = (arr[0] or {}).get("cvssData") or {}
            base_score = cdata.get("baseScore")
            base_severity = cdata.get("baseSeverity", "") or ""
            vector = cdata.get("vectorString", "") or ""
            break
    if base_score is None:
        arr = metrics.get("cvssMetricV2") or []
        if arr and isinstance(arr, list):
            entry = arr[0] or {}
            cdata = entry.get("cvssData") or {}
            base_score = cdata.get("baseScore")
            base_severity = entry.get("baseSeverity", "") or ""
            vector = cdata.get("vectorString", "") or ""

    # Weaknesses (CWE).
    cwes: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in (w.get("description") or []):
            val = d.get("value", "")
            if val and val not in cwes:
                cwes.append(val)

    return {
        "source": "nvd",
        "entity_type": "CVE_NUMBER",
        "entity_value": cve_id,
        "description": description,
        "base_score": base_score,
        "base_severity": base_severity,
        "vector": vector,
        "cwes": cwes,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "vuln_status": cve.get("vulnStatus", ""),
    }


async def fetch_nvd_cve(cve_id: str, session: Optional[aiohttp.ClientSession] = None) -> Optional[dict]:
    """
    Fetch a single CVE from NVD 2.0. Returns a parsed result dict, or None on
    error / not-found. Cached by (CVE_NUMBER, cve_id, "nvd").
    """
    if not _CVE_RE.match(cve_id or ""):
        return None
    cve_id = cve_id.upper()

    cache = await _get_enrichment_cache()
    cached = await cache.get("CVE_NUMBER", cve_id, "nvd")
    if cached is not None:
        logger.debug("NVD cache hit: %s", cve_id)
        return cached

    headers = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    key = _api_key()
    if key:
        headers["apiKey"] = key

    owns_session = session is None
    try:
        if owns_session:
            timeout = aiohttp.ClientTimeout(total=20)
            session = aiohttp.ClientSession(timeout=timeout, headers=headers)
        assert session is not None
        async with session.get(_NVD_BASE_URL, params={"cveId": cve_id}) as resp:
            if resp.status == 404:
                return None
            if resp.status == 403 or resp.status == 429:
                logger.warning("NVD: rate limited (HTTP %s) for %s", resp.status, cve_id)
                return None
            if resp.status != 200:
                logger.debug("NVD: HTTP %s for %s", resp.status, cve_id)
                return None
            data = await resp.json(content_type=None)
    except asyncio.TimeoutError:
        logger.warning("NVD: timed out for %s", cve_id)
        return None
    except Exception as exc:
        logger.debug("NVD: error for %s: %s", cve_id, exc)
        return None
    finally:
        if owns_session and session is not None:
            await session.close()

    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    cve_obj = (vulns[0] or {}).get("cve") or {}
    if not cve_obj:
        return None

    result = _parse_cve(cve_obj)
    # Cache successful lookups only.
    await cache.set("CVE_NUMBER", cve_id, "nvd", result, DEFAULT_TTL["nvd"])
    return result


async def enrich_nvd(entities: list[dict]) -> list[dict]:
    """
    For each CVE_NUMBER entity, fetch NVD 2.0 metadata.

    Rate-limited (key-aware) and capped at MAX_CVES_PER_INVESTIGATION, with a
    soft time budget so a CVE-heavy investigation returns partial results rather
    than blowing the enclosing Phase-A deadline.
    """
    cve_ids: list[str] = []
    seen: set[str] = set()
    for e in entities:
        et = e.get("type") or e.get("entity_type", "")
        ev = (e.get("value") or e.get("entity_value", "") or "").upper()
        if et == "CVE_NUMBER" and ev and _CVE_RE.match(ev) and ev not in seen:
            seen.add(ev)
            cve_ids.append(ev)

    if not cve_ids:
        return []

    cve_ids = cve_ids[:MAX_CVES_PER_INVESTIGATION]
    delay = _request_delay()
    logger.info(
        "NVD: enriching %d CVE(s) (key=%s, delay=%.1fs)",
        len(cve_ids), "yes" if _api_key() else "no", delay,
    )

    results: list[dict] = []
    started = time.monotonic()

    headers = {
        "User-Agent": "VoidAccess-OSINT/1.1 (security research)",
        "Accept": "application/json",
    }
    key = _api_key()
    if key:
        headers["apiKey"] = key

    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        for idx, cve_id in enumerate(cve_ids):
            if time.monotonic() - started > _NVD_SOFT_BUDGET:
                logger.warning(
                    "NVD: soft time budget (%.0fs) reached — enriched %d of %d CVEs",
                    _NVD_SOFT_BUDGET, len(results), len(cve_ids),
                )
                break
            result = await fetch_nvd_cve(cve_id, session=session)
            if result is not None:
                results.append(result)
            # Pace between requests, but not after the last one.
            if idx < len(cve_ids) - 1:
                await asyncio.sleep(delay)

    logger.info("NVD: %d CVE(s) enriched", len(results))
    return results
