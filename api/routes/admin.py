"""
Admin routes for VoidAccess API.

Provides administrative endpoints for monitoring and managing the system.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends

from api.auth import get_current_user
from search.search import SEARCH_ENGINES
from search.circuit_breaker import get_all_states, record_success, is_open, _engine_failures, _engine_last_success

router = APIRouter(tags=["admin"])


@router.get("/circuit-breakers")
async def get_circuit_breakers(current_user=Depends(get_current_user)) -> dict:
    """
    Get the current state of all search engine circuit breakers.
    Returns state, failure count, and last success timestamp for each engine.
    """
    engines = {}
    for engine in SEARCH_ENGINES:
        name = engine["name"]
        failures = _engine_failures.get(name, 0)
        open_state = await is_open(name)
        engines[name] = {
            "state": "open" if open_state else "closed",
            "failure_count": failures,
            "url": engine.get("url", "").split("{")[0]  # strip query param
        }
    return {"engines": engines}


@router.post("/circuit-breakers/{engine_name}/reset", dependencies=[Depends(get_current_user)])
async def reset_circuit_breaker(engine_name: str) -> dict:
    """Reset a circuit breaker to closed state manually."""
    await record_success(engine_name)
    return {"engine": engine_name, "state": "closed", "message": "Circuit breaker reset"}


@router.post("/circuit-breakers/reset-all", dependencies=[Depends(get_current_user)])
async def reset_all_circuit_breakers() -> dict:
    """Reset all circuit breakers to closed state."""
    from search.search import SEARCH_ENGINES
    for engine in SEARCH_ENGINES:
        await record_success(engine["name"])
    return {"reset_count": len(SEARCH_ENGINES), "state": "all closed"}


@router.get("/content-safety/events", dependencies=[Depends(get_current_user)])
async def get_content_safety_events() -> dict:
    """
    Return content safety block event counts for operator review.
    Returns counts only — never the blocked content itself.
    """
    try:
        import os
        if not os.getenv("DATABASE_URL"):
            return {
                "last_24h": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
                "total": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
            }

        from db.session import get_session
        from db.models import ContentSafetyEvent
        from sqlalchemy import func

        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

        event_types = ["query_blocked", "url_blocked", "content_blocked"]

        with get_session() as session:
            last_24h: dict[str, int] = {}
            total: dict[str, int] = {}
            for et in event_types:
                last_24h[et] = int(
                    session.query(func.count(ContentSafetyEvent.id))
                    .filter(
                        ContentSafetyEvent.event_type == et,
                        ContentSafetyEvent.timestamp >= cutoff,
                    )
                    .scalar()
                    or 0
                )
                total[et] = int(
                    session.query(func.count(ContentSafetyEvent.id))
                    .filter(ContentSafetyEvent.event_type == et)
                    .scalar()
                    or 0
                )

        return {"last_24h": last_24h, "total": total}

    except Exception as exc:
        return {
            "error": str(exc)[:200],
            "last_24h": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
            "total": {"query_blocked": 0, "url_blocked": 0, "content_blocked": 0},
        }