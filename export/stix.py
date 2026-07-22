"""
export/stix.py — Converts VoidAccess entities and investigations into STIX 2.1 bundles.

Uses the stix2 Python library throughout; no manual JSON construction.

Public interface
----------------
entity_to_stix_indicator(entity)                                    → stix2.Indicator | None
entity_to_stix_malware(entity)                                      → stix2.Malware | None
entity_to_stix_threat_actor(entity)                                 → stix2.ThreatActor | None
investigation_to_stix_bundle(investigation_id, include_relationships) → stix2.Bundle
bundle_to_json(bundle)                                              → str
bundle_to_dict(bundle)                                              → dict
"""

from __future__ import annotations

import json
import logging
import os
import warnings
from typing import Any, Optional
import uuid

logger = logging.getLogger(__name__)

# MED-9: suppress SQLAlchemy SAWarning from ORM IN-clause coercion internals.
# This is a belt-and-suspenders guard — the actual fix for this warning is
# replacing the subquery-IN pattern with a JOIN (Phase 0).  Keeping this filter
# here prevents any residual SAWarnings from leaking to stderr on every export.
try:
    import sqlalchemy
    warnings.filterwarnings(
        "ignore",
        message=r".*IN expression list.*",
        category=sqlalchemy.exc.SAWarning,
    )
except Exception:
    pass  # Non-fatal if sqlalchemy is not installed
_LAST_RELATIONSHIP_WARNING: Optional[str] = None

# ---------------------------------------------------------------------------
# Graceful import of stix2
# ---------------------------------------------------------------------------

try:
    import stix2  # type: ignore
    _STIX2_AVAILABLE = True
except ImportError:
    stix2 = None  # type: ignore
    _STIX2_AVAILABLE = False
    logger.warning(
        "stix2 not installed — export/stix.py functions will return None / empty Bundle"
    )


# ---------------------------------------------------------------------------
# STIX pattern templates per entity type
# ---------------------------------------------------------------------------

_STIX_PATTERNS: dict[str, str] = {
    "BITCOIN_ADDRESS":   "[cryptocurrency-wallet:address = '{value}']",
    "ETHEREUM_ADDRESS":  "[cryptocurrency-wallet:address = '{value}']",
    "MONERO_ADDRESS":    "[cryptocurrency-wallet:address = '{value}']",
    "EMAIL_ADDRESS":     "[email-message:from_ref.value = '{value}']",
    "FILE_HASH_MD5":     "[file:hashes.MD5 = '{value}']",
    "FILE_HASH_SHA1":    "[file:hashes.'SHA-1' = '{value}']",
    "FILE_HASH_SHA256":  "[file:hashes.'SHA-256' = '{value}']",
    "ONION_URL":         "[url:value = '{value}']",
    "IP_ADDRESS":        "[ipv4-addr:value = '{value}']",
    "CVE_NUMBER":        "[vulnerability:name = '{value}']",
    "MALWARE_FAMILY":    "[malware:name = '{value}']",
    "RANSOMWARE_GROUP":  "[malware:name = '{value}']",
}

# Entity types that map to STIX Malware objects
_MALWARE_TYPES = frozenset({"MALWARE_FAMILY", "RANSOMWARE_GROUP"})

# ---------------------------------------------------------------------------
# Confidence mapping: VoidAccess float → STIX integer (0-100)
# ---------------------------------------------------------------------------


def _to_stix_confidence(confidence: float) -> int:
    return min(100, max(0, int(round(confidence * 100))))


# ---------------------------------------------------------------------------
# Public conversion functions
# ---------------------------------------------------------------------------


def entity_to_stix_indicator(entity: Any) -> Optional[Any]:
    """
    Convert a single NormalizedEntity to a STIX 2.1 Indicator object.

    Returns None for entity types without a clear STIX pattern mapping,
    and returns None (with a warning) if stix2 is not installed.
    """
    if not _STIX2_AVAILABLE:
        return None

    pattern_template = _STIX_PATTERNS.get(entity.entity_type)
    if pattern_template is None:
        return None

    safe_value = entity.value.replace("'", "\\'")
    pattern = pattern_template.format(value=safe_value)

    # Determine indicator_types from entity_type
    indicator_types = ["unknown"]
    etype = entity.entity_type
    if etype in ("MALWARE_FAMILY", "RANSOMWARE_GROUP"):
        indicator_types = ["malicious-activity"]
    elif etype in ("BITCOIN_ADDRESS", "ETHEREUM_ADDRESS", "MONERO_ADDRESS"):
        indicator_types = ["malicious-activity"]
    elif etype in ("FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256"):
        indicator_types = ["malicious-activity"]
    elif etype in ("IP_ADDRESS", "ONION_URL"):
        indicator_types = ["malicious-activity"]
    elif etype == "CVE_NUMBER":
        indicator_types = ["compromised"]

    try:
        indicator = stix2.Indicator(
            name=f"{entity.entity_type}: {entity.value[:80]}",
            pattern=pattern,
            pattern_type="stix",
            indicator_types=indicator_types,
            confidence=_to_stix_confidence(entity.confidence),
            allow_custom=True,
            x_voidaccess_source_quality=getattr(entity, "source_quality", 1.0),
            external_references=(
                [{"source_name": "voidaccess", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return indicator
    except Exception as exc:
        logger.warning("entity_to_stix_indicator failed for %r: %s", entity.value, exc)
        return None


def entity_to_stix_malware(entity: Any) -> Optional[Any]:
    """
    Convert a MALWARE_FAMILY or RANSOMWARE_GROUP entity to a STIX 2.1 Malware object.

    Returns None for all other entity types.
    """
    if not _STIX2_AVAILABLE:
        return None

    if entity.entity_type not in _MALWARE_TYPES:
        return None

    try:
        malware = stix2.Malware(
            name=entity.value,
            is_family=True,
            confidence=_to_stix_confidence(entity.confidence),
            allow_custom=True,
            x_voidaccess_source_quality=getattr(entity, "source_quality", 1.0),
            external_references=(
                [{"source_name": "voidaccess", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return malware
    except Exception as exc:
        logger.warning("entity_to_stix_malware failed for %r: %s", entity.value, exc)
        return None


def entity_to_stix_threat_actor(entity: Any) -> Optional[Any]:
    """
    Convert a THREAT_ACTOR_HANDLE entity to a STIX 2.1 ThreatActor object.

    Returns None for all other entity types.
    """
    if not _STIX2_AVAILABLE:
        return None

    if entity.entity_type != "THREAT_ACTOR_HANDLE":
        return None

    try:
        threat_actor = stix2.ThreatActor(
            name=entity.value,
            aliases=[entity.value],
            confidence=_to_stix_confidence(entity.confidence),
            allow_custom=True,
            x_voidaccess_source_quality=getattr(entity, "source_quality", 1.0),
            external_references=(
                [{"source_name": "voidaccess", "url": entity.source_url}]
                if entity.source_url
                else []
            ),
        )
        return threat_actor
    except Exception as exc:
        logger.warning(
            "entity_to_stix_threat_actor failed for %r: %s", entity.value, exc
        )
        return None


def investigation_to_stix_bundle(
    investigation_id: Any,
    include_relationships: bool = True,
    entity_ids: Optional[list[str]] = None,
) -> Any:
    """
    Load all entities for an investigation and return a STIX 2.1 Bundle.

    If include_relationships=True, adds STIX Relationship objects for entity pairs
    that have edges in the graph (loaded via graph.build_graph_from_db).

    Returns an empty Bundle if:
    - stix2 is not installed
    - DATABASE_URL is not set
    - investigation not found
    """
    if not _STIX2_AVAILABLE:
        _set_relationship_warning("stix2 is not installed")
        return _empty_bundle()

    filter_uuids: Optional[list[uuid.UUID]] = None
    if entity_ids:
        filter_uuids = []
        for raw in entity_ids:
            try:
                filter_uuids.append(uuid.UUID(str(raw)))
            except (ValueError, AttributeError):
                continue
        if not filter_uuids:
            return _empty_bundle()

    entities = _load_entities_for_investigation(investigation_id, entity_ids=filter_uuids)
    if not entities:
        return _empty_bundle()

    try:
        from graph.builder import _make_node_id  # noqa: PLC0415
    except Exception:  # pragma: no cover — graph layer optional
        def _make_node_id(entity_type, value, source_url):  # type: ignore
            return value

    stix_objects: list[Any] = []
    # Maps BOTH the raw entity.value AND the graph node_id → stix_object.id.
    # Graph edges are keyed by node_id (which for THREAT_ACTOR_HANDLE is
    # "value@domain", not the bare value), so registering only entity.value
    # here silently dropped every threat-actor relationship — the exact
    # "silently dropped relationships" failure mode the CHANGELOG keeps
    # re-fixing.  Registering the node_id alias lets typed edges (which very
    # often have a threat-actor endpoint) survive into the bundle.
    stix_id_map: dict[str, str] = {}

    def _register(entity: Any, stix_id: str) -> None:
        stix_id_map.setdefault(entity.value, stix_id)
        try:
            node_id = _make_node_id(
                entity.entity_type,
                entity.value,
                getattr(entity, "source_url", "") or "",
            )
        except Exception:
            node_id = entity.value
        if node_id:
            stix_id_map.setdefault(node_id, stix_id)

    for entity in entities:
        indicator = entity_to_stix_indicator(entity)
        if indicator:
            stix_objects.append(indicator)
            _register(entity, indicator.id)

        malware = entity_to_stix_malware(entity)
        if malware:
            stix_objects.append(malware)
            _register(entity, malware.id)

        actor = entity_to_stix_threat_actor(entity)
        if actor:
            stix_objects.append(actor)
            _register(entity, actor.id)

    if include_relationships and stix_objects:
        relationships, relationship_warning = _build_stix_relationships(
            investigation_id, stix_id_map
        )
        stix_objects.extend(relationships)
        _set_relationship_warning(relationship_warning)
    else:
        _set_relationship_warning(None)

    try:
        return stix2.Bundle(*stix_objects, allow_custom=True)
    except Exception as exc:
        logger.warning("investigation_to_stix_bundle: Bundle construction failed: %s", exc)
        return _empty_bundle()


def bundle_to_json(bundle: Any) -> str:
    """Return JSON string of a STIX bundle (pretty-printed, 2-space indent)."""
    if not _STIX2_AVAILABLE or bundle is None:
        return "{}"
    try:
        return bundle.serialize(pretty=True, indent=2)
    except Exception as exc:
        logger.warning("bundle_to_json failed: %s", exc)
        return "{}"


def bundle_to_dict(bundle: Any) -> dict:
    """Return a plain Python dict representation of the bundle (no stix2 objects)."""
    if not _STIX2_AVAILABLE or bundle is None:
        return {}
    try:
        raw = bundle_to_json(bundle)
        return json.loads(raw)
    except Exception as exc:
        logger.warning("bundle_to_dict failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _empty_bundle() -> Any:
    """Return an empty STIX Bundle, or a plain dict sentinel if stix2 absent."""
    if not _STIX2_AVAILABLE:
        return None
    try:
        return stix2.Bundle(allow_custom=True)
    except Exception:
        return stix2.Bundle()


def _set_relationship_warning(message: Optional[str]) -> None:
    global _LAST_RELATIONSHIP_WARNING
    _LAST_RELATIONSHIP_WARNING = message


def get_last_relationship_warning() -> Optional[str]:
    """Return the last relationship-build warning, if any."""
    return _LAST_RELATIONSHIP_WARNING


def _load_entities_for_investigation(
    investigation_id: Any,
    entity_ids: Optional[list[uuid.UUID]] = None,
    session: Optional[Any] = None,
) -> list[Any]:
    """
    Load entities from DB for the given investigation_id.

    Includes entities owned directly by the investigation AND entities linked
    via InvestigationEntityLink (canonical dedup junction table).

    Parameters
    ----------
    investigation_id: UUID or string UUID of the investigation.
    entity_ids: Optional list of entity UUIDs to filter to.
    session: Optional existing SQLAlchemy Session. When provided, the caller
        controls the session boundary (commits, rollbacks). When None (the
        default), this function opens its own session via get_session() and
        commits on exit. Exposing session enables test injection of the
        fixture's session so the function sees uncommitted data.

    Returns [] if DATABASE_URL is not set, investigation not found, or any error.
    """
    if session is None and not os.getenv("DATABASE_URL"):
        return []

    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import get_investigation_by_id_or_run  # noqa: PLC0415
        from db.models import Entity, InvestigationEntityLink  # noqa: PLC0415
        from extractor.normalizer import NormalizedEntity  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        if inv_uuid is None:
            return []

        def _do_query(sess: Any) -> list[Any]:
            nonlocal inv_uuid
            inv = get_investigation_by_id_or_run(sess, inv_uuid)
            if inv is None:
                return []

            direct_q = sess.query(Entity).filter(Entity.investigation_id == inv.id)
            linked_q = (
                sess.query(Entity)
                .join(
                    InvestigationEntityLink,
                    InvestigationEntityLink.entity_id == Entity.id,
                )
                .filter(InvestigationEntityLink.investigation_id == inv.id)
            )
            db_entities = direct_q.union(linked_q).all()

            if entity_ids is not None:
                want = frozenset(entity_ids)
                db_entities = [e for e in db_entities if e.id in want]

            result: list[NormalizedEntity] = []
            for e in db_entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass
                result.append(NormalizedEntity(
                    entity_type=e.entity_type,
                    value=e.canonical_value or e.value,
                    confidence=e.confidence,
                    source_url=source_url,
                    page_id=e.page_id,
                    context_snippet=e.context_snippet or "",
                    extraction_method="db",
                    source_quality=getattr(e, "source_quality", 1.0),
                ))
            return result

        if session is not None:
            return _do_query(session)
        with get_session() as sess:
            return _do_query(sess)

    except Exception as exc:
        logger.warning("_load_entities_for_investigation failed: %s", exc)
        return []


def _build_stix_relationships(
    investigation_id: Any,
    stix_id_map: dict[str, str],
) -> tuple[list[Any], Optional[str]]:
    """
    Build STIX Relationship objects from graph edges for the investigation.

    Returns [] on any error.
    """
    if not _STIX2_AVAILABLE:
        return [], "stix2 is not installed"
    try:
        from graph.builder import build_graph_from_db  # noqa: PLC0415

        inv_uuid = _coerce_uuid(investigation_id)
        graph = build_graph_from_db(investigation_id=inv_uuid)

        relationships: list[Any] = []
        seen_relationships: set[tuple[str, str, str]] = set()
        for source_node, target_node, data in graph.edges(data=True):
            src_stix_id = stix_id_map.get(source_node)
            tgt_stix_id = stix_id_map.get(target_node)
            if not src_stix_id or not tgt_stix_id:
                continue
            edge_type = data.get("edge_type", "related-to")
            # Map VoidAccess edge types to STIX relationship types
            rel_type = _edge_type_to_stix(edge_type)
            relationship_key = (rel_type, src_stix_id, tgt_stix_id)
            if relationship_key in seen_relationships:
                continue
            seen_relationships.add(relationship_key)
            # Carry the edge's own confidence onto the SRO.  Typed relationships
            # have a claim-specific confidence distinct from co-occurrence's
            # flat value; STIX 2.1 confidence is an int 0-100.
            rel_kwargs: dict[str, Any] = {
                "relationship_type": rel_type,
                "source_ref": src_stix_id,
                "target_ref": tgt_stix_id,
                "allow_custom": True,
            }
            try:
                edge_conf = data.get("confidence")
                if edge_conf is not None:
                    rel_kwargs["confidence"] = _to_stix_confidence(float(edge_conf))
            except (TypeError, ValueError):
                pass
            try:
                rel = stix2.Relationship(**rel_kwargs)
                relationships.append(rel)
            except Exception:
                # Retry without confidence in case the value tripped validation.
                try:
                    rel_kwargs.pop("confidence", None)
                    relationships.append(stix2.Relationship(**rel_kwargs))
                except Exception:
                    continue
        return relationships, None
    except Exception as exc:
        logger.warning("_build_stix_relationships failed: %s", exc)
        return [], f"_build_stix_relationships failed: {exc}"


def _edge_type_to_stix(edge_type: str) -> str:
    """Map VoidAccess graph edge types to STIX relationship type strings."""
    mapping = {
        "CO_APPEARED_ON": "related-to",
        "CO_INVESTIGATION": "related-to",
        "POSTED_BY": "attributed-to",
        "LINKED_TO": "related-to",
        "PAID_TO": "related-to",
        "MEMBER_OF": "member-of",
        "USED": "uses",
        "CLAIMED": "attributed-to",
        "LIKELY_SAME_ACTOR": "related-to",
        "CONFIRMED_SAME_ACTOR": "related-to",
        "FUNDED_BY": "related-to",
        # Typed relationships from the LLM relationship-extraction pass.  These
        # map to documented STIX 2.1 common relationship types where one
        # exists; CONTROLS has no standard STIX verb so it degrades to the
        # safe "related-to" default rather than emitting a non-spec type.
        "DROPS": "drops",
        "TARGETS": "targets",
        "EXPLOITS": "exploits",
        "COMMUNICATES_WITH": "communicates-with",
        "CONTROLS": "related-to",
    }
    return mapping.get(edge_type, "related-to")


def _coerce_uuid(value: Any) -> Optional[uuid.UUID]:
    """Try to coerce an arbitrary value to uuid.UUID. Returns None on failure."""
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None
