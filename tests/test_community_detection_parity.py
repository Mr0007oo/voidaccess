"""API/CLI community-detection parity checks."""

from __future__ import annotations

import networkx as nx
from unittest.mock import MagicMock, patch
import uuid


def _grouping(partition: dict[str, int]) -> set[frozenset[str]]:
    groups: dict[int, set[str]] = {}
    for node_id, community_id in partition.items():
        groups.setdefault(community_id, set()).add(node_id)
    return {frozenset(nodes) for nodes in groups.values()}


def test_api_graph_adapter_matches_cli_graph_shape_for_detection():
    """The API adapter and CLI's simple Graph produce the same partition."""
    from api.routes.investigations import _detect_communities_for_graph
    from graph.builder import detect_communities

    api_graph = nx.MultiDiGraph()
    api_graph.add_edges_from(
        [
            ("actor-a", "malware-a"),
            ("malware-a", "infra-a"),
            ("infra-a", "actor-a"),
            ("actor-b", "malware-b"),
            ("malware-b", "infra-b"),
            ("infra-b", "actor-b"),
        ]
    )

    api_partition = _detect_communities_for_graph(api_graph)
    cli_graph = nx.Graph(api_graph)
    cli_partition = detect_communities(cli_graph)

    assert _grouping(api_partition) == _grouping(cli_partition)
    assert set(api_partition) == set(api_graph.nodes)


def test_api_detection_uses_complete_graph_not_display_slice():
    """Detection includes nodes beyond the graph endpoint's display limit."""
    from api.routes.investigations import _detect_communities_for_graph

    graph = nx.MultiDiGraph()
    graph.add_edges_from((f"node-{i}", f"node-{i + 1}") for i in range(5))

    partition = _detect_communities_for_graph(graph)

    assert set(partition) == {f"node-{i}" for i in range(6)}


async def test_api_graph_phase_detects_before_returning_to_finalize():
    """The API graph phase invokes detection after persistence, pre-finalize."""
    from api.routes import investigations

    graph = nx.MultiDiGraph()
    graph.add_edges_from(
        [("actor", "malware"), ("malware", "infra"), ("infra", "actor")]
    )
    events: list[str] = []
    session = MagicMock()
    session_context = MagicMock()
    session_context.__enter__.return_value = session
    session_context.__exit__.return_value = False

    with (
        patch("graph.builder.build_graph_from_db", return_value=graph),
        patch("graph.builder.infer_relationships", side_effect=lambda value: value),
        patch(
            "api.routes.investigations._persist_graph_edges_sync",
            side_effect=lambda *_args: (
                events.append("persist") or {"status": "written", "edges_written": 3}
            ),
        ),
        patch(
            "api.routes.investigations._detect_communities_for_graph",
            side_effect=lambda _graph: (events.append("detect") or {"actor": 0, "malware": 0, "infra": 0}),
        ),
        patch(
            "api.routes.investigations._set_communities",
            side_effect=lambda *_args: events.append("store"),
        ),
        patch("db.session.get_session", return_value=session_context),
    ):
        result = await investigations._build_graph_phase(
            [], uuid.uuid4(), uuid.uuid4()
        )

    assert result is True
    assert events == ["persist", "detect", "store"]
