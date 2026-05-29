import networkx as nx
from typing import List, Dict, Any
from enum import Enum

class NodeType(Enum):
    EXTERNAL_ASSET = "External Asset"
    SERVICE = "Service"
    TECHNOLOGY = "Technology"
    IDENTITY_BOUNDARY = "Identity Boundary"
    CLOUD_RESOURCE = "Cloud Resource"
    API_SURFACE = "API Surface"
    TRUST_RELATIONSHIP = "Trust Relationship"
    OBSERVABILITY_SURFACE = "Observability Surface"
    POTENTIAL_WEAKNESS = "Potential Weakness"
    GOVERNANCE_GAP = "Governance Gap"

class EdgeType(Enum):
    REACHABLE_FROM = "reachable_from"
    TRUSTS = "trusts"
    EXPOSES = "exposes"
    PROXIES = "proxies"
    AUTHENTICATES_TO = "authenticates_to"
    FEDERATES_WITH = "federates_with"
    LEAKS_METADATA_TO = "leaks_metadata_to"
    SHARES_SESSION_BOUNDARY = "shares_session_boundary"
    HAS_CLOUD_ROLE = "has_cloud_role"
    PUBLISHES_METRICS_TO = "publishes_metrics_to"

class ExposureGraph:
    """
    Models the Attack Surface as a Directed Acyclic Graph.
    Uses NetworkX to correlate exposure chains and privilege relationships.
    """
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_node(self, node_id: str, node_type: NodeType, properties: Dict[str, Any] = None):
        if properties is None:
            properties = {}
        self.graph.add_node(node_id, node_type=node_type.value, **properties)

    def add_edge(self, source_id: str, target_id: str, edge_type: EdgeType, properties: Dict[str, Any] = None):
        if properties is None:
            properties = {}
        # Ensure nodes exist
        if source_id not in self.graph:
            self.add_node(source_id, NodeType.POTENTIAL_WEAKNESS) # Fallback type
        if target_id not in self.graph:
            self.add_node(target_id, NodeType.POTENTIAL_WEAKNESS)
            
        self.graph.add_edge(source_id, target_id, relationship=edge_type.value, **properties)

    def get_lateral_paths(self, start_node: str, target_type: NodeType = NodeType.CLOUD_RESOURCE) -> List[List[str]]:
        """
        Uses NetworkX pathfinding to find routes from an entrypoint to high-value targets.
        """
        if start_node not in self.graph:
            return []
            
        targets = [n for n, attr in self.graph.nodes(data=True) if attr.get('node_type') == target_type.value]
        paths = []
        for target in targets:
            try:
                # Find all simple paths (avoids cycles)
                for path in nx.all_simple_paths(self.graph, source=start_node, target=target):
                    paths.append(path)
            except nx.NetworkXNoPath:
                continue
        return paths

    def export_graphml(self, filepath: str):
        """Exports the graph to GraphML format for visualizers like Neo4j or BloodHound."""
        nx.write_graphml(self.graph, filepath)
        
    def to_dict(self) -> Dict[str, Any]:
        """Serializes graph to a dictionary for reporting."""
        from networkx.readwrite import json_graph
        return json_graph.node_link_data(self.graph)
