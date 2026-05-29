from typing import Dict, Any
from aegisx.core.analysis.attack_graph import ExposureGraph, NodeType, EdgeType
from aegisx.core.ui.console import ConsoleUI

class GraphLearningEngine:
    """
    Applies the AI's proposed GraphMutations to the actual NetworkX ExposureGraph.
    Tracks memory and prevents infinite loops.
    """
    
    @staticmethod
    def apply_learning(state: Dict[str, Any]) -> Dict[str, Any]:
        mutation_dict = state.get("graph_mutation")
        if not mutation_dict:
            return state
            
        ConsoleUI.info("Applying Graph Intelligence mutations to persistent memory...")
        
        # Load the graph
        graph = ExposureGraph()
        graph.from_dict(state.get("serialized_graph", {}))
        
        # Load memory of seen nodes
        graph_memory = state.get("graph_memory", {"seen_nodes": [], "failed_paths": []})
        seen_nodes = set(graph_memory["seen_nodes"])
        
        nodes_added = 0
        edges_added = 0
        
        # Apply Node Mutations
        for node in mutation_dict.get("nodes", []):
            node_id = node["node_id"]
            
            # Map string to enum
            try:
                ntype = NodeType(node["node_type"])
            except ValueError:
                ntype = NodeType.POTENTIAL_WEAKNESS
                
            if node_id not in seen_nodes:
                graph.add_node(node_id, ntype, node.get("properties", {}))
                seen_nodes.add(node_id)
                nodes_added += 1
            elif node.get("confidence_delta", 0) > 0:
                # Update confidence if it exists and AI requested a boost
                graph.update_confidence(node_id, node["confidence_delta"], source="AttackGraphIntelligenceAgent")
                
        # Apply Edge Mutations
        for edge in mutation_dict.get("edges", []):
            try:
                etype = EdgeType(edge["edge_type"])
            except ValueError:
                etype = EdgeType.TRUSTS
                
            graph.add_edge(edge["source_id"], edge["target_id"], etype, edge.get("properties", {}))
            edges_added += 1
            
        # Apply Attack Paths
        for path in mutation_dict.get("attack_paths", []):
            if path not in state.get("attack_paths", []):
                state["attack_paths"] = state.get("attack_paths", []) + [path]
                
        # Save back to state
        state["serialized_graph"] = graph.to_dict()
        graph_memory["seen_nodes"] = list(seen_nodes)
        state["graph_memory"] = graph_memory
        
        # Clean up the mutation so it doesn't get applied twice
        state.pop("graph_mutation", None)
        
        ConsoleUI.success(f"Graph Learning Complete. Current Graph Size: {len(seen_nodes)} nodes.")
        
        return state
