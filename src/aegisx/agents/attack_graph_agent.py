from typing import Dict, Any, List
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI
import json

class AttackGraphIntelligenceAgent(BaseAgent):
    """
    Deterministically transforms flat scan results and evidence into a 
    relational Attack Graph (Phase 5). Does not use LLMs for node creation.
    """
    def __init__(self):
        super().__init__("AttackGraphIntelligenceAgent")

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("Deterministic Attack Graph Builder")
        
        nodes = []
        edges = []
        
        # Add Routes
        for r in state.get("routes", []):
            path = r.get("path", "")
            if path:
                node_id = f"route_{path}"
                nodes.append({
                    "node_id": node_id,
                    "node_type": "Route",
                    "properties": r,
                    "confidence_delta": 0.1
                })
                
        # Add Sessions & Roles
        for s in state.get("sessions", []):
            role = s.get("role", "unknown")
            node_id = f"session_{role}"
            nodes.append({
                "node_id": node_id,
                "node_type": "Session",
                "properties": s,
                "confidence_delta": 0.1
            })
            
            # Edges to authenticated routes
            for auth_route in state.get("authenticated_routes", []):
                edges.append({
                    "source_id": node_id,
                    "target_id": f"route_{auth_route}",
                    "edge_type": "accesses",
                    "properties": {}
                })
                
        # Add Parameters
        for p in state.get("parameters", []):
            name = p.get("name", "")
            route = p.get("route", "")
            if name and route:
                node_id = f"param_{name}_{route}"
                nodes.append({
                    "node_id": node_id,
                    "node_type": "Parameter",
                    "properties": p,
                    "confidence_delta": 0.1
                })
                edges.append({
                    "source_id": f"route_{route}",
                    "target_id": node_id,
                    "edge_type": "owns",
                    "properties": {}
                })
                
        # Add Findings
        for f in state.get("findings", []):
            title = f.get("title", "") if isinstance(f, dict) else getattr(f, "title", "Unknown")
            node_id = f"finding_{title}"
            
            f_dict = f if isinstance(f, dict) else f.model_dump() if hasattr(f, 'model_dump') else {}
            
            nodes.append({
                "node_id": node_id,
                "node_type": "Finding",
                "properties": f_dict,
                "confidence_delta": 0.5
            })
            
            # Try to link to route
            evidence = str(f_dict.get("evidence", ""))
            for r in state.get("routes", []):
                path = r.get("path")
                if path and path in evidence:
                    edges.append({
                        "source_id": node_id,
                        "target_id": f"route_{path}",
                        "edge_type": "exploits",
                        "properties": {}
                    })

        ConsoleUI.success(f"Deterministically built {len(nodes)} nodes and {len(edges)} edges.")
        
        state["graph_mutation"] = {
            "nodes": nodes,
            "edges": edges,
            "attack_paths": [],
            "reasoning": "Deterministic construction from evidence."
        }
        
        return state
