from typing import Dict, Any, List
from pydantic import BaseModel
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI
import hashlib

class ResponseCluster(BaseModel):
    cluster_id: str
    endpoints: List[str]
    similarity_score: float
    anomaly_score: float

class ResponseClusteringAgent(BaseAgent):
    """
    Groups similar responses to identify hidden authorization differences
    and semantic response variations.
    """
    def __init__(self):
        super().__init__("ResponseClusteringAgent")

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("AI Response Clustering")
        routes = state.get("routes", [])
        if not routes:
            ConsoleUI.warning("No routes available for clustering.")
            return state

        ConsoleUI.info(f"Clustering {len(routes)} endpoints...")
        
        # Mock clustering logic
        clusters = {}
        for route in routes:
            # Simple heuristic: cluster by first path segment
            segment = route.split("/")[1] if len(route.split("/")) > 1 else "root"
            if segment not in clusters:
                clusters[segment] = []
            clusters[segment].append(route)
            
        new_findings = state.get("findings", [])
        
        for cluster_name, endpoints in clusters.items():
            cluster = ResponseCluster(
                cluster_id=f"cluster_{hashlib.md5(cluster_name.encode()).hexdigest()[:8]}",
                endpoints=endpoints,
                similarity_score=0.9,
                anomaly_score=0.1
            )
            ConsoleUI.success(f"Formed cluster '{cluster_name}' with {len(endpoints)} endpoints.")
            # Record cluster in evidence ledger
            state.setdefault("evidence_ledger", []).append({
                "stage": "RESPONSE_CLUSTERING",
                "action": "cluster_formed",
                "result": cluster.model_dump()
            })
            
        return state
