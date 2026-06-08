from typing import Dict, Any, List
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class FindingCorrelationAgent(BaseAgent):
    """
    Stage 6 Agent: Merges duplicate or overlapping vulnerability indicators
    into a single unified finding. (e.g., 10 IDOR indicators on the same route -> 1 IDOR finding)
    """
    def __init__(self):
        super().__init__(agent_id="FindingCorrelationAgent")

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("STAGE 6: Finding Correlation")
        scored_findings = state.get("scored_findings", [])
        
        # Merge logic based on Route + Vulnerability Type
        correlated_map = {}
        for finding in scored_findings:
            key = f"{finding.get('route', 'unknown')}_{finding.get('type', 'unknown')}"
            if key not in correlated_map:
                correlated_map[key] = finding
                correlated_map[key]["indicator_count"] = 1
            else:
                # Merge evidence
                correlated_map[key]["indicator_count"] += 1
                if "merged_evidence" not in correlated_map[key]:
                    correlated_map[key]["merged_evidence"] = []
                correlated_map[key]["merged_evidence"].append(finding.get("evidence", "additional evidence"))

        correlated = list(correlated_map.values())
        
        if correlated:
            ConsoleUI.success(f"Correlated {len(scored_findings)} indicators into {len(correlated)} unified findings.")
            
        self.log_action("correlation_complete", {"correlated_count": len(correlated)})
        
        return {
            "status": "COMPLETED",
            "correlated_findings": correlated
        }
