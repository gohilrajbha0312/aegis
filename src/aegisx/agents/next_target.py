from typing import Dict, Any, List
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class NextTargetAgent(BaseAgent):
    """
    Stage 7 Agent: Marks routes as analyzed and selects the next target
    based on priority. (Unanalyzed routes -> New params -> New roles)
    """
    def __init__(self):
        super().__init__(agent_id="NextTargetAgent")

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("STAGE 7: Next Target Selection")
        
        analyzed_routes = state.get("analyzed_routes", [])
        all_routes = state.get("routes", [])
        
        # Mark current target as analyzed
        current = state.get("target")
        if current and current not in analyzed_routes:
            analyzed_routes.append(current)
            
        # Priority 1: Unanalyzed routes
        next_target = None
        for r in all_routes:
            route_str = r if isinstance(r, str) else r.get("route", str(r))
            if route_str not in analyzed_routes:
                next_target = route_str
                break
                
        if next_target:
            ConsoleUI.info(f"Selected Next Target: {next_target}")
        else:
            ConsoleUI.warning("No unanalyzed routes remaining in current graph.")

        self.log_action("target_selection_complete", {"next_target": next_target})
        
        return {
            "status": "COMPLETED",
            "analyzed_routes": analyzed_routes,
            "next_target": next_target
        }
