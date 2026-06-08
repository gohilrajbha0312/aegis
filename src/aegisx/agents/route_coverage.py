from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class RouteCoverageAgent(BaseAgent):
    """
    SKILL 147: RouteCoverageAgent
    Tracks total routes discovered vs routes actively tested.
    Calculates coverage = (routes_tested / routes_discovered) * 100.
    If coverage < 90, force the campaign to continue.
    """
    def __init__(self):
        super().__init__(agent_id="RouteCoverageAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        routes_discovered = len(state.get("routes", []))
        routes_tested = len(state.get("tested_routes", []))
        
        if routes_discovered == 0:
            return state
            
        coverage = (routes_tested / routes_discovered) * 100
        state["route_coverage_score"] = coverage
        
        ConsoleUI.info(f"[RouteCoverageAgent] Metrics: Discovered={routes_discovered}, Tested={routes_tested}, Coverage={coverage:.2f}%")
        
        if coverage < 90:
            ConsoleUI.warning(f"[RouteCoverageAgent] Coverage < 90%. Continuing campaign to test {routes_discovered - routes_tested} untested routes.")
            state["is_complete"] = False
            
            unav = state.setdefault("unavailable_agents", [])
            if "ReportingAgent" not in unav:
                unav.append("ReportingAgent")
                
        return state
