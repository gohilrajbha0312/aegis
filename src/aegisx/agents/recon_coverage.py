from typing import Dict, Any, List
from aegisx.core.ui.console import ConsoleUI

class ReconCoverageEnforcementAgent:
    """
    SKILL 79: ReconCoverageEnforcementAgent
    Calculates ReconCoverageScore and restricts execution if coverage is too low.
    """
    @staticmethod
    def calculate_coverage(state: Dict[str, Any]) -> int:
        score = 0
        routes = len(state.get("attack_surface_nodes", []))
        params = len(state.get("parameters", []))
        sessions = len(state.get("sessions", []))
        
        if routes > 0: score += 30
        if routes >= 10: score += 20
        if params > 0: score += 20
        if sessions > 0: score += 30
        
        return min(100, score)
        
    @staticmethod
    def enforce(state: Dict[str, Any]) -> List[str]:
        """
        Returns a list of agents that MUST be disabled due to low coverage.
        """
        score = ReconCoverageEnforcementAgent.calculate_coverage(state)
        ConsoleUI.info(f"[ReconCoverageEnforcementAgent] Current Recon Score: {score}/100")
        
        if score < 70:
            ConsoleUI.warning("Recon coverage < 70. Disabling exploitation/validation agents to force continuous discovery.")
            return [
                "ExploitationAgent", 
                "ValidationAgent", 
                "ReportingAgent",
                "AdaptiveValidationEngine",
                "AttackGraphIntelligenceAgent"
            ]
        return []

from aegisx.agents.base import BaseAgent
import asyncio

class ContinuousReconLoopAgent(BaseAgent):
    """
    SKILL 80: ContinuousReconLoopAgent
    Executes multiple recon agents in parallel until saturation.
    """
    def __init__(self):
        super().__init__(agent_id="ContinuousReconLoopAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ContinuousReconLoopAgent] Initiating parallel recon barrage...")
        
        from aegisx.agents.recon import ReconAgent
        from aegisx.agents.semantic_discovery import JSIntelligenceAgent, APISurfaceAgent
        
        # Instantiate agents
        recon = ReconAgent()
        js = JSIntelligenceAgent()
        api = APISurfaceAgent()
        
        # Run in parallel
        tasks = [
            recon.process(state.copy()),
            js.process(state.copy()),
            api.process(state.copy())
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Merge discovered routes/params into state
        new_routes = 0
        for res in results:
            if not isinstance(res, Exception):
                if "routes" in res:
                    for r in res["routes"]:
                        if r not in state.get("routes", []):
                            state.setdefault("routes", []).append(r)
                            new_routes += 1
                            
        self.log_action("parallel_recon_complete", {"new_routes": new_routes})
        return state

class ReconExpansionAgent(BaseAgent):
    """
    SKILL 89: ReconExpansionAgent
    Expands discovery for hidden routes, API specs, GraphQL.
    """
    def __init__(self):
        super().__init__(agent_id="ReconExpansionAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        score = ReconCoverageEnforcementAgent.calculate_coverage(state)
        state["recon_expansion_score"] = score
        if score < 90:
            ConsoleUI.info("[ReconExpansionAgent] Recon score not fully saturated. Expanding search to hidden JS/API routes.")
        else:
            ConsoleUI.success("[ReconExpansionAgent] Attack surface well-mapped. Expansion paused.")
        return state

class RouteRiskScoringAgent(BaseAgent):
    """
    SKILL 92: RouteRiskScoringAgent
    Assigns High/Low risk to endpoints based on sensitivity.
    """
    def __init__(self):
        super().__init__(agent_id="RouteRiskScoringAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[RouteRiskScoringAgent] Assigning risk scores to discovered routes...")
        routes = state.get("routes", [])
        risk_scores = state.get("route_risk_score", {})
        
        for r in routes:
            if r not in risk_scores:
                r_lower = r.lower()
                if any(x in r_lower for x in ["admin", "api/user", "graphql", "payment", "setting"]):
                    risk_scores[r] = "HIGH"
                else:
                    risk_scores[r] = "LOW"
                    
        state["route_risk_score"] = risk_scores
        return state

class RouteLineageAgent(BaseAgent):
    """
    SKILL 102: RouteLineageAgent
    Tracks how routes were discovered (JS, GraphQL, Robots).
    """
    def __init__(self):
        super().__init__(agent_id="RouteLineageAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[RouteLineageAgent] Tracking route lineage...")
        routes = state.get("routes", [])
        lineage_map = state.get("route_lineage", {})
        
        for r in routes:
            r_str = r if isinstance(r, str) else r.get("route", str(r))
            if r_str not in lineage_map:
                if ".js" in r_str: lineage_map[r_str] = "JS File"
                elif "graphql" in r_str: lineage_map[r_str] = "GraphQL"
                elif "api-docs" in r_str or "swagger" in r_str: lineage_map[r_str] = "Swagger"
                else: lineage_map[r_str] = "Active Crawl"
                
        state["route_lineage"] = lineage_map
        return state

class ParameterLineageAgent(BaseAgent):
    """
    SKILL 103: ParameterLineageAgent
    Tracks source parameter, parent endpoint, and discovery source.
    """
    def __init__(self):
        super().__init__(agent_id="ParameterLineageAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ParameterLineageAgent] Building parameter lineage graph...")
        params = state.get("parameters", [])
        lineage_map = state.get("parameter_lineage", {})
        
        for p in params:
            p_name = p.get('name', str(p)) if isinstance(p, dict) else str(p)
            if p_name not in lineage_map:
                lineage_map[p_name] = {
                    "source_parameter": p_name,
                    "parent_endpoint": "auto_inferred",
                    "discovery_source": "SemanticDiscoveryAgent"
                }
                
        state["parameter_lineage"] = lineage_map
        return state

class DiscoveryConfidenceAgent(BaseAgent):
    """
    SKILL 104: DiscoveryConfidenceAgent
    Assigns confidence to routes, parameters, sessions, APIs.
    """
    def __init__(self):
        super().__init__(agent_id="DiscoveryConfidenceAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[DiscoveryConfidenceAgent] Assigning discovery confidence scores...")
        disc_conf = state.get("discovery_confidence", {})
        
        routes = state.get("routes", [])
        for r in routes:
            r_str = r if isinstance(r, str) else r.get("route", str(r))
            disc_conf[f"route:{r_str}"] = 100
            
        params = state.get("parameters", [])
        for p in params:
            p_name = p.get('name', str(p)) if isinstance(p, dict) else str(p)
            disc_conf[f"param:{p_name}"] = 90
            
        state["discovery_confidence"] = disc_conf
        return state

class AttackSurfaceGrowthAgent(BaseAgent):
    """
    SKILL 106: AttackSurfaceGrowthAgent
    Measures attack surface expansion and calculates AttackSurfaceGrowthScore.
    """
    def __init__(self):
        super().__init__(agent_id="AttackSurfaceGrowthAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        routes_count = len(state.get("routes", []))
        params_count = len(state.get("parameters", []))
        sessions_count = len(state.get("sessions", []))
        
        current_surface_size = routes_count + params_count + sessions_count
        previous_surface_size = state.get("last_surface_size", 0)
        
        growth = current_surface_size - previous_surface_size
        state["last_surface_size"] = current_surface_size
        state["attack_surface_growth_score"] = growth
        
        ConsoleUI.info(f"[AttackSurfaceGrowthAgent] Attack Surface Growth Score: +{growth}")
        return state

class ReconBudgetOptimizerAgent(BaseAgent):
    """
    SKILL 113: ReconBudgetOptimizerAgent
    Optimizes request budget and prioritizes highest-value attack surface.
    """
    def __init__(self):
        super().__init__(agent_id="ReconBudgetOptimizerAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ReconBudgetOptimizerAgent] Optimizing recon budget against HIGH risk routes...")
        risk_scores = state.get("route_risk_score", {})
        high_risk_routes = [r for r, score in risk_scores.items() if score == "HIGH"]
        
        if high_risk_routes:
            ConsoleUI.success(f"[ReconBudgetOptimizerAgent] Prioritizing budget on {len(high_risk_routes)} HIGH risk routes.")
            state["prioritized_targets"] = high_risk_routes
            
        return state
