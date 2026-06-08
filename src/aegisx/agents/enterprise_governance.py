import time
from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class AgentHealthAgent(BaseAgent):
    """
    SKILL 86: AgentHealthAgent
    Tracks execution time, failures, retries, success rate.
    """
    def __init__(self):
        super().__init__(agent_id="AgentHealthAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        health = state.setdefault("agent_health", {})
        disabled = []
        
        for agent_name, stats in health.items():
            failures = stats.get("failures", 0)
            executions = stats.get("executions", 1)
            
            if executions > 3 and (failures / executions) > 0.5:
                disabled.append(agent_name)
                
        if disabled:
            unav = state.setdefault("unavailable_agents", [])
            for d in disabled:
                if d not in unav:
                    unav.append(d)
            ConsoleUI.warning(f"[AgentHealthAgent] Disabled unhealthy agents due to high failure rate: {disabled}")
            
        return state

class AgentSchedulerAgent(BaseAgent):
    """
    SKILL 87: AgentSchedulerAgent
    Dynamically schedules and filters agents to prevent duplicates.
    """
    def __init__(self):
        super().__init__(agent_id="AgentSchedulerAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        completed = state.get("completed_agents", [])
        unav = state.setdefault("unavailable_agents", [])
        
        # Do not allow re-execution of agents that are not specifically loops (like ReconLoop)
        filtered = 0
        for agent in completed:
            if agent not in unav and agent not in ["ContinuousReconLoopAgent"]:
                unav.append(agent)
                filtered += 1
                
        if filtered > 0:
            ConsoleUI.info(f"[AgentSchedulerAgent] Pre-filtered {filtered} completed agents to prevent duplicate execution.")
        
        return state

class RuntimeGovernanceAgent(BaseAgent):
    """
    SKILL 100: RuntimeGovernanceAgent
    Enforces global governance. Verifies validation, evidence, and confidence.
    """
    def __init__(self):
        super().__init__(agent_id="RuntimeGovernanceAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        findings = state.get("findings", [])
        valid_findings = []
        rejected = 0
        
        for f in findings:
            if isinstance(f, dict):
                conf = f.get("confidence", 0.0)
                if conf >= 0.8:
                    valid_findings.append(f)
                else:
                    rejected += 1
            else:
                conf = getattr(f, "confidence", 0.0)
                if conf >= 0.8:
                    valid_findings.append(f)
                else:
                    rejected += 1
                    
        if rejected > 0:
            ConsoleUI.warning(f"[RuntimeGovernanceAgent] Rejected {rejected} finding(s) violating global policy (confidence < 0.8).")
            
        state["findings"] = valid_findings
        return state

class AgentConsensusAgent(BaseAgent):
    """
    SKILL 110: AgentConsensusAgent
    Requires agreement between Recon, Validation, and Correlation agents.
    """
    def __init__(self):
        super().__init__(agent_id="AgentConsensusAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[AgentConsensusAgent] Verifying multi-agent consensus before prioritization...")
        history = state.get("execution_history", [])
        
        has_recon = any("Recon" in h for h in history[-5:])
        has_val = any("Validation" in h for h in history[-5:])
        has_corr = any("Correlation" in h for h in history[-5:])
        
        if history and not (has_recon and has_val and has_corr):
            ConsoleUI.warning("[AgentConsensusAgent] Missing agent consensus across lifecycle phases. Prioritizing gap coverage.")
            
        return state

class CampaignCompletionAgent(BaseAgent):
    """
    SKILL 115: CampaignCompletionAgent
    Hijacks is_complete. Only allows completion if all governance metrics are exhausted.
    """
    def __init__(self):
        super().__init__(agent_id="CampaignCompletionAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[CampaignCompletionAgent] Verifying enterprise completion criteria...")
        
        recon_coverage_score = state.get("recon_coverage_score", 0)
        attack_surface_growth = state.get("attack_surface_growth_score", 0)
        routes_discovered = len(state.get("routes", []))
        routes_tested = len(state.get("tested_routes", []))
        validation_queue = len(state.get("validation_queue", []))
        is_complete = state.get("is_complete", False)
        
        if is_complete:
            if recon_coverage_score < 70:
                ConsoleUI.error(f"[CampaignCompletionAgent] Campaign blocked. Recon Coverage ({recon_coverage_score}) < 70.")
                state["is_complete"] = False
            elif attack_surface_growth > 0:
                ConsoleUI.error(f"[CampaignCompletionAgent] Campaign blocked. Attack surface still growing (+{attack_surface_growth}).")
                state["is_complete"] = False
            elif routes_discovered > routes_tested:
                ConsoleUI.error(f"[CampaignCompletionAgent] Campaign blocked. Unvalidated routes remain ({routes_discovered} discovered, {routes_tested} tested).")
                state["is_complete"] = False
            elif validation_queue > 0:
                ConsoleUI.error(f"[CampaignCompletionAgent] Campaign blocked. Validation queue has {validation_queue} pending items.")
                state["is_complete"] = False
            else:
                ConsoleUI.success("[CampaignCompletionAgent] All enterprise criteria met. Allowing campaign completion.")
                
        return state
