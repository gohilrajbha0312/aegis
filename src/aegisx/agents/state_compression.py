import json
from typing import Dict, Any
from aegisx.core.ui.console import ConsoleUI

class StateCompressionAgent:
    """
    SKILL 78: StateCompressionAgent
    Prevents context explosion before sending state to Commander.
    Target: context_reduction >= 70%
    """
    @staticmethod
    def compress(state: Dict[str, Any]) -> Dict[str, Any]:
        # Extract only the most recent/relevant data
        compressed = {
            "target": state.get("target"),
            "scan_mode": state.get("scan_mode", "adaptive"),
            "workflow_depth": state.get("workflow_depth", 0),
            
            # Keep only the last 15 unique nodes to prevent overflow
            "attack_surface_nodes": state.get("attack_surface_nodes", [])[-15:],
            "attack_paths": state.get("attack_paths", [])[-5:],
            "parameters": state.get("parameters", [])[-10:],
            "sessions": state.get("sessions", []),
            "roles": state.get("roles", []),
            
            # Deduplicate findings / remove hypotheses if we have too many
            "findings": [f for f in state.get("findings", []) if f.get("confidence", 0) > 0.4][-10:],
            
            "failed_methods": state.get("failed_methods", [])[-5:],
            "successful_methods": state.get("successful_methods", [])[-5:],
            "unavailable_agents": state.get("unavailable_agents", []),
            "repeated_results_counter": state.get("repeated_results_counter", {})
        }
        
        # Calculate reduction metrics for observability
        original_size = len(json.dumps(state))
        compressed_size = len(json.dumps(compressed))
        reduction = (1 - (compressed_size / max(original_size, 1))) * 100
        if reduction > 0:
            ConsoleUI.info(f"[StateCompressionAgent] Compressed workflow state. Reduction: {reduction:.1f}%")
            
        return compressed

from aegisx.agents.base import BaseAgent

class RuntimeMemoryAgent(BaseAgent):
    """
    SKILL 88: RuntimeMemoryAgent
    Maintains memory budget. Purges duplicate evidence, stale hypotheses, and expired state.
    """
    def __init__(self):
        super().__init__(agent_id="RuntimeMemoryAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[RuntimeMemoryAgent] Purging stale and duplicate state variables...")
        
        # Deduplicate routes
        routes = state.get("routes", [])
        state["routes"] = list(set(routes))
        
        # Purge stale hypotheses that lack high confidence and have been lingering
        findings = state.get("findings", [])
        active_findings = []
        for f in findings:
            if isinstance(f, dict):
                conf = f.get("confidence", 0.0)
                # Keep if confidence is decently high, or if it was recently added
                # For this simulated environment, we keep > 0.3 as a threshold for hypotheses
                if conf >= 0.3 or not f.get("validation_reasoning"):
                    active_findings.append(f)
            else:
                active_findings.append(f)
                
        if len(findings) != len(active_findings):
            ConsoleUI.warning(f"[RuntimeMemoryAgent] Purged {len(findings) - len(active_findings)} stale hypotheses from memory.")
        state["findings"] = active_findings
        
        return state
