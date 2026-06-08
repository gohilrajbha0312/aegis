"""
Skill 15: ReconCompletenessSkill
==================================
Calculates the Recon Score.
If score is insufficient, sets flag to continue recon. Do not enter vuln discovery.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("GOVERNANCE SKILL 15: Recon Completeness")
    
    score = state.calculate_recon_score()
    
    if not state.recon_complete:
        ConsoleUI.warning(f"  [Recon Incomplete] Score: {score:.2f} < 0.5. More reconnaissance required.")
    else:
        ConsoleUI.success(f"  [Recon Complete] Score: {score:.2f} >= 0.5. Ready for vulnerability discovery.")

    if "recon_completeness" not in state.explored_paths:
        state.explored_paths.append("recon_completeness")
        
    state.evidence_ledger.append({
        "stage": "GOVERNANCE_RECON_COMPLETENESS", "timestamp": time.time(),
        "action": "completeness_check",
        "result": {"score": score, "is_complete": state.recon_complete}
    })
    
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_completeness", name="Recon Completeness",
        description="Calculates Recon Score and determines if evidence is sufficient to proceed",
        category="governance", noise_score=0, required_inputs=["routes", "parameters", "sessions", "roles", "business_flows", "api_inventory"],
        produced_outputs=[],
        supported_phases=["Governance"],
        requires_evidence=False, execute_fn=_execute
    ))
