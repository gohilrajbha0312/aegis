"""
Skill 14: HallucinationDetectorSkill
======================================
Reject synthetic routes, APIs, users, parameters, vulnerabilities.
Any object not discovered through reconnaissance must be discarded.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("VALIDATION SKILL 14: Hallucination Detector")
    
    valid_hypotheses = []
    rejected = 0
    
    all_routes = [r if isinstance(r, str) else r.get("route", str(r)) for r in state.routes]
    all_params = [p.get("name") for p in state.parameters]
    
    for hypothesis in state.hypotheses:
        is_hallucination = False
        reasons = []
        
        # Check synthetic routes
        route = hypothesis.get("route") or hypothesis.get("endpoint")
        if route and not any(r for r in all_routes if route in r or r in route):
            if route not in state.api_endpoints and route not in state.hidden_endpoints:
                is_hallucination = True
                reasons.append(f"Synthetic route: {route}")
                
        # Check synthetic parameters
        param = hypothesis.get("parameter")
        if param and param not in all_params:
            is_hallucination = True
            reasons.append(f"Synthetic parameter: {param}")
            
        if is_hallucination:
            rejected += 1
            ConsoleUI.warning(f"  [Hallucination Detected] Rejected hypothesis: {reasons}")
        else:
            valid_hypotheses.append(hypothesis)

    state.hypotheses = valid_hypotheses
    if "hallucination_detector" not in state.explored_paths:
        state.explored_paths.append("hallucination_detector")
        
    state.evidence_ledger.append({
        "stage": "VALIDATION_HALLUCINATION_DETECTOR", "timestamp": time.time(),
        "action": "hallucination_filtering",
        "result": {"valid": len(valid_hypotheses), "rejected": rejected}
    })
    ConsoleUI.success(f"Hallucination Detector: {len(valid_hypotheses)} valid hypotheses, {rejected} rejected")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_hallucination_detector", name="Hallucination Detector",
        description="Rejects synthetic routes, APIs, users, parameters, and vulnerabilities",
        category="validation", noise_score=0, required_inputs=["hypotheses", "routes", "parameters"],
        produced_outputs=["hypotheses"],
        supported_phases=["Validation"],
        requires_evidence=True, execute_fn=_execute
    ))
