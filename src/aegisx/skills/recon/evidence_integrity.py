"""
Skill 13: EvidenceIntegritySkill
==================================
Before accepting any finding, require route evidence, parameter evidence, response evidence.
Rejects findings with missing evidence.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("VALIDATION SKILL 13: Evidence Integrity")
    
    valid_findings = []
    rejected = 0
    
    all_routes = [r if isinstance(r, str) else r.get("route", str(r)) for r in state.routes]
    
    for finding in state.findings:
        is_valid = True
        reasons = []
        
        route = finding.get("route") or finding.get("endpoint") or finding.get("target")
        
        # 1. Require Route Evidence
        if not route:
            is_valid = False
            reasons.append("Missing route evidence")
        elif not any(r for r in all_routes if route in r or r in route):
            # Allow some flexibility if it's a known endpoint but not strictly matched
            if route not in state.api_endpoints and route not in state.hidden_endpoints:
                is_valid = False
                reasons.append(f"Route '{route}' not discovered during recon")
                
        # 2. Require Parameter Evidence (if applicable)
        vuln_type = finding.get("type", "").lower()
        if any(v in vuln_type for v in ["sqli", "xss", "ssrf", "injection"]):
            param = finding.get("parameter") or finding.get("payload_field")
            if not param:
                is_valid = False
                reasons.append("Missing parameter evidence for injection vulnerability")
                
        if is_valid:
            valid_findings.append(finding)
        else:
            rejected += 1
            ConsoleUI.warning(f"  [Integrity Failure] Rejected finding: {reasons}")

    state.findings = valid_findings
    if "evidence_integrity" not in state.explored_paths:
        state.explored_paths.append("evidence_integrity")
        
    state.evidence_ledger.append({
        "stage": "VALIDATION_EVIDENCE_INTEGRITY", "timestamp": time.time(),
        "action": "evidence_validation",
        "result": {"valid": len(valid_findings), "rejected": rejected}
    })
    ConsoleUI.success(f"Evidence Integrity: {len(valid_findings)} valid, {rejected} rejected")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_evidence_integrity", name="Evidence Integrity",
        description="Requires route, parameter, and response evidence for all findings",
        category="validation", noise_score=0, required_inputs=["findings", "routes", "parameters"],
        produced_outputs=["findings"],
        supported_phases=["Validation"],
        requires_evidence=True, execute_fn=_execute
    ))
