"""
Error Analysis Reasoning Skill
===============================
Analyzes error patterns, validation differences, exception handling,
and response inconsistencies to infer backend logic.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Error Analysis Reasoning: Examine evidence ledger for error patterns
    and response inconsistencies. Purely passive analysis.
    """
    ConsoleUI.header("SKILL: Error Analysis Reasoning")

    hypotheses = []

    # 1. Scan evidence ledger for error patterns
    error_stages = []
    for item in state.evidence_ledger:
        result = item.get("result", {})
        if isinstance(result, dict):
            error = result.get("error", "")
            if error:
                error_stages.append({
                    "stage": item.get("stage", "unknown"),
                    "error": str(error)[:200]
                })

    if error_stages:
        # Categorize errors
        connection_errors = [e for e in error_stages if "timeout" in e["error"].lower() or "connection" in e["error"].lower()]
        auth_errors = [e for e in error_stages if "401" in e["error"] or "403" in e["error"] or "unauthorized" in e["error"].lower()]
        
        if connection_errors:
            hypotheses.append({
                "type": "connectivity_issues",
                "count": len(connection_errors),
                "confidence": 0.6,
                "reasoning": f"{len(connection_errors)} connection/timeout errors suggest WAF or rate limiting"
            })
            ConsoleUI.info(f"  [Hypothesis] {len(connection_errors)} connectivity errors (possible WAF/rate limiting)")

        if auth_errors:
            hypotheses.append({
                "type": "auth_enforcement_detected",
                "count": len(auth_errors),
                "confidence": 0.8,
                "reasoning": f"{len(auth_errors)} auth errors confirm access-control enforcement"
            })
            ConsoleUI.info(f"  [Hypothesis] {len(auth_errors)} auth errors confirm access-control presence")

    # 2. Analyze failed methods for methodology improvement
    if state.failed_methods:
        hypotheses.append({
            "type": "methodology_failure_analysis",
            "failed": state.failed_methods,
            "confidence": 0.7,
            "reasoning": f"Previously failed methods: {', '.join(state.failed_methods)}"
        })
        ConsoleUI.info(f"  [Analysis] Failed methods: {', '.join(state.failed_methods)}")

    # Store results
    if hypotheses:
        state.attack_surface_nodes.extend(hypotheses)

    if "error_analysis" not in state.explored_paths:
        state.explored_paths.append("error_analysis")

    state.evidence_ledger.append({
        "stage": "SKILL_ERROR_ANALYSIS",
        "timestamp": time.time(),
        "action": "error_pattern_analysis",
        "result": {"hypotheses": len(hypotheses), "error_stages": len(error_stages)}
    })

    ConsoleUI.success(f"Error analysis complete: {len(hypotheses)} hypotheses from {len(error_stages)} error records")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="error_analysis_reasoning",
        name="Error Analysis Reasoning",
        description="Analyzes error patterns and response inconsistencies to infer backend logic",
        category="error_analysis",
        noise_score=0,  # Purely passive
        required_inputs=["evidence_ledger", "failed_methods"],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Semantic Discovery", "Vulnerability Discovery", "Validation"],
        requires_evidence=False,
        execute_fn=_execute
    ))
