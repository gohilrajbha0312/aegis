"""
Authorization Reasoning Skill
==============================
Analyzes trust boundaries, ownership enforcement, and access-control consistency.
Uses minimal requests — compares response differentials across roles.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Authorization Reasoning: Analyze routes for IDOR/BOLA indicators
    by comparing sequential IDs, role-based response differentials,
    and frontend-exposed admin routes.
    """
    ConsoleUI.header("SKILL: Authorization Reasoning")
    target = state.normalized_target
    base = f"http://{target}"

    findings = []
    hypotheses = []

    # 1. Check for sequential resource IDs in discovered routes
    sequential_routes = [r for r in state.routes if any(
        seg.isdigit() for seg in r.split("/") if seg
    )]
    if sequential_routes:
        hypotheses.append({
            "type": "sequential_resource_ids",
            "routes": sequential_routes[:5],
            "confidence": 0.6,
            "reasoning": "Sequential numeric IDs in routes suggest potential IDOR"
        })
        ConsoleUI.info(f"  [Hypothesis] Sequential IDs found in {len(sequential_routes)} routes")

    # 2. Check for admin routes exposed in frontend JS
    admin_routes = [r for r in state.discovered_js_routes if "admin" in r.lower()]
    if admin_routes:
        hypotheses.append({
            "type": "admin_route_exposure",
            "routes": admin_routes,
            "confidence": 0.7,
            "reasoning": "Admin routes exposed in frontend JavaScript bundles"
        })
        ConsoleUI.warning(f"  [Hypothesis] {len(admin_routes)} admin routes exposed in JS")

    # 3. Minimal validation: Check if admin endpoints respond differently without auth
    for route in admin_routes[:3]:  # Max 3 requests
        try:
            url = f"{base}{route}"
            resp = http_client.get(url, timeout=5)
            if resp.status_code in [200, 302]:
                findings.append({
                    "finding_type": "Authorization Weakness",
                    "title": f"Admin route accessible: {route}",
                    "severity": "HIGH" if resp.status_code == 200 else "MEDIUM",
                    "endpoint": url,
                    "evidence": f"Status {resp.status_code} without authentication",
                    "confidence": 0.75,
                    "validation": "deterministic_response_check",
                    "risk_level": "HIGH"
                })
                ConsoleUI.warning(f"  [Finding] Admin route {route} returned {resp.status_code}")
        except Exception:
            pass

    # 4. Store hypotheses and findings
    if hypotheses:
        state.attack_surface_nodes.extend(hypotheses)
    if findings:
        state.findings.extend(findings)

    if "authorization_reasoning" not in state.explored_paths:
        state.explored_paths.append("authorization_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_AUTHORIZATION_REASONING",
        "timestamp": time.time(),
        "action": "authz_analysis",
        "result": {"hypotheses": len(hypotheses), "findings": len(findings)}
    })

    ConsoleUI.success(f"Authorization reasoning complete: {len(hypotheses)} hypotheses, {len(findings)} findings")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="authorization_reasoning",
        name="Authorization Reasoning",
        description="Analyzes access-control consistency, IDOR patterns, and privilege boundaries",
        category="authorization",
        noise_score=2,
        required_inputs=["routes", "discovered_js_routes"],
        produced_outputs=["findings", "attack_surface_nodes"],
        supported_phases=["Authorization Analysis", "Vulnerability Discovery"],
        requires_evidence=True,
        execute_fn=_execute
    ))
