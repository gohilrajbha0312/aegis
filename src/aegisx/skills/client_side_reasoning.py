"""
Client-Side Security Reasoning Skill
=====================================
Inspects DOM patterns, frontend rendering, CSP, and JS trust boundaries.
Purely passive — analyzes previously extracted JS data.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Client-Side Reasoning: Analyze JS routes, CSP headers, and 
    frontend patterns for client-side security issues.
    """
    ConsoleUI.header("SKILL: Client-Side Security Reasoning")
    
    hypotheses = []
    findings = []

    # 1. CSP Analysis (purely from discovered headers — zero requests)
    csp = state.discovered_headers.get("security:csp", "")
    if not csp:
        csp = state.discovered_headers.get("content-security-policy", "")
    
    if not csp:
        findings.append({
            "finding_type": "Missing Content-Security-Policy",
            "title": "No Content-Security-Policy header detected",
            "severity": "MEDIUM",
            "endpoint": f"http://{state.normalized_target}",
            "evidence": "CSP header absent from HTTP response",
            "confidence": 0.9,
            "validation": "header_absence_check",
            "risk_level": "MEDIUM"
        })
        ConsoleUI.warning("  [Finding] No CSP header detected")
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        issues = []
        if "unsafe-inline" in csp:
            issues.append("unsafe-inline")
        if "unsafe-eval" in csp:
            issues.append("unsafe-eval")
        findings.append({
            "finding_type": "Weak CSP Configuration",
            "title": f"CSP allows {', '.join(issues)}",
            "severity": "MEDIUM",
            "endpoint": f"http://{state.normalized_target}",
            "evidence": f"CSP: {csp[:300]}",
            "confidence": 0.85,
            "validation": "header_content_check",
            "risk_level": "MEDIUM"
        })
        ConsoleUI.warning(f"  [Finding] CSP contains: {', '.join(issues)}")

    # 2. Detect client-side frameworks from technology fingerprints
    client_frameworks = []
    for tech in state.detected_technologies:
        tech_lower = tech.lower()
        if any(fw in tech_lower for fw in ["react", "angular", "vue", "next", "nuxt", "svelte"]):
            client_frameworks.append(tech)
    
    if client_frameworks:
        hypotheses.append({
            "type": "client_framework_detected",
            "frameworks": client_frameworks,
            "confidence": 0.85,
            "reasoning": f"Client-side frameworks detected: {', '.join(client_frameworks)}"
        })
        ConsoleUI.info(f"  [Framework] Client-side: {', '.join(client_frameworks)}")

    # 3. Check for sensitive routes exposed in JS (passive analysis)
    sensitive_patterns = ["api_key", "secret", "token", "password", "admin", "debug", "internal"]
    sensitive_js_routes = [
        r for r in state.discovered_js_routes
        if any(pat in r.lower() for pat in sensitive_patterns)
    ]
    if sensitive_js_routes:
        hypotheses.append({
            "type": "sensitive_routes_in_js",
            "routes": sensitive_js_routes,
            "confidence": 0.7,
            "reasoning": "Sensitive-looking routes discovered in JavaScript bundles"
        })
        ConsoleUI.warning(f"  [Hypothesis] {len(sensitive_js_routes)} sensitive routes found in JS")

    # 4. X-Frame-Options check (passive)
    xfo = state.discovered_headers.get("x-frame-options", "")
    xfo_sec = state.discovered_headers.get("security:x-frame-options", "")
    if not xfo and not xfo_sec:
        findings.append({
            "finding_type": "Missing X-Frame-Options",
            "title": "No X-Frame-Options header (clickjacking risk)",
            "severity": "LOW",
            "endpoint": f"http://{state.normalized_target}",
            "evidence": "X-Frame-Options header absent",
            "confidence": 0.85,
            "validation": "header_absence_check",
            "risk_level": "LOW"
        })

    # Store results
    if hypotheses:
        state.attack_surface_nodes.extend(hypotheses)
    if findings:
        state.findings.extend(findings)

    if "client_side_reasoning" not in state.explored_paths:
        state.explored_paths.append("client_side_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_CLIENT_SIDE_REASONING",
        "timestamp": time.time(),
        "action": "client_side_analysis",
        "result": {"hypotheses": len(hypotheses), "findings": len(findings)}
    })

    ConsoleUI.success(f"Client-side reasoning complete: {len(hypotheses)} hypotheses, {len(findings)} findings")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="client_side_reasoning",
        name="Client-Side Security Reasoning",
        description="Inspects CSP, DOM patterns, JS trust boundaries, and frontend rendering security",
        category="client_side",
        noise_score=0,  # Purely passive
        required_inputs=["discovered_headers", "discovered_js_routes", "detected_technologies"],
        produced_outputs=["findings", "attack_surface_nodes"],
        supported_phases=["Semantic Discovery", "Vulnerability Discovery"],
        requires_evidence=True,
        execute_fn=_execute
    ))
