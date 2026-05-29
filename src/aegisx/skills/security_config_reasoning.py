"""
Security Misconfiguration Reasoning Skill
==========================================
Inspects headers, CORS, caching, transport security, and debug endpoints.
Entirely passive — analyzes data already in WorkflowState.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Security Configuration Reasoning: Analyze headers and response
    metadata for insecure defaults and misconfigurations.
    """
    ConsoleUI.header("SKILL: Security Misconfiguration Reasoning")
    target = state.normalized_target
    base = f"http://{target}"

    findings = []

    # 1. CORS analysis (from discovered headers — zero requests)
    cors = state.discovered_headers.get("access-control-allow-origin", "")
    if cors == "*":
        findings.append({
            "finding_type": "Overly Permissive CORS",
            "title": "Access-Control-Allow-Origin: * (wildcard CORS)",
            "severity": "MEDIUM",
            "endpoint": base,
            "evidence": f"CORS header: {cors}",
            "confidence": 0.9,
            "validation": "header_content_check",
            "risk_level": "MEDIUM"
        })
        ConsoleUI.warning("  [Finding] Wildcard CORS detected: Access-Control-Allow-Origin: *")

    # 2. X-Content-Type-Options
    xcto = state.discovered_headers.get("x-content-type-options", "")
    if not xcto:
        findings.append({
            "finding_type": "Missing X-Content-Type-Options",
            "title": "X-Content-Type-Options header absent (MIME sniffing risk)",
            "severity": "LOW",
            "endpoint": base,
            "evidence": "Header absent from response",
            "confidence": 0.85,
            "validation": "header_absence_check",
            "risk_level": "LOW"
        })

    # 3. Strict-Transport-Security
    hsts = state.discovered_headers.get("strict-transport-security", "")
    if not hsts:
        findings.append({
            "finding_type": "Missing HSTS",
            "title": "Strict-Transport-Security header absent",
            "severity": "LOW",
            "endpoint": base,
            "evidence": "HSTS header absent — transport downgrade risk",
            "confidence": 0.8,
            "validation": "header_absence_check",
            "risk_level": "LOW"
        })

    # 4. Cache-Control on sensitive endpoints
    cache = state.discovered_headers.get("cache-control", "")
    if cache and "public" in cache.lower():
        # Check if there are auth-related routes (suggests caching of sensitive data)
        has_auth = any("auth" in r.lower() or "login" in r.lower() for r in state.routes)
        if has_auth:
            findings.append({
                "finding_type": "Public Caching on Auth Application",
                "title": "Cache-Control: public on application with authentication",
                "severity": "LOW",
                "endpoint": base,
                "evidence": f"Cache-Control: {cache}",
                "confidence": 0.6,
                "validation": "header_context_analysis",
                "risk_level": "LOW"
            })

    # 5. Check for exposed debug/monitoring endpoints (1-2 requests max)
    debug_paths = ["/debug", "/metrics", "/actuator", "/actuator/health", "/.env", "/trace"]
    for path in debug_paths:
        if path in state.routes or path in state.discovered_js_routes:
            try:
                resp = http_client.get(f"{base}{path}", timeout=5)
                if resp.status_code == 200:
                    findings.append({
                        "finding_type": "Exposed Debug/Monitoring Endpoint",
                        "title": f"Debug endpoint accessible: {path}",
                        "severity": "MEDIUM",
                        "endpoint": f"{base}{path}",
                        "evidence": f"Status 200, Content-Length: {len(resp.text)}",
                        "confidence": 0.85,
                        "validation": "deterministic_response_check",
                        "risk_level": "MEDIUM"
                    })
                    ConsoleUI.warning(f"  [Finding] Debug endpoint exposed: {path}")
            except Exception:
                pass

    # 6. Feature-Policy / Permissions-Policy check
    fp = state.discovered_headers.get("feature-policy", state.discovered_headers.get("permissions-policy", ""))
    if fp:
        ConsoleUI.info(f"  [Config] Feature-Policy detected: {fp[:100]}")

    # Store results
    if findings:
        state.findings.extend(findings)

    if "security_config_reasoning" not in state.explored_paths:
        state.explored_paths.append("security_config_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_SECURITY_CONFIG",
        "timestamp": time.time(),
        "action": "config_analysis",
        "result": {"findings": len(findings)}
    })

    ConsoleUI.success(f"Security config reasoning complete: {len(findings)} findings")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="security_config_reasoning",
        name="Security Misconfiguration Reasoning",
        description="Inspects CORS, HSTS, caching, debug endpoints, and security headers",
        category="configuration",
        noise_score=1,
        required_inputs=["discovered_headers", "routes"],
        produced_outputs=["findings"],
        supported_phases=["Semantic Discovery", "Vulnerability Discovery"],
        requires_evidence=True,
        execute_fn=_execute
    ))
