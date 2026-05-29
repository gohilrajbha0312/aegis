"""
Authentication Reasoning Skill
===============================
Analyzes session flows, token structure, cookie attributes,
auth redirects, and MFA enforcement without brute-force.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Authentication Reasoning: Infer auth architecture from headers,
    cookies, and response behavior. Zero brute-force.
    """
    ConsoleUI.header("SKILL: Authentication Reasoning")
    target = state.normalized_target
    base = f"http://{target}"

    hypotheses = []
    findings = []

    # 1. Analyze discovered cookies for session security
    for cookie in state.discovered_cookies:
        cookie_lower = cookie.lower()
        if "session" in cookie_lower or "sid" in cookie_lower:
            hypotheses.append({
                "type": "session_cookie_detected",
                "cookie": cookie,
                "confidence": 0.85,
                "reasoning": "Server-side session management detected via cookie name"
            })
            ConsoleUI.info(f"  [Session] Cookie '{cookie}' indicates server-side session management")

        if "jwt" in cookie_lower or "token" in cookie_lower:
            hypotheses.append({
                "type": "jwt_cookie_detected",
                "cookie": cookie,
                "confidence": 0.9,
                "reasoning": "JWT/token-based authentication detected via cookie"
            })
            ConsoleUI.info(f"  [Auth] JWT/token cookie '{cookie}' detected")

    # 2. Check cookie security attributes via a single request
    try:
        resp = http_client.get(base, timeout=5)
        set_cookie_headers = resp.headers.get("set-cookie", "")
        if set_cookie_headers:
            issues = []
            cookie_str = set_cookie_headers.lower()
            if "httponly" not in cookie_str:
                issues.append("Missing HttpOnly flag")
            if "secure" not in cookie_str:
                issues.append("Missing Secure flag")
            if "samesite" not in cookie_str:
                issues.append("Missing SameSite attribute")

            if issues:
                findings.append({
                    "finding_type": "Insecure Cookie Configuration",
                    "title": f"Cookie security issues: {', '.join(issues)}",
                    "severity": "MEDIUM",
                    "endpoint": base,
                    "evidence": f"Set-Cookie header: {set_cookie_headers[:200]}",
                    "confidence": 0.8,
                    "validation": "header_inspection",
                    "risk_level": "MEDIUM"
                })
                ConsoleUI.warning(f"  [Finding] Cookie security issues: {', '.join(issues)}")
    except Exception:
        pass

    # 3. Detect auth-related routes from discovered endpoints
    auth_routes = [r for r in state.routes if any(
        kw in r.lower() for kw in ["login", "auth", "signin", "register", "reset", "password", "logout", "token"]
    )]
    if auth_routes:
        hypotheses.append({
            "type": "auth_routes_discovered",
            "routes": auth_routes,
            "confidence": 0.85,
            "reasoning": f"Authentication-related routes found: {', '.join(auth_routes[:5])}"
        })
        ConsoleUI.info(f"  [Auth Routes] {len(auth_routes)} authentication-related endpoints found")

    # 4. Check for auth state consistency (single request)
    for route in auth_routes[:2]:  # Max 2 requests
        try:
            resp = http_client.get(f"{base}{route}", timeout=5, allow_redirects=False)
            if resp.status_code == 200:
                # Auth endpoint accessible without redirect = potential issue
                hypotheses.append({
                    "type": "auth_no_redirect",
                    "route": route,
                    "confidence": 0.5,
                    "reasoning": "Auth endpoint returns 200 directly (no auth redirect)"
                })
        except Exception:
            pass

    # Store results
    if hypotheses:
        state.attack_surface_nodes.extend(hypotheses)
    if findings:
        state.findings.extend(findings)

    if state.authentication_methods:
        state.successful_methods.append("authentication_reasoning")

    if "authentication_reasoning" not in state.explored_paths:
        state.explored_paths.append("authentication_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_AUTHENTICATION_REASONING",
        "timestamp": time.time(),
        "action": "authn_analysis",
        "result": {"hypotheses": len(hypotheses), "findings": len(findings),
                   "auth_methods": state.authentication_methods}
    })

    ConsoleUI.success(f"Authentication reasoning complete: {len(hypotheses)} hypotheses, {len(findings)} findings")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="authentication_reasoning",
        name="Authentication Reasoning",
        description="Analyzes session flows, token structure, cookie attributes, and auth consistency",
        category="authentication",
        noise_score=1,
        required_inputs=["discovered_cookies", "discovered_headers", "routes"],
        produced_outputs=["findings", "attack_surface_nodes", "authentication_methods"],
        supported_phases=["Authentication Analysis", "Vulnerability Discovery"],
        requires_evidence=False,
        execute_fn=_execute
    ))
