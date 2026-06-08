"""
Skill 3: AuthenticationDiscoverySkill
=======================================
Identify login, logout, registration, password reset, MFA, OAuth, JWT, session cookies.
"""
import time
import re
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client

AUTH_KEYWORDS = {
    "login": ["login", "signin", "sign-in", "sign_in", "authenticate"],
    "logout": ["logout", "signout", "sign-out", "sign_out"],
    "register": ["register", "signup", "sign-up", "sign_up", "create-account"],
    "password_reset": ["reset-password", "forgot-password", "forgot_password", "password-reset"],
    "mfa": ["2fa", "mfa", "totp", "otp", "two-factor", "verify-code"],
    "oauth": ["oauth", "authorize", "callback", "openid", "sso"],
    "token": ["token", "refresh", "jwt", "api-key"],
}


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 3: Authentication Discovery")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    auth_surface = []

    # 1. Scan discovered routes for auth-related endpoints
    all_routes = []
    for r in state.routes:
        route_str = r if isinstance(r, str) else r.get("route", str(r))
        all_routes.append(route_str)

    for route in all_routes:
        route_lower = route.lower()
        for auth_type, keywords in AUTH_KEYWORDS.items():
            if any(kw in route_lower for kw in keywords):
                if not any(a.get("endpoint") == route and a.get("type") == auth_type for a in auth_surface):
                    auth_surface.append({
                        "type": auth_type, "endpoint": route,
                        "source": "route_analysis", "confidence": 0.85
                    })

    # 2. Check cookies for session/JWT indicators
    for cookie in state.discovered_cookies:
        cl = cookie.lower()
        if any(kw in cl for kw in ["session", "sid", "connect.sid", "phpsessid"]):
            auth_surface.append({"type": "session_cookie", "endpoint": "global", "cookie": cookie,
                                 "source": "cookie_analysis", "confidence": 0.9})
        if any(kw in cl for kw in ["jwt", "token", "bearer", "access_token"]):
            auth_surface.append({"type": "jwt_cookie", "endpoint": "global", "cookie": cookie,
                                 "source": "cookie_analysis", "confidence": 0.9})

    # 3. Check for Set-Cookie in response headers (already collected)
    for key, val in state.discovered_headers.items():
        if "set-cookie" in key.lower():
            auth_surface.append({"type": "session_management", "endpoint": "global",
                                 "evidence": val[:200], "source": "header_analysis", "confidence": 0.85})

    # 4. Check for Authorization header patterns in extracted tokens
    for token in state.extracted_tokens:
        if token.startswith("eyJ"):  # JWT indicator
            auth_surface.append({"type": "jwt_token", "endpoint": "global",
                                 "evidence": f"JWT: {token[:20]}...", "source": "token_analysis", "confidence": 0.95})

    state.auth_surface = auth_surface
    if "auth_discovery" not in state.explored_paths:
        state.explored_paths.append("auth_discovery")
    state.evidence_ledger.append({
        "stage": "RECON_AUTH_DISCOVERY", "timestamp": time.time(),
        "action": "auth_surface_mapping",
        "result": {"auth_endpoints": len(auth_surface)}
    })
    ConsoleUI.success(f"Auth Discovery: {len(auth_surface)} auth surface elements found")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_auth_discovery", name="Authentication Discovery",
        description="Maps login, logout, registration, password reset, MFA, OAuth, JWT, session endpoints",
        category="recon_intelligence", noise_score=1, required_inputs=["routes"],
        produced_outputs=["auth_surface"],
        supported_phases=["Reconnaissance"],
        requires_evidence=False, execute_fn=_execute
    ))
