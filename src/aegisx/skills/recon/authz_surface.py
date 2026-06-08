"""
Skill 4: AuthorizationSurfaceSkill
====================================
Map trust boundaries and roles: Guest, User, Moderator, Admin, Support, Service.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

ROLE_INDICATORS = {
    "admin": ["admin", "administrator", "administration", "superuser"],
    "user": ["user", "member", "account", "profile", "dashboard"],
    "guest": ["guest", "public", "anonymous"],
    "moderator": ["moderator", "mod", "review", "approve"],
    "support": ["support", "helpdesk", "ticket", "agent"],
    "service": ["service", "api", "internal", "system", "webhook", "cron"],
}


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 4: Authorization Surface")
    roles_found = set(state.roles)
    authz_matrix = []

    all_routes = []
    for r in state.routes:
        route_str = r if isinstance(r, str) else r.get("route", str(r))
        all_routes.append(route_str)

    # 1. Infer roles from route names
    for route in all_routes:
        rl = route.lower()
        for role, indicators in ROLE_INDICATORS.items():
            if any(ind in rl for ind in indicators):
                roles_found.add(role)
                authz_matrix.append({
                    "role": role, "route": route,
                    "access": "inferred", "source": "route_name_analysis",
                    "confidence": 0.6
                })

    # 2. Infer roles from JS routes
    for route in state.discovered_js_routes:
        rl = route.lower()
        for role, indicators in ROLE_INDICATORS.items():
            if any(ind in rl for ind in indicators):
                roles_found.add(role)
                if not any(m.get("role") == role and m.get("route") == route for m in authz_matrix):
                    authz_matrix.append({
                        "role": role, "route": route,
                        "access": "inferred", "source": "js_route_analysis",
                        "confidence": 0.55
                    })

    # 3. Infer from auth surface
    for auth_item in state.auth_surface:
        if auth_item.get("type") in ["login", "register"]:
            roles_found.add("user")
        if auth_item.get("type") == "oauth":
            roles_found.add("user")

    # Always assume guest exists
    roles_found.add("guest")

    state.roles = sorted(roles_found)
    state.authorization_matrix = authz_matrix
    if "authz_surface" not in state.explored_paths:
        state.explored_paths.append("authz_surface")
    state.evidence_ledger.append({
        "stage": "RECON_AUTHZ_SURFACE", "timestamp": time.time(),
        "action": "authorization_mapping",
        "result": {"roles": list(roles_found), "matrix_entries": len(authz_matrix)}
    })
    ConsoleUI.success(f"AuthZ Surface: {len(roles_found)} roles, {len(authz_matrix)} matrix entries")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_authz_surface", name="Authorization Surface",
        description="Maps trust boundaries, roles, and authorization matrix from evidence",
        category="recon_intelligence", noise_score=0, required_inputs=["routes"],
        produced_outputs=["roles", "authorization_matrix"],
        supported_phases=["Reconnaissance"],
        requires_evidence=True, execute_fn=_execute
    ))
