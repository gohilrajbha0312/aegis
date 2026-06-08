"""
Broken Authentication Reasoning Skill
=======================================
Covers: Password resets, security questions, 2FA, credential stuffing, OSINT.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

BROKEN_AUTH_CHALLENGES = [
    {"id": "AUTH-01", "name": "Password Strength", "desc": "Log in with the administrator's user credentials without SQLi.", "difficulty": 2, "tags": ["Brute Force", "Tutorial"], "vectors": ["weak password guessing"], "recon": ["login endpoint"]},
    {"id": "AUTH-02", "name": "Bjoern's Favorite Pet", "desc": "Reset Bjoern's OWASP account password via Forgot Password with original answer.", "difficulty": 3, "tags": ["OSINT"], "vectors": ["security question OSINT"], "recon": ["/rest/user/reset-password", "forgot password"]},
    {"id": "AUTH-03", "name": "Reset Jim's Password", "desc": "Reset Jim's password via Forgot Password with original answer.", "difficulty": 3, "tags": ["OSINT"], "vectors": ["security question OSINT"], "recon": ["/rest/user/reset-password"]},
    {"id": "AUTH-04", "name": "Reset Bender's Password", "desc": "Reset Bender's password via Forgot Password with original answer.", "difficulty": 4, "tags": ["OSINT"], "vectors": ["security question OSINT"], "recon": ["/rest/user/reset-password"]},
    {"id": "AUTH-05", "name": "Reset Bjoern's Password", "desc": "Reset Bjoern's internal account password via Forgot Password.", "difficulty": 5, "tags": ["OSINT"], "vectors": ["security question OSINT"], "recon": ["/rest/user/reset-password"]},
    {"id": "AUTH-06", "name": "Reset Uvogin's Password", "desc": "Reset Uvogin's password via Forgot Password.", "difficulty": 4, "tags": ["OSINT"], "vectors": ["security question OSINT"], "recon": ["/rest/user/reset-password"]},
    {"id": "AUTH-07", "name": "Reset Morty's Password", "desc": "Reset Morty's password with his obfuscated answer.", "difficulty": 5, "tags": ["OSINT", "Brute Force"], "vectors": ["obfuscated security answer"], "recon": ["/rest/user/reset-password"]},
    {"id": "AUTH-08", "name": "GDPR Data Erasure", "desc": "Log in with Chris' erased user account.", "difficulty": 3, "vectors": ["login with deleted account"], "recon": ["login endpoint", "user erasure"]},
    {"id": "AUTH-09", "name": "Login Bjoern", "desc": "Log in with Bjoern's Gmail account without changing password or SQLi.", "difficulty": 4, "tags": ["Code Analysis"], "vectors": ["OAuth/password reset chain"], "recon": ["login endpoint", "OAuth"]},
    {"id": "AUTH-10", "name": "Change Bender's Password", "desc": "Change Bender's password into slurmCl4ssic without SQLi or Forgot Password.", "difficulty": 5, "vectors": ["CSRF on password change", "API manipulation"], "recon": ["/rest/user/change-password"]},
    {"id": "AUTH-11", "name": "Two Factor Authentication", "desc": "Solve the 2FA challenge for user wurstbrot.", "difficulty": 5, "vectors": ["TOTP token extraction"], "recon": ["/rest/2fa", "2fa endpoint"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("SKILL: Broken Authentication Reasoning")
    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_eps = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in BROKEN_AUTH_CHALLENGES:
        relevance = any(h.lower() in all_eps for h in ch["recon"])
        hypotheses.append({
            "type": "broken_auth_challenge", "challenge_id": ch["id"],
            "challenge_name": ch["name"], "description": ch["desc"],
            "attack_vectors": ch["vectors"], "recon_hints": ch["recon"],
            "confidence": 0.5 if relevance else 0.2, "evidence_matched": relevance,
            "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)
    if "broken_auth_reasoning" not in state.explored_paths:
        state.explored_paths.append("broken_auth_reasoning")
    state.evidence_ledger.append({
        "stage": "SKILL_BROKEN_AUTH_REASONING", "timestamp": time.time(),
        "action": "auth_knowledge_injection",
        "result": {"total": len(BROKEN_AUTH_CHALLENGES), "matched": matched}
    })
    ConsoleUI.success(f"Broken Auth: {len(BROKEN_AUTH_CHALLENGES)} challenges, {matched} matched")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="broken_auth_reasoning", name="Broken Authentication Reasoning",
        description="Password reset, 2FA, OSINT-based auth challenge knowledge",
        category="broken_authentication", noise_score=0, required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Authentication Analysis", "Vulnerability Discovery"],
        requires_evidence=False, execute_fn=_execute
    ))
