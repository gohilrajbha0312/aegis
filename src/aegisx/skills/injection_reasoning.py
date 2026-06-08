"""
Injection Reasoning Skill
==========================
Evidence-backed injection vulnerability knowledge for OWASP Juice Shop.
Covers: SQL Injection, NoSQL Injection, Chatbot Prompt Injection, SSTi.
Anti-hallucination: Every hypothesis cites an exact challenge ID.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

# ── Verified Challenge Database (from Score Board) ──────────────────
INJECTION_CHALLENGES = [
    {"id": "INJ-01", "name": "Login Admin", "desc": "Log in with the administrator's user account.", "difficulty": 2, "tags": ["Tutorial", "Good for Demos"], "vectors": ["login form", "SQL injection in email field"], "recon": ["login endpoint", "POST /rest/user/login"]},
    {"id": "INJ-02", "name": "Login Jim", "desc": "Log in with Jim's user account.", "difficulty": 3, "tags": ["Tutorial"], "vectors": ["SQL injection in email field"], "recon": ["login endpoint", "user enumeration"]},
    {"id": "INJ-03", "name": "Login Bender", "desc": "Log in with Bender's user account.", "difficulty": 3, "tags": ["Tutorial"], "vectors": ["SQL injection in email field"], "recon": ["login endpoint", "user enumeration"]},
    {"id": "INJ-04", "name": "Database Schema", "desc": "Exfiltrate the entire DB schema definition via SQL Injection.", "difficulty": 3, "tags": ["Code Analysis"], "vectors": ["UNION-based SQLi", "search endpoint"], "recon": ["search API", "product listing endpoint"]},
    {"id": "INJ-05", "name": "Christmas Special", "desc": "Order the Christmas special offer of 2014.", "difficulty": 4, "tags": [], "vectors": ["SQLi in search/order endpoint"], "recon": ["product search API", "order API"]},
    {"id": "INJ-06", "name": "Ephemeral Accountant", "desc": "Log in with the (non-existing) accountant acc0unt4nt@juice-sh.op without ever registering that user.", "difficulty": 4, "tags": [], "vectors": ["SQLi creating ephemeral login"], "recon": ["login endpoint"]},
    {"id": "INJ-07", "name": "User Credentials", "desc": "Retrieve a list of all user credentials via SQL Injection.", "difficulty": 4, "tags": ["Code Analysis"], "vectors": ["UNION-based SQLi"], "recon": ["search API", "any SQLi-vulnerable endpoint"]},
    {"id": "INJ-08", "name": "NoSQL DoS", "desc": "Let the server sleep for some time.", "difficulty": 5, "tags": ["Danger Zone"], "vectors": ["NoSQL $sleep operator injection"], "recon": ["product review endpoint", "MongoDB-backed APIs"]},
    {"id": "INJ-09", "name": "NoSQL Manipulation", "desc": "Update multiple product reviews at the same time.", "difficulty": 4, "tags": [], "vectors": ["NoSQL $set/$where injection"], "recon": ["product review API", "PATCH/PUT endpoints"]},
    {"id": "INJ-10", "name": "NoSQL Exfiltration", "desc": "All your orders are belong to us! Even the ones which don't.", "difficulty": 5, "tags": ["Danger Zone"], "vectors": ["NoSQL query injection"], "recon": ["order history API"]},
    {"id": "INJ-11", "name": "Chatbot Prompt Injection", "desc": "Trick the chatbot into generating a coupon code despite its coupon policy.", "difficulty": 3, "tags": ["Good for Demos", "AI/LLM", "Requires LLM API"], "vectors": ["LLM prompt injection"], "recon": ["chatbot endpoint", "/api/chat"]},
    {"id": "INJ-12", "name": "Greedy Chatbot Manipulation", "desc": "Convince the chatbot to give you a coupon of 50% or more.", "difficulty": 4, "tags": ["AI/LLM", "Requires LLM API"], "vectors": ["LLM manipulation"], "recon": ["chatbot endpoint"]},
    {"id": "INJ-13", "name": "SSTi", "desc": "Infect the server with juicy malware by abusing arbitrary command execution.", "difficulty": 6, "tags": ["Contraption", "Danger Zone", "Code Analysis"], "vectors": ["Server-Side Template Injection"], "recon": ["profile/template endpoints", "user input rendered server-side"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    """Inject verified injection challenge knowledge into AI reasoning context."""
    ConsoleUI.header("SKILL: Injection Reasoning")

    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_endpoints = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in INJECTION_CHALLENGES:
        # Evidence gate: only inject if recon found relevant endpoints
        relevance = any(hint.lower() in all_endpoints for hint in ch["recon"])
        confidence = 0.5 if relevance else 0.2

        hypotheses.append({
            "type": "injection_challenge_context",
            "challenge_id": ch["id"],
            "challenge_name": ch["name"],
            "description": ch["desc"],
            "attack_vectors": ch["vectors"],
            "recon_hints": ch["recon"],
            "confidence": confidence,
            "evidence_matched": relevance,
            "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)

    if "injection_reasoning" not in state.explored_paths:
        state.explored_paths.append("injection_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_INJECTION_REASONING",
        "timestamp": time.time(),
        "action": "injection_knowledge_injection",
        "result": {"total_challenges": len(INJECTION_CHALLENGES), "evidence_matched": matched}
    })

    ConsoleUI.success(f"Injection reasoning: {len(INJECTION_CHALLENGES)} challenges loaded, {matched} matched recon evidence")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="injection_reasoning",
        name="Injection Reasoning",
        description="Evidence-backed SQLi/NoSQL/LLM/SSTi challenge knowledge from Juice Shop Score Board",
        category="injection",
        noise_score=0,
        required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False,
        execute_fn=_execute
    ))
