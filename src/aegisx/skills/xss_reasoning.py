"""
XSS Reasoning Skill
=====================
Evidence-backed XSS vulnerability knowledge for OWASP Juice Shop.
Covers: DOM XSS, Reflected XSS, Stored XSS, CSP Bypass, HTTP-Header XSS.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

XSS_CHALLENGES = [
    {"id": "XSS-01", "name": "DOM XSS", "desc": 'Perform a DOM XSS attack with <iframe src="javascript:alert(`xss`)">.', "difficulty": 1, "tags": ["Tutorial", "Good for Demos"], "vectors": ["DOM-based XSS via URL fragment/search"], "recon": ["search bar", "URL hash parameters", "/#/search"]},
    {"id": "XSS-02", "name": "Bonus Payload", "desc": "Use the bonus payload (SoundCloud iframe) in the DOM XSS challenge.", "difficulty": 1, "tags": ["Shenanigans", "Tutorial"], "vectors": ["DOM XSS with SoundCloud iframe"], "recon": ["search bar", "DOM XSS endpoint"]},
    {"id": "XSS-03", "name": "Reflected XSS", "desc": 'Perform a reflected XSS attack with <iframe src="javascript:alert(`xss`)">.', "difficulty": 2, "tags": ["Tutorial", "Danger Zone", "Good for Demos"], "vectors": ["Reflected XSS in order tracking"], "recon": ["order tracking endpoint", "/rest/track-order"]},
    {"id": "XSS-04", "name": "API-only XSS", "desc": 'Perform a persisted XSS attack with <iframe src="javascript:alert(`xss`)"> without using the frontend.', "difficulty": 3, "tags": ["Danger Zone"], "vectors": ["Stored XSS via direct API call"], "recon": ["user profile API", "product API", "POST endpoints"]},
    {"id": "XSS-05", "name": "Client-side XSS Protection", "desc": 'Perform a persisted XSS attack bypassing a client-side security mechanism.', "difficulty": 3, "tags": ["Danger Zone"], "vectors": ["Bypass client-side sanitization"], "recon": ["feedback form", "product review", "user profile"]},
    {"id": "XSS-06", "name": "Server-side XSS Protection", "desc": 'Perform a persisted XSS attack bypassing a server-side security mechanism.', "difficulty": 4, "tags": ["Danger Zone"], "vectors": ["Bypass server-side sanitization via encoding"], "recon": ["product review", "feedback endpoints"]},
    {"id": "XSS-07", "name": "CSP Bypass", "desc": 'Bypass the Content Security Policy and perform an XSS attack on a legacy page.', "difficulty": 4, "tags": ["Danger Zone"], "vectors": ["CSP bypass on legacy page"], "recon": ["legacy pages", "/promotion", "CSP header analysis"]},
    {"id": "XSS-08", "name": "HTTP-Header XSS", "desc": 'Perform a persisted XSS attack through an HTTP header.', "difficulty": 4, "tags": ["Danger Zone"], "vectors": ["XSS via HTTP header injection"], "recon": ["User-Agent logging", "referrer logging", "header reflection"]},
    {"id": "XSS-09", "name": "Video XSS", "desc": 'Embed an XSS payload </script><script>alert(`xss`)</script> into our promo video.', "difficulty": 6, "tags": ["Danger Zone"], "vectors": ["XSS in video subtitle/metadata"], "recon": ["video endpoints", "promo video", "subtitle files"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("SKILL: XSS Reasoning")
    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_endpoints = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in XSS_CHALLENGES:
        relevance = any(hint.lower() in all_endpoints for hint in ch["recon"])
        hypotheses.append({
            "type": "xss_challenge_context",
            "challenge_id": ch["id"], "challenge_name": ch["name"],
            "description": ch["desc"], "attack_vectors": ch["vectors"],
            "recon_hints": ch["recon"], "confidence": 0.5 if relevance else 0.2,
            "evidence_matched": relevance, "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)
    if "xss_reasoning" not in state.explored_paths:
        state.explored_paths.append("xss_reasoning")
    state.evidence_ledger.append({
        "stage": "SKILL_XSS_REASONING", "timestamp": time.time(),
        "action": "xss_knowledge_injection",
        "result": {"total_challenges": len(XSS_CHALLENGES), "evidence_matched": matched}
    })
    ConsoleUI.success(f"XSS reasoning: {len(XSS_CHALLENGES)} challenges loaded, {matched} matched")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="xss_reasoning", name="XSS Reasoning",
        description="Evidence-backed DOM/Reflected/Stored/CSP-bypass XSS challenge knowledge",
        category="xss", noise_score=0, required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False, execute_fn=_execute
    ))
