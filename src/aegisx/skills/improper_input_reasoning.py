"""
Improper Input Validation Reasoning Skill
===========================================
Covers: Zero Stars, Upload bypasses, Admin Registration, Payback Time, Poison Null Byte, etc.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

INPUT_CHALLENGES = [
    {"id": "IIV-01", "name": "Missing Encoding", "desc": "Retrieve the photo of Bjoern's cat in melee combat-mode.", "difficulty": 1, "vectors": ["URL encoding bypass"], "recon": ["/assets/public/images", "photo assets"]},
    {"id": "IIV-02", "name": "Repetitive Registration", "desc": "Follow the DRY principle while registering a user.", "difficulty": 1, "vectors": ["password repeat field manipulation"], "recon": ["/api/Users", "registration endpoint"]},
    {"id": "IIV-03", "name": "Zero Stars", "desc": "Give a devastating zero-star feedback to the store.", "difficulty": 1, "vectors": ["rating value manipulation below minimum"], "recon": ["/api/Feedbacks", "feedback form"]},
    {"id": "IIV-04", "name": "Empty User Registration", "desc": "Register a user with an empty email and password.", "difficulty": 2, "vectors": ["bypass client-side validation"], "recon": ["/api/Users", "registration"]},
    {"id": "IIV-05", "name": "Admin Registration", "desc": "Register as a user with administrator privileges.", "difficulty": 3, "vectors": ["role field injection in registration"], "recon": ["/api/Users", "registration body params"]},
    {"id": "IIV-06", "name": "Deluxe Fraud", "desc": "Obtain a Deluxe Membership without paying for it.", "difficulty": 3, "vectors": ["payment bypass on membership"], "recon": ["/rest/deluxe-membership", "deluxe endpoint"]},
    {"id": "IIV-07", "name": "Payback Time", "desc": "Place an order that makes you rich.", "difficulty": 3, "vectors": ["negative quantity/price manipulation"], "recon": ["/api/BasketItems", "/rest/basket/checkout"]},
    {"id": "IIV-08", "name": "Upload Size", "desc": "Upload a file larger than 100 kB.", "difficulty": 3, "vectors": ["file size limit bypass"], "recon": ["/file-upload", "complaint form"]},
    {"id": "IIV-09", "name": "Upload Type", "desc": "Upload a file that has no .pdf or .zip extension.", "difficulty": 3, "vectors": ["file type validation bypass"], "recon": ["/file-upload", "complaint form"]},
    {"id": "IIV-10", "name": "Expired Coupon", "desc": "Successfully redeem an expired campaign coupon code.", "difficulty": 4, "vectors": ["coupon validation bypass"], "recon": ["/rest/basket/coupon", "coupon endpoint"]},
    {"id": "IIV-11", "name": "Poison Null Byte", "desc": "Bypass a security control with a Poison Null Byte.", "difficulty": 4, "vectors": ["null byte injection in file path"], "recon": ["/ftp", "file access endpoints"]},
    {"id": "IIV-12", "name": "Mint the Honey Pot", "desc": "Mint the Honey Pot NFT by gathering BEEs from the bee haven.", "difficulty": 5, "tags": ["Web3"], "vectors": ["NFT minting manipulation"], "recon": ["Web3 endpoints", "NFT minting"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("SKILL: Improper Input Validation Reasoning")
    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_eps = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in INPUT_CHALLENGES:
        relevance = any(h.lower() in all_eps for h in ch["recon"])
        hypotheses.append({
            "type": "input_validation_challenge", "challenge_id": ch["id"],
            "challenge_name": ch["name"], "description": ch["desc"],
            "attack_vectors": ch["vectors"], "recon_hints": ch["recon"],
            "confidence": 0.5 if relevance else 0.2, "evidence_matched": relevance,
            "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)
    if "improper_input_reasoning" not in state.explored_paths:
        state.explored_paths.append("improper_input_reasoning")
    state.evidence_ledger.append({
        "stage": "SKILL_INPUT_VALIDATION", "timestamp": time.time(),
        "action": "input_knowledge_injection",
        "result": {"total": len(INPUT_CHALLENGES), "matched": matched}
    })
    ConsoleUI.success(f"Input Validation: {len(INPUT_CHALLENGES)} challenges, {matched} matched")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="improper_input_reasoning", name="Improper Input Validation Reasoning",
        description="Upload bypass, registration manipulation, payment fraud challenge knowledge",
        category="improper_input_validation", noise_score=0, required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False, execute_fn=_execute
    ))
