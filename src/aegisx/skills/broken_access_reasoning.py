"""
Broken Access Control Reasoning Skill
=======================================
Covers: Admin Section, View/Manipulate Basket, Forged Feedback/Review,
CSRF, SSRF, Easter Egg, Web3 Sandbox, NFT, Wallet Depletion.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

BAC_CHALLENGES = [
    {"id": "BAC-01", "name": "Admin Section", "desc": "Access the administration section of the store.", "difficulty": 2, "vectors": ["direct URL access to admin panel"], "recon": ["/#/administration", "admin routes in JS"]},
    {"id": "BAC-02", "name": "View Basket", "desc": "View another user's shopping basket.", "difficulty": 2, "vectors": ["IDOR on basket ID"], "recon": ["/rest/basket/", "basket API"]},
    {"id": "BAC-03", "name": "Five-Star Feedback", "desc": "Get rid of all 5-star customer feedback.", "difficulty": 2, "vectors": ["DELETE on feedback endpoint"], "recon": ["/api/Feedbacks", "feedback API"]},
    {"id": "BAC-04", "name": "Forged Feedback", "desc": "Post some feedback in another user's name.", "difficulty": 3, "vectors": ["UserId manipulation in POST body"], "recon": ["/api/Feedbacks", "POST feedback"]},
    {"id": "BAC-05", "name": "Forged Review", "desc": "Post a product review as another user or edit any user's existing review.", "difficulty": 3, "vectors": ["author field manipulation"], "recon": ["/rest/products/reviews", "review API"]},
    {"id": "BAC-06", "name": "Manipulate Basket", "desc": "Put an additional product into another user's shopping basket.", "difficulty": 3, "vectors": ["BasketId manipulation in POST"], "recon": ["/api/BasketItems", "basket item API"]},
    {"id": "BAC-07", "name": "Product Tampering", "desc": "Change the href of the link within the O-Saft product description.", "difficulty": 3, "vectors": ["PUT on product endpoint"], "recon": ["/api/Products/", "product update API"]},
    {"id": "BAC-08", "name": "CSRF", "desc": "Change the name of a user by performing Cross-Site Request Forgery.", "difficulty": 3, "vectors": ["CSRF on profile update"], "recon": ["/profile", "/api/Users/"]},
    {"id": "BAC-09", "name": "Easter Egg", "desc": "Find the hidden easter egg.", "difficulty": 4, "vectors": ["FTP directory traversal", "hidden file access"], "recon": ["/ftp", "confidential files"]},
    {"id": "BAC-10", "name": "SSRF", "desc": "Request a hidden resource on server through server.", "difficulty": 6, "vectors": ["Server-Side Request Forgery"], "recon": ["/profile/image/url", "URL fetch endpoints"]},
    {"id": "BAC-11", "name": "AI Debugging", "desc": "Reveal behind-the-scenes information on the chatbot as non-admin.", "difficulty": 2, "vectors": ["chatbot debug info extraction"], "recon": ["/api/chat", "chatbot endpoint"]},
    {"id": "BAC-12", "name": "Web3 Sandbox", "desc": "Find an accidentally deployed code sandbox for writing smart contracts.", "difficulty": 2, "vectors": ["hidden Web3 page"], "recon": ["/#/web3-sandbox", "JS route analysis"]},
    {"id": "BAC-13", "name": "Wallet Depletion", "desc": "Withdraw more ETH from the new wallet than you deposited.", "difficulty": 5, "vectors": ["smart contract reentrancy"], "recon": ["wallet endpoints", "Web3 APIs"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("SKILL: Broken Access Control Reasoning")
    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_eps = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in BAC_CHALLENGES:
        relevance = any(h.lower() in all_eps for h in ch["recon"])
        hypotheses.append({
            "type": "broken_access_challenge", "challenge_id": ch["id"],
            "challenge_name": ch["name"], "description": ch["desc"],
            "attack_vectors": ch["vectors"], "recon_hints": ch["recon"],
            "confidence": 0.5 if relevance else 0.2, "evidence_matched": relevance,
            "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)
    if "broken_access_reasoning" not in state.explored_paths:
        state.explored_paths.append("broken_access_reasoning")
    state.evidence_ledger.append({
        "stage": "SKILL_BROKEN_ACCESS_REASONING", "timestamp": time.time(),
        "action": "bac_knowledge_injection",
        "result": {"total": len(BAC_CHALLENGES), "matched": matched}
    })
    ConsoleUI.success(f"Broken Access Control: {len(BAC_CHALLENGES)} challenges, {matched} matched")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="broken_access_reasoning", name="Broken Access Control Reasoning",
        description="IDOR/BOLA/CSRF/SSRF challenge knowledge from Juice Shop Score Board",
        category="broken_access_control", noise_score=0, required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False, execute_fn=_execute
    ))
