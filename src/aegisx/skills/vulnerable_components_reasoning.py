"""
Vulnerable Components Reasoning Skill
=======================================
Covers: Typosquatting, Vulnerable libraries, JWT forging, Local File Read,
Supply Chain Attack, Arbitrary File Write.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

VC_CHALLENGES = [
    {"id": "VC-01", "name": "Legacy Typosquatting", "desc": "Inform the shop about a typosquatting trick it has been a victim of at least in v6.2.0-SNAPSHOT.", "difficulty": 4, "vectors": ["npm package typosquatting"], "recon": ["package.json", "node_modules"]},
    {"id": "VC-02", "name": "Frontend Typosquatting", "desc": "Inform the shop about a typosquatting imposter in the frontend.", "difficulty": 5, "vectors": ["frontend package typosquatting"], "recon": ["package.json", "frontend dependencies"]},
    {"id": "VC-03", "name": "Vulnerable Library", "desc": "Inform the shop about a vulnerable library it is using. (Mention exact name and version)", "difficulty": 4, "tags": ["OSINT"], "vectors": ["known CVE in dependency"], "recon": ["package.json", "JS bundles", "library versions"]},
    {"id": "VC-04", "name": "Local File Read", "desc": "Gain read access to an arbitrary local file on the web server.", "difficulty": 5, "tags": ["OSINT", "Danger Zone"], "vectors": ["path traversal via vulnerable lib"], "recon": ["file serving endpoints", "static assets"]},
    {"id": "VC-05", "name": "Supply Chain Attack", "desc": "Inform the development team about a danger to some of their credentials.", "difficulty": 5, "tags": ["OSINT"], "vectors": ["leaked credentials in supply chain"], "recon": ["GitHub repos", "npm packages"]},
    {"id": "VC-06", "name": "Unsigned JWT", "desc": "Forge an essentially unsigned JWT token that impersonates jwtn3d@juice-sh.op.", "difficulty": 5, "vectors": ["JWT alg:none attack"], "recon": ["JWT tokens", "Authorization header"]},
    {"id": "VC-07", "name": "Forged Signed JWT", "desc": "Forge an almost properly RSA-signed JWT token impersonating rsa_lord@juice-sh.op.", "difficulty": 6, "vectors": ["JWT RSA/HMAC confusion attack"], "recon": ["JWT tokens", "public key files"]},
    {"id": "VC-08", "name": "Arbitrary File Write", "desc": "Overwrite the Legal Information file.", "difficulty": 6, "tags": ["Danger Zone"], "vectors": ["zip slip / path traversal in upload"], "recon": ["/file-upload", "/ftp", "file handling endpoints"]},
    {"id": "VC-09", "name": "Blockchain Hype", "desc": "Learn about the Token Sale before its official announcement.", "difficulty": 5, "tags": ["Web3", "Code Analysis"], "vectors": ["hidden route in JS bundles"], "recon": ["JS route analysis", "/#/token-sale"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("SKILL: Vulnerable Components Reasoning")
    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_eps = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in VC_CHALLENGES:
        relevance = any(h.lower() in all_eps for h in ch["recon"])
        hypotheses.append({
            "type": "vulnerable_component_challenge", "challenge_id": ch["id"],
            "challenge_name": ch["name"], "description": ch["desc"],
            "attack_vectors": ch["vectors"], "recon_hints": ch["recon"],
            "confidence": 0.5 if relevance else 0.2, "evidence_matched": relevance,
            "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)
    if "vulnerable_components_reasoning" not in state.explored_paths:
        state.explored_paths.append("vulnerable_components_reasoning")
    state.evidence_ledger.append({
        "stage": "SKILL_VULNERABLE_COMPONENTS", "timestamp": time.time(),
        "action": "vc_knowledge_injection",
        "result": {"total": len(VC_CHALLENGES), "matched": matched}
    })
    ConsoleUI.success(f"Vulnerable Components: {len(VC_CHALLENGES)} challenges, {matched} matched")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="vulnerable_components_reasoning", name="Vulnerable Components Reasoning",
        description="Typosquatting, JWT forging, supply chain, local file read challenge knowledge",
        category="vulnerable_components", noise_score=0, required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False, execute_fn=_execute
    ))
