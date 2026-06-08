"""
Sensitive Data Exposure Reasoning Skill
========================================
Covers: Confidential docs, exposed credentials, geo stalking, backups, blueprints, leaked keys.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

SDE_CHALLENGES = [
    {"id": "SDE-01", "name": "Confidential Document", "desc": "Access a confidential document.", "difficulty": 1, "vectors": ["FTP directory listing"], "recon": ["/ftp", "directory listing"]},
    {"id": "SDE-02", "name": "Exposed credentials", "desc": "A developer hardcoded unused but valid credentials client-side.", "difficulty": 2, "vectors": ["JS source code analysis"], "recon": ["main.js", "JavaScript bundles", "hardcoded credentials"]},
    {"id": "SDE-03", "name": "Login MC SafeSearch", "desc": "Log in with MC SafeSearch's original credentials without SQLi.", "difficulty": 2, "tags": ["OSINT"], "vectors": ["OSINT from public info"], "recon": ["login endpoint", "user enumeration"]},
    {"id": "SDE-04", "name": "Meta Geo Stalking", "desc": "Determine John's security question answer from Photo Wall upload metadata.", "difficulty": 2, "tags": ["OSINT"], "vectors": ["EXIF metadata extraction"], "recon": ["/photo-wall", "image uploads", "EXIF data"]},
    {"id": "SDE-05", "name": "Visual Geo Stalking", "desc": "Determine Emma's security question answer from Photo Wall upload.", "difficulty": 2, "tags": ["OSINT"], "vectors": ["visual analysis of photo"], "recon": ["/photo-wall", "image uploads"]},
    {"id": "SDE-06", "name": "NFT Takeover", "desc": "Take over the wallet containing our official Soul Bound Token.", "difficulty": 2, "tags": ["Web3"], "vectors": ["wallet key exposure"], "recon": ["NFT endpoints", "Web3 wallet"]},
    {"id": "SDE-07", "name": "Password Hash Leak", "desc": "Obtain the password hash of the currently logged-in user from REST API.", "difficulty": 2, "vectors": ["excessive data in API response"], "recon": ["/rest/user/whoami", "user profile API"]},
    {"id": "SDE-08", "name": "Login Amy", "desc": "Log in with Amy's original credentials. (93.83 billion trillion trillion centuries to brute force)", "difficulty": 3, "tags": ["OSINT"], "vectors": ["Kerckhoffs' principle / passphrase from book"], "recon": ["login endpoint"]},
    {"id": "SDE-09", "name": "Forgotten Developer Backup", "desc": "Access a developer's forgotten backup file.", "difficulty": 4, "vectors": ["FTP directory + null byte bypass"], "recon": ["/ftp", "backup files", ".bak"]},
    {"id": "SDE-10", "name": "Forgotten Sales Backup", "desc": "Access a salesman's forgotten backup file.", "difficulty": 4, "vectors": ["FTP directory access"], "recon": ["/ftp", "backup files"]},
    {"id": "SDE-11", "name": "GDPR Data Theft", "desc": "Steal someone else's personal data without using Injection.", "difficulty": 4, "vectors": ["IDOR on data export"], "recon": ["/rest/user/data-export", "GDPR export"]},
    {"id": "SDE-12", "name": "Email Leak", "desc": "Perform unwanted information disclosure by accessing data cross-domain.", "difficulty": 5, "vectors": ["cross-domain data access"], "recon": ["CORS misconfiguration", "API endpoints"]},
    {"id": "SDE-13", "name": "Leaked Unsafe Product", "desc": "Identify an unsafe product removed from the shop.", "difficulty": 4, "tags": ["OSINT"], "vectors": ["deleted product recovery"], "recon": ["/api/Products", "product search"]},
    {"id": "SDE-14", "name": "Leaked API Key", "desc": "Inform the shop about a leaked API key.", "difficulty": 5, "vectors": ["source code / config file leak"], "recon": ["JS bundles", "config files", "environment variables"]},
    {"id": "SDE-15", "name": "Leaked Access Logs", "desc": "Dumpster dive the Internet for a leaked password.", "difficulty": 5, "tags": ["OSINT"], "vectors": ["public paste / log analysis"], "recon": ["access logs", "external OSINT"]},
    {"id": "SDE-16", "name": "Retrieve Blueprint", "desc": "Download the blueprint for one of the products.", "difficulty": 5, "vectors": ["hidden file path guessing"], "recon": ["/ftp", "product assets", "3D model files"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("SKILL: Sensitive Data Exposure Reasoning")
    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_eps = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in SDE_CHALLENGES:
        relevance = any(h.lower() in all_eps for h in ch["recon"])
        hypotheses.append({
            "type": "sensitive_data_challenge", "challenge_id": ch["id"],
            "challenge_name": ch["name"], "description": ch["desc"],
            "attack_vectors": ch["vectors"], "recon_hints": ch["recon"],
            "confidence": 0.5 if relevance else 0.2, "evidence_matched": relevance,
            "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)
    if "sensitive_data_reasoning" not in state.explored_paths:
        state.explored_paths.append("sensitive_data_reasoning")
    state.evidence_ledger.append({
        "stage": "SKILL_SENSITIVE_DATA_REASONING", "timestamp": time.time(),
        "action": "sde_knowledge_injection",
        "result": {"total": len(SDE_CHALLENGES), "matched": matched}
    })
    ConsoleUI.success(f"Sensitive Data: {len(SDE_CHALLENGES)} challenges, {matched} matched")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="sensitive_data_reasoning", name="Sensitive Data Exposure Reasoning",
        description="Credential leaks, backup files, OSINT, geo-stalking challenge knowledge",
        category="sensitive_data_exposure", noise_score=0, required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False, execute_fn=_execute
    ))
