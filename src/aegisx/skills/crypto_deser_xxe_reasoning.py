"""
Crypto / Deserialization / XXE Reasoning Skill
================================================
Covers: Weird Crypto, Forged Coupon, Nested Easter Egg, RCE DoS,
Memory Bomb, XXE Data Access/DoS, Imaginary Challenge, Premium Paywall.
Also: Miscellaneous, Security through Obscurity, Broken Anti-Automation, Observability, Unvalidated Redirects.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

MISC_CHALLENGES = [
    # Cryptographic Issues
    {"id": "CRY-01", "name": "Weird Crypto", "desc": "Inform the shop about an algorithm or library it should definitely not use.", "difficulty": 2, "cat": "Cryptographic Issues", "vectors": ["identify weak crypto algorithm"], "recon": ["contact form", "customer feedback"]},
    {"id": "CRY-02", "name": "Nested Easter Egg", "desc": "Apply advanced cryptanalysis to find the real easter egg.", "difficulty": 4, "cat": "Cryptographic Issues", "vectors": ["decode nested encodings"], "recon": ["/ftp", "easter egg file", "base64/rot13"]},
    {"id": "CRY-03", "name": "Forged Coupon", "desc": "Forge a coupon code that gives you a discount of at least 80%.", "difficulty": 6, "cat": "Cryptographic Issues", "vectors": ["reverse-engineer coupon algorithm"], "recon": ["/rest/basket/coupon", "coupon codes in JS"]},
    {"id": "CRY-04", "name": "Imaginary Challenge", "desc": "Solve challenge #999. Unfortunately, this challenge does not exist.", "difficulty": 6, "cat": "Cryptographic Issues", "vectors": ["JWT/API manipulation for non-existent challenge"], "recon": ["/api/Challenges", "challenge API"]},
    {"id": "CRY-05", "name": "Premium Paywall", "desc": "Unlock Premium Challenge to access exclusive content.", "difficulty": 6, "cat": "Cryptographic Issues", "vectors": ["payment/crypto bypass"], "recon": ["premium endpoints", "wallet"]},
    # Insecure Deserialization
    {"id": "DES-01", "name": "Blocked RCE DoS", "desc": "Perform a Remote Code Execution that would keep a less hardened application busy forever.", "difficulty": 5, "cat": "Insecure Deserialization", "vectors": ["deserialization payload"], "recon": ["/api/", "file upload", "B2B interface"]},
    {"id": "DES-02", "name": "Successful RCE DoS", "desc": "Perform an RCE that occupies the server without infinite loops.", "difficulty": 6, "cat": "Insecure Deserialization", "vectors": ["deserialization RCE"], "recon": ["/api/", "file upload"]},
    {"id": "DES-03", "name": "Memory Bomb", "desc": "Drop explosive data into a vulnerable file-handling endpoint.", "difficulty": 5, "cat": "Insecure Deserialization", "vectors": ["zip bomb / decompression bomb"], "recon": ["/file-upload", "file handling"]},
    # XXE
    {"id": "XXE-01", "name": "XXE Data Access", "desc": "Retrieve the content of C:\\Windows\\system.ini or /etc/passwd from the server.", "difficulty": 3, "cat": "XXE", "vectors": ["XXE via XML file upload"], "recon": ["/file-upload", "B2B XML endpoint", "deprecated interface"]},
    {"id": "XXE-02", "name": "XXE DoS", "desc": "Give the server something to chew on for quite a while.", "difficulty": 5, "cat": "XXE", "vectors": ["billion laughs attack"], "recon": ["/file-upload", "XML processing"]},
    # Miscellaneous
    {"id": "MISC-01", "name": "Score Board", "desc": "Find the carefully hidden 'Score Board' page.", "difficulty": 1, "cat": "Miscellaneous", "vectors": ["JS source code analysis"], "recon": ["/#/score-board", "JS routes"]},
    {"id": "MISC-02", "name": "Privacy Policy", "desc": "Read our privacy policy.", "difficulty": 1, "cat": "Miscellaneous", "vectors": ["navigation"], "recon": ["/#/privacy-security/privacy-policy"]},
    {"id": "MISC-03", "name": "Mass Dispel", "desc": "Close multiple Challenge solved notifications in one go.", "difficulty": 1, "cat": "Miscellaneous", "vectors": ["API call to dismiss all"], "recon": ["/api/Challenges", "notification API"]},
    {"id": "MISC-04", "name": "Security Policy", "desc": "Behave like any white-hat should before getting into the action.", "difficulty": 2, "cat": "Miscellaneous", "vectors": ["find security.txt"], "recon": ["/.well-known/security.txt", "/security.txt"]},
    {"id": "MISC-05", "name": "Security Advisory", "desc": "Inform about a known vulnerability with a suitable checksum.", "difficulty": 4, "cat": "Miscellaneous", "vectors": ["CVE/advisory lookup"], "recon": ["package.json", "Snyk/npm audit"]},
    # Security through Obscurity
    {"id": "STO-01", "name": "Privacy Policy Inspection", "desc": "Prove that you actually read our privacy policy.", "difficulty": 3, "cat": "Security through Obscurity", "vectors": ["hidden link/endpoint in policy"], "recon": ["/privacy-security", "policy page source"]},
    {"id": "STO-02", "name": "Steganography", "desc": "Rat out a notorious character hiding in plain sight.", "difficulty": 4, "cat": "Security through Obscurity", "vectors": ["steganographic analysis"], "recon": ["/assets", "product images"]},
    # Broken Anti-Automation
    {"id": "BAA-01", "name": "CAPTCHA Bypass", "desc": "Submit 10 or more customer feedbacks within 20 seconds.", "difficulty": 3, "cat": "Broken Anti Automation", "vectors": ["CAPTCHA replay attack"], "recon": ["/api/Feedbacks", "CAPTCHA endpoint"]},
    {"id": "BAA-02", "name": "Extra Language", "desc": "Retrieve the language file that never made it into production.", "difficulty": 5, "cat": "Broken Anti Automation", "vectors": ["brute force i18n file names"], "recon": ["/i18n/", "language files"]},
    {"id": "BAA-03", "name": "Multiple Likes", "desc": "Like any review at least three times as the same user.", "difficulty": 6, "cat": "Broken Anti Automation", "vectors": ["race condition / replay"], "recon": ["/rest/products/reviews", "like endpoint"]},
    # Observability Failures
    {"id": "OBS-01", "name": "Exposed Metrics", "desc": "Find the endpoint serving usage data for monitoring.", "difficulty": 1, "cat": "Observability Failures", "vectors": ["Prometheus metrics endpoint"], "recon": ["/metrics", "monitoring endpoint"]},
    {"id": "OBS-02", "name": "Access Log", "desc": "Gain access to any access log file of the server.", "difficulty": 4, "cat": "Observability Failures", "vectors": ["log file access"], "recon": ["/support/logs", "log endpoints"]},
    {"id": "OBS-03", "name": "Misplaced Signature File", "desc": "Access a misplaced SIEM signature file.", "difficulty": 4, "cat": "Observability Failures", "vectors": ["file path guessing"], "recon": ["/ftp", "suspicious files"]},
    # Unvalidated Redirects
    {"id": "RED-01", "name": "Outdated Allowlist", "desc": "Let us redirect you to a deprecated crypto currency address.", "difficulty": 1, "cat": "Unvalidated Redirects", "vectors": ["redirect parameter manipulation"], "recon": ["/redirect", "redirect endpoint"]},
    {"id": "RED-02", "name": "Allowlist Bypass", "desc": "Enforce a redirect to a page you are not supposed to redirect to.", "difficulty": 4, "cat": "Unvalidated Redirects", "vectors": ["URL parsing bypass"], "recon": ["/redirect", "redirect allowlist"]},
    # Security Misconfiguration extras
    {"id": "SCM-01", "name": "Deprecated Interface", "desc": "Use a deprecated B2B interface that was not properly shut down.", "difficulty": 2, "cat": "Security Misconfiguration", "vectors": ["XML file upload to B2B endpoint"], "recon": ["/file-upload", "/api/", "B2B"]},
    {"id": "SCM-02", "name": "Error Handling", "desc": "Provoke an error that is neither very gracefully nor consistently handled.", "difficulty": 1, "cat": "Security Misconfiguration", "vectors": ["trigger unhandled error"], "recon": ["/api/", "invalid input to REST"]},
    {"id": "SCM-03", "name": "Cross-Site Imaging", "desc": "Stick cute cross-domain kittens all over our delivery boxes.", "difficulty": 5, "cat": "Security Misconfiguration", "vectors": ["CORS / image URL injection"], "recon": ["/profile/image/url", "image upload"]},
    {"id": "SCM-04", "name": "Login Support Team", "desc": "Log in with the support team's original credentials.", "difficulty": 6, "cat": "Security Misconfiguration", "vectors": ["credential extraction from source"], "recon": ["login", "support team", "code analysis"]},
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("SKILL: Crypto/Deser/XXE/Misc Reasoning")
    hypotheses = []
    route_strs = [str(r).lower() for r in state.routes]
    all_eps = " ".join(route_strs + [e.lower() for e in state.api_endpoints])

    for ch in MISC_CHALLENGES:
        relevance = any(h.lower() in all_eps for h in ch["recon"])
        hypotheses.append({
            "type": f"{ch['cat'].lower().replace(' ', '_')}_challenge",
            "challenge_id": ch["id"], "challenge_name": ch["name"],
            "description": ch["desc"], "category": ch["cat"],
            "attack_vectors": ch["vectors"], "recon_hints": ch["recon"],
            "confidence": 0.5 if relevance else 0.2, "evidence_matched": relevance,
            "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
            "reasoning": f"[{ch['id']}] {ch['name']}: {ch['desc']}"
        })

    matched = sum(1 for h in hypotheses if h["evidence_matched"])
    state.attack_surface_nodes.extend(hypotheses)
    if "crypto_deser_xxe_reasoning" not in state.explored_paths:
        state.explored_paths.append("crypto_deser_xxe_reasoning")
    state.evidence_ledger.append({
        "stage": "SKILL_CRYPTO_DESER_XXE", "timestamp": time.time(),
        "action": "misc_knowledge_injection",
        "result": {"total": len(MISC_CHALLENGES), "matched": matched}
    })
    ConsoleUI.success(f"Crypto/Deser/XXE/Misc: {len(MISC_CHALLENGES)} challenges, {matched} matched")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="crypto_deser_xxe_reasoning",
        name="Crypto/Deserialization/XXE/Misc Reasoning",
        description="Crypto issues, XXE, deserialization, anti-automation, redirects, observability challenge knowledge",
        category="cryptographic_and_misc", noise_score=0, required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False, execute_fn=_execute
    ))
