"""
OWASP Juice Shop Master Reasoning Skill
=========================================
Orchestrates all Juice Shop sub-skills and provides a unified challenge context.
Cross-references discovered routes against known challenge targets.

Anti-Hallucination Gate: Every hypothesis MUST cite an exact challenge_id.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI


def _get_all_challenge_count() -> int:
    """Count total challenges across all sub-skill modules."""
    from aegisx.skills.injection_reasoning import INJECTION_CHALLENGES
    from aegisx.skills.xss_reasoning import XSS_CHALLENGES
    from aegisx.skills.broken_access_reasoning import BAC_CHALLENGES
    from aegisx.skills.broken_auth_reasoning import BROKEN_AUTH_CHALLENGES
    from aegisx.skills.sensitive_data_reasoning import SDE_CHALLENGES
    from aegisx.skills.improper_input_reasoning import INPUT_CHALLENGES
    from aegisx.skills.vulnerable_components_reasoning import VC_CHALLENGES
    from aegisx.skills.crypto_deser_xxe_reasoning import MISC_CHALLENGES

    return (len(INJECTION_CHALLENGES) + len(XSS_CHALLENGES) + len(BAC_CHALLENGES) +
            len(BROKEN_AUTH_CHALLENGES) + len(SDE_CHALLENGES) + len(INPUT_CHALLENGES) +
            len(VC_CHALLENGES) + len(MISC_CHALLENGES))


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Juice Shop Master Reasoning: Injects a summary context node and
    validates that all sub-skills have been loaded.
    """
    ConsoleUI.header("SKILL: OWASP Juice Shop Master Reasoning")

    total_challenges = _get_all_challenge_count()

    # Summary context for the AI Commander
    juice_shop_context = {
        "finding_type": "OWASP Juice Shop Challenge Context",
        "title": "OWASP Juice Shop Target Identified",
        "severity": "INFO",
        "endpoint": "global",
        "evidence": f"Juice Shop challenge profile loaded: {total_challenges} challenges across 10+ categories.",
        "confidence": 1.0,
        "validation": "manual_skill_activation",
        "risk_level": "INFO",
        "provenance": "OWASP_JUICE_SHOP_SCOREBOARD",
        "details": (
            f"The target is an OWASP Juice Shop instance. {total_challenges} challenges loaded:\n"
            "- Injection (SQLi, NoSQL, LLM Prompt Injection, SSTi)\n"
            "- XSS (DOM, Reflected, Stored, CSP Bypass, HTTP-Header, Video)\n"
            "- Broken Access Control (IDOR, CSRF, SSRF, Admin Panel, Web3)\n"
            "- Broken Authentication (Password Reset, 2FA, OSINT, Credential Stuffing)\n"
            "- Sensitive Data Exposure (FTP Backups, Geo Stalking, Leaked Keys, Blueprints)\n"
            "- Improper Input Validation (Upload Bypass, Payment Fraud, Admin Registration)\n"
            "- Vulnerable Components (Typosquatting, JWT Forging, Supply Chain)\n"
            "- Cryptographic Issues (Weak Crypto, Forged Coupons, Nested Encoding)\n"
            "- XXE (Data Access, DoS via Billion Laughs)\n"
            "- Insecure Deserialization (RCE, Memory Bomb)\n"
            "- Security Misconfiguration, Observability, Anti-Automation, Redirects\n\n"
            "ANTI-HALLUCINATION: All hypotheses reference exact challenge IDs from the Score Board."
        )
    }

    state.attack_surface_nodes.append(juice_shop_context)

    if "juice_shop_reasoning" not in state.explored_paths:
        state.explored_paths.append("juice_shop_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_JUICE_SHOP_REASONING",
        "timestamp": time.time(),
        "action": "inject_juice_shop_master_context",
        "result": {"context_injected": True, "total_challenges": total_challenges}
    })

    ConsoleUI.success(f"Injected OWASP Juice Shop master context: {total_challenges} challenges across all categories.")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="juice_shop_reasoning",
        name="OWASP Juice Shop Master Reasoning",
        description=f"Master orchestrator for all Juice Shop challenge skills — anti-hallucination enabled.",
        category="custom_targets",
        noise_score=0,
        required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False,
        execute_fn=_execute
    ))
