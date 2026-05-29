"""
OWASP Juice Shop Reasoning Skill
================================
Injects context and hypotheses specifically tailored for OWASP Juice Shop challenges.
This skill provides the AI Commander with knowledge of known vulnerabilities in the Juice Shop application.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Juice Shop Reasoning: Injects known Juice Shop challenges into the attack surface
    to guide the AI in targeting specific vulnerabilities.
    """
    ConsoleUI.header("SKILL: OWASP Juice Shop Reasoning")
    
    # We consolidate the challenges into broad categories to avoid token overflow,
    # but give the AI enough context to know what to look for based on the Juice Shop Score Board.
    
    juice_shop_context = {
        "finding_type": "OWASP Juice Shop Challenge Context",
        "title": "OWASP Juice Shop Target Identified",
        "severity": "INFO",
        "endpoint": "global",
        "evidence": "User loaded Juice Shop challenge profile.",
        "confidence": 1.0,
        "validation": "manual_skill_activation",
        "risk_level": "INFO",
        "details": (
            "The target is an OWASP Juice Shop instance. Known challenges include:\n"
            "- XSS: DOM XSS, Reflected XSS, API-only XSS, Bonus Payload, HTTP-Header XSS.\n"
            "- Injection: Login Admin/Jim/Bender, SQLi Database Schema extraction, NoSQL DoS/Manipulation.\n"
            "- Broken Access Control: View/Manipulate Basket, Admin Section, Forged Feedback/Review, SSRF.\n"
            "- Sensitive Data Exposure: Confidential Document, Exposed Credentials, Password Hash Leak, FTP Backups.\n"
            "- Improper Input Validation: Zero Stars, Payback Time, Upload Size/Type bypass, Deluxe Fraud.\n"
            "- Broken Authentication: Password Strength, CAPTCHA Bypass, 2FA bypass, JWT forging.\n"
            "- Security Misconfiguration: Error Handling, Deprecated Interfaces, B2B Interface.\n"
            "- AI/LLM: AI Debugging, Chatbot Prompt Injection, Greedy Chatbot Manipulation.\n"
            "- Vulnerable Components: Legacy Typosquatting, Local File Read, Supply Chain Attack.\n"
            "- XXE: XXE Data Access, XXE DoS.\n"
            "- Cryptographic Issues: Weird Crypto, Forged Coupon, Nested Easter Egg."
        )
    }

    # Add the consolidated context as a hypothesis/attack surface node
    state.attack_surface_nodes.append(juice_shop_context)
    
    if "juice_shop_reasoning" not in state.explored_paths:
        state.explored_paths.append("juice_shop_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_JUICE_SHOP_REASONING",
        "timestamp": time.time(),
        "action": "inject_juice_shop_challenges",
        "result": {"context_injected": True}
    })

    ConsoleUI.success("Injected OWASP Juice Shop challenge context into AI state.")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="juice_shop_reasoning",
        name="OWASP Juice Shop Reasoning",
        description="Injects known OWASP Juice Shop challenges (XSS, Injection, Broken Access Control, etc.) into the AI context.",
        category="custom_targets",
        noise_score=0,  # Passive skill, only injects knowledge
        required_inputs=[],
        produced_outputs=["attack_surface_nodes"],
        supported_phases=["Reconnaissance", "Vulnerability Discovery"],
        requires_evidence=False,
        execute_fn=_execute
    ))
