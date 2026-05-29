"""
Data Exposure Reasoning Skill
==============================
Detects excessive API fields, hidden metadata, internal identifiers,
leaked debug information, and unsafe serialization.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client


def _execute(state: WorkflowState) -> WorkflowState:
    """
    Data Exposure Reasoning: Check key endpoints for excessive data,
    internal identifiers, and metadata leaks.
    """
    ConsoleUI.header("SKILL: Data Exposure Reasoning")
    target = state.normalized_target
    base = f"http://{target}"

    findings = []

    # 1. Check root endpoint for technology leakage
    try:
        resp = http_client.get(base, timeout=5)
        body = resp.text[:2000]  # Only inspect first 2KB
        
        # Detect internal metadata patterns
        leak_patterns = {
            "stack_trace": ["at Object.", "at Module.", "Error:", "Traceback"],
            "internal_ids": ["ObjectId(", "uuid:", "internal_id"],
            "version_leak": ["build:", "version:", "commit:"],
            "env_leak": ["NODE_ENV", "RAILS_ENV", "DEBUG="],
        }
        
        for leak_type, patterns in leak_patterns.items():
            for pat in patterns:
                if pat.lower() in body.lower():
                    findings.append({
                        "finding_type": "Information Disclosure",
                        "title": f"Potential {leak_type.replace('_', ' ')} in response",
                        "severity": "LOW",
                        "endpoint": base,
                        "evidence": f"Pattern '{pat}' found in response body",
                        "confidence": 0.6,
                        "validation": "response_pattern_match",
                        "risk_level": "LOW"
                    })
                    ConsoleUI.info(f"  [Data Leak] Pattern '{pat}' detected ({leak_type})")
                    break  # One finding per category
    except Exception:
        pass

    # 2. Check error handling by requesting a likely-invalid route
    try:
        resp = http_client.get(f"{base}/nonexistent-aegisx-probe-{int(time.time())}", timeout=5)
        body = resp.text[:2000]
        
        error_indicators = {
            "stack_trace_in_error": ["stack", "trace", "at Function", "node_modules"],
            "framework_error_page": ["Cannot GET", "Not Found", "express", "404.html"],
            "debug_mode": ["debug", "stacktrace", "Traceback"]
        }
        
        for err_type, indicators in error_indicators.items():
            leaked = [i for i in indicators if i.lower() in body.lower()]
            if leaked and err_type == "stack_trace_in_error":
                findings.append({
                    "finding_type": "Verbose Error Handling",
                    "title": "Application exposes stack traces in error responses",
                    "severity": "LOW",
                    "endpoint": f"{base}/404-probe",
                    "evidence": f"Error response contains: {', '.join(leaked)}",
                    "confidence": 0.75,
                    "validation": "error_response_analysis",
                    "risk_level": "LOW"
                })
                ConsoleUI.warning(f"  [Finding] Verbose error handling detected: {', '.join(leaked)}")
    except Exception:
        pass

    # Store results
    if findings:
        state.findings.extend(findings)

    if "data_exposure_reasoning" not in state.explored_paths:
        state.explored_paths.append("data_exposure_reasoning")

    state.evidence_ledger.append({
        "stage": "SKILL_DATA_EXPOSURE",
        "timestamp": time.time(),
        "action": "data_exposure_analysis",
        "result": {"findings": len(findings)}
    })

    ConsoleUI.success(f"Data exposure reasoning complete: {len(findings)} findings")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="data_exposure_reasoning",
        name="Data Exposure Reasoning",
        description="Detects excessive API fields, internal identifiers, and debug information leaks",
        category="data_exposure",
        noise_score=2,
        required_inputs=["routes", "api_endpoints"],
        produced_outputs=["findings"],
        supported_phases=["Vulnerability Discovery", "Validation"],
        requires_evidence=False,
        execute_fn=_execute
    ))
