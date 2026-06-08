"""
Skill 9: SecurityHeaderIntelligenceSkill
==========================================
Collect CSP, HSTS, XFO, CORS, COOP, CORP headers. Purely passive.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client

SECURITY_HEADERS = {
    "content-security-policy": {"abbr": "CSP", "severity": "MEDIUM"},
    "strict-transport-security": {"abbr": "HSTS", "severity": "LOW"},
    "x-frame-options": {"abbr": "XFO", "severity": "LOW"},
    "x-content-type-options": {"abbr": "XCTO", "severity": "LOW"},
    "access-control-allow-origin": {"abbr": "CORS", "severity": "MEDIUM"},
    "cross-origin-opener-policy": {"abbr": "COOP", "severity": "LOW"},
    "cross-origin-resource-policy": {"abbr": "CORP", "severity": "LOW"},
    "cross-origin-embedder-policy": {"abbr": "COEP", "severity": "LOW"},
    "referrer-policy": {"abbr": "RP", "severity": "LOW"},
    "permissions-policy": {"abbr": "PP", "severity": "LOW"},
    "x-xss-protection": {"abbr": "XSS-P", "severity": "INFO"},
}


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 9: Security Header Intelligence")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    headers_intel = {}

    # 1. Collect from already-discovered headers
    for hdr_name, meta in SECURITY_HEADERS.items():
        val = state.discovered_headers.get(hdr_name, "")
        if val:
            headers_intel[meta["abbr"]] = {"header": hdr_name, "value": val, "present": True, "source": "prior_discovery"}
        else:
            headers_intel[meta["abbr"]] = {"header": hdr_name, "value": None, "present": False, "source": "prior_discovery"}

    # 2. One fresh request to fill gaps
    try:
        resp = http_client.get(base, timeout=5)
        for hdr_name, meta in SECURITY_HEADERS.items():
            val = resp.headers.get(hdr_name, "")
            if val and not headers_intel.get(meta["abbr"], {}).get("present"):
                headers_intel[meta["abbr"]] = {"header": hdr_name, "value": val, "present": True, "source": "active_probe"}
    except Exception:
        pass

    present = sum(1 for v in headers_intel.values() if v.get("present"))
    missing = sum(1 for v in headers_intel.values() if not v.get("present"))

    state.security_headers = headers_intel
    if "security_header_intel" not in state.explored_paths:
        state.explored_paths.append("security_header_intel")
    state.evidence_ledger.append({
        "stage": "RECON_SECURITY_HEADERS", "timestamp": time.time(),
        "action": "header_collection",
        "result": {"present": present, "missing": missing}
    })
    ConsoleUI.success(f"Security Headers: {present} present, {missing} missing")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_security_header_intel", name="Security Header Intelligence",
        description="Collects CSP, HSTS, XFO, CORS, COOP, CORP and all security headers",
        category="recon_intelligence", noise_score=0, required_inputs=[],
        produced_outputs=["security_headers"],
        supported_phases=["Reconnaissance"],
        requires_evidence=False, execute_fn=_execute
    ))
