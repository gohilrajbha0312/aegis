"""
Skill 5: JavaScriptIntelligenceSkill
======================================
Analyze JavaScript for fetch(), axios(), websockets, hidden APIs, feature flags, JWT handling.
"""
import time
import re
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client

JS_PATTERNS = {
    "fetch_call": r"""fetch\s*\(\s*['"](\/[^'"]+)['"]""",
    "axios_call": r"""axios\.\w+\s*\(\s*['"](\/[^'"]+)['"]""",
    "xhr_open": r"""\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH)['"]\s*,\s*['"](\/[^'"]+)['"]""",
    "websocket": r"""new\s+WebSocket\s*\(\s*['"](wss?:\/\/[^'"]+)['"]""",
    "api_route": r"""['"](\/api\/[^'"]+)['"]""",
    "rest_route": r"""['"](\/rest\/[^'"]+)['"]""",
}

SENSITIVE_PATTERNS = {
    "feature_flag": r"""(?:feature|flag|toggle|experiment)[_\-]?\w*\s*[:=]\s*['"]\w+['"]""",
    "jwt_handling": r"""(?:jwt|token|bearer|authorization)\s*[:=]""",
    "role_check": r"""(?:isAdmin|isUser|hasRole|checkPermission|requireAuth)""",
    "hardcoded_key": r"""(?:api[_\-]?key|secret|password)\s*[:=]\s*['"][a-zA-Z0-9_\-]{10,}['"]""",
}


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 5: JavaScript Intelligence")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    js_intel = []
    hidden_eps = list(state.hidden_endpoints)

    # 1. Analyze already-discovered JS routes
    for route in state.discovered_js_routes:
        js_intel.append({"route": route, "source": "prior_js_extraction", "pattern": "js_route", "confidence": 0.85})

    # 2. Try to fetch main JS bundle (if discoverable from root page)
    try:
        resp = http_client.get(base, timeout=5)
        if resp.status_code == 200:
            scripts = re.findall(r'src=["\']([^"\']*\.js)["\']', resp.text)
            for script_src in scripts[:5]:  # Max 5 JS files
                if script_src.startswith("/"):
                    js_url = f"{base}{script_src}"
                elif script_src.startswith("http"):
                    js_url = script_src
                else:
                    js_url = f"{base}/{script_src}"

                try:
                    js_resp = http_client.get(js_url, timeout=5)
                    if js_resp.status_code == 200:
                        js_text = js_resp.text[:50000]  # Cap at 50KB per file

                        # Extract API routes from JS
                        for pattern_name, pattern in JS_PATTERNS.items():
                            matches = re.findall(pattern, js_text, re.IGNORECASE)
                            for match in matches:
                                if not any(j.get("route") == match for j in js_intel):
                                    js_intel.append({
                                        "route": match, "source": script_src,
                                        "pattern": pattern_name, "confidence": 0.8
                                    })
                                if match not in hidden_eps and match.startswith("/"):
                                    hidden_eps.append(match)

                        # Check for sensitive patterns
                        for sens_name, sens_pat in SENSITIVE_PATTERNS.items():
                            if re.search(sens_pat, js_text, re.IGNORECASE):
                                js_intel.append({
                                    "route": "N/A", "source": script_src,
                                    "pattern": sens_name, "confidence": 0.7,
                                    "finding": f"Sensitive pattern '{sens_name}' detected"
                                })
                except Exception:
                    pass
    except Exception:
        pass

    state.js_routes = js_intel
    state.hidden_endpoints = hidden_eps
    if "js_intelligence" not in state.explored_paths:
        state.explored_paths.append("js_intelligence")
    state.evidence_ledger.append({
        "stage": "RECON_JS_INTELLIGENCE", "timestamp": time.time(),
        "action": "js_analysis",
        "result": {"js_routes": len(js_intel), "hidden_endpoints": len(hidden_eps)}
    })
    ConsoleUI.success(f"JS Intelligence: {len(js_intel)} items, {len(hidden_eps)} hidden endpoints")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_js_intelligence", name="JavaScript Intelligence",
        description="Extracts fetch/axios/XHR calls, hidden APIs, feature flags, JWT handling from JS",
        category="recon_intelligence", noise_score=1, required_inputs=[],
        produced_outputs=["js_routes", "hidden_endpoints"],
        supported_phases=["Reconnaissance"],
        requires_evidence=False, execute_fn=_execute
    ))
