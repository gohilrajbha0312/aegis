"""
Skill 2: ParameterDiscoverySkill
==================================
Extract all parameters from discovered routes, forms, and JS.
Each parameter must have name, type, and route provenance.
"""
import time
import re
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI


PARAM_PATTERNS = [
    "id", "userId", "user_id", "accountId", "account_id", "orderId", "order_id",
    "uuid", "token", "role", "email", "username", "password", "name", "q",
    "search", "query", "page", "limit", "offset", "sort", "filter", "type",
    "category", "productId", "product_id", "basketId", "basket_id", "feedbackId",
]


def _infer_type(name: str) -> str:
    if any(kw in name.lower() for kw in ["id", "count", "page", "limit", "offset", "quantity"]):
        return "integer"
    if any(kw in name.lower() for kw in ["email"]):
        return "email"
    if any(kw in name.lower() for kw in ["token", "uuid", "hash"]):
        return "string:token"
    if any(kw in name.lower() for kw in ["password", "secret"]):
        return "string:sensitive"
    return "string"


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 2: Parameter Discovery")
    params = list(state.parameters)  # preserve existing

    # 1. Extract params from route paths (e.g., /api/users/:id or /api/users/{id})
    for r in state.routes:
        route_str = r if isinstance(r, str) else r.get("route", str(r))
        # Match {param} and :param patterns
        path_params = re.findall(r'\{(\w+)\}|:(\w+)', route_str)
        for match in path_params:
            name = match[0] or match[1]
            if not any(p.get("name") == name and p.get("route") == route_str for p in params):
                params.append({"name": name, "type": _infer_type(name), "route": route_str, "source": "path_parameter"})

    # 2. Extract params from query strings in discovered routes
    for r in state.routes:
        route_str = r if isinstance(r, str) else r.get("route", str(r))
        if "?" in route_str:
            qs = route_str.split("?", 1)[1]
            for pair in qs.split("&"):
                if "=" in pair:
                    name = pair.split("=")[0]
                    if name and not any(p.get("name") == name and p.get("route") == route_str for p in params):
                        params.append({"name": name, "type": _infer_type(name), "route": route_str, "source": "query_string"})

    # 3. Extract from HTML forms (stored in state.forms)
    for form in state.forms:
        form_action = form.get("action", "unknown")
        for field in form.get("fields", []):
            name = field if isinstance(field, str) else field.get("name", "")
            if name and not any(p.get("name") == name and p.get("route") == form_action for p in params):
                params.append({"name": name, "type": _infer_type(name), "route": form_action, "source": "html_form"})

    # 4. Match known parameter names against discovered JS routes
    for js_route in state.discovered_js_routes:
        for pattern in PARAM_PATTERNS:
            if pattern.lower() in js_route.lower():
                if not any(p.get("name") == pattern and p.get("route") == js_route for p in params):
                    params.append({"name": pattern, "type": _infer_type(pattern), "route": js_route, "source": "js_analysis"})

    state.parameters = params
    if "parameter_discovery" not in state.explored_paths:
        state.explored_paths.append("parameter_discovery")
    state.evidence_ledger.append({
        "stage": "RECON_PARAMETER_DISCOVERY", "timestamp": time.time(),
        "action": "parameter_extraction",
        "result": {"parameters_discovered": len(params)}
    })
    ConsoleUI.success(f"Parameter Discovery: {len(params)} parameters extracted")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_parameter_discovery", name="Parameter Discovery",
        description="Extracts all parameters from routes, forms, and JS with type inference",
        category="recon_intelligence", noise_score=0, required_inputs=["routes"],
        produced_outputs=["parameters"],
        supported_phases=["Reconnaissance"],
        requires_evidence=True, execute_fn=_execute
    ))
