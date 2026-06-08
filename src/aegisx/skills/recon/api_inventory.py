"""
Skill 11: APIInventorySkill
==============================
Build complete API inventory: method, route, auth, parameters, response codes.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 11: API Inventory")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    inventory = list(state.api_inventory)

    # 1. Merge from OpenAPI inventory (already structured)
    for item in state.openapi_inventory:
        if not any(i.get("route") == item.get("route") and i.get("method") == item.get("method") for i in inventory):
            inventory.append({
                "route": item["route"], "method": item.get("method", "GET"),
                "auth_required": item.get("auth_required", False),
                "parameters": item.get("parameters", []),
                "response_codes": [], "source": "openapi_spec", "confidence": 0.95
            })

    # 2. Build from route inventory — probe API routes with OPTIONS (low-noise)
    api_routes = []
    for r in state.routes:
        route_str = r if isinstance(r, str) else r.get("route", str(r))
        if any(kw in route_str.lower() for kw in ["/api/", "/rest/", "/v1/", "/v2/", "/v3/"]):
            api_routes.append(route_str)

    for route in api_routes[:10]:  # Max 10 probes
        if any(i.get("route") == route for i in inventory):
            continue
        try:
            resp = http_client.options(f"{base}{route}", timeout=3)
            allowed = resp.headers.get("allow", "").upper()
            methods = [m.strip() for m in allowed.split(",") if m.strip() in HTTP_METHODS] if allowed else ["GET"]
            for method in methods:
                inventory.append({
                    "route": route, "method": method,
                    "auth_required": False, "parameters": [],
                    "response_codes": [resp.status_code],
                    "source": "options_probe", "confidence": 0.8
                })
        except Exception:
            # Fallback: just record as GET
            inventory.append({
                "route": route, "method": "GET",
                "auth_required": False, "parameters": [],
                "response_codes": [], "source": "route_inference", "confidence": 0.6
            })

    # 3. Merge GraphQL endpoints
    if state.graphql_inventory:
        inventory.append({
            "route": "/graphql", "method": "POST",
            "auth_required": False, "parameters": [{"name": "query", "type": "string"}],
            "response_codes": [200], "source": "graphql_discovery", "confidence": 0.9
        })

    state.api_inventory = inventory
    if "api_inventory" not in state.explored_paths:
        state.explored_paths.append("api_inventory")
    state.evidence_ledger.append({
        "stage": "RECON_API_INVENTORY", "timestamp": time.time(),
        "action": "api_inventory_build",
        "result": {"endpoints": len(inventory)}
    })
    ConsoleUI.success(f"API Inventory: {len(inventory)} endpoints catalogued")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_api_inventory", name="API Inventory",
        description="Builds complete API inventory with methods, auth, parameters, response codes",
        category="recon_intelligence", noise_score=2, required_inputs=["routes"],
        produced_outputs=["api_inventory"],
        supported_phases=["Reconnaissance"],
        requires_evidence=True, execute_fn=_execute
    ))
