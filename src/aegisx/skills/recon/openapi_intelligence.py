"""
Skill 6: OpenAPIIntelligenceSkill
===================================
Search for /swagger.json, /openapi.json, /api-docs. Parse routes, schemas, parameters, auth.
"""
import time
import json
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client

OPENAPI_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs", "/api-docs.json",
    "/swagger/v1/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/docs/openapi.json",
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 6: OpenAPI Intelligence")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    inventory = []

    for path in OPENAPI_PATHS:
        try:
            resp = http_client.get(f"{base}{path}", timeout=5)
            if resp.status_code == 200:
                try:
                    spec = json.loads(resp.text)
                except json.JSONDecodeError:
                    continue

                paths = spec.get("paths", {})
                for route, methods in paths.items():
                    for method, details in methods.items():
                        if method.lower() in ["get", "post", "put", "delete", "patch"]:
                            params = []
                            for p in details.get("parameters", []):
                                params.append({"name": p.get("name"), "in": p.get("in"), "type": p.get("schema", {}).get("type", "string")})
                            inventory.append({
                                "route": route, "method": method.upper(),
                                "summary": details.get("summary", ""),
                                "parameters": params,
                                "auth_required": bool(details.get("security")),
                                "source": path, "confidence": 0.95
                            })

                ConsoleUI.info(f"  [OpenAPI] Found spec at {path}: {len(paths)} paths")
                break  # Found one spec, stop probing
        except Exception:
            pass

    state.openapi_inventory = inventory
    # Also add discovered routes to main route list
    for item in inventory:
        route = item["route"]
        if not any((r if isinstance(r, str) else r.get("route", "")) == route for r in state.routes):
            state.routes.append({"route": route, "source": f"openapi:{item['source']}", "confidence": 0.95})

    if "openapi_intelligence" not in state.explored_paths:
        state.explored_paths.append("openapi_intelligence")
    state.evidence_ledger.append({
        "stage": "RECON_OPENAPI", "timestamp": time.time(),
        "action": "openapi_discovery",
        "result": {"endpoints_discovered": len(inventory)}
    })
    ConsoleUI.success(f"OpenAPI Intelligence: {len(inventory)} endpoints from spec")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_openapi_intelligence", name="OpenAPI Intelligence",
        description="Discovers and parses Swagger/OpenAPI specs for routes, schemas, auth requirements",
        category="recon_intelligence", noise_score=2, required_inputs=[],
        produced_outputs=["openapi_inventory", "routes"],
        supported_phases=["Reconnaissance"],
        requires_evidence=False, execute_fn=_execute
    ))
