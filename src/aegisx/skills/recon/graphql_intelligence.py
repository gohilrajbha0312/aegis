"""
Skill 7: GraphQLIntelligenceSkill
===================================
Detect /graphql, /playground, /graphiql. Extract schema, queries, mutations.
"""
import time
import json
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client

GQL_PATHS = ["/graphql", "/playground", "/graphiql", "/api/graphql", "/gql"]
INTROSPECTION_QUERY = '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}'


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 7: GraphQL Intelligence")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    inventory = []

    for path in GQL_PATHS:
        try:
            resp = http_client.post(
                f"{base}{path}", data=INTROSPECTION_QUERY,
                headers={"Content-Type": "application/json"}, timeout=5
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                try:
                    data = json.loads(resp.text)
                    schema = data.get("data", {}).get("__schema", {})
                    types = schema.get("types", [])
                    user_types = [t for t in types if not t.get("name", "").startswith("__")]
                    for t in user_types:
                        fields = [f.get("name") for f in t.get("fields", []) if f.get("name")]
                        inventory.append({
                            "type_name": t.get("name"), "kind": t.get("kind"),
                            "fields": fields[:20], "source": path, "confidence": 0.95
                        })
                    ConsoleUI.info(f"  [GraphQL] Introspection at {path}: {len(user_types)} types")
                except json.JSONDecodeError:
                    pass
                break
            elif resp.status_code == 200:
                inventory.append({"type_name": "graphql_endpoint", "kind": "ENDPOINT",
                                  "fields": [], "source": path, "confidence": 0.7,
                                  "note": "GraphQL endpoint found but introspection may be disabled"})
                ConsoleUI.info(f"  [GraphQL] Endpoint at {path} (introspection disabled)")
                break
        except Exception:
            pass

    state.graphql_inventory = inventory
    if "graphql_intelligence" not in state.explored_paths:
        state.explored_paths.append("graphql_intelligence")
    state.evidence_ledger.append({
        "stage": "RECON_GRAPHQL", "timestamp": time.time(),
        "action": "graphql_discovery",
        "result": {"types_discovered": len(inventory)}
    })
    ConsoleUI.success(f"GraphQL Intelligence: {len(inventory)} types/endpoints discovered")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_graphql_intelligence", name="GraphQL Intelligence",
        description="Detects GraphQL endpoints and extracts schema via introspection",
        category="recon_intelligence", noise_score=2, required_inputs=[],
        produced_outputs=["graphql_inventory"],
        supported_phases=["Reconnaissance"],
        requires_evidence=False, execute_fn=_execute
    ))
