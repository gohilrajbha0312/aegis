"""
API Intelligence Reasoning Skill
=================================
Analyzes API schemas, parameter relationships, response structures,
and trust propagation. Builds API topology graphs.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client


def _execute(state: WorkflowState) -> WorkflowState:
    """
    API Intelligence: Map API topology, identify inconsistent validation,
    and detect excessive data exposure.
    """
    ConsoleUI.header("SKILL: API Intelligence Reasoning")
    target = state.normalized_target
    base = f"http://{target}"

    hypotheses = []
    findings = []

    # 1. Categorize discovered routes into API groups
    api_routes = [r for r in state.routes if "/api" in r.lower() or "/graphql" in r.lower()]
    non_api_routes = [r for r in state.routes if r not in api_routes]

    ConsoleUI.info(f"  Analyzing {len(api_routes)} API routes, {len(non_api_routes)} frontend routes")

    # 2. Detect API versioning patterns
    versions = set()
    for route in api_routes:
        parts = route.split("/")
        for part in parts:
            if part.startswith("v") and len(part) <= 3 and part[1:].isdigit():
                versions.add(part)
    
    if len(versions) > 1:
        hypotheses.append({
            "type": "multiple_api_versions",
            "versions": list(versions),
            "confidence": 0.7,
            "reasoning": f"Multiple API versions detected ({', '.join(versions)}). Shadow/legacy API risk."
        })
        ConsoleUI.warning(f"  [Hypothesis] Multiple API versions: {', '.join(versions)}")

    # 3. Check for GraphQL introspection (1 targeted request)
    if "/graphql" in state.api_endpoints or any("graphql" in r.lower() for r in state.routes):
        try:
            introspection_query = '{"query":"{ __schema { types { name } } }"}'
            resp = http_client.post(
                f"{base}/graphql",
                data=introspection_query,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            if resp.status_code == 200 and "__schema" in resp.text:
                findings.append({
                    "finding_type": "GraphQL Introspection Enabled",
                    "title": "GraphQL introspection is enabled (schema leak)",
                    "severity": "MEDIUM",
                    "endpoint": f"{base}/graphql",
                    "evidence": f"Introspection query returned schema types",
                    "confidence": 0.95,
                    "validation": "deterministic_introspection_check",
                    "risk_level": "MEDIUM"
                })
                ConsoleUI.warning("  [Finding] GraphQL introspection is ENABLED")
            else:
                ConsoleUI.info("  GraphQL introspection appears disabled")
        except Exception:
            pass

    # 4. Check for excessive data exposure on a health/status endpoint
    health_routes = [r for r in api_routes if any(kw in r.lower() for kw in ["health", "status", "info", "debug"])]
    for route in health_routes[:2]:  # Max 2 requests
        try:
            resp = http_client.get(f"{base}{route}", timeout=5)
            if resp.status_code == 200:
                body = resp.text
                # Check for internal information leakage
                leak_indicators = ["version", "hostname", "env", "debug", "database", "internal"]
                leaks = [ind for ind in leak_indicators if ind in body.lower()]
                if leaks:
                    findings.append({
                        "finding_type": "Information Disclosure via API",
                        "title": f"Excessive data exposure on {route}",
                        "severity": "LOW",
                        "endpoint": f"{base}{route}",
                        "evidence": f"Leaked fields: {', '.join(leaks)}",
                        "confidence": 0.7,
                        "validation": "response_content_check",
                        "risk_level": "LOW"
                    })
                    ConsoleUI.info(f"  [Finding] Data exposure on {route}: {', '.join(leaks)}")
        except Exception:
            pass

    # Store results
    if hypotheses:
        state.attack_surface_nodes.extend(hypotheses)
    if findings:
        state.findings.extend(findings)

    if "api_intelligence" not in state.explored_paths:
        state.explored_paths.append("api_intelligence")

    state.evidence_ledger.append({
        "stage": "SKILL_API_INTELLIGENCE",
        "timestamp": time.time(),
        "action": "api_topology_analysis",
        "result": {"api_routes": len(api_routes), "hypotheses": len(hypotheses), "findings": len(findings)}
    })

    ConsoleUI.success(f"API intelligence complete: {len(hypotheses)} hypotheses, {len(findings)} findings")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="api_intelligence",
        name="API Intelligence Reasoning",
        description="Analyzes API schemas, versioning, GraphQL introspection, and data exposure",
        category="api",
        noise_score=2,
        required_inputs=["routes", "api_endpoints"],
        produced_outputs=["findings", "attack_surface_nodes"],
        supported_phases=["API Discovery", "Vulnerability Discovery"],
        requires_evidence=True,
        execute_fn=_execute
    ))
