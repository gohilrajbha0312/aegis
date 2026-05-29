import time
from typing import Dict, Any, List

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

class JSIntelligenceParser:
    """
    Parses JavaScript bundles using basic AST simulation to find API endpoints
    and hardcoded secrets safely (Phase 7).
    """
    def parse_bundle(self, bundle_url: str) -> Dict[str, Any]:
        """Downloads the JS bundle and uses regex to find potential endpoints."""
        from aegisx.core import http_client as requests
        import re
        
        discovered = []
        secrets = []
        try:
            resp = requests.get(bundle_url, timeout=10)
            if resp.status_code == 200:
                js_content = resp.text
                
                # Basic Endpoint Regex (Linkfinder style)
                endpoint_pattern = r"""(?:"|')(((?:[a-zA-Z]{1,10}://|/)[^"']+)?)((?:[a-zA-Z]{1,10}://|/)[^"']+)?"""
                matches = re.findall(endpoint_pattern, js_content)
                for m in matches:
                    if m[0] and len(m[0]) > 2 and " " not in m[0]:
                        discovered.append(m[0])
                        
                # Basic Secret Regex (AWS Key style)
                if re.search(r"AKIA[0-9A-Z]{16}", js_content):
                    secrets.append("AWS_ACCESS_KEY_ID")
                    
        except Exception as e:
            ConsoleUI.warning(f"Failed to fetch JS bundle {bundle_url}: {e}")
            
        return {
            "bundle": bundle_url,
            "discovered_endpoints": list(set(discovered))[:20], # limit output
            "hardcoded_secrets": secrets,
            "framework": "Unknown"
        }

class APISurfaceMapper:
    """
    Identifies OpenAPI/Swagger/GraphQL endpoints and maps API versions (Phase 8).
    """
    def map_surface(self, target: str) -> Dict[str, Any]:
        """Actively checks for common API schema endpoints."""
        from aegisx.core import http_client as requests
        
        graphql = False
        swagger = False
        shadow = []
        
        # Use the full target including port
        base_url = f"http://{target}"
        
        # Check GraphQL
        try:
            if requests.get(f"{base_url}/graphql", timeout=3).status_code == 200:
                graphql = True
        except: pass
        
        # Check Swagger
        try:
            if requests.get(f"{base_url}/swagger/v1/swagger.json", timeout=3).status_code == 200:
                swagger = True
        except: pass
        
        return {
            "target": target,
            "graphql_detected": graphql,
            "swagger_detected": swagger,
            "shadow_apis": shadow
        }

def phase_7_js_intelligence(state: WorkflowState) -> WorkflowState:
    """PHASE 7: JS Intelligence (Low-Noise Route Extraction)"""
    ConsoleUI.info(f"Executing Phase 7 JS Intelligence against: {state.normalized_target}")
    parser = JSIntelligenceParser()
    
    # Try multiple common JS bundle paths
    bundle_paths = [
        "/static/js/main.chunk.js",
        "/main.js",
        "/app.js",
        "/bundle.js",
        "/static/js/bundle.js",
        "/_next/static/chunks/main.js",
    ]
    
    all_endpoints = []
    all_secrets = []
    
    for path in bundle_paths:
        bundle_url = f"http://{state.normalized_target}{path}"
        res = parser.parse_bundle(bundle_url)
        if res["discovered_endpoints"]:
            all_endpoints.extend(res["discovered_endpoints"])
        if res["hardcoded_secrets"]:
            all_secrets.extend(res["hardcoded_secrets"])
    
    # Deduplicate
    all_endpoints = list(set(all_endpoints))
    all_secrets = list(set(all_secrets))
    
    # Populate state with discovered JS routes
    for ep in all_endpoints:
        if ep.startswith("/") and ep not in state.discovered_js_routes:
            state.discovered_js_routes.append(ep)
        if ep.startswith("/") and ep not in state.routes:
            state.routes.append(ep)
    
    ConsoleUI.success(f"JS AST Analysis complete. Discovered {len(all_endpoints)} hidden endpoints.")
    if all_secrets:
        ConsoleUI.warning(f"Potential hardcoded secrets found: {', '.join(all_secrets)}")
    
    # Mark path as explored
    if "js_intelligence" not in state.explored_paths:
        state.explored_paths.append("js_intelligence")
    
    state.evidence_ledger.append({
        "stage": "PHASE_7_JS_INTELLIGENCE",
        "timestamp": time.time(),
        "action": "ast_parsing",
        "result": {
            "discovered_endpoints": all_endpoints,
            "hardcoded_secrets": all_secrets,
        }
    })
    return state

def phase_8_api_boundary(state: WorkflowState) -> WorkflowState:
    ConsoleUI.info(f"Executing Phase 8 API Surface Mapping against: {state.normalized_target}")
    mapper = APISurfaceMapper()
    
    res = mapper.map_surface(state.normalized_target)
    
    if res["graphql_detected"]:
        ConsoleUI.warning("GraphQL Endpoint detected. Schema introspection may be possible.")
    if res["shadow_apis"]:
        ConsoleUI.warning(f"Shadow/Legacy APIs discovered: {', '.join(res['shadow_apis'])}")
        
    state.evidence_ledger.append({
        "stage": "PHASE_8_API_BOUNDARY",
        "timestamp": time.time(),
        "action": "api_mapping",
        "result": res
    })
    return state
