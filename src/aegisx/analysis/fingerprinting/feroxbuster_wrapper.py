import json
import time
from typing import Dict, Any

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI
from aegisx.analysis.intelligence.directory_vuln_engine import DirectoryVulnerabilityEngine

def execute_feroxbuster_scan(target: str) -> Dict[str, Any]:
    """
    Executes feroxbuster via CommandGateway for route and API endpoint discovery.
    Accepts target as 'host' or 'host:port'.
    """
    base_url = f"http://{target}" if ":" in target else f"http://{target}"
    cmd = ["ffuf", "-u", f"{base_url}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,204,301,302,401,403", "-t", "20", "-s", "-json"]
    
    try:
        result = CommandGateway.execute(cmd, timeout=300, description="Route & API Discovery (No Recursion)")
        
        parsed_results = []
        raw_out = result.get("stdout", "")
        for line in raw_out.strip().split('\n'):
            if line:
                try:
                    parsed_results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
                    
        return {
            "success": result["success"],
            "raw_output": parsed_results,
            "error": result.get("stderr"),
            "command": result.get("command")
        }
    except Exception as e:
        return {
            "success": False,
            "raw_output": [],
            "error": str(e),
            "command": " ".join(cmd)
        }

def fallback_python_crawl(target: str) -> Dict[str, Any]:
    """Fallback basic crawl using python requests if feroxbuster is missing."""
    import requests
    routes = []
    base_url = f"http://{target}"
    common_paths = [
        "/", "/api", "/api/v1", "/api/v1/health", "/api/v1/users",
        "/admin", "/admin/login", "/login", "/logout", "/register",
        "/static", "/graphql", "/swagger", "/swagger-ui", "/api-docs",
        "/metrics", "/actuator", "/actuator/health", "/actuator/env",
        "/debug", "/config", "/backup", "/upload", "/uploads",
        "/api/v1/admin", "/api/v2", "/api/v2/health"
    ]
    from aegisx.core.ui.console import ConsoleUI
    for path in common_paths:
        try:
            url = f"{base_url}{path}"
            resp = requests.get(url, timeout=5, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 401, 403, 405]:
                routes.append({"url": url, "status": resp.status_code})
                ConsoleUI.stream_line(f"  [{resp.status_code}] {url}")
        except:
            pass
    return {
        "success": True,
        "raw_output": routes,
        "error": None,
        "command": f"python_requests_fallback {base_url}"
    }

def phase_6_route_discovery(state: WorkflowState) -> WorkflowState:
    """
    PHASE 6: Route Discovery
    Uses Feroxbuster to discover endpoints safely without aggressive recursion.
    """
    ConsoleUI.info(f"Executing Phase 6 Route Discovery against: {state.normalized_target}")
    
    from aegisx.core.runtime_governor import RuntimeGovernor, ScanMode
    gov = RuntimeGovernor.instance()
    
    if gov.mode != ScanMode.DEEP_ANALYSIS and gov.mode != ScanMode.HIGH_INTENSITY:
        ConsoleUI.info("Skipping aggressive FFUF route discovery (Enable DEEP_ANALYSIS to run).")
        scan_result = fallback_python_crawl(state.normalized_target)
    else:
        scan_result = execute_feroxbuster_scan(state.normalized_target)
        
        if not scan_result["success"] and "not found" in scan_result.get("error", ""):
            ConsoleUI.warning(f"FFUF binary not found. Falling back to Python basic discovery.")
            scan_result = fallback_python_crawl(state.normalized_target)
        elif not scan_result["success"]:
            ConsoleUI.warning(f"FFUF scan failed or denied: {scan_result['error']}")
        
    if scan_result["success"]:
        if scan_result["raw_output"]:
            routes = []
            for r in scan_result["raw_output"]:
                if isinstance(r, dict):
                    routes.append(r.get("url"))
                elif isinstance(r, str):
                    routes.append(r)
                    
            routes = [r for r in routes if r]
            ConsoleUI.success(f"Discovered {len(routes)} significant routes.")
            
            # Active Directory Vulnerability Checking
            ConsoleUI.info("Invoking Directory Vulnerability Engine...")
            dir_vuln = DirectoryVulnerabilityEngine()
            vuln_res = dir_vuln.check_vulnerabilities(state.normalized_target, routes)
            
            state.evidence_ledger.append({
                "stage": "PHASE_6_ROUTE_DISCOVERY",
                "timestamp": time.time(),
                "action": "ffuf_scan",
                "result": {"raw_output": routes, "directory_vulns": vuln_res}
            })
    return state
