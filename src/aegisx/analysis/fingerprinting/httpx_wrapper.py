import json
import time
from typing import Dict, Any

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.orchestration.command_gateway import CommandGateway

def execute_httpx_scan(target: str) -> Dict[str, Any]:
    """
    Executes httpx via CommandGateway.
    Accepts target as 'host' or 'host:port'.
    """
    url = f"http://{target}"
    # projectdiscovery/httpx is missing/conflicting with Python httpx module. Use curl as a reliable fallback for header extraction.
    cmd = ["curl", "-I", "-s", "-L", url]
    
    try:
        result = CommandGateway.execute(cmd, timeout=120, description="HTTP Metadata & Fingerprinting")
        
        raw_out = result.get("stdout", "")
        # The python httpx command outputs the raw response or basic headers.
        # We will capture it as raw string and try to parse basic tech from Server headers
        parsed_results = [{"raw_response": raw_out[:500]}]
                    
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

def phase_4_http_intelligence(state: WorkflowState) -> WorkflowState:
    """
    PHASE 4: HTTP Intelligence (Low-Noise)
    Extracts headers, cookies, technology signatures, and metadata.
    Populates WorkflowState for semantic correlation by the AI Commander.
    """
    from aegisx.core.ui.console import ConsoleUI
    import re
    ConsoleUI.info(f"Executing Phase 4 HTTP Intelligence against: {state.normalized_target}")
    
    scan_result = execute_httpx_scan(state.normalized_target)
    
    if not scan_result["success"]:
        ConsoleUI.warning(f"httpx scan failed or denied: {scan_result['error']}")
    else:
        raw = scan_result.get("raw_output", [{}])
        raw_text = raw[0].get("raw_response", "") if raw else ""
        
        if raw_text:
            ConsoleUI.success("Received HTTP response headers.")
            
            # Extract headers into state for semantic correlation
            for line in raw_text.strip().split("\n"):
                line = line.strip()
                if ":" in line and not line.startswith("HTTP/"):
                    key, _, val = line.partition(":")
                    key = key.strip().lower()
                    val = val.strip()
                    state.discovered_headers[key] = val
                    
                    # Technology fingerprinting from headers
                    if key == "x-powered-by":
                        tech = val.strip()
                        if tech and tech not in state.detected_technologies:
                            state.detected_technologies.append(tech)
                            state.technology_fingerprints[tech] = 0.9
                            ConsoleUI.success(f"  [Tech] {tech} (confidence: 0.90)")
                    elif key == "server":
                        tech = val.strip()
                        if tech and tech not in state.detected_technologies:
                            state.detected_technologies.append(tech)
                            state.technology_fingerprints[tech] = 0.85
                            ConsoleUI.success(f"  [Tech] {tech} (confidence: 0.85)")
                    elif key == "set-cookie":
                        cookie_name = val.split("=")[0].strip()
                        if cookie_name and cookie_name not in state.discovered_cookies:
                            state.discovered_cookies.append(cookie_name)
                            ConsoleUI.info(f"  [Cookie] {cookie_name}")
                            # Infer auth method from cookie patterns
                            if "jwt" in cookie_name.lower() or "token" in cookie_name.lower():
                                if "JWT" not in state.authentication_methods:
                                    state.authentication_methods.append("JWT")
                            elif "session" in cookie_name.lower() or "sid" in cookie_name.lower():
                                if "Session" not in state.authentication_methods:
                                    state.authentication_methods.append("Session")
                    elif key == "location":
                        loc = val.strip()
                        if loc.startswith("/"):
                            path = loc
                        elif not loc.startswith("http"):
                            path = "/" + loc
                        else:
                            from urllib.parse import urlparse
                            path = urlparse(loc).path
                            if not path: path = "/"
                            
                        route_exists = any(r.get("path") == path for r in state.routes)
                        if not route_exists:
                            route_obj = {
                                "path": path,
                                "source": "HTTP_Redirect",
                                "confidence": 1.0,
                                "timestamp": time.time(),
                                "method": "GET",
                                "auth_required": False
                            }
                            state.routes.append(route_obj)
                            state.discovered_routes.append(route_obj)
                            ConsoleUI.success(f"  [Route] Discovered via Location header: {path}")
                    elif key == "x-frame-options":
                        state.discovered_headers["security:x-frame-options"] = val
                    elif key == "content-security-policy":
                        state.discovered_headers["security:csp"] = val
            
            # Ensure the base route "/" is in the discovered routes so agents have a starting point
            route_exists = any(r.get("path") == "/" for r in state.routes)
            if not route_exists:
                route_obj = {
                    "path": "/",
                    "source": "HTTP_Root",
                    "confidence": 1.0,
                    "timestamp": time.time(),
                    "method": "GET",
                    "auth_required": False
                }
                state.routes.append(route_obj)
                state.discovered_routes.append(route_obj)
            if "http_header_analysis" not in state.explored_paths:
                state.explored_paths.append("http_header_analysis")
        
    state.evidence_ledger.append({
        "stage": "PHASE_4_HTTP_INTELLIGENCE",
        "timestamp": time.time(),
        "action": "httpx_execution",
        "result": scan_result
    })
    
    return state
