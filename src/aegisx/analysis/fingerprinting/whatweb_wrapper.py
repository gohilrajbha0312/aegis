import json
import time
from typing import Dict, Any

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.orchestration.command_gateway import CommandGateway

def execute_whatweb_scan(target: str) -> Dict[str, Any]:
    """
    Executes whatweb via CommandGateway for deep technology fingerprinting.
    Uses strict timeouts.
    """
    cmd = ["whatweb", "-a", "1", "--log-json", "/tmp/whatweb_out.json", "-q", target]
    
    try:
        result = CommandGateway.execute(cmd, timeout=120, description="Deep Technology Fingerprinting")
        
        parsed_results = []
        try:
            with open("/tmp/whatweb_out.json", "r") as f:
                parsed_results = json.load(f)
        except Exception:
            pass
            
        return {
            "success": result["success"] or len(parsed_results) > 0,
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

def phase_5_tech_fingerprinting(state: WorkflowState) -> WorkflowState:
    """
    PHASE 5: Technology Fingerprinting
    Uses WhatWeb to extract deep technology signatures.
    """
    from aegisx.core.ui.console import ConsoleUI
    ConsoleUI.info(f"Executing Phase 5 Tech Fingerprinting against: {state.normalized_target}")
    
    scan_result = execute_whatweb_scan(state.normalized_target)
    
    if not scan_result["success"]:
        ConsoleUI.warning(f"whatweb scan failed or denied: {scan_result['error']}")
    else:
        if scan_result["raw_output"]:
            plugins = list(scan_result["raw_output"][0].get("plugins", {}).keys())
            ConsoleUI.success(f"Identified Fingerprints: {', '.join(plugins) if plugins else 'None'}")
        
    state.evidence_ledger.append({
        "stage": "PHASE_5_TECH_FINGERPRINTING",
        "timestamp": time.time(),
        "action": "whatweb_execution",
        "result": scan_result
    })
    
    return state
