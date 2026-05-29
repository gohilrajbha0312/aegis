import subprocess
import time
from typing import Dict, Any, Optional

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.orchestration.command_gateway import CommandGateway

def execute_nmap_scan(target: str, port: int = None) -> Dict[str, Any]:
    """
    Executes a bounded nmap scan via subprocess.
    Uses strict timeouts to prevent hanging processes.
    """
    # -Pn: Treat hosts as online
    # -T4: Aggressive timing
    # -sV: Probe open ports to determine service/version info
    # -O: Enable OS detection
    # --script=discovery,safe,vuln: Run advanced sub-attacks and enumerations
    # --host-timeout: Give up on target after 10m (increased for scripts)
    cmd = ["nmap", "-Pn", "-T4", "-sV", "-O", "--script=discovery,safe,vuln", "--host-timeout", "10m"]
    
    if port:
        cmd.extend(["-p", str(port)])
    else:
        cmd.extend(["-F"]) # Fast mode, top 100 ports if no specific port is provided
        
    cmd.append(target)
    
    try:
        # Run via Command Gateway
        result = CommandGateway.execute(cmd, timeout=660, description="Network Discovery & Fingerprinting")
        
        # Parse output
        raw_out = result.get("stdout", "")
        # For this demonstration, we capture the raw string output
        # A full implementation would parse XML.
        
        return {
            "success": result["success"],
            "raw_output": raw_out,
            "error": result.get("stderr"),
            "command": result.get("command")
        }
    except Exception as e:
        return {
            "success": False,
            "raw_output": "",
            "error": str(e),
            "command": " ".join(cmd)
        }

def stage_2_discovery(state: WorkflowState) -> WorkflowState:
    """
    STAGE 2: Network Discovery
    Uses Nmap to identify open ports, services, and OS metadata.
    """
    print(f"[Stage 2] Executing Network Discovery against: {state.normalized_target}")
    
    # Extract port if parsed in Stage 1
    port = None
    if state.evidence_ledger and "result" in state.evidence_ledger[0]:
        port = state.evidence_ledger[0]["result"].get("port")
        
    scan_result = execute_nmap_scan(state.normalized_target, port=port)
    
    if not scan_result["success"]:
        # Log failure but don't necessarily halt if there are other analysis paths
        print(f"[Stage 2] WARNING: Nmap scan failed: {scan_result['error']}")
        
    state.evidence_ledger.append({
        "stage": "STAGE_2_DISCOVERY",
        "timestamp": time.time(),
        "action": "nmap_execution",
        "result": scan_result
    })
    
    print("[Stage 2] Network Discovery complete.")
    return state
