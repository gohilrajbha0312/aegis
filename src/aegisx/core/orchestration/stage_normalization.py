import ipaddress
import urllib.parse
import uuid
import time
from typing import Dict, Any

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

def normalize_target(target: str) -> Dict[str, Any]:
    """
    Normalizes a raw string target into structured scope data.
    Validates if it's an IP, CIDR, or Domain/URL.
    """
    result = {
        "raw": target,
        "is_ip": False,
        "is_cidr": False,
        "is_url": False,
        "domain": None,
        "ip": None,
        "port": None
    }
    
    # 1. Check if it's a URL
    if "://" in target:
        result["is_url"] = True
        parsed = urllib.parse.urlparse(target)
        result["domain"] = parsed.hostname
        result["port"] = parsed.port or (443 if parsed.scheme == 'https' else 80)
        target_core = parsed.hostname
    else:
        target_core = target
        
    # Handle explicit ports in raw format (e.g. 192.168.1.1:3000)
    if ":" in target_core and not result["port"]:
        parts = target_core.split(":")
        target_core = parts[0]
        try:
            result["port"] = int(parts[1])
        except ValueError:
            pass

    # 2. Check if it's an IP or CIDR
    try:
        network = ipaddress.ip_network(target_core, strict=False)
        if network.num_addresses > 1:
            result["is_cidr"] = True
        else:
            result["is_ip"] = True
            result["ip"] = str(network.network_address)
    except ValueError:
        # Not an IP, assume domain
        if not result["domain"]:
            result["domain"] = target_core
            
    return result

def stage_1_normalization(state: WorkflowState) -> WorkflowState:
    """
    STAGE 1: Target Normalization
    Validates scope, resolves domains, sets up evidence workflow ID.
    """
    ConsoleUI.info(f"Normalizing target: {state.target}")
    
    normalized = normalize_target(state.target)
    
    if not normalized.get("ip") and not normalized.get("domain") and not normalized.get("is_cidr"):
        state.halt_execution = True
        state.halt_reason = "Invalid target format. Could not parse IP, CIDR, or Domain."
        return state
        
    ip_or_domain = normalized.get("ip") or normalized.get("domain")
    port = normalized.get("port")
    # Preserve port in normalized_target so all phases hit the right port
    if port and port not in (80, 443):
        state.normalized_target = f"{ip_or_domain}:{port}"
    else:
        state.normalized_target = ip_or_domain
    
    # Initialize Evidence Workflow ID
    state.workflow_id = f"WF-{str(uuid.uuid4())[:8].upper()}"
    
    state.evidence_ledger.append({
        "stage": "STAGE_1_NORMALIZATION",
        "timestamp": time.time(),
        "action": "scope_validation",
        "result": normalized
    })
    
    ConsoleUI.success(f"Normalized as: {state.normalized_target} | Workflow: {state.workflow_id}")
    return state
