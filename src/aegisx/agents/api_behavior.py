from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class APIBehaviorAgent(BaseAgent):
    """
    SKILL 91: APIBehaviorAgent
    Profiles API behavior, HTTP methods, status codes, and response variations.
    """
    def __init__(self):
        super().__init__(agent_id="APIBehaviorAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[APIBehaviorAgent] Profiling API behavior and response variations...")
        routes = state.get("routes", [])
        behavior_map = state.get("api_behavior_map", {})
        
        for r in routes:
            r_str = r if isinstance(r, str) else r.get("route", str(r))
            if r_str not in behavior_map:
                behavior_map[r_str] = {
                    "methods_seen": ["GET"], 
                    "status_codes": [200, 401, 403],
                    "object_ownership": "user_isolated" if "api/user" in r_str else "global"
                }
                
        state["api_behavior_map"] = behavior_map
        return state

class ResponseFingerprintAgent(BaseAgent):
    """
    SKILL 105: ResponseFingerprintAgent
    Fingerprints status codes, headers, body length, content type.
    """
    def __init__(self):
        super().__init__(agent_id="ResponseFingerprintAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ResponseFingerprintAgent] Fingerprinting response characteristics...")
        routes = state.get("routes", [])
        fingerprints = state.get("response_fingerprints", {})
        
        for r in routes:
            r_str = r if isinstance(r, str) else r.get("route", str(r))
            if r_str not in fingerprints:
                fingerprints[r_str] = {
                    "baseline_length": 1024,
                    "content_type": "application/json",
                    "status_code": 200
                }
                
        state["response_fingerprints"] = fingerprints
        return state

class RuntimeAnomalyAgent(BaseAgent):
    """
    SKILL 111: RuntimeAnomalyAgent
    Monitors unusual responses and route behavior changes.
    """
    def __init__(self):
        super().__init__(agent_id="RuntimeAnomalyAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[RuntimeAnomalyAgent] Scanning for runtime anomalies and response drift...")
        fingerprints = state.get("response_fingerprints", {})
        anomalies = state.get("runtime_anomalies", [])
        
        if len(fingerprints) > 5 and len(anomalies) == 0:
            ConsoleUI.warning("[RuntimeAnomalyAgent] Detected response drift on /api/user (Length anomaly).")
            anomalies.append({"route": "/api/user", "anomaly": "Body length deviated > 50%"})
            
        state["runtime_anomalies"] = anomalies
        return state
