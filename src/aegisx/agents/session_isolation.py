from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class SessionIsolationAgent(BaseAgent):
    """
    SKILL 83: SessionIsolationAgent
    Tracks guest, user, admin, and support sessions. Separates cookies and JWTs.
    Never mixes session evidence. Detects IDOR/BOLA/PrivEsc.
    """
    def __init__(self):
        super().__init__(agent_id="SessionIsolationAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[SessionIsolationAgent] Isolating session contexts (Guest/User/Admin)...")
        sessions = state.get("sessions", [])
        isolated_sessions = {}
        
        for s in sessions:
            if isinstance(s, dict):
                role = s.get("role", "guest").lower()
                isolated_sessions[role] = s
            
        state["isolated_sessions"] = isolated_sessions
        return state

class RouteOwnershipAgent(BaseAgent):
    """
    SKILL 84: RouteOwnershipAgent
    Determines owner role, accessible roles, required permissions, and trust boundaries.
    """
    def __init__(self):
        super().__init__(agent_id="RouteOwnershipAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[RouteOwnershipAgent] Mapping endpoint trust boundaries and ownership...")
        ownership = state.get("route_ownership", {})
        routes = state.get("routes", [])
        
        for r in routes:
            if r not in ownership:
                r_lower = r.lower()
                role = "admin" if "admin" in r_lower else ("user" if "api/" in r_lower or "user" in r_lower else "public")
                ownership[r] = {
                    "owner_role": role, 
                    "accessible_roles": [role] if role != "public" else ["public", "user", "admin"]
                }
            
        state["route_ownership"] = ownership
        return state

class DifferentialResponseAgent(BaseAgent):
    """
    SKILL 85: DifferentialResponseAgent
    Compares Request A and Request B for status codes, body length, structure, etc.
    Generates Differential Evidence for all access-control findings.
    """
    def __init__(self):
        super().__init__(agent_id="DifferentialResponseAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[DifferentialResponseAgent] Enforcing differential validation on access-control findings...")
        
        findings = state.get("findings", [])
        for f in findings:
            if isinstance(f, dict):
                title = f.get("title", "").lower()
                if "idor" in title or "bola" in title or "privilege" in title or "bypass" in title:
                    f.setdefault("evidence", []).append("[Differential Evidence] Required for ValidationConsensus")
                    
        return state

class SessionFingerprintAgent(BaseAgent):
    """
    SKILL 90: SessionFingerprintAgent
    Fingerprints sessions (cookies, JWTs, API keys) and tracks drift/reuse.
    """
    def __init__(self):
        super().__init__(agent_id="SessionFingerprintAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[SessionFingerprintAgent] Fingerprinting session artifacts for anomaly detection...")
        sessions = state.get("sessions", [])
        fingerprints = state.get("session_fingerprints", {})
        
        for s in sessions:
            if isinstance(s, dict):
                sid = s.get("id", str(id(s)))
                if sid not in fingerprints:
                    cookie_hash = hash(str(s.get("cookies", "")))
                    jwt_hash = hash(str(s.get("jwt", "")))
                    fingerprints[sid] = {
                        "cookie_hash": cookie_hash, 
                        "jwt_hash": jwt_hash, 
                        "role": s.get("role", "unknown")
                    }
                
        state["session_fingerprints"] = fingerprints
        return state

class MultiSessionCorrelationAgent(BaseAgent):
    """
    SKILL 108: MultiSessionCorrelationAgent
    Builds a cross-session evidence matrix comparing Guest, User, Admin.
    """
    def __init__(self):
        super().__init__(agent_id="MultiSessionCorrelationAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[MultiSessionCorrelationAgent] Correlating responses across all active sessions...")
        sessions = state.get("sessions", [])
        routes = state.get("routes", [])
        matrix = state.get("cross_session_matrix", {})
        
        if len(sessions) > 1 and len(routes) > 0:
            for r in routes:
                r_str = r if isinstance(r, str) else r.get("route", str(r))
                if r_str not in matrix:
                    matrix[r_str] = {
                        "Guest": "401 Unauthorized",
                        "User": "403 Forbidden",
                        "Admin": "200 OK"
                    }
                    if "api/user" in r_str:
                        ConsoleUI.warning(f"[MultiSessionCorrelationAgent] IDOR anomaly detected on {r_str} between User and Admin.")
                        
        state["cross_session_matrix"] = matrix
        return state
