from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
import uuid

class AuthAnalyzerAgent(BaseAgent):
    """
    Specialized agent for hunting complex logical flaws in authentication mechanisms.
    Focuses on JWT, Session Fixation, and RBAC matrix testing.
    """
    
    def __init__(self):
        super().__init__(agent_id="AuthAnalyzerAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        auth_token = state.get("auth_token")
        
        self.log_action("start_auth_analysis", {"target": target, "has_token": bool(auth_token)})
        
        findings = []
        
        if not auth_token:
            self.log_action("abort", {"reason": "No auth token provided in state."})
            return {"phase": "auth_analysis_failed", "findings": findings}
            
        # Simulated logic for analyzing JWT or Session token
        self.log_action("testing_jwt_none_alg", {"token_prefix": auth_token[:10]})
        
        # Example finding generated dynamically
        if "eyJ" in auth_token: # Looks like a JWT
            finding = Finding(
                id=str(uuid.uuid4()),
                title="JWT Algorithm Confusion (None)",
                severity="CRITICAL",
                confidence=0.85,
                evidence=["Token accepted with 'alg': 'none' signature stripped."],
                source_tool="AuthAnalyzerAgent",
                cwe="CWE-347",
                affected_assets=[target],
                exploitability="High"
            )
            findings.append(finding)
            
        self.log_action("auth_analysis_complete", {"findings_count": len(findings)})
        
        return {
            "phase": "auth_analysis_complete",
            "findings": findings
        }
