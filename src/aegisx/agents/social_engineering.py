from aegisx.core.models import default_model
from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
from pydantic_ai import Agent
import uuid

se_ai = Agent(
    default_model,
    system_prompt="You are a Social Engineering Defense Agent. Analyze domains, emails, and MFA workflows to validate enterprise awareness and email security posture."
)

class SocialEngineeringAgent(BaseAgent):
    """Agent for enterprise awareness validation and email security evaluation."""
    
    def __init__(self):
        super().__init__(agent_id="SocialEngineeringAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        self.log_action("start_se_analysis", {"target": target})
        
        domain_records = state.get("domain_records", "v=spf1 ~all; No DMARC record found.")
        
        result = await se_ai.run(f"Analyze these domain records for spoofing risks:\n{domain_records}")
        
        findings = []
        if "No DMARC" in domain_records:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="Email Spoofing Risk: Missing DMARC Record",
                severity="MEDIUM",
                confidence=1.0,
                evidence=[domain_records, result.output[:100]],
                source_tool="SocialEngineeringAgent",
                affected_assets=[target],
                exploitability="High"
            ))
            
        self.log_action("se_analysis_complete", {"findings": len(findings)})
        return {"phase": "se_analysis_complete", "findings": findings}
