from aegisx.core.models import default_model
from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
from pydantic_ai import Agent
import uuid

mobile_ai = Agent(
    default_model,
    system_prompt="You are a Mobile Application Security Agent. Analyze APK/IPA metadata, permissions, and decompiled code snippets to detect insecure storage and hardcoded secrets."
)

class MobileSecurityAgent(BaseAgent):
    """Agent for secure mobile application assessments and API security validation."""
    
    def __init__(self):
        super().__init__(agent_id="MobileSecurityAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        self.log_action("start_mobile_analysis", {"target": target})
        
        mobsf_output = state.get("mobsf_output", "AndroidManifest.xml: android:allowBackup='true'")
        
        result = await mobile_ai.run(f"Analyze this mobile application metadata for vulnerabilities:\n{mobsf_output}")
        
        findings = []
        if "allowBackup='true'" in mobsf_output:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="Mobile Security: Insecure Android Backup Enabled",
                severity="MEDIUM",
                confidence=1.0,
                evidence=[mobsf_output, result.output[:100]],
                source_tool="MobileSecurityAgent",
                affected_assets=[target],
                exploitability="Medium"
            ))
            
        self.log_action("mobile_analysis_complete", {"findings": len(findings)})
        return {"phase": "mobile_analysis_complete", "findings": findings}
