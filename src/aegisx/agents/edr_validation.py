from aegisx.core.models import default_model
from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
from pydantic_ai import Agent
import uuid

edr_ai = Agent(
    default_model,
    system_prompt="You are an EDR Validation Agent. Validate enterprise detections, map SOC visibility gaps, and evaluate defensive controls against simulated attack telemetry."
)

class EDRValidationAgent(BaseAgent):
    """Agent for validating SOC detections and evaluating defensive controls."""
    
    def __init__(self):
        super().__init__(agent_id="EDRValidationAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        self.log_action("start_edr_validation", {"target": target})
        
        telemetry = state.get("telemetry", "EventID 4688: cmd.exe /c powershell -enc JAB...")
        
        result = await edr_ai.run(f"Analyze this telemetry against standard Sigma rules for evasion:\n{telemetry}")
        
        findings = []
        if "powershell -enc" in telemetry:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="SOC Visibility Gap: Unalerted Encoded PowerShell",
                severity="HIGH",
                confidence=0.85,
                evidence=[telemetry, result.output[:100]],
                source_tool="EDRValidationAgent",
                affected_assets=[target],
                exploitability="N/A"
            ))
            
        self.log_action("edr_validation_complete", {"findings": len(findings)})
        return {"phase": "edr_validation_complete", "findings": findings}
