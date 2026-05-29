from aegisx.core.models import default_model
from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
from pydantic_ai import Agent
import uuid

wifi_ai = Agent(
    default_model,
    system_prompt="You are a Wireless Security Agent. Audit WPA/WPA2/WPA3 configurations, detect rogue APs, and correlate physical exposure risks from wireless network scans."
)

class WirelessSecurityAgent(BaseAgent):
    """Agent for enterprise wireless auditing and rogue AP detection."""
    
    def __init__(self):
        super().__init__(agent_id="WirelessSecurityAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        self.log_action("start_wireless_analysis", {"target": target})
        
        scan_data = state.get("wireless_scan", "BSSID: 00:11:22:33:44:55, Encryption: WEP, ESSID: CorpNet")
        
        result = await wifi_ai.run(f"Analyze this wireless scan data for weak encryption or rogue APs:\n{scan_data}")
        
        findings = []
        if "WEP" in scan_data:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                title="Wireless Security: Deprecated WEP Encryption Detected",
                severity="CRITICAL",
                confidence=1.0,
                evidence=[scan_data, result.output[:100]],
                source_tool="WirelessSecurityAgent",
                affected_assets=[target],
                exploitability="High"
            ))
            
        self.log_action("wireless_analysis_complete", {"findings": len(findings)})
        return {"phase": "wireless_analysis_complete", "findings": findings}
