from typing import Dict, Any, List
from aegisx.agents.base import BaseAgent
from aegisx.scanners.nmap import NmapAdapter
from aegisx.scanners.nuclei import NucleiAdapter
from aegisx.scanners.ffuf import FFUFAdapter

class ReconAgent(BaseAgent):
    """
    Autonomous Reconnaissance Agent.
    Responsible for selecting and executing the right scanning adapters.
    """
    
    def __init__(self):
        super().__init__(agent_id="ReconAgent")
        self.nmap = NmapAdapter()
        self.ffuf = FFUFAdapter()
        self.nuclei = NucleiAdapter()
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        self.log_action("start_recon", {"target": target})
        
        # Example of calling a tool adapter asynchronously
        # In full implementation, PydanticAI would choose which adapter to call dynamically.
        nmap_results = await self.nmap.execute({"target": target})
        
        findings = nmap_results.get("findings", [])
        self.log_action("nmap_complete", {"findings_count": len(findings)})
        
        return {
            "phase": "recon_complete",
            "findings": findings
        }
