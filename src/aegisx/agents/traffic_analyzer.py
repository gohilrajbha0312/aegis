from typing import Dict, Any, List
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
import uuid
import os
from pathlib import Path
from pydantic import BaseModel, Field
from pydantic_ai import Agent

# Ensure environment variables are loaded for API Keys
env_path = Path(os.getcwd()) / ".env"
if env_path.exists():
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                k, v = line.split('=', 1)
                os.environ[k] = v
                if k.startswith('OPENROUTER_API_KEY'):
                    os.environ[k] = v

class WorkflowMap(BaseModel):
    """Map of legitimate workflows extracted from traffic."""
    request_chains: List[str] = Field(..., description="Common sequences of endpoints called together")
    token_transitions: List[str] = Field(..., description="Where tokens are acquired and used")
    trust_assumptions: List[str] = Field(..., description="Inferred trust models (e.g., frontend state dictating admin access)")
    potential_injection_points: List[str] = Field(..., description="Complex parameters, headers, or serialized objects ripe for Injection (SQLi, NoSQLi, Command Injection).")
    reflection_points: List[str] = Field(..., description="Inputs that appear to be reflected back in the response (useful for XSS detection).")
    baseline_behavior: str = Field(..., description="Summary of normal application behavior")

from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider

openrouter_provider = OpenAIProvider(base_url='https://openrouter.ai/api/v1', api_key=os.getenv("OPENROUTER_API_KEY", "dummy"))
model = OpenAIModel(os.getenv('AEGIS_MODEL', ''), provider=openrouter_provider)

traffic_learning_ai = Agent(
    model,
    output_type=WorkflowMap,
    system_prompt=(
        "You are the AEGIS-X Traffic Learning Engine. "
        "Analyze a sample of legitimate HTTP traffic (HAR/Proxy logs). "
        "Identify normal workflows, API request sequences, token transitions, "
        "and frontend state changes. Map the baseline behavior and trust boundaries. "
        "Crucially, identify potential complex injection points (for SQLi, SSRF, Command Injection) "
        "and reflection points (for XSS). "
        "Do NOT focus on generating exploits yet; focus on mapping the attack surface structure."
    )
)

class TrafficAnalyzerAgent(BaseAgent):
    """
    Traffic Learning Engine. Captures legitimate workflows, token transitions,
    and API sequences to inform downstream semantic mutation.
    """
    
    def __init__(self):
        super().__init__(agent_id="TrafficAnalyzerAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        findings = state.get("findings", [])
        
        self.log_action("start_traffic_analysis", {"target": target})
        
        new_findings = []
        
        # Analyze existing findings from scanners (like TsharkAdapter or MitmProxyAdapter)
        # to add business logic context or escalate.
        exposed_tokens_found = False
        captured_requests = []
        for f in findings:
            if isinstance(f, Finding):
                if f.source_tool == "tshark" and "Unencrypted Session Data" in f.title:
                    exposed_tokens_found = True
                    self.log_action("escalating_tshark_finding", {"finding_id": f.id})
            elif isinstance(f, dict):
                if f.get("source_tool") == "tshark" and "Unencrypted Session Data" in f.get("title", ""):
                    exposed_tokens_found = True
                    self.log_action("escalating_tshark_finding", {"finding_id": f.get("id")})
                    
        # Simulate getting captured requests directly from state (if passed by MitmProxyAdapter)
        # In a real setup, TrafficAnalyzerAgent might parse a raw pcap or flow file directly.
        # Here we just pass through what the adapter might have put in state.
        captured_requests.extend(state.get("captured_requests", []))
                    
        # Simulate generating a contextual logical finding based on the raw network data
        if exposed_tokens_found:
            self.log_action("logical_deduction", {"reason": "Session tokens found in plaintext traffic"})
            finding = Finding(
                id=str(uuid.uuid4()),
                title="Broken Access Control: Unencrypted Session Token Exposure",
                severity="CRITICAL",
                confidence=0.95,
                evidence=["Tshark captured session cookies or auth headers over HTTP without TLS."],
                source_tool="TrafficAnalyzerAgent",
                cwe="CWE-319",
                affected_assets=[target],
                exploitability="High"
            )
            new_findings.append(finding)
        else:
            self.log_action("analysis_complete", {"reason": "No plaintext session exposure detected."})
            
        # Traffic Learning Phase
        workflow_map = None
        if captured_requests:
            self.log_action("learning_workflows_from_traffic", {"sample_size": min(10, len(captured_requests))})
            traffic_sample = "\\n\\n---\\n\\n".join(captured_requests[:10])
            try:
                # Wrap the async call in a synchronous run (if running under asyncio.run in orchestrator)
                # But since process() is async, we can just await it directly here.
                result = await traffic_learning_ai.run(f"Analyze this traffic sample and map workflows:\\n{traffic_sample}")
                workflow_map = result.output.model_dump()
                self.log_action("workflow_map_generated", {"chains": len(workflow_map['request_chains'])})
            except Exception as e:
                self.log_action("traffic_learning_failed", {"error": str(e)})

        self.log_action("traffic_analysis_complete", {"new_findings_count": len(new_findings), "requests_captured": len(captured_requests)})
        
        return {
            "phase": "traffic_analysis_complete",
            "findings": new_findings,
            "captured_requests": captured_requests,
            "workflow_map": workflow_map
        }
