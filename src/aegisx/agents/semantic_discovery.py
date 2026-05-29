from aegisx.core.models import default_model
from typing import Dict, Any, List
import uuid
from pydantic import BaseModel, Field
from pydantic_ai import Agent
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
import os
from pathlib import Path

# Ensure environment variables are loaded for API Keys
env_path = Path(os.getcwd()) / ".env"
if env_path.exists():
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                k, v = line.split('=', 1)
                os.environ[k] = v
                if k == 'OPENROUTER_API_KEY_2':
                    os.environ['GOOGLE_API_KEY'] = v

class DiscoveryInsight(BaseModel):
    """Structured output for semantic discovery inferences."""
    frameworks: List[str] = Field(..., description="Inferred frameworks (e.g., Express.js, Next.js, React)")
    api_style: str = Field(..., description="Inferred API style (e.g., REST, GraphQL, SOAP)")
    inferred_endpoints: List[str] = Field(..., description="High-probability endpoints discovered passively")
    routing_structure: str = Field(..., description="Description of how routing appears to work")
    trust_boundaries: List[str] = Field(..., description="Inferred authorization or trust boundaries")

discovery_ai = Agent(
    default_model,
    output_type=DiscoveryInsight,
    system_prompt=(
        "You are the AEGIS-X Semantic Discovery Agent. "
        "Your goal is to perform passive-first discovery of a web application's structure. "
        "Analyze the provided passive data (JS bundles, Swagger specs, GraphQL schemas, HAR traffic) "
        "and infer the target's framework, routing conventions, API styles, and trust boundaries. "
        "Do NOT suggest brute-force fuzzing. Extract high-probability endpoints contextually."
    )
)

class SemanticDiscoveryAgent(BaseAgent):
    """
    Performs passive-first discovery by analyzing JS bundles, 
    source maps, OpenAPI/Swagger, GraphQL introspection, etc.
    Replaces blind path mutation.
    """
    
    def __init__(self):
        super().__init__(agent_id="SemanticDiscoveryAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        self.log_action("start_semantic_discovery", {"target": target})
        
        passive_evidence = state.get("evidence_ledger", [])
        
        # In a real scenario, this would extract JS bundle text, Swagger JSON, etc.
        # Here we mock the context aggregation for the AI.
        context_block = "Passive Evidence Context:\n"
        for ev in passive_evidence:
            if ev.get("stage") in ("PHASE_7_JS_INTELLIGENCE", "PHASE_8_API_BOUNDARY"):
                context_block += str(ev.get("result", {})) + "\n"
                
        if not context_block.strip() or len(context_block) < 50:
            context_block = f"No significant passive data found for {target}. Target appears to be a basic web application."

        self.log_action("analyzing_passive_data", {"context_len": len(context_block)})
        
        try:
            result = await discovery_ai.run(f"Analyze this passive discovery data and infer the application structure:\n{context_block}")
            insight: DiscoveryInsight = result.output
            
            self.log_action("semantic_discovery_complete", {
                "frameworks": insight.frameworks,
                "endpoints_found": len(insight.inferred_endpoints)
            })
            
            # Update state with inferred semantic data
            return {
                "phase": "semantic_discovery_complete",
                "frameworks": insight.frameworks,
                "api_style": insight.api_style,
                "inferred_endpoints": insight.inferred_endpoints,
                "routing_structure": insight.routing_structure,
                "trust_boundaries": insight.trust_boundaries
            }
            
        except Exception as e:
            self.log_action("semantic_discovery_failed", {"error": str(e)})
            return {"phase": "semantic_discovery_failed", "error": str(e)}
