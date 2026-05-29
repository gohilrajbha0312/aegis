from aegisx.core.models import default_model
import asyncio
import os
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
from aegisx.core.ui.console import ConsoleUI

class ValidatedFindings(BaseModel):
    """The schema outputted by the AI Validation Agent."""
    confirmed_indices: List[int] = Field(..., description="Indices (0-based) of findings that are confirmed vulnerabilities.")
    false_positive_indices: List[int] = Field(..., description="Indices (0-based) of findings that are false positives.")
    reasoning: str = Field(..., description="The AI's justification for its validation decisions.")

validation_ai_gemini = Agent(
    default_model,
    output_type=ValidatedFindings,
    system_prompt=(
        "You are the ValidationAgent for AEGIS-X, an enterprise penetration testing platform. "
        "Your job is to analyze a list of vulnerability findings and determine which are actual vulnerabilities "
        "and which are false positives. "
        "Rules: "
        "1. Carefully evaluate the reasoning and evidence for each finding. "
        "2. If a finding relies on weak evidence (e.g., low entropy without sequence predictability) or is a known common false positive, mark its index in false_positive_indices. "
        "3. If a finding has strong evidence (e.g., confirmed time delay in blind SQLi, successful brute force login), mark its index in confirmed_indices. "
        "4. Output must include every index provided in the input, categorized into one of the two lists. "
        "5. Explain your reasoning clearly."
    )
)

openrouter_provider = OpenAIProvider(
    base_url='https://openrouter.ai/api/v1',
    api_key=os.getenv("OPENROUTER_API_KEY", "dummy")
)
nemotron_model = OpenAIModel(
    'meta-llama/llama-3.1-8b-instruct',
    provider=openrouter_provider
)

validation_ai_nemotron = Agent(
    nemotron_model,
    output_type=ValidatedFindings,
    system_prompt=(
        "You are the ValidationAgent for AEGIS-X, an enterprise penetration testing platform. "
        "Your job is to analyze a list of vulnerability findings and determine which are actual vulnerabilities "
        "and which are false positives. "
        "Rules: "
        "1. Carefully evaluate the reasoning and evidence for each finding. "
        "2. If a finding relies on weak evidence or is a common false positive, mark its index in false_positive_indices. "
        "3. If a finding has strong evidence, mark its index in confirmed_indices. "
        "4. Output must include every index provided in the input. "
        "5. Explain your reasoning clearly."
    )
)

class ValidationAgent(BaseAgent):
    """
    The decision maker agent. Uses PydanticAI to validate findings and prune false positives.
    """
    
    def __init__(self, model_override=None):
        super().__init__(agent_id="ValidationAgent")
        self.model_override = model_override
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        routes = state.get("routes", [])
        parameters = state.get("parameters", [])
        
        if len(routes) == 0:
            ConsoleUI.warning("ValidationAgent skipped: No routes discovered (evidence_count=0).")
            return state
            
        if len(parameters) == 0:
            ConsoleUI.warning("ValidationAgent skipped: No parameters discovered (evidence_count=0).")
            return state
            
        findings = state.get("findings", [])
        if not findings:
            return state

        self.log_action("validate_findings", {"count": len(findings)})
        
        prompt = "Please validate the following findings:\n\n"
        for idx, f in enumerate(findings):
            if isinstance(f, dict):
                prompt += f"[{idx}] {f.get('finding_type', 'Unknown')} - Risk: {f.get('risk_level', 'UNKNOWN')}\n"
                prompt += f"    Reasoning: {f.get('reasoning', [])}\n\n"
            else:
                prompt += f"[{idx}] {getattr(f, 'title', 'Unknown')} - Risk: {getattr(f, 'severity', 'UNKNOWN')}\n\n"

        gemini_task = asyncio.create_task(validation_ai_gemini.run(prompt, model=self.model_override))
        nemotron_task = asyncio.create_task(validation_ai_nemotron.run(prompt))
        
        self.log_action("dual_ai_validation_started", {"models": ["gemini-2.5-flash", "meta-llama/llama-3.1-8b-instruct"]})
        
        validation_result = None
        for coro in asyncio.as_completed([gemini_task, nemotron_task]):
            try:
                result = await coro
                validation_result = result.output
                break # First successful AI wins
            except Exception as e:
                self.log_action("ai_model_failed", {"error": str(e)})
                continue
                
        for task in [gemini_task, nemotron_task]:
            if not task.done():
                task.cancel()
                
        if not validation_result:
            ConsoleUI.warning("[ValidationAgent] AI failed to validate findings. Proceeding without pruning.")
            return state
            
        self.log_action("validation_complete", validation_result.model_dump())
        ConsoleUI.info(f"[ValidationAgent] Reasoning: {validation_result.reasoning}")
        
        # Filter findings
        confirmed_findings = []
        false_positives = 0
        for idx, f in enumerate(findings):
            if idx in validation_result.confirmed_indices:
                confirmed_findings.append(f)
            else:
                false_positives += 1
                
        if false_positives > 0:
            ConsoleUI.success(f"[ValidationAgent] Pruned {false_positives} false positives.")
            
        state["findings"] = confirmed_findings
        return state
