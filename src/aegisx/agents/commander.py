import asyncio
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.openai import OpenAIProvider
from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
from aegisx.knowledge.vector_memory import VectorMemory

# Ensure environment variables are loaded so providers don't initialize with dummy keys
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


class AgentAction(BaseModel):
    agent: str = Field(..., description="The name of the agent to execute")
    priority: int = Field(..., description="Priority of this action (1-10)")
    reason: str = Field(..., description="Why this action is needed")
    triggered_by: List[str] = Field(default_factory=list, description="Findings or events that triggered this action")
    expected_outcome: str = Field(..., description="What this agent is expected to accomplish")

class DynamicPipeline(BaseModel):
    """The schema outputted by the AI Commander."""
    workflow_phase: str = Field(..., description="Current logical phase of the pentest (e.g., 'Network Discovery', 'Vulnerability Validation')")
    reasoning: str = Field(..., description="The AI's justification for generating this pipeline state.")
    state_summary: Dict[str, Any] = Field(default_factory=dict, description="Summary of current target state.")
    new_findings: List[str] = Field(default_factory=list, description="Any new high-level intelligence discovered.")
    confidence_updates: List[str] = Field(default_factory=list, description="Updates to finding confidence scores.")
    attack_graph_updates: List[Dict[str, Any]] = Field(default_factory=list, description="Structured node and edge additions to the ExposureGraph.")
    methodology_pivot: str = Field("", description="If a pivot is required, describe the new methodology.")
    next_actions: List[AgentAction] = Field(..., description="List of structured actions/agents to execute next.")
    validation_actions: List[str] = Field(default_factory=list, description="Actions required to validate previous findings.")
    report_candidates: List[str] = Field(default_factory=list, description="Findings that are ready for final reporting.")
    phase_transition: str = Field(..., description="Whether to transition to a new phase or stay in the current one.")
    requires_human_approval: bool = Field(False, description="True if any action is high-risk.")
    is_complete: bool = Field(False, description="Set to True ONLY when the entire penetration testing campaign is finished and all paths are exhausted.")

def load_master_prompt():
    prompt_path = Path(__file__).parent.parent / "prompts" / "master_orchestrator.txt"
    try:
        with open(prompt_path, "r") as f:
            return f.read() + "\n\n"
    except Exception:
        return ""

master_prompt = load_master_prompt()

# We define the PydanticAI Agent here.
# It expects a list of findings and the current state, and outputs a DynamicPipeline.

available_agents_text = (
    "\n\nAvailable agents (prefer low-noise first):\n"
    "LOW-NOISE REASONING SKILLS (Highly Preferred): 'AuthorizationReasoningSkill', 'AuthenticationReasoningSkill', "
    "'ClientSideReasoningSkill', 'APIIntelligenceSkill', 'SecurityConfigReasoningSkill', "
    "'DataExposureReasoningSkill', 'ErrorAnalysisReasoningSkill'.\n"
    "LOW-NOISE AGENTS (Preferred): 'ReconAgent', 'TrafficAnalyzerAgent', 'JSIntelligenceAgent', "
    "'APISurfaceAgent', 'SemanticDiscoveryAgent', 'AdaptiveValidationEngine', "
    "'AuthAnalyzerAgent', 'ValidationAgent', 'LoginDetectionAgent', 'AttackGraphIntelligenceAgent'.\n"
    "MEDIUM-NOISE (evidence required): 'WebCrawlerAgent', 'ActiveScanner', 'ExploitationAgent', 'ReportingAgent'.\n"
    "HIGH-NOISE (disabled unless DEEP_ANALYSIS): 'FuzzingAgent', 'HydraAdapter'.\n"
    "NEVER schedule high-noise agents without prior low-noise evidence.\n\n"
    "EXECUTION PRIORITIZATION (STRICT):\n"
    "1. Evidence Collection\n"
    "2. Authentication Discovery (LoginDetectionAgent)\n"
    "3. Authenticated Crawling\n"
    "4. Route & Parameter Discovery\n"
    "5. Attack Graph Construction (AttackGraphIntelligenceAgent)\n"
    "6. AI Reasoning\n"
    "7. Validation\n"
    "8. Correlation\n"
    "9. Reporting\n\n"
    "EVIDENCE MANDATE: Do NOT generate hypotheses if there is no supporting evidence in the SAFE_STATE_SUMMARY. "
    "If evidence_count == 0 (no routes, params, or sessions discovered), DO NOT schedule validation or reasoning agents. Instead, schedule Evidence Collection agents."
)

prompt_1 = master_prompt + "\n\nYOUR ROLE: RECONNAISSANCE & ROUTING EXPERT.\nYou specialize in scheduling ReconAgent, JSIntelligenceAgent, and APISurfaceAgent.\n" + available_agents_text
provider_1 = OpenAIProvider(
    base_url='https://openrouter.ai/api/v1',
    api_key=os.getenv("OPENROUTER_API_KEY", "dummy")
)
model_1 = OpenAIModel('openai/gpt-oss-120b:free', provider=provider_1)
ai_1 = Agent(model_1, output_type=DynamicPipeline, system_prompt=prompt_1)

prompt_2 = master_prompt + "\n\nYOUR ROLE: VULNERABILITY DISCOVERY EXPERT.\nYou specialize in AI traffic manipulation and logic flaws. You MUST actively schedule TrafficAnalyzerAgent and SurgicalMutationAgent to hunt for Business Logic, XSS, and SQLi flaws.\n" + available_agents_text
provider_2 = OpenAIProvider(
    base_url='https://openrouter.ai/api/v1',
    api_key=os.getenv("OPENROUTER_API_KEY_2", "dummy")
)
model_2 = OpenAIModel('deepseek/deepseek-v4-flash:free', provider=provider_2)
ai_2 = Agent(model_2, output_type=DynamicPipeline, system_prompt=prompt_2)

prompt_3 = master_prompt + "\n\nYOUR ROLE: VALIDATION & AUTHENTICATION EXPERT.\nYou specialize in reasoning skills and validation. Focus on AuthAnalyzerAgent and Reasoning Skills.\n" + available_agents_text
provider_3 = OpenAIProvider(
    base_url='https://openrouter.ai/api/v1',
    api_key=os.getenv("OPENROUTER_API_KEY_3", "dummy")
)
model_3 = OpenAIModel('meta-llama/llama-3.3-70b-instruct:free', provider=provider_3)
ai_3 = Agent(model_3, output_type=DynamicPipeline, system_prompt=prompt_3)

class CommanderAgent(BaseAgent):
    """
    The orchestrator agent. Uses PydanticAI to dynamically generate 
    the execution pipeline instead of relying on a static DAG.
    """
    
    def __init__(self, model_override=None):
        super().__init__(agent_id="CommanderAgent")
        self.model_override = model_override
        self.memory_engine = VectorMemory()
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        target = state.get("target")
        findings: List[Finding] = state.get("findings", [])
        execution_history: List[str] = state.get("execution_history", [])
        
        self.log_action("evaluate_state", {"target": target, "findings_count": len(findings)})
        
        try:
            from aegisx.core.runtime_governor import RuntimeGovernor
            gov = RuntimeGovernor.instance()
            scan_mode = gov.mode.value
        except ImportError:
            scan_mode = "adaptive"

        # Build the prompt
        prompt = f"Target: {target}\nScan Mode: {scan_mode}\n"
        
        # Inject Historical Context
        history = self.memory_engine.retrieve_context(target)
        if history:
            prompt += f"Historical Context from Vector Memory:\n- {history}\n\n"
            
        import json
        
        # Build SAFE_STATE_SUMMARY to prevent prompt overload
        completed_agents = state.get("completed_agents", [])
        validated_findings = state.get("validated_findings", [])
        failed_methods = state.get("failed_methods", [])
        successful_methods = state.get("successful_methods", [])
        routes = state.get("routes", [])
        
        safe_state = {
            "target": target,
            "current_phase": state.get("current_stage", "Unknown"),
            "completed_agents": completed_agents[-10:] if len(completed_agents) > 10 else completed_agents,
            "validated_findings": [f.get("title") for f in validated_findings][-5:],
            "open_ports": state.get("open_ports", []),
            "frameworks": state.get("frameworks", []),
            "recent_routes": routes[-20:] if len(routes) > 20 else routes,
            "sessions": state.get("sessions", []),
            "roles": state.get("roles", []),
            "parameters": state.get("parameters", [])[-20:] if len(state.get("parameters", [])) > 20 else state.get("parameters", []),
            "forms": state.get("forms", [])[-10:] if len(state.get("forms", [])) > 10 else state.get("forms", []),
            "failed_methods": failed_methods[-5:] if len(failed_methods) > 5 else failed_methods,
            "successful_methods": successful_methods[-5:] if len(successful_methods) > 5 else successful_methods,
            "next_candidate_actions": state.get("next_candidate_actions", []),
            "workflow_depth": state.get("workflow_depth", 0),
            "unavailable_agents": state.get("unavailable_agents", []),
            "repeated_results_counter": state.get("repeated_results_counter", {}),
            "attack_surface_nodes": state.get("attack_surface_nodes", [])[-20:],
            "attack_paths": state.get("attack_paths", [])[-10:]
        }
        
        prompt += "SAFE_STATE_SUMMARY (Compressed Context):\n"
        prompt += json.dumps(safe_state, indent=2)
        prompt += "\n\nCRITICAL DIRECTIVE: DO NOT schedule agents listed in 'unavailable_agents'. Penalize agents in 'repeated_results_counter' if their count is high. Pivot methodology if stuck.\n\n"
            
        from aegisx.core.ui.console import ConsoleUI
        
        # Estimate token size (rough heuristic: 1 char ~= 0.25 tokens)
        estimated_tokens = len(prompt) // 4
        ConsoleUI.info(f"AI Prompt injected with SAFE_STATE_SUMMARY (Estimated Tokens: {estimated_tokens})")
                
        # ── Retry Loop for API Rate Limits (429) ──
        max_retries = 3
        pipeline = None
        
        for attempt in range(max_retries):
            # Wrap all 3 AI calls in asyncio tasks
            # Wait for all of them up to 60 seconds using gather
            self.log_action("multi_ai_consensus_started", {
                "models": ["gpt-oss-120b (Recon)", "deepseek-v4-flash (Vuln)", "llama-3.3-70b (Auth)"], 
                "attempt": attempt + 1
            })
            
            try:
                task_1 = asyncio.create_task(ai_1.run(prompt))
                await asyncio.sleep(1)
                task_2 = asyncio.create_task(ai_2.run(prompt))
                await asyncio.sleep(1)
                task_3 = asyncio.create_task(ai_3.run(prompt))
                
                results = await asyncio.wait_for(
                    asyncio.gather(task_1, task_2, task_3, return_exceptions=True),
                    timeout=60.0
                )
            except asyncio.TimeoutError:
                self.log_action("ai_model_timeout", {"timeout": 60.0})
                ConsoleUI.warning("AI Commander consensus timed out.")
                results = []
                
            valid_pipelines = []
            for res in results:
                if not isinstance(res, Exception):
                    valid_pipelines.append(res.output)
                else:
                    self.log_action("ai_model_failed", {"error": str(res)})
                    
            # We allow degraded consensus to proceed if the free-tier models are rate-limited,
            # because the master prompt still enforces the vulnerability agents globally.
            if valid_pipelines:
                if len(valid_pipelines) < 3:
                    ConsoleUI.warning(f"Consensus degraded! Only {len(valid_pipelines)}/3 experts responded (likely due to free-tier rate limits). Proceeding with available models.")
                    
                # Merge the valid pipelines into one super-pipeline!
                base = valid_pipelines[0]
                merged_actions = list(base.next_actions)
                merged_reasoning = "CONSENSUS: " + base.reasoning
                is_complete = base.is_complete
                
                for p in valid_pipelines[1:]:
                    # Merge unique actions
                    for act in p.next_actions:
                        if act.agent not in [a.agent for a in merged_actions]:
                            merged_actions.append(act)
                    merged_reasoning += " | " + p.reasoning
                    # If ANY model says we aren't done, we keep going!
                    if not p.is_complete:
                        is_complete = False
                        
                base.next_actions = merged_actions
                base.reasoning = merged_reasoning
                base.is_complete = is_complete
                pipeline = base
                break # Success!
                
            # If we reach here, all 3 models failed on this attempt
            if attempt < max_retries - 1:
                wait_time = (attempt + 1) * 15 # Wait 15s, then 30s
                ConsoleUI.warning(f"AI Quota/Timeout hit. Retrying in {wait_time}s...")
                await asyncio.sleep(wait_time)
                
        if not pipeline:
            ConsoleUI.warning("Both AI Commanders failed completely. Engaging Fallback Planner.")
            self.log_action("fallback_planner_engaged", {})
            pipeline = self._fallback_planner(state)
        
        self.log_action("pipeline_generated", pipeline.model_dump())
        
        # Enforce HITL if required
        if pipeline.requires_human_approval:
            self.log_action("hitl_pause", {"reasoning": "High-risk agents scheduled."})
            return {
                "status": "WAITING_FOR_APPROVAL",
                "pipeline": pipeline.model_dump()
            }
            
        return {
            "status": "PROCEED",
            "pipeline": pipeline.model_dump() if isinstance(pipeline, DynamicPipeline) else pipeline
        }

    def _fallback_planner(self, state: Dict[str, Any]) -> DynamicPipeline:
        """
        Deterministic fallback planner if the AI Commander fails.
        Prevents orchestration stalls by blindly progressing the state machine.
        """
        completed = state.get("completed_agents", [])
        
        # Simple state machine based on what hasn't run yet
        if "ReconAgent" not in completed:
            next_action = "ReconAgent"
            phase = "Network Discovery"
        elif "TrafficAnalyzerAgent" not in completed:
            next_action = "TrafficAnalyzerAgent"
            phase = "HTTP Intelligence"
        elif "JSIntelligenceAgent" not in completed:
            next_action = "JSIntelligenceAgent"
            phase = "Route Intelligence"
        elif "APISurfaceAgent" not in completed:
            next_action = "APISurfaceAgent"
            phase = "Route Intelligence"
        elif "AuthenticationReasoningSkill" not in completed:
            next_action = "AuthenticationReasoningSkill"
            phase = "Authentication Analysis"
        elif "ClientSideReasoningSkill" not in completed:
            next_action = "ClientSideReasoningSkill"
            phase = "Vulnerability Discovery"
        else:
            # Everything basic has run, just do reporting
            next_action = "ReportingAgent"
            phase = "Reporting"
            
        return DynamicPipeline(
            workflow_phase=phase,
            reasoning="Fallback Planner engaged due to AI timeout/failure.",
            state_summary={},
            new_findings=[],
            confidence_updates=[],
            attack_graph_updates=[],
            methodology_pivot="Switched to deterministic fallback execution.",
            next_actions=[AgentAction(agent=next_action, priority=1, reason="Fallback fallback_planner fallback", expected_outcome="deterministic action")],
            validation_actions=[],
            report_candidates=[],
            phase_transition="Continuing deterministic progression",
            requires_human_approval=False,
            is_complete=(next_action == "ReportingAgent")
        )
