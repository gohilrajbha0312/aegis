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
                v = v.strip('"').strip("'")
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
    "LOW-NOISE AGENTS (Preferred): 'ContinuousReconLoopAgent', 'ReconAgent', 'TrafficAnalyzerAgent', 'JSIntelligenceAgent', "
    "'APISurfaceAgent', 'SemanticDiscoveryAgent', 'AdaptiveValidationEngine', "
    "'AuthAnalyzerAgent', 'ValidationAgent', 'LoginDetectionAgent', 'AttackGraphIntelligenceAgent', "
    "'EvidenceGraphAgent', 'SessionIsolationAgent', 'RouteOwnershipAgent', 'DifferentialResponseAgent', "
    "'RuntimeMemoryAgent', 'ReconExpansionAgent', 'RouteRiskScoringAgent', "
    "'RouteLineageAgent', 'ParameterLineageAgent', 'DiscoveryConfidenceAgent', 'AttackSurfaceGrowthAgent', 'ReconBudgetOptimizerAgent', "
    "'SessionFingerprintAgent', 'APIBehaviorAgent', 'AttackPathCorrelationAgent', "
    "'MultiSessionCorrelationAgent', 'ResponseFingerprintAgent', 'RuntimeAnomalyAgent', "
    "'EvidenceTrustAgent', 'EvidenceConflictAgent', "
    "'AttackPathExpansionAgent', 'AgentConsensusAgent', 'CampaignCompletionAgent', "
    "'TokenAnalysisAgent', 'PriceManipulationAgent'.\n"
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
    "If evidence_count == 0, DO NOT schedule validation or reasoning agents. Instead, schedule Evidence Collection agents.\n\n"
    "SKILL 97 (ReconPersistence): Every finding MUST trigger additional route/parameter/session discovery. Never stop at the first vulnerability. Ensure ReconExpansionAgent is called frequently."
)

prompt_1 = master_prompt + "\n\nYOUR ROLE: RECONNAISSANCE & ROUTING EXPERT.\nYou specialize in scheduling ReconAgent, JSIntelligenceAgent, and APISurfaceAgent.\n" + available_agents_text
prompt_2 = master_prompt + "\n\nYOUR ROLE: VULNERABILITY DISCOVERY EXPERT.\nYou specialize in AI traffic manipulation and logic flaws. You MUST actively schedule TrafficAnalyzerAgent and SurgicalMutationAgent to hunt for Business Logic, XSS, and SQLi flaws.\n" + available_agents_text
prompt_3 = master_prompt + "\n\nYOUR ROLE: VALIDATION & AUTHENTICATION EXPERT.\nYou specialize in reasoning skills and validation. Focus on AuthAnalyzerAgent and Reasoning Skills.\n" + available_agents_text

# Agents are now built dynamically in the process method using the failover engine

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
        
        # SKILL 78: State Compression
        from aegisx.agents.state_compression import StateCompressionAgent
        safe_state = StateCompressionAgent.compress(state)
        
        # Merge in a few extra commander-specific fields
        safe_state["current_phase"] = state.get("current_stage", "Unknown")
        safe_state["completed_agents"] = completed_agents[-10:] if len(completed_agents) > 10 else completed_agents
        safe_state["validated_findings"] = [f.get("title") for f in validated_findings][-5:]
        safe_state["open_ports"] = state.get("open_ports", [])
        safe_state["recent_routes"] = routes[-20:] if len(routes) > 20 else routes
        
        # SKILL 79: Recon Coverage Enforcement
        from aegisx.agents.recon_coverage import ReconCoverageEnforcementAgent
        disabled_agents = ReconCoverageEnforcementAgent.enforce(state)
        if disabled_agents:
            safe_state["unavailable_agents"] = list(set(safe_state.get("unavailable_agents", []) + disabled_agents))
            prompt += "\n[!] RECON COVERAGE < 70%: Vulnerability/Exploitation validation is DISABLED. You MUST focus on ReconAgent, JSIntelligenceAgent, SessionAgent, etc.\n"
        
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
        
        from aegisx.agents.model_health import model_health_engine
        
        for attempt in range(max_retries):
            # Dynamically build agent to respect failover state
            ai_1 = model_health_engine.failover.build_agent(prompt_1, DynamicPipeline)
            
            self.log_action("single_ai_started", {
                "models": [model_health_engine.failover.current_model_name], 
                "attempt": attempt + 1
            })
            
            try:
                result = await asyncio.wait_for(
                    ai_1.run(prompt),
                    timeout=180.0
                )
                results = [result]
            except asyncio.TimeoutError:
                self.log_action("ai_model_timeout", {"timeout": 180.0})
                ConsoleUI.warning("AI Commander consensus timed out.")
                results = []
            except Exception as e:
                results = [e]
                
            valid_pipelines = []
            rate_limit_hit = False
            for res in results:
                if not isinstance(res, Exception):
                    valid_pipelines.append(res.output)
                else:
                    err_str = str(res)
                    self.log_action("ai_model_failed", {"error": err_str})
                    if "429" in err_str or "Rate limit" in err_str or "Quota" in err_str:
                        rate_limit_hit = True
                    
            if valid_pipelines:
                base = valid_pipelines[0]
                final_actions = base.next_actions
                merged_reasoning = base.reasoning
                is_complete = base.is_complete

                base.next_actions = final_actions
                base.reasoning = merged_reasoning
                base.is_complete = is_complete
                pipeline = base
                break # Success!
                
            # If we reach here, all 3 models failed on this attempt
            if rate_limit_hit and not valid_pipelines:
                # SKILL 76/77: ModelHealthAgent Failover Trigger
                can_retry = model_health_engine.handle_failure("OpenRouter Rate Limit (429)")
                if not can_retry:
                    ConsoleUI.error("OpenRouter API Quota Exhausted and model pool depleted. Fast-failing to deterministic fallback planner.")
                    break
                else:
                    # Model swapped! Retry immediately on the new model without sleeping
                    continue

            if attempt < max_retries - 1:
                # A generic error occurred, trigger health check
                can_retry = model_health_engine.handle_failure(err_str if 'err_str' in locals() else "Unknown Error")
                if can_retry:
                    continue
                else:
                    wait_time = (attempt + 1) * 15 # Wait 15s, then 30s
                    ConsoleUI.warning(f"AI Error ({err_str if 'err_str' in locals() else 'Unknown'}). Retrying in {wait_time}s...")
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
        
        # Fetch metrics for reporting gates
        recon_score = state.get("recon_coverage_score", 0)
        growth = state.get("attack_surface_growth_score", 0)
        routes_discovered = len(state.get("routes", []))
        routes_tested = len(state.get("tested_routes", []))
        val_queue = len(state.get("validation_queue", []))

        can_report = (recon_score >= 90) and (growth == 0) and (routes_tested >= routes_discovered) and (val_queue == 0)

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
        elif "GraphQLExpansionAgent" not in completed and any("graphql" in str(r).lower() for r in state.get("routes", [])):
            next_action = "GraphQLExpansionAgent"
            phase = "GraphQL Expansion"
        elif "TokenAnalysisAgent" not in completed and any("eyJ" in str(s) for s in state.get("sessions", [])):
            next_action = "TokenAnalysisAgent"
            phase = "Token Analysis"
        elif "PriceManipulationAgent" not in completed and any(kw in str(r).lower() for kw in ['checkout', 'cart', 'payment', 'order', 'pay'] for r in state.get("routes", [])):
            next_action = "PriceManipulationAgent"
            phase = "Business Logic Testing"
        elif "SessionValidationAgent" not in completed and any(kw in str(r).lower() for kw in ['auth', 'login', 'admin', 'user', 'profile'] for r in state.get("routes", [])):
            next_action = "SessionValidationAgent"
            phase = "Session Validation"
        elif "RouteCoverageAgent" not in completed:
            next_action = "RouteCoverageAgent"
            phase = "Coverage Analysis"
        elif "AuthenticationReasoningSkill" not in completed:
            next_action = "AuthenticationReasoningSkill"
            phase = "Authentication Analysis"
        elif "ClientSideReasoningSkill" not in completed:
            next_action = "ClientSideReasoningSkill"
            phase = "Vulnerability Discovery"
        else:
            if can_report:
                next_action = "ReportingAgent"
                phase = "Reporting"
            else:
                next_action = "ReconAgent"
                phase = "Network Discovery (Forced Continue)"
            
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
