import time
import networkx as nx
from typing import Callable, Dict, Any, List, Optional
from pydantic import BaseModel, Field
from aegisx.core.orchestration.command_gateway import CommandGateway


class WorkflowState(BaseModel):
    target: str
    normalized_target: Optional[str] = None
    workflow_id: str = ""
    evidence_ledger: List[Dict[str, Any]] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    captured_requests: List[str] = Field(default_factory=list)
    halt_execution: bool = False
    halt_reason: Optional[str] = None
    current_stage: str = "INIT"
    execution_history: List[str] = Field(default_factory=list)
    
    # ── Memory-Driven Orchestration Fields ───────────────────────────
    completed_agents: List[str] = Field(default_factory=list)
    completed_tasks: List[str] = Field(default_factory=list)
    running_tasks: List[str] = Field(default_factory=list)
    failed_tasks: List[str] = Field(default_factory=list)
    executed_commands: List[str] = Field(default_factory=list)
    
    open_ports: List[int] = Field(default_factory=list)
    detected_services: List[str] = Field(default_factory=list)
    detected_technologies: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    authentication_methods: List[str] = Field(default_factory=list)
    
    routes: List[str] = Field(default_factory=list)
    api_endpoints: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    
    validated_findings: List[Dict[str, Any]] = Field(default_factory=list)
    
    attack_surface_nodes: List[Dict[str, Any]] = Field(default_factory=list)
    attack_paths: List[str] = Field(default_factory=list)
    explored_paths: List[str] = Field(default_factory=list)
    unexplored_paths: List[str] = Field(default_factory=list)
    
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    risk_scores: Dict[str, float] = Field(default_factory=dict)
    failed_methods: List[str] = Field(default_factory=list)
    successful_methods: List[str] = Field(default_factory=list)
    
    phase_history: List[str] = Field(default_factory=list)
    repeated_results_counter: Dict[str, int] = Field(default_factory=dict)
    next_candidate_actions: List[Dict[str, Any]] = Field(default_factory=list)
    
    # ── Low-Noise Intelligence Fields ────────────────────────────────
    discovered_headers: Dict[str, str] = Field(default_factory=dict)
    extracted_tokens: List[str] = Field(default_factory=list)
    discovered_js_routes: List[str] = Field(default_factory=list)
    discovered_cookies: List[str] = Field(default_factory=list)
    session_behaviors: List[str] = Field(default_factory=list)
    technology_fingerprints: Dict[str, float] = Field(default_factory=dict)

    # ── Runtime Governance Fields ────────────────────────────────────
    scan_mode: str = "adaptive"
    workflow_depth: int = 0
    max_workflow_depth: int = 5

    # ── Bounded Collections ─────────────────────────────────────────
    max_evidence_entries: int = 200
    max_findings: int = 500
    
    # ── Dynamic AI Execution Plans ──────────────────────────────────
    tool_execution_plan: Dict[str, Any] = Field(default_factory=dict)

    def append_evidence(self, entry: Dict[str, Any]):
        """Append to evidence ledger with automatic rotation."""
        self.evidence_ledger.append(entry)
        if len(self.evidence_ledger) > self.max_evidence_entries:
            # Rotate: keep the most recent entries
            overflow = len(self.evidence_ledger) - self.max_evidence_entries
            self.evidence_ledger = self.evidence_ledger[overflow:]

    def append_finding(self, finding: Dict[str, Any]) -> bool:
        """Append a finding. Returns False if cap exceeded."""
        if len(self.findings) >= self.max_findings:
            return False
        self.findings.append(finding)
        return True

    def extend_findings(self, new_findings: List[Dict[str, Any]]):
        """Extend findings list up to the cap."""
        remaining = self.max_findings - len(self.findings)
        if remaining > 0:
            self.findings.extend(new_findings[:remaining])


class DAGOrchestrator:
    """
    Deterministic orchestration engine utilizing NetworkX to enforce
    strict sequential stage progression and state passing.

    Enhanced with per-phase timeouts and RuntimeGovernor integration.
    """
    def __init__(self):
        self.graph = nx.DiGraph()
        self.stages: Dict[str, Callable[[WorkflowState], WorkflowState]] = {}
        self._build_16_stage_dag()

    def _build_16_stage_dag(self):
        """Construct the 16-stage deterministic execution model."""
        stages = [
            "STAGE_1_NORMALIZATION",
            "STAGE_2_DISCOVERY",
            "STAGE_3_UNKNOWN_SERVICE",
            "STAGE_4_HTTP_FINGERPRINT",
            "STAGE_5_WEB_ENUMERATION",
            "STAGE_6_HTTP_SECURITY",
            "STAGE_7_DOM_ANALYSIS",
            "STAGE_8_API_MAPPING",
            "STAGE_9_CLOUD_ANALYSIS",
            "STAGE_10_STATIC_BRIDGE",
            "STAGE_11_CONSENSUS",
            "STAGE_12_RISK_MODELING",
            "STAGE_13_GOVERNANCE",
            "STAGE_14_SANDBOX",
            "STAGE_15_EVIDENCE",
            "STAGE_16_REPORTING"
        ]

        for stage in stages:
            self.graph.add_node(stage)
        for i in range(len(stages) - 1):
            self.graph.add_edge(stages[i], stages[i+1])

    def register_stage(self, stage_name: str, func: Callable[[WorkflowState], WorkflowState]):
        """Register a Python function to handle a specific stage's execution."""
        if not self.graph.has_node(stage_name):
            raise ValueError(f"Stage {stage_name} is not defined in the DAG.")
        self.stages[stage_name] = func

    def execute(self, initial_state: WorkflowState) -> WorkflowState:
        """Execute the DAG deterministically with per-phase timeouts and health checks."""
        from aegisx.core.runtime_governor import RuntimeGovernor

        state = initial_state
        gov = RuntimeGovernor.instance()
        phase_timeout = gov.profile.phase_timeout_seconds

        # Apply governor limits to state
        state.max_evidence_entries = gov.profile.max_evidence_entries
        state.max_findings = gov.profile.max_findings
        state.scan_mode = gov.mode.value
        state.max_workflow_depth = gov.profile.max_workflow_depth

        execution_order = list(nx.topological_sort(self.graph))

        for stage_name in execution_order:
            # ── Check session deny ──────────────────────────────────
            if CommandGateway._session_denied:
                state.halt_execution = True
                state.halt_reason = "Execution denied for this session by operator."
                print(f"[DAG Engine] {state.halt_reason}")
                break

            # ── Check halt ──────────────────────────────────────────
            if state.halt_execution:
                print(f"[DAG Engine] Execution halted at {state.current_stage}. Reason: {state.halt_reason}")
                break

            # ── Check governor pause ────────────────────────────────
            if gov.is_paused:
                state.halt_execution = True
                state.halt_reason = f"RuntimeGovernor paused: {gov.pause_reason}"
                print(f"[DAG Engine] {state.halt_reason}")
                break

            # ── Check system health ─────────────────────────────────
            sys_health = gov.check_system_health()
            if sys_health["action"] == "PAUSED":
                state.halt_execution = True
                state.halt_reason = f"Memory pressure: {sys_health['rss_mb']:.0f} MB"
                print(f"[DAG Engine] {state.halt_reason}")
                break

            # ── Check target health ─────────────────────────────────
            target_health = gov.check_target_health()
            if target_health["action"] == "PAUSED":
                state.halt_execution = True
                state.halt_reason = "Target critically unstable"
                print(f"[DAG Engine] {state.halt_reason}")
                break
            elif "DOWNGRADED" in target_health.get("action", ""):
                print(f"[DAG Engine] Target unstable — {target_health['action']}")
                # Refresh state limits from new profile
                state.scan_mode = gov.mode.value

            state.current_stage = stage_name

            if stage_name in self.stages:
                try:
                    # ── AI Commander Gatekeeper ─────────────────────
                    try:
                        from aegisx.agents.commander import CommanderAgent
                        import asyncio
                        commander = CommanderAgent()
                        state_dict = {
                            "target": state.target,
                            "findings": state.findings,
                            "workflow_depth": state.workflow_depth,
                        }
                        
                        print(f"[DAG Engine] Consulting AI Commander for {stage_name}...")
                        pipeline_result = asyncio.run(commander.process(state_dict))
                        
                        if pipeline_result.get("status") == "HALT":
                            state.halt_execution = True
                            state.halt_reason = "AI Commander halted execution."
                            print("[DAG Engine] AI Commander halted execution.")
                            break
                            
                        reasoning = pipeline_result.get("pipeline", {}).get("reasoning", "")
                        if reasoning:
                            print(f"[DAG Engine] AI Reasoning: {reasoning}")
                            
                    except Exception as e:
                        print(f"[DAG Engine] AI Commander skipped due to error: {e}")

                    stage_start = time.monotonic()
                    state = self.stages[stage_name](state)
                    stage_duration = time.monotonic() - stage_start

                    # ── Phase timeout check ─────────────────────────
                    if stage_duration > phase_timeout:
                        print(f"[DAG Engine] WARNING: {stage_name} took {stage_duration:.1f}s (limit: {phase_timeout}s)")

                except Exception as e:
                    state.halt_execution = True
                    state.halt_reason = f"Exception in {stage_name}: {str(e)}"
                    print(f"[DAG Engine] FATAL ERROR: {state.halt_reason}")
                    break

        return state
