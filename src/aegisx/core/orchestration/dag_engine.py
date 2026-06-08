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
    unavailable_agents: List[str] = Field(default_factory=list)
    
    open_ports: List[int] = Field(default_factory=list)
    detected_services: List[str] = Field(default_factory=list)
    detected_technologies: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    authentication_methods: List[str] = Field(default_factory=list)
    
    routes: List[Dict[str, Any]] = Field(default_factory=list)
    api_endpoints: List[str] = Field(default_factory=list)
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    
    sessions: List[Dict[str, Any]] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    authenticated_routes: List[str] = Field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    
    validated_findings: List[Dict[str, Any]] = Field(default_factory=list)
    
    attack_surface_nodes: List[Dict[str, Any]] = Field(default_factory=list)
    attack_paths: List[List[str]] = Field(default_factory=list)
    explored_paths: List[str] = Field(default_factory=list)
    unexplored_paths: List[str] = Field(default_factory=list)
    
    serialized_graph: Dict[str, Any] = Field(default_factory=dict)
    graph_memory: Dict[str, Any] = Field(default_factory=dict)
    
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    consensus_scores: Dict[str, float] = Field(default_factory=dict)
    agent_scores: Dict[str, float] = Field(default_factory=dict)
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
    discovered_routes: List[Dict[str, Any]] = Field(default_factory=list)
    discovered_cookies: List[str] = Field(default_factory=list)
    session_behaviors: List[str] = Field(default_factory=list)
    technology_fingerprints: Dict[str, float] = Field(default_factory=dict)

    # ── Enterprise Recon Intelligence Fields ────────────────────────
    auth_surface: List[Dict[str, Any]] = Field(default_factory=list)
    authorization_matrix: List[Dict[str, Any]] = Field(default_factory=list)
    js_routes: List[Dict[str, Any]] = Field(default_factory=list)
    hidden_endpoints: List[str] = Field(default_factory=list)
    openapi_inventory: List[Dict[str, Any]] = Field(default_factory=list)
    graphql_inventory: List[Dict[str, Any]] = Field(default_factory=list)
    hidden_assets: List[Dict[str, Any]] = Field(default_factory=list)
    security_headers: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    state_transitions: List[Dict[str, Any]] = Field(default_factory=list)
    business_flows: List[Dict[str, Any]] = Field(default_factory=list)
    api_inventory: List[Dict[str, Any]] = Field(default_factory=list)
    recon_score: float = 0.0
    recon_complete: bool = False

    # ── Runtime Governance Fields ────────────────────────────────────
    scan_mode: str = "adaptive"
    
    # ── Enterprise Intelligence & Governance (Skills 86-115) ────────
    agent_health: Dict[str, Any] = Field(default_factory=dict)
    evidence_graph: Dict[str, Any] = Field(default_factory=dict)
    session_fingerprints: Dict[str, Any] = Field(default_factory=dict)
    api_behavior_map: Dict[str, Any] = Field(default_factory=dict)
    route_risk_score: Dict[str, Any] = Field(default_factory=dict)
    route_lineage: Dict[str, Any] = Field(default_factory=dict)
    parameter_lineage: Dict[str, Any] = Field(default_factory=dict)
    discovery_confidence: Dict[str, Any] = Field(default_factory=dict)
    last_surface_size: int = 0
    attack_surface_growth_score: int = 0
    prioritized_targets: List[str] = Field(default_factory=list)
    runtime_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    response_fingerprints: Dict[str, Any] = Field(default_factory=dict)
    cross_session_matrix: Dict[str, Any] = Field(default_factory=dict)
    evidence_chain: Dict[str, Any] = Field(default_factory=dict)
    force_expansion: bool = False
    recon_expansion_score: float = 0.0
    workflow_depth: int = 0
    max_workflow_depth: int = 5

    # ── Autonomous Runtime Intelligence (Skills 116-130) ────────────
    target_priority_scores: Dict[str, float] = Field(default_factory=dict)
    evidence_states: Dict[str, str] = Field(default_factory=dict)
    route_clusters: Dict[str, List[str]] = Field(default_factory=dict)
    parameter_relationship_graph: Dict[str, Any] = Field(default_factory=dict)
    session_trust_score: Dict[str, float] = Field(default_factory=dict)
    validation_success_rate: Dict[str, float] = Field(default_factory=dict)
    recon_intelligence_score: float = 0.0
    attack_path_scores: Dict[str, float] = Field(default_factory=dict)
    campaign_memory: Dict[str, Any] = Field(default_factory=dict)
    enterprise_audit_log: List[Dict[str, Any]] = Field(default_factory=list)

    # ── Autonomous Campaign Management (Skills 131-145) ─────────────
    campaign_strategy: str = "RECON_FOCUSED"
    ai_utilization_score: float = 100.0
    recon_depth_score: float = 0.0
    validation_queue: List[Dict[str, Any]] = Field(default_factory=list)
    session_behavior_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    ownership_baseline_evidence: Dict[str, Any] = Field(default_factory=dict)
    runtime_learning_base: Dict[str, Any] = Field(default_factory=dict)
    enterprise_metrics: Dict[str, Any] = Field(default_factory=dict)

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

    def calculate_recon_score(self) -> float:
        """Calculate recon completeness score (0.0 - 1.0)."""
        components = {
            "routes": min(len(self.routes) / 10.0, 1.0),
            "parameters": min(len(self.parameters) / 5.0, 1.0),
            "sessions": min(len(self.sessions) / 1.0, 1.0) if self.sessions else 0.0,
            "roles": min(len(self.roles) / 2.0, 1.0) if self.roles else 0.0,
            "api_inventory": min(len(self.api_inventory) / 5.0, 1.0),
            "auth_surface": min(len(self.auth_surface) / 2.0, 1.0),
        }
        self.recon_score = sum(components.values()) / len(components)
        self.recon_complete = self.recon_score >= 0.5
        return self.recon_score

    def check_vuln_gate(self, attack_type: str) -> dict:
        """Check if sufficient recon evidence exists to proceed with vulnerability testing."""
        gates = {
            "IDOR": len(self.routes) > 0 and len(self.parameters) > 0,
            "BOLA": len(self.routes) > 0 and len(self.parameters) > 0,
            "SSRF": len(self.routes) > 0,
            "XSS": len(self.routes) > 0 and len(self.parameters) > 0,
            "SQLi": len(self.routes) > 0 and len(self.parameters) > 0,
            "NoSQLi": len(self.routes) > 0 and len(self.parameters) > 0,
            "SSTI": len(self.routes) > 0 and len(self.parameters) > 0,
            "XXE": len(self.routes) > 0,
            "JWT": len(self.sessions) > 0 or len(self.extracted_tokens) > 0,
            "PromptInjection": len(self.routes) > 0,
        }
        allowed = gates.get(attack_type, len(self.routes) > 0)
        return {
            "attack_type": attack_type,
            "allowed": allowed,
            "reason": "EVIDENCE_SUFFICIENT" if allowed else "INSUFFICIENT_EVIDENCE",
            "recon_score": self.recon_score,
        }


class DAGOrchestrator:
    """
    Deterministic orchestration engine utilizing NetworkX to enforce
    strict sequential stage progression and state passing.

    Enhanced with per-phase timeouts and RuntimeGovernor integration.
    """
    def __init__(self):
        self.graph = nx.DiGraph()
        self.stages: Dict[str, Callable[[WorkflowState], WorkflowState]] = {}
        self._build_7_stage_dag()

    def _build_7_stage_dag(self):
        """Construct the 7-stage continuous deterministic execution model."""
        stages = [
            "STAGE_1_RECON",
            "STAGE_2_ATTACK_SURFACE",
            "STAGE_3_HYPOTHESIS",
            "STAGE_4_VALIDATION",
            "STAGE_5_SCORING",
            "STAGE_6_CORRELATION",
            "STAGE_7_NEXT_TARGET"
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
        
        continuous_mode = True
        loop_count = 0

        while continuous_mode and not state.halt_execution:
            loop_count += 1
            print(f"\\n[DAG Engine] === CONTINUOUS DISCOVERY LOOP {loop_count} ===")
            
            # Snapshots to detect if new evidence was found
            start_routes = len(state.routes)
            start_params = len(state.parameters)
            start_sessions = len(state.sessions)

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
            
            # Check if new evidence was found during this loop
            if not state.halt_execution:
                new_routes = len(state.routes) - start_routes
                new_params = len(state.parameters) - start_params
                new_sessions = len(state.sessions) - start_sessions
                
                if new_routes == 0 and new_params == 0 and new_sessions == 0:
                    print(f"[DAG Engine] Continuous Discovery exhausted. No new evidence found.")
                    continuous_mode = False
                else:
                    print(f"[DAG Engine] Loop {loop_count} complete. Found {new_routes} new routes, {new_params} new params, {new_sessions} new sessions. Looping back...")

        return state
