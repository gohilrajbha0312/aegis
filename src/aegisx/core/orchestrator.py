import time
from typing import Dict, Any

from aegisx.core.orchestration.dag_engine import DAGOrchestrator, WorkflowState
from aegisx.core.orchestration.stage_normalization import stage_1_normalization
from aegisx.analysis.fingerprinting.nmap_wrapper import stage_2_discovery as phase_3_network_enum
from aegisx.core.orchestration.stage_consensus import stage_11_consensus as phase_10_ai_correlation
from aegisx.analysis.intelligence.active_scanner import phase_12_active_scanning
from aegisx.analysis.vulnscan.scanner_orchestrator import phase_12b_web_vuln_suite

from aegisx.analysis.fingerprinting.httpx_wrapper import phase_4_http_intelligence
from aegisx.analysis.fingerprinting.whatweb_wrapper import phase_5_tech_fingerprinting
from aegisx.analysis.intelligence.js_api_parser import phase_7_js_intelligence, phase_8_api_boundary
from aegisx.analysis.auth.bola_engine import phase_9_auth_boundary
from aegisx.skills.registry import get_skill_registry

# Mock Stages
from aegisx.core.orchestration.stage_mocks import (
    phase_2_asset_discovery, phase_9_cloud_intelligence, phase_13_reporting
)

from aegisx.governance.policy.engine import GovernancePolicyEngine, GovernanceActionRequest, RiskLevel
from aegisx.core.taxonomy.vulnerability_taxonomy import GovernanceClass
from aegisx.governance.evidence.chain import ForensicEvidenceChain
from aegisx.governance.auth.session import AuthSessionManager
from aegisx.governance.approval.gateway import HumanApprovalGateway, OperatorRole, CryptographicSignature
from aegisx.core.analysis.attack_graph import ExposureGraph, NodeType, EdgeType
from aegisx.core.ui.console import ConsoleUI
from aegisx.core.runtime_governor import RuntimeGovernor, ScanMode
from aegisx.core import http_client
from aegisx.core.telemetry.tracer import TelemetryEngine

class AIOperationsOrchestrator:
    """
    Master orchestrator that binds the full 13-Phase Pipeline, 
    including AI, Governance, Consensus, and Evidence generation.
    """
    def __init__(self, scan_mode: ScanMode = ScanMode.ADAPTIVE_VALIDATION):
        self.policy_engine = GovernancePolicyEngine()
        self.evidence_chain = ForensicEvidenceChain(hmac_secret=b'mock-aegisx-secret')
        self.auth_manager = AuthSessionManager()
        
        # Setup Approval Gateway
        self.gateway_secret = b'mock-aegisx-secret'
        self.approval_gateway = HumanApprovalGateway(hmac_secret=self.gateway_secret)
        self.approval_gateway.register_operator("admin", OperatorRole(role_id="admin", permissions=["approve_all"]))
        
        self.telemetry = TelemetryEngine()
        
        # Initialize RuntimeGovernor with the chosen scan mode
        self.governor = RuntimeGovernor.instance()
        self.governor.set_mode(scan_mode)
        http_client.reset_request_counter()
        
        self._build_agent_registry()

    def _build_agent_registry(self):
        """Maps AI-requested agent names to their executing Python functions.
        
        Registry is organized by noise level:
        - LOW-NOISE: Preferred by default (semantic, JS parsing, header analysis)
        - MEDIUM-NOISE: Requires prior evidence from low-noise agents
        - HIGH-NOISE: Only under DEEP_ANALYSIS mode
        """
        self.registry = {
            # ── LOW-NOISE (Preferred) ────────────────────────────────
            "ContinuousReconLoopAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['ContinuousReconLoopAgent']).ContinuousReconLoopAgent().process(state)),
            "ReconAgent": phase_3_network_enum,                    # Single nmap scan
            "TrafficAnalyzerAgent": phase_4_http_intelligence,     # HTTP header intelligence
            "JSIntelligenceAgent": phase_7_js_intelligence,        # JS route extraction
            "APISurfaceAgent": phase_8_api_boundary,               # API schema discovery
            "SemanticDiscoveryAgent": phase_12b_web_vuln_suite,    # AI semantic analysis
            "AdaptiveValidationEngine": phase_12b_web_vuln_suite,  # AI adaptive validation
            "ValidationAgent": self._validation_wrapper,           # Finding validation
            "AuthAnalyzerAgent": phase_9_auth_boundary,            # Auth boundary analysis (low-noise)
            "EvidenceGraphAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.evidence_graph', fromlist=['EvidenceGraphAgent']).EvidenceGraphAgent().process(state)),
            "SessionIsolationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.session_isolation', fromlist=['SessionIsolationAgent']).SessionIsolationAgent().process(state)),
            "RouteOwnershipAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.session_isolation', fromlist=['RouteOwnershipAgent']).RouteOwnershipAgent().process(state)),
            "DifferentialResponseAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.session_isolation', fromlist=['DifferentialResponseAgent']).DifferentialResponseAgent().process(state)),
            
            # ── ENTERPRISE RECON & MEMORY (Skills 88, 89, 92, 102, 103, 104, 106, 113) ────────
            "RuntimeMemoryAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.state_compression', fromlist=['RuntimeMemoryAgent']).RuntimeMemoryAgent().process(state)),
            "ReconExpansionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['ReconExpansionAgent']).ReconExpansionAgent().process(state)),
            "RouteRiskScoringAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['RouteRiskScoringAgent']).RouteRiskScoringAgent().process(state)),
            "RouteLineageAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['RouteLineageAgent']).RouteLineageAgent().process(state)),
            "ParameterLineageAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['ParameterLineageAgent']).ParameterLineageAgent().process(state)),
            "DiscoveryConfidenceAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['DiscoveryConfidenceAgent']).DiscoveryConfidenceAgent().process(state)),
            "AttackSurfaceGrowthAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['AttackSurfaceGrowthAgent']).AttackSurfaceGrowthAgent().process(state)),
            "ReconBudgetOptimizerAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.recon_coverage', fromlist=['ReconBudgetOptimizerAgent']).ReconBudgetOptimizerAgent().process(state)),
            
            # ── ENTERPRISE BEHAVIOR & CORRELATION (Skills 90, 91, 98, 105, 108, 111) 
            "SessionFingerprintAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.session_isolation', fromlist=['SessionFingerprintAgent']).SessionFingerprintAgent().process(state)),
            "MultiSessionCorrelationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.session_isolation', fromlist=['MultiSessionCorrelationAgent']).MultiSessionCorrelationAgent().process(state)),
            "APIBehaviorAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.api_behavior', fromlist=['APIBehaviorAgent']).APIBehaviorAgent().process(state)),
            "ResponseFingerprintAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.api_behavior', fromlist=['ResponseFingerprintAgent']).ResponseFingerprintAgent().process(state)),
            "RuntimeAnomalyAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.api_behavior', fromlist=['RuntimeAnomalyAgent']).RuntimeAnomalyAgent().process(state)),
            "AttackPathCorrelationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.evidence_graph', fromlist=['AttackPathCorrelationAgent']).AttackPathCorrelationAgent().process(state)),
            
            # ── ENTERPRISE VALIDATION TRUST & CONFLICT (Skills 101, 112) ──
            "EvidenceTrustAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.validation', fromlist=['EvidenceTrustAgent']).EvidenceTrustAgent().process(state)),
            "EvidenceConflictAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.validation', fromlist=['EvidenceConflictAgent']).EvidenceConflictAgent().process(state)),
            
            # ── ENTERPRISE GOVERNANCE & COMPLETION (Skills 86-100, 109, 110, 115) ────────────────
            "AgentHealthAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.enterprise_governance', fromlist=['AgentHealthAgent']).AgentHealthAgent().process(state)),
            "AgentSchedulerAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.enterprise_governance', fromlist=['AgentSchedulerAgent']).AgentSchedulerAgent().process(state)),
            "RuntimeGovernanceAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.enterprise_governance', fromlist=['RuntimeGovernanceAgent']).RuntimeGovernanceAgent().process(state)),
            "AttackPathExpansionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.evidence_graph', fromlist=['AttackPathExpansionAgent']).AttackPathExpansionAgent().process(state)),
            "AgentConsensusAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.enterprise_governance', fromlist=['AgentConsensusAgent']).AgentConsensusAgent().process(state)),
            "CampaignCompletionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.enterprise_governance', fromlist=['CampaignCompletionAgent']).CampaignCompletionAgent().process(state)),
            
            # ── NEW EXTENSION AGENTS (Skills 146-150) ────────────────
            "GraphQLExpansionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.graphql_expansion', fromlist=['GraphQLExpansionAgent']).GraphQLExpansionAgent().process(state)),
            "RouteCoverageAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.route_coverage', fromlist=['RouteCoverageAgent']).RouteCoverageAgent().process(state)),
            "SessionValidationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.session_validation', fromlist=['SessionValidationAgent']).SessionValidationAgent().process(state)),
            "TokenAnalysisAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.token_analysis', fromlist=['TokenAnalysisAgent']).TokenAnalysisAgent().process(state)),
            "PriceManipulationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.price_manipulation', fromlist=['PriceManipulationAgent']).PriceManipulationAgent().process(state)),
            
            # ── AUTONOMOUS RUNTIME INTELLIGENCE (Skills 116-130) ─────────────────────────
            "TargetPrioritizationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['TargetPrioritizationAgent']).TargetPrioritizationAgent().process(state)),
            "EvidenceLifecycleAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['EvidenceLifecycleAgent']).EvidenceLifecycleAgent().process(state)),
            "RouteClusteringAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['RouteClusteringAgent']).RouteClusteringAgent().process(state)),
            "ParameterRelationshipAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['ParameterRelationshipAgent']).ParameterRelationshipAgent().process(state)),
            "SessionTrustAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['SessionTrustAgent']).SessionTrustAgent().process(state)),
            "ValidationStabilityAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['ValidationStabilityAgent']).ValidationStabilityAgent().process(state)),
            "ResourceEfficiencyAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['ResourceEfficiencyAgent']).ResourceEfficiencyAgent().process(state)),
            "ReconIntelligenceAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['ReconIntelligenceAgent']).ReconIntelligenceAgent().process(state)),
            "EvidenceAgingAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['EvidenceAgingAgent']).EvidenceAgingAgent().process(state)),
            "AttackPathScoringAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['AttackPathScoringAgent']).AttackPathScoringAgent().process(state)),
            "MultiAgentConflictResolutionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['MultiAgentConflictResolutionAgent']).MultiAgentConflictResolutionAgent().process(state)),
            "CampaignMemoryAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['CampaignMemoryAgent']).CampaignMemoryAgent().process(state)),
            "EnterpriseAuditAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['EnterpriseAuditAgent']).EnterpriseAuditAgent().process(state)),
            "ReportingGovernanceAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['ReportingGovernanceAgent']).ReportingGovernanceAgent().process(state)),
            "AutonomousDecisionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.runtime_intelligence', fromlist=['AutonomousDecisionAgent']).AutonomousDecisionAgent().process(state)),
            
            # ── AUTONOMOUS CAMPAIGN MANAGEMENT (Skills 131-145) ──────────────────────────
            "CampaignStrategyAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['CampaignStrategyAgent']).CampaignStrategyAgent().process(state)),
            "AIUtilizationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['AIUtilizationAgent']).AIUtilizationAgent().process(state)),
            "DynamicModelSelectionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['DynamicModelSelectionAgent']).DynamicModelSelectionAgent().process(state)),
            "HypothesisQualityAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['HypothesisQualityAgent']).HypothesisQualityAgent().process(state)),
            "ReconDepthAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['ReconDepthAgent']).ReconDepthAgent().process(state)),
            "AttackSurfaceDriftAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['AttackSurfaceDriftAgent']).AttackSurfaceDriftAgent().process(state)),
            "ValidationQueueAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['ValidationQueueAgent']).ValidationQueueAgent().process(state)),
            "SessionBehaviorAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['SessionBehaviorAgent']).SessionBehaviorAgent().process(state)),
            "RouteOwnershipVerificationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['RouteOwnershipVerificationAgent']).RouteOwnershipVerificationAgent().process(state)),
            "EvidenceCompressionAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['EvidenceCompressionAgent']).EvidenceCompressionAgent().process(state)),
            "RuntimeLearningAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['RuntimeLearningAgent']).RuntimeLearningAgent().process(state)),
            "ConsensusGovernanceAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['ConsensusGovernanceAgent']).ConsensusGovernanceAgent().process(state)),
            "AutonomousRecoveryAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['AutonomousRecoveryAgent']).AutonomousRecoveryAgent().process(state)),
            "EnterpriseMetricsAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['EnterpriseMetricsAgent']).EnterpriseMetricsAgent().process(state)),
            "CampaignTerminationAgent": lambda state: __import__('asyncio').run(__import__('aegisx.agents.campaign_management', fromlist=['CampaignTerminationAgent']).CampaignTerminationAgent().process(state)),
            
            # ── VULNERABILITY REASONING SKILLS (Zero/Low Noise) ──────
            "AuthorizationReasoningSkill": lambda state: get_skill_registry().execute_skill("authorization_reasoning", state),
            "AuthenticationReasoningSkill": lambda state: get_skill_registry().execute_skill("authentication_reasoning", state),
            "ClientSideReasoningSkill": lambda state: get_skill_registry().execute_skill("client_side_reasoning", state),
            "APIIntelligenceSkill": lambda state: get_skill_registry().execute_skill("api_intelligence", state),
            "SecurityConfigReasoningSkill": lambda state: get_skill_registry().execute_skill("security_config_reasoning", state),
            "DataExposureReasoningSkill": lambda state: get_skill_registry().execute_skill("data_exposure_reasoning", state),
            "ErrorAnalysisReasoningSkill": lambda state: get_skill_registry().execute_skill("error_analysis_reasoning", state),
            
            # ── MEDIUM-NOISE (Evidence Required) ─────────────────────
            "WebCrawlerAgent": self._intelligent_route_discovery,  # Intelligent crawl (NOT brute-force)
            "ActiveScanner": phase_12_active_scanning,             # Active scanning
            "ExploitationAgent": phase_10_ai_correlation,          # Exploit correlation
            "ReportingAgent": self._phase_13_reporting_wrapper,    # Reporting
            
            # ── TECH FINGERPRINTING ──────────────────────────────────
            "TechFingerprintAgent": phase_5_tech_fingerprinting,   # WhatWeb fingerprinting
            
            # ── VULNERABILITY DISCOVERY AGENTS ───────────────────────
            "SurgicalMutationAgent": self._surgical_mutation_wrapper,
            "SemanticMutationAgent": self._surgical_mutation_wrapper,
            "DifferentialAccessAgent": self._differential_access_wrapper,
            "OwnershipValidationAgent": self._differential_access_wrapper, # Temporarily share the differential wrapper for both
            "ApplicationFlowIntelligenceAgent": phase_12b_web_vuln_suite,
            "ResponseClusteringAgent": self._response_clustering_wrapper,
            "StateTransitionAnalyzer": self._state_transition_wrapper,
            "AttackGraphIntelligenceAgent": self._attack_graph_wrapper,
            "LoginDetectionAgent": self._login_detection_wrapper,
            
            # ── CONTINUOUS DISCOVERY AGENTS ──────────────────────────
            "ConfidenceScoringAgent": self._confidence_scoring_wrapper,
            "FindingCorrelationAgent": self._finding_correlation_wrapper,
            "NextTargetAgent": self._next_target_wrapper,
        }
        
    def _login_detection_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.login_detection import LoginDetectionAgent
        import asyncio
        agent = LoginDetectionAgent()
        try:
            state_dict = state.model_dump()
            new_state = asyncio.run(agent.process(state_dict))
            state.sessions = new_state.get("sessions", state.sessions)
            state.roles = new_state.get("roles", state.roles)
            state.authenticated_routes = new_state.get("authenticated_routes", state.authenticated_routes)
            state.routes = new_state.get("routes", state.routes)
        except Exception as e:
            ConsoleUI.warning(f"Login Detection skipped: {e}")
        return state

    def _confidence_scoring_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.confidence_scoring import ConfidenceScoringAgent
        import asyncio
        agent = ConfidenceScoringAgent()
        try:
            new_state = asyncio.run(agent.process(state.model_dump()))
            state.findings = new_state.get("scored_findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"Confidence Scoring skipped: {e}")
        return state

    def _ai_validation_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.validation import ValidationConsensusAgent, EvidenceReplayAgent, EvidenceTrustAgent, EvidenceConflictAgent
        import asyncio
        
        # SKILL 101: EvidenceTrustAgent
        agent_trust = EvidenceTrustAgent()
        try:
            new_state = asyncio.run(agent_trust.process(state.model_dump()))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"EvidenceTrust skipped: {e}")
            
        # SKILL 93/107: EvidenceReplayAgent
        agent1 = EvidenceReplayAgent()
        try:
            new_state = asyncio.run(agent1.process(state.model_dump()))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"EvidenceReplay skipped: {e}")
            
        agent2 = ValidationConsensusAgent()
        try:
            new_state = asyncio.run(agent2.process(state.model_dump()))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"AI Validation Consensus skipped: {e}")
            
        # SKILL 112: EvidenceConflictAgent
        agent_conflict = EvidenceConflictAgent()
        try:
            new_state = asyncio.run(agent_conflict.process(state.model_dump()))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"EvidenceConflict skipped: {e}")
            
        return state

    def _finding_correlation_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.finding_correlation import FindingCorrelationAgent
        import asyncio
        agent = FindingCorrelationAgent()
        try:
            new_state = asyncio.run(agent.process(state.model_dump()))
            state.findings = new_state.get("correlated_findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"Finding Correlation skipped: {e}")
        return state

    def _next_target_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.next_target import NextTargetAgent
        import asyncio
        agent = NextTargetAgent()
        try:
            new_state = asyncio.run(agent.process(state.model_dump()))
            state.analyzed_routes = new_state.get("analyzed_routes", state.analyzed_routes)
            state.target = new_state.get("next_target", state.target)
        except Exception as e:
            ConsoleUI.warning(f"Next Target Selection skipped: {e}")
        return state
        
    def validate_registry(self, state: WorkflowState) -> WorkflowState:
        """Validates all agents in registry before execution pool."""
        ConsoleUI.info("Validating Agent Registry...")
        unavailable = []
        for name, func in self.registry.items():
            if not callable(func):
                ConsoleUI.warning(f"Agent '{name}' is not callable. Marking unavailable.")
                unavailable.append(name)
        
        state.unavailable_agents = unavailable
        if unavailable:
            ConsoleUI.warning(f"Removed {len(unavailable)} broken agents from scheduling pool.")
        else:
            ConsoleUI.success("All registered agents are valid and available.")
        return state
        
    def _resolve_agent(self, action: str):
        """Attempts to match an AI's string output to an actual agent in the registry."""
        action_lower = action.lower()
        for key, func in self.registry.items():
            if key.lower() in action_lower:
                return func
        return None


    def _intelligent_route_discovery(self, state: WorkflowState) -> WorkflowState:
        """Low-noise route discovery: JS intelligence + API schema instead of brute-force."""
        ConsoleUI.header("INTELLIGENT ROUTE DISCOVERY (Low-Noise)")
        ConsoleUI.info("Using JS parsing + API schema analysis instead of brute-force fuzzing.")
        
        # Step 1: Extract routes from JavaScript bundles
        state = phase_7_js_intelligence(state)
        
        # Step 2: Discover API schemas (OpenAPI, GraphQL)
        state = phase_8_api_boundary(state)
        
        # Step 3: Extract and store discovered routes into state
        for item in state.evidence_ledger:
            if item.get("stage") == "PHASE_7_JS_INTELLIGENCE":
                result = item.get("result", {})
                for ep in result.get("discovered_endpoints", []):
                    if ep and ep not in state.routes:
                        state.routes.append(ep)
            elif item.get("stage") == "PHASE_8_API_BOUNDARY":
                result = item.get("result", {})
                if result.get("graphql_detected") and "/graphql" not in state.api_endpoints:
                    state.api_endpoints.append("/graphql")
                    state.detected_technologies.append("GraphQL")
                if result.get("swagger_detected") and "/swagger" not in state.api_endpoints:
                    state.api_endpoints.append("/swagger/v1/swagger.json")
        
        ConsoleUI.success(f"Discovered {len(state.routes)} routes and {len(state.api_endpoints)} API endpoints via low-noise methods.")
        return state

    def _validation_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.validation import ValidationAgent
        import asyncio
        ConsoleUI.header("AI Vulnerability Validation")
        if not state.findings:
            ConsoleUI.info("No findings to validate.")
            return state
        agent = ValidationAgent()
        try:
            new_state = asyncio.run(agent.process({"findings": state.findings}))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"Validation skipped: {e}")
        return state

    def _surgical_mutation_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.surgical_mutation import SurgicalMutationAgent
        import asyncio
        ConsoleUI.header("AI Surgical Parameter Mutation")
        
        agent = SurgicalMutationAgent()
        try:
            new_state = asyncio.run(agent.process({"target": state.target, "routes": state.routes, "api_endpoints": state.api_endpoints, "findings": state.findings}))
            # Update findings if any new ones were discovered
            if "findings" in new_state:
                for new_finding in new_state["findings"]:
                    if new_finding not in state.findings:
                        state.findings.append(new_finding)
        except Exception as e:
            ConsoleUI.warning(f"Surgical Mutation skipped: {e}")
        return state

    def _differential_access_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.differential_access import DifferentialAccessAgent
        import asyncio
        ConsoleUI.header("AI Differential Access Validation")
        agent = DifferentialAccessAgent()
        try:
            # PydanticAI/LangGraph state dictionary adaptation
            state_dict = {"routes": state.routes, "findings": state.findings, "target": state.target}
            new_state = asyncio.run(agent.process(state_dict))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"Differential Access skipped: {e}")
        return state

    def _response_clustering_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.response_clustering import ResponseClusteringAgent
        import asyncio
        agent = ResponseClusteringAgent()
        try:
            state_dict = {"routes": state.routes, "findings": state.findings, "evidence_ledger": state.evidence_ledger}
            new_state = asyncio.run(agent.process(state_dict))
            state.evidence_ledger = new_state.get("evidence_ledger", state.evidence_ledger)
        except Exception as e:
            ConsoleUI.warning(f"Response Clustering skipped: {e}")
        return state

    def _state_transition_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.state_transition import StateTransitionAnalyzer
        import asyncio
        agent = StateTransitionAnalyzer()
        try:
            state_dict = {"routes": state.routes, "findings": state.findings}
            new_state = asyncio.run(agent.process(state_dict))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"State Transition Analysis skipped: {e}")
        return state

    def _attack_graph_wrapper(self, state: WorkflowState) -> WorkflowState:
        from aegisx.agents.attack_graph_agent import AttackGraphIntelligenceAgent
        import asyncio
        agent = AttackGraphIntelligenceAgent()
        try:
            state_dict = state.model_dump()
            new_state = asyncio.run(agent.process(state_dict))
            state.graph_mutation = new_state.get("graph_mutation")
        except Exception as e:
            ConsoleUI.warning(f"Attack Graph Intelligence skipped: {e}")
        return state

    def _phase_11_governance_wrapper(self, state: WorkflowState) -> WorkflowState:
        """Phase 15: Summarize findings. No blocking in pen testing mode."""
        ConsoleUI.info("Summarizing Attack Surface Intelligence...")

        if not state.findings:
            ConsoleUI.warning("No findings correlated yet.")
            return state

        for finding in state.findings:
            risk = finding.get("risk_level", "LOW")
            ftype = finding.get("finding_type", "Unknown")
            conf = finding.get("consensus_score", finding.get("base_confidence", 0.0))
            gov = finding.get("governance_class", "PASSIVE_ANALYSIS")
            ConsoleUI.success(f"[{risk}] {ftype}  |  Confidence: {conf:.2f}  |  Class: {gov}")

        # Render rich findings table
        ConsoleUI.finding_table(state.findings)

        return state


    def _phase_12_evidence_wrapper(self, state: WorkflowState) -> WorkflowState:
        """Explicit wrapper for Phase 12 to flush to ForensicEvidenceChain."""
        ConsoleUI.info(f"Executing Phase 12: Hashing and signing evidence chain")
        for item in state.evidence_ledger:
            self.evidence_chain.capture_evidence(
                workflow_id=state.workflow_id,
                content={
                    "stage": item['stage'],
                    "data": str(item.get('result', '')),
                    "actor": "SystemOrchestrator"
                }
            )
        is_valid = self.evidence_chain.verify_chain()
        ConsoleUI.success(f"Evidence Chain Integrity Valid: {is_valid}")
        ConsoleUI.success(f"Committed {len(self.evidence_chain._chain)} cryptographic blocks.")
        return state

    def _phase_13_reporting_wrapper(self, state: WorkflowState) -> WorkflowState:
        """Explicit wrapper for Phase 13 to build and export the Exposure Graph."""
        import asyncio
        ConsoleUI.info(f"Executing Phase 13: Generating Attack Surface Graph & Reporting")
        
        if not state.findings:
            ConsoleUI.warning("No findings found to generate graph.")
            return state
            
        graph_engine = ExposureGraph()
        
        # Deterministic Structural Node Generation
        for r in state.routes:
            route_path = r.get("path", str(r)) if isinstance(r, dict) else str(r)
            graph_engine.add_node(f"route:{route_path}", NodeType.APPLICATION_ROUTE, {"path": route_path})
        for p in state.parameters:
            param_name = p.get("name", str(p)) if isinstance(p, dict) else str(p)
            graph_engine.add_node(f"param:{param_name}", NodeType.EXTERNAL_ASSET, {"name": param_name})
        for s in getattr(state, "sessions", []):
            sess_id = s.get("id", str(s)) if isinstance(s, dict) else str(s)
            graph_engine.add_node(f"session:{sess_id}", NodeType.EXTERNAL_ASSET, {"session_id": sess_id})
            
        # Populate Graph from AI Findings
        for finding in state.findings:
            nodes = finding.get("nodes", [])
            edges = finding.get("edges", [])
            
            for n in nodes:
                try:
                    node_type = NodeType(n['node_type'])
                except ValueError:
                    node_type = NodeType.POTENTIAL_WEAKNESS
                graph_engine.add_node(n['node_id'], node_type, n.get('properties', {}))
                
            for e in edges:
                try:
                    edge_type = EdgeType(e['edge_type'])
                except ValueError:
                    edge_type = EdgeType.TRUSTS
                graph_engine.add_edge(e['source_id'], e['target_id'], edge_type)
        
        # Export Graph
        import os
        import json
        
        os.makedirs("reports", exist_ok=True)
        graphml_path = f"reports/attack_graph_{state.workflow_id}.graphml"
        json_path = f"reports/attack_graph_{state.workflow_id}.json"
        
        if graph_engine.graph.number_of_nodes() > 0:
            graph_engine.export_graphml(graphml_path)
            with open(json_path, 'w') as f:
                json.dump(graph_engine.to_dict(), f, indent=4)
                
            ConsoleUI.success(f"Graph generated with {graph_engine.graph.number_of_nodes()} nodes and {graph_engine.graph.number_of_edges()} edges.")
            ConsoleUI.success(f"Graph exported to: {graphml_path}")
            
            # Print simple path analysis
            ConsoleUI.header("Lateral Movement Risk Model")
            for n in graph_engine.graph.nodes():
                if graph_engine.graph.nodes[n].get("node_type") == NodeType.EXTERNAL_ASSET.value:
                    paths = graph_engine.get_lateral_paths(n, NodeType.CLOUD_RESOURCE)
                    if paths:
                        ConsoleUI.warning(f"Found {len(paths)} potential escalation paths from {n} to Cloud Resources.")
                        for p in paths:
                            print(f"      {' -> '.join(p)}")
        else:
            ConsoleUI.warning("Graph engine initialized but no nodes were correlated.")

        # Phase 12: Evidence Correlation Graph
        from aegisx.agents.evidence_graph import EvidenceGraphAgent, EvidenceChainIntegrityAgent
        ConsoleUI.header("PHASE 12: EVIDENCE CORRELATION & CHAIN INTEGRITY")
        try:
            agent = EvidenceGraphAgent()
            new_state = asyncio.run(agent.process(state.model_dump()))
            state.findings = new_state.get("findings", state.findings)
            state.evidence_graph = new_state.get("evidence_graph", state.evidence_graph)
            
            # SKILL 95: EvidenceChainIntegrityAgent
            integrity_agent = EvidenceChainIntegrityAgent()
            new_state = asyncio.run(integrity_agent.process(state.model_dump()))
            state.findings = new_state.get("findings", state.findings)
        except Exception as e:
            ConsoleUI.warning(f"Phase 12 (Evidence Graph) failed: {e}")
            
        # Phase 13: Enterprise Report Generation
        ConsoleUI.header("PHASE 13: ENTERPRISE REPORTING")
        
        # SKILL 114: EnterpriseReportIntegrityAgent
        ConsoleUI.info("[EnterpriseReportIntegrityAgent] Enforcing global reporting standard (Evidence, Replay, Validation, Confidence >= 80).")
        validated = []
        rejected = 0
        for f in state.findings:
            conf = f.get('confidence', 0) if isinstance(f, dict) else getattr(f, 'confidence', 0)
            if conf >= 80:
                ev_str = str(f.get("evidence", [])).lower()
                if "replay" in ev_str and "differential" in ev_str:
                    validated.append(f)
                else:
                    rejected += 1
                    ConsoleUI.warning(f"Finding rejected by EnterpriseReportIntegrityAgent: Missing Replay/Differential evidence.")
            else:
                rejected += 1
                
        if rejected > 0:
            ConsoleUI.warning(f"[EnterpriseReportIntegrityAgent] Stripped {rejected} unvalidated hypotheses from final report.")
        state.findings = validated
        
        from aegisx.core.reporting.pdf_reporter import PDFReportGenerator
        try:
            reporter = PDFReportGenerator(output_dir="reports")
            pdf_path = reporter.generate(
                workflow_id=state.workflow_id,
                target=state.target,
                findings=state.findings,
                evidence_ledger=state.evidence_ledger
            )
            if pdf_path:
                ConsoleUI.success(f"PDF Report generated: {pdf_path}")
        except Exception as e:
            ConsoleUI.warning(f"PDF generation failed: {e}")

        return state



    def execute_campaign(self, target: str) -> WorkflowState:
        """Kicks off the fully autonomous AI-driven dynamic loop."""
        import asyncio
        from aegisx.agents.commander import CommanderAgent
        
        ConsoleUI.header("AEGIS-X AUTONOMOUS DYNAMIC WORKFLOW")
        
        # Display governor status
        gov_status = self.governor.status_summary()
        ConsoleUI.info(f"Scan Mode: {gov_status['scan_mode'].upper()}")
        ConsoleUI.info(f"Request Budget: {gov_status['max_requests']} | Rate: {gov_status['max_rps']} req/s")
        ConsoleUI.info(f"Phase Timeout: {gov_status['phase_timeout']}s | Max Scanners: {gov_status['max_scanners']}")
        
        state = WorkflowState(
            target=target,
            scan_mode=self.governor.mode.value,
        )
        # Force initial normalization
        state = stage_1_normalization(state)
        
        # Pre-execution validation
        state = self.validate_registry(state)
        
        commander = CommanderAgent()
        import time
        start_time = time.time()
        
        max_iterations = 15
        iteration = 0
        is_complete = False
        
        # State tracking for Methodology Pivot Engine
        phase_history = []
        last_findings_count = len(state.findings)
        last_evidence_count = len(state.evidence_ledger)
        last_route_count = len(state.discovered_routes) + len(state.routes)
        
        while iteration < max_iterations and not is_complete:
            iteration += 1
            ConsoleUI.header(f"Autonomous Loop Iteration: {iteration}/{max_iterations}")
            
            # 1. Consult AI Commander
            ConsoleUI.info("Consulting AI Commander for next actions...")
            try:
                # SKILL 87: Pre-filter agents
                from aegisx.agents.enterprise_governance import AgentSchedulerAgent
                state_dict = state.model_dump()
                state_dict = asyncio.run(AgentSchedulerAgent().process(state_dict))
                
                # Provide the entire state object so AI sees graphs, paths, history

                
                llm_start = time.time()
                pipeline_result = asyncio.run(commander.process(state_dict))
                llm_duration = time.time() - llm_start
                ConsoleUI.info(f"LLM Reasoning Latency: {llm_duration:.2f}s")
                
                if pipeline_result["status"] == "WAITING_FOR_APPROVAL":
                    ConsoleUI.warning("HITL Approval Required. Auto-approving for this session.")
                
                pipeline = pipeline_result["pipeline"]
                next_actions_objects = pipeline.get("next_actions", [])
                
                # Extract agent names from the structured AgentAction objects
                next_actions = [action.get("agent") for action in next_actions_objects if action.get("agent")]
                
                reasoning = pipeline.get("reasoning", "No reasoning provided.")
                is_complete = pipeline.get("is_complete", False)
                workflow_phase = pipeline.get("workflow_phase", "Unknown")
                methodology_pivot = pipeline.get("methodology_pivot", "")
                attack_graph_updates = pipeline.get("attack_graph_updates", [])
                
                ConsoleUI.success(f"[AI Phase] {workflow_phase}")
                ConsoleUI.success(f"[AI Commander] Reasoning: {reasoning}")
                
                # ── Methodology Pivot Engine & Agent Scoring ──
                current_findings_count = len(state.findings)
                current_evidence_count = len(state.evidence_ledger)
                current_route_count = len(state.discovered_routes) + len(state.routes)
                
                findings_gained = current_findings_count - last_findings_count
                evidence_gained = current_evidence_count - last_evidence_count
                routes_gained = current_route_count - last_route_count
                
                last_findings_count = current_findings_count
                last_evidence_count = current_evidence_count
                last_route_count = current_route_count
                
                phase_history.append(workflow_phase)
                # If we've been in the same phase for 3 iterations with no new findings or evidence, force pivot
                if len(phase_history) >= 3 and all(p == workflow_phase for p in phase_history[-3:]):
                    if findings_gained == 0 and evidence_gained == 0 and not methodology_pivot:
                        ConsoleUI.warning(f"Stall Detected: 3 iterations in {workflow_phase} with 0 new evidence/findings.")
                        ConsoleUI.warning("Forcing Methodology Pivot...")
                        methodology_pivot = "AUTO-PIVOT: Previous methodology yielded no results. Analyze attack graph for unexplored nodes and select a new methodology."
                        phase_history.clear() # Reset pivot tracker
                
                if methodology_pivot:
                    ConsoleUI.success(f"[AI Pivot] {methodology_pivot}")
                
                ConsoleUI.success(f"[AI Commander] Scheduled Actions: {', '.join(next_actions)}")
                
                if attack_graph_updates:
                    ConsoleUI.info(f"[AI Graph] Generated {len(attack_graph_updates)} graph updates.")
                    for update in attack_graph_updates:
                        state.attack_surface_nodes.append(update)
                
                if is_complete:
                    ConsoleUI.success("AI Commander has declared the campaign complete.")
                    break
                    
                # 2. Execute Dynamic Actions
                executed_this_loop = set()
                for action in next_actions:
                    if action in executed_this_loop:
                        continue # Prevent duplicate runs in the same loop
                        
                    # ── Duplicate Action Prevention ──
                    if action in state.completed_agents[-3:] and not methodology_pivot:
                        state.repeated_results_counter[action] = state.repeated_results_counter.get(action, 0) + 1
                        if state.repeated_results_counter[action] > 2:
                            ConsoleUI.warning(f"Duplicate Action Prevention: Skipping '{action}' (repeated > 2 times, penalizing).")
                            continue
                        ConsoleUI.warning(f"Duplicate Action Prevention: Skipping '{action}' (recently executed, no pivot declared).")
                        continue
                        
                    agent_func = self._resolve_agent(action)
                    if agent_func:
                        ConsoleUI.info(f"Executing: {action}")
                        try:
                            state = agent_func(state)
                            executed_this_loop.add(action)
                            state.completed_agents.append(action)
                            state.execution_history.append(action)
                            
                            # SKILL 86: Track Health
                            if not hasattr(state, 'agent_health') or not isinstance(getattr(state, 'agent_health', None), dict):
                                state.agent_health = {}
                            stats = state.agent_health.setdefault(action, {"executions": 0, "failures": 0})
                            stats["executions"] += 1
                            
                            # Agent Effectiveness Scoring for single execution
                            _post_findings = len(state.findings)
                            _post_evidence = len(state.evidence_ledger)
                            _post_routes = len(state.discovered_routes) + len(state.routes)
                            
                            _f_gain = _post_findings - current_findings_count
                            _e_gain = _post_evidence - current_evidence_count
                            _r_gain = _post_routes - current_route_count
                            
                            agent_score = _f_gain + _e_gain + _r_gain
                            state.agent_scores[action] = state.agent_scores.get(action, 0.0) + agent_score
                            
                            if agent_score == 0:
                                state.repeated_results_counter[action] = state.repeated_results_counter.get(action, 0) + 1
                                if state.repeated_results_counter[action] >= 3 and action not in state.unavailable_agents:
                                    ConsoleUI.warning(f"Agent '{action}' yielded 0 value for 3 iterations. Disabling temporarily.")
                                    state.unavailable_agents.append(action)
                            else:
                                state.repeated_results_counter[action] = 0
                                
                            # Update currents for next agent in this loop
                            current_findings_count = _post_findings
                            current_evidence_count = _post_evidence
                            current_route_count = _post_routes
                            
                        except Exception as e:
                            ConsoleUI.error(f"Error executing {action}: {e}")
                            if not hasattr(state, 'agent_health') or not isinstance(getattr(state, 'agent_health', None), dict):
                                state.agent_health = {}
                            stats = state.agent_health.setdefault(action, {"executions": 0, "failures": 0})
                            stats["executions"] += 1
                            stats["failures"] += 1
                    else:
                        # Ignore booleans or weird reasoning strings accidentally passed as actions
                        if str(action).lower() not in ['true', 'false'] and "reasoning" not in str(action).lower():
                            ConsoleUI.warning(f"Agent '{action}' requested by AI but not found in registry. Skipping.")
                
                # Post-loop Governance (Skills 86 & 100)
                from aegisx.agents.enterprise_governance import AgentHealthAgent, RuntimeGovernanceAgent
                state_dict = state.model_dump()
                state_dict = asyncio.run(AgentHealthAgent().process(state_dict))
                state_dict = asyncio.run(RuntimeGovernanceAgent().process(state_dict))
                state.unavailable_agents = state_dict.get("unavailable_agents", state.unavailable_agents)
                state.agent_health = state_dict.get("agent_health", state.agent_health)
                
                # Apply strictly governed findings
                gov_findings = state_dict.get("findings", [])
                if len(gov_findings) < len(state.findings):
                    state.findings = [f for f in state.findings if f in gov_findings or getattr(f, 'title', None) in [x.get('title') for x in gov_findings]]
                        
            except Exception as e:
                ConsoleUI.error(f"AI Commander execution failed: {e}")
                state.halt_execution = True
                state.halt_reason = str(e)
                break
                
                if state.halt_reason:
                    break
                    
            # ── Correlate Evidence ──
            try:
                from aegisx.core.analysis.evidence_correlation import EvidenceCorrelationEngine
                state_dict = state.model_dump()
                state_dict = EvidenceCorrelationEngine.correlate(state_dict)
                state.findings = state_dict.get("findings", state.findings)
                state.consensus_scores = state_dict.get("consensus_scores", state.confidence_scores)
            except Exception as e:
                ConsoleUI.warning(f"Evidence Correlation failed: {e}")
                
            # ── AI Graph Learning ──
            try:
                if hasattr(state, "graph_mutation") and state.graph_mutation:
                    from aegisx.core.analysis.graph_learning import GraphLearningEngine
                    state_dict = state.model_dump()
                    state_dict = GraphLearningEngine.apply_learning(state_dict)
                    
                    state.serialized_graph = state_dict.get("serialized_graph", state.serialized_graph)
                    state.graph_memory = state_dict.get("graph_memory", state.graph_memory)
                    state.attack_paths = state_dict.get("attack_paths", state.attack_paths)
                    
                    # Clean up mutation so it doesn't leak to next iteration
                    state.graph_mutation = None
            except Exception as e:
                ConsoleUI.warning(f"Graph Learning failed: {e}")
                
            if state.halt_execution:
                break
                
        # Finalization
        ConsoleUI.header("Finalizing Autonomous Workflow")
        self._phase_11_governance_wrapper(state)
        self._phase_12_evidence_wrapper(state)
        self._phase_13_reporting_wrapper(state)
        
        duration = time.time() - start_time
        ConsoleUI.header(f"Execution Completed in {duration:.2f}s")
        print(f" Workflow ID: {state.workflow_id}")
        print(f" Requests Used: {http_client.get_request_count()}/{gov_status['max_requests']}")
        print(f" Findings: {len(state.findings)}/{state.max_findings}")
        if state.halt_reason:
            ConsoleUI.error(f"Halt Reason: {state.halt_reason}")
        print()
        return state
