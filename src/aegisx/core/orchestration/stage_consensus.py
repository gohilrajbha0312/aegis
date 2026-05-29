import time
from typing import Dict, Any

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.agents.reasoning import AIReasoningEngine
from aegisx.core.agents.advisor import AIGovernanceAdvisor
from aegisx.core.consensus.engine import MultiAgentConsensusEngine, AgentVote
from aegisx.core.ui.console import ConsoleUI

def stage_11_consensus(state: WorkflowState) -> WorkflowState:
    """
    STAGE 11: Multi-Agent Correlation
    Invokes the AI Cognitive Layer to analyze evidence, generate hypotheses,
    and vote via the Consensus Engine.
    """
    ConsoleUI.info(f"Executing Phase 10 (Stage 11 internal): AI Cognitive Layer Correlation...")
    
    # Initialize AI Engines
    reasoning_engine = AIReasoningEngine(use_mock=False)
    advisor_engine = AIGovernanceAdvisor(use_mock=False)
    consensus_engine = MultiAgentConsensusEngine()
    
    # Optional Bayesian and Trust engines
    from aegisx.core.consensus.bayesian import BayesianConfidenceEngine
    from aegisx.core.agents.trust_calibration import AnalystTrustCalibrator
    bayesian_engine = BayesianConfidenceEngine()
    trust_calibrator = AnalystTrustCalibrator()
    
    # 1. Generate Hypotheses from Evidence
    hypotheses = reasoning_engine.generate_hypotheses(state)
    
    if not hypotheses:
        ConsoleUI.warning("No vulnerability hypotheses generated.")
        return state
        
    # Process the highest confidence hypothesis for this stage demonstration
    primary_hypothesis = sorted(hypotheses, key=lambda x: x.confidence, reverse=True)[0]
    ConsoleUI.info(f"Primary Hypothesis: {primary_hypothesis.hypothesis} (Conf: {primary_hypothesis.confidence})")
    
    # 2. AI Governance Advisor evaluates risk and required validation
    ai_output = advisor_engine.advise(primary_hypothesis)
    ConsoleUI.info(f"Recommended Governance Class: {ai_output.governance_class}")
    
    # 3. Multi-Agent Consensus Voting (Dynamic AI Independent Votes)
    # Using Trust Calibrator weights to influence votes based on historical accuracy
    base_conf = ai_output.confidence
    
    # Apply Trust Weights to simulate actual agent confidence levels based on past performance
    recon_weight = trust_calibrator.get_trust_multiplier("ReconAgent")
    vuln_weight = trust_calibrator.get_trust_multiplier("VulnAgent")
    gov_weight = trust_calibrator.get_trust_multiplier("GovernanceAgent")
    
    # Calculate independent confidence scores adjusted by trust weights
    recon_conf = min(1.0, base_conf * recon_weight)
    vuln_conf = min(1.0, (base_conf + 0.05) * vuln_weight)
    gov_conf = min(1.0, (base_conf - 0.02) * gov_weight)
    
    votes = [
        AgentVote(agent_id="ReconAgent", confidence_score=recon_conf, finding_id="HYP-1", reasoning="Network exposure supports this finding."),
        AgentVote(agent_id="VulnAgent", confidence_score=vuln_conf, finding_id="HYP-1", reasoning="Tool output and heuristic patterns match."),
        AgentVote(agent_id="CorrelationAgent", confidence_score=base_conf, finding_id="HYP-1", reasoning="Correlates with observed HTTP responses."),
        AgentVote(agent_id="GovernanceAgent", confidence_score=gov_conf, finding_id="HYP-1", reasoning="Matches active risk policy profile.")
    ]
    
    # Get initial consensus
    consensus_result = consensus_engine.evaluate_votes(votes)
    
    # Apply formal probability equation via Bayesian engine
    # Runtime score comes from consensus, behavioral and historical are estimated here
    final_bayesian_conf = bayesian_engine.calculate_confidence(
        runtime_score=consensus_result.final_consensus_score,
        historical_score=0.80, # E.g., past occurrences of this finding
        behavioral_score=0.85, # E.g., unusual target behavior
        agent_votes=[v.confidence_score for v in votes]
    )
    
    consensus_result.final_consensus_score = final_bayesian_conf
    
    # Store results in findings
    finding = {
        "finding_type": ai_output.finding_type,
        "base_confidence": ai_output.confidence,
        "consensus_score": consensus_result.final_consensus_score,
        "score_conflict": consensus_result.has_score_conflict,
        "risk_level": ai_output.risk_level,
        "governance_class": ai_output.governance_class,
        "requires_human_approval": ai_output.requires_human_approval,
        "recommended_validation": ai_output.recommended_validation,
        "nodes": [n.model_dump() for n in ai_output.nodes] if ai_output.nodes else [],
        "edges": [e.model_dump() for e in ai_output.edges] if ai_output.edges else []
    }
    
    state.findings.append(finding)
    
    # Log to evidence ledger
    state.evidence_ledger.append({
        "stage": "STAGE_11_CONSENSUS",
        "timestamp": time.time(),
        "action": "ai_cognitive_correlation",
        "result": finding
    })
    
    ConsoleUI.info(f"Consensus Reached: {consensus_result.final_consensus_score:.2f}")
    if consensus_result.has_score_conflict:
        ConsoleUI.warning(f"Consensus Conflict: {consensus_result.conflict_details}")
        
    return state
