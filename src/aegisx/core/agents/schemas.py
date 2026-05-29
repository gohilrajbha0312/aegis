from pydantic import BaseModel, Field
from typing import List, Optional

class CognitiveFinding(BaseModel):
    """
    Strict structured output schema enforced upon all AI Reasoning Agents.
    Prevents hallucinatory prose and ensures DAG-compatible orchestration.
    """
    finding_id: str = Field(..., description="Unique deterministic ID for the finding")
    finding_type: str = Field(..., description="Classification of the vulnerability or intelligence (e.g. BOLA, Hardcoded Secret)")
    confidence: float = Field(..., description="Bayesian probability score from 0.0 to 1.0", ge=0.0, le=1.0)
    evidence: List[str] = Field(..., description="Array of specific evidence tokens supporting the claim")
    reasoning: str = Field(..., description="Brief, factual explanation of how the evidence supports the finding")
    governance_class: str = Field(..., description="Risk category: PASSIVE_ANALYSIS, ACTIVE_VALIDATION, EXPLOIT_SIMULATION")
    recommended_action: str = Field(..., description="Next step for the operator or pipeline")
    attack_path_probability: float = Field(..., description="Likelihood this enables lateral movement (0.0 to 1.0)", ge=0.0, le=1.0)

class AgentConsensusVote(BaseModel):
    """
    Schema for Multi-Agent Consensus voting.
    """
    agent_id: str
    target_finding_id: str
    vote_confidence: float
    reasoning: str

class AttackNode(BaseModel):
    node_id: str
    node_type: str
    properties: dict = {}

class AttackEdge(BaseModel):
    source_id: str
    target_id: str
    edge_type: str

class AIHypothesis(BaseModel):
    hypothesis: str
    confidence: float
    reasoning: List[str]
    validation_required: bool = True
    nodes: List[AttackNode] = []
    edges: List[AttackEdge] = []

class AIOutput(BaseModel):
    finding_type: str = ""
    confidence: float = 0.0
    risk_level: str = "LOW"
    governance_class: str = "PASSIVE_ANALYSIS"
    requires_human_approval: bool = False
    recommended_validation: List[str] = []
    reasoning: List[str] = []
    nodes: List[AttackNode] = []
    edges: List[AttackEdge] = []
