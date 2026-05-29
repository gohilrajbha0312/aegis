from typing import List, Dict, Optional
from pydantic import BaseModel
import itertools

class AgentVote(BaseModel):
    agent_id: str
    confidence_score: float  # 0.0 to 1.0
    finding_id: str
    reasoning: str

class ConsensusResult(BaseModel):
    approved_by_quorum: bool
    requires_analyst_review: bool
    has_score_conflict: bool
    final_consensus_score: float
    conflict_details: Optional[str] = None

class MultiAgentConsensusEngine:
    """
    Evaluates votes from specialized AI agents and enforces strict quorum 
    and contradiction detection policies.
    """
    
    REQUIRED_QUORUM = 3
    MAX_VOTES = 5
    CONFLICT_THRESHOLD = 0.30
    CONFIDENCE_THRESHOLD_FOR_AUTONOMY = 0.90

    def evaluate_votes(self, votes: List[AgentVote]) -> ConsensusResult:
        """
        Evaluate a list of agent votes based on strict enterprise governance rules.
        """
        if len(votes) < self.REQUIRED_QUORUM:
            return ConsensusResult(
                approved_by_quorum=False,
                requires_analyst_review=True,
                has_score_conflict=False,
                final_consensus_score=0.0,
                conflict_details="Failed to reach minimum vote count for quorum."
            )

        # 1. Detect Contradictions (Score Conflicts)
        has_conflict = False
        conflict_details = None
        
        # Compare every pair of votes
        for vote_a, vote_b in itertools.combinations(votes, 2):
            diff = abs(vote_a.confidence_score - vote_b.confidence_score)
            if diff > self.CONFLICT_THRESHOLD:
                has_conflict = True
                conflict_details = f"SCORE_CONFLICT detected between {vote_a.agent_id} ({vote_a.confidence_score}) and {vote_b.agent_id} ({vote_b.confidence_score}). Diff: {diff:.2f}"
                break # Stop at first major conflict
                
        # 2. Calculate average consensus score
        avg_score = sum(v.confidence_score for v in votes) / len(votes)
        
        # 3. Determine if Analyst Review is required
        # Review is required IF there is a conflict OR confidence is below 0.90
        requires_review = False
        if has_conflict or avg_score < self.CONFIDENCE_THRESHOLD_FOR_AUTONOMY:
            requires_review = True
            
        return ConsensusResult(
            approved_by_quorum=True,
            requires_analyst_review=requires_review,
            has_score_conflict=has_conflict,
            final_consensus_score=avg_score,
            conflict_details=conflict_details
        )
