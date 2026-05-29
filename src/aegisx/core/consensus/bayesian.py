from typing import List

class BayesianConfidenceEngine:
    """
    Implements the formal probability equation:
    FINAL_CONFIDENCE = (runtime * 0.45) + (historical * 0.20) + (behavioral * 0.20) + (agent * 0.15)
    """
    
    def calculate_confidence(self, runtime_score: float, historical_score: float, 
                           behavioral_score: float, agent_votes: List[float]) -> float:
        
        # Calculate Agent Consensus Average
        if not agent_votes:
            agent_score = 0.0
        else:
            agent_score = sum(agent_votes) / len(agent_votes)
            
        final_confidence = (
            (runtime_score * 0.45) + 
            (historical_score * 0.20) + 
            (behavioral_score * 0.20) + 
            (agent_score * 0.15)
        )
        
        # Bound between 0 and 1
        return max(0.0, min(1.0, final_confidence))
        
    def detect_conflict(self, agent_votes: List[float], threshold: float = 0.30) -> bool:
        """
        Detects if independent agents radically disagree, requiring HITL escalation.
        """
        if not agent_votes or len(agent_votes) < 2:
            return False
            
        max_vote = max(agent_votes)
        min_vote = min(agent_votes)
        
        return (max_vote - min_vote) > threshold
