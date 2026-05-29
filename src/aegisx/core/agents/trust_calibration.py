from typing import Dict, Any

class AnalystTrustCalibrator:
    """
    Analyst Trust Calibration.
    Implements Bayesian trust updating based on whether analysts approve or reject AI findings.
    """
    def __init__(self):
        # Default trust score for all agents starts at 1.0 (neutral)
        self.agent_trust_scores = {
            "ReconAgent": 1.0,
            "TechnologyAgent": 1.0,
            "AuthBoundaryAgent": 1.0,
            "GovernanceAgent": 1.0,
            "GraphArchitectAgent": 1.0
        }

    def record_feedback(self, agent_id: str, approved: bool) -> None:
        """
        Updates the agent's rolling confidence weighting.
        Penalty is harsher for rejected false positives to enforce precision.
        """
        if agent_id not in self.agent_trust_scores:
            self.agent_trust_scores[agent_id] = 1.0
            
        current_trust = self.agent_trust_scores[agent_id]
        
        if approved:
            # Slow incremental trust gain
            self.agent_trust_scores[agent_id] = min(2.0, current_trust + 0.05)
        else:
            # Harsher penalty for hallucinated / rejected findings
            self.agent_trust_scores[agent_id] = max(0.1, current_trust - 0.15)

    def get_trust_multiplier(self, agent_id: str) -> float:
        """
        Returns the current confidence weight multiplier for a specific AI agent.
        """
        return self.agent_trust_scores.get(agent_id, 1.0)
