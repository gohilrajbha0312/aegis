from typing import Dict, Any, List
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI
import time

class ConfidenceScoringAgent(BaseAgent):
    """
    Stage 5 Agent: Scores validated findings based on accumulated evidence.
    Findings below 80 confidence are held back.
    """
    def __init__(self):
        super().__init__(agent_id="ConfidenceScoringAgent")

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("STAGE 5: Confidence Scoring")
        validated = state.get("validated_findings", [])
        highly_confident = []

        for finding in validated:
            score = 0
            
            # Technical Evidence (e.g. status code, payload presence)
            if finding.get("technical_evidence"):
                score += 30
                
            # Behavior Evidence (e.g. response time, bypass success)
            if finding.get("behavior_evidence"):
                score += 25
                
            # Response Evidence (e.g. leaked sensitive data)
            if finding.get("response_evidence"):
                score += 25
                
            # Validation Evidence (e.g. Differential validation passed)
            if finding.get("validation_evidence"):
                score += 20
                
            # Default minimum confidence if passed validation stage
            if score == 0 and finding.get("status") == "VALIDATED":
                score = 85

            finding["confidence_score"] = score
            
            if score >= 80:
                highly_confident.append(finding)
                ConsoleUI.success(f"  [Confidence 80+] Proceeding: {finding.get('title')} (Score: {score})")
            else:
                ConsoleUI.warning(f"  [Low Confidence] Holding back: {finding.get('title')} (Score: {score})")

        self.log_action("confidence_scoring_complete", {"passed": len(highly_confident)})
        
        return {
            "status": "COMPLETED",
            "scored_findings": highly_confident
        }
