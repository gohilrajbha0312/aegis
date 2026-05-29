from typing import Dict, Any, List
from pydantic import BaseModel
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class StateTransitionFinding(BaseModel):
    transition: str
    expected_state: str
    actual_state: str
    severity: str
    evidence: str

class StateTransitionAnalyzer(BaseAgent):
    """
    Models business workflows and discovers logic flaws like workflow bypass
    or unauthorized state transitions.
    """
    def __init__(self):
        super().__init__("StateTransitionAnalyzer")

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("AI State Transition Analysis")
        routes = state.get("routes", [])
        if not routes:
            ConsoleUI.warning("No routes available for state transition analysis.")
            return state

        ConsoleUI.info("Analyzing business logic workflows...")
        
        findings = state.get("findings", [])
        # Mock logic flaw detection
        if "/checkout" in routes and "/cart" in routes:
            ConsoleUI.warning("Found potential workflow bypass: cart -> checkout")
            finding = StateTransitionFinding(
                transition="cart -> checkout",
                expected_state="cart_validated",
                actual_state="checkout_accessed_directly",
                severity="HIGH",
                evidence="Accessed /checkout without completing /cart POST"
            )
            findings.append({
                "title": "Business Logic Bypass: Cart to Checkout",
                "risk_level": "HIGH",
                "finding_type": "Business Logic Abuse",
                "base_confidence": 0.85,
                "consensus_score": 0.85,
                "governance_class": "ACTIVE_VALIDATION",
                "evidence": finding.model_dump_json(),
                "nodes": [{"node_id": "workflow_bypass", "node_type": "Vulnerability"}],
                "edges": []
            })
            
        state["findings"] = findings
        return state
