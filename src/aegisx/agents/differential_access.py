from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI
from aegisx.analysis.vulnscan.differential_engine import differential_engine

class DifferentialAccessAgent(BaseAgent):
    """
    Compares responses across trust contexts (guest vs user vs admin) 
    to validate broken access control, IDOR, and BOLA hypotheses.
    """
    def __init__(self):
        super().__init__("DifferentialAccessAgent")

    def run(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("AI Differential Access Validation")
        routes = state.get("routes", [])
        findings = state.get("findings", [])
        target = state.get("target")

        if not routes:
            ConsoleUI.warning("No routes available for differential validation.")
            return state

        # We need absolute URLs for httpx
        if not target.startswith("http"):
            target = f"http://{target}"

        tested = 0
        vulnerable = 0

        # We will test up to 5 routes to limit noise
        for route in routes[:5]:
            url = f"{target}{route}"
            ConsoleUI.info(f"Testing differential access on: {url}")
            
            # Compare admin vs standard user
            confidence, diff = differential_engine.test_idor_hypothesis(
                method="GET", 
                url=url, 
                base_context="admin", 
                test_context="user"
            )
            
            tested += 1
            if confidence >= 0.70:
                ConsoleUI.success(f"[!] Vulnerable path discovered! Admin data exposed to User on {route} (Confidence: {confidence})")
                finding = {
                    "title": f"Broken Access Control (BOLA) on {route}",
                    "risk_level": "HIGH",
                    "finding_type": "BOLA",
                    "base_confidence": confidence,
                    "consensus_score": confidence,
                    "governance_class": "ACTIVE_VALIDATION",
                    "evidence": diff,
                    "nodes": [{"node_id": "bola_hypothesis", "node_type": "WEAKNESS"}],
                    "edges": []
                }
                findings.append(finding)
                vulnerable += 1
            else:
                ConsoleUI.info(f"[-] Access control enforced on {route}")

        ConsoleUI.success(f"Differential validation complete. Tested {tested} routes, found {vulnerable} BOLA vulnerabilities.")
        state["findings"] = findings
        return state
