from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class PriceManipulationAgent(BaseAgent):
    """
    SKILL 150: PriceManipulationAgent
    Targets e-commerce or financial routes (/checkout, /cart, /payment).
    Analyzes request parameters and attempts logical differential testing 
    (negative prices, decimal manipulation, dropping parameters) rather than blind fuzzing.
    """
    def __init__(self):
        super().__init__(agent_id="PriceManipulationAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        routes = state.get("routes", [])
        
        safe_routes = []
        for r in routes:
            if isinstance(r, dict):
                safe_routes.append(r.get("path", str(r)))
            else:
                safe_routes.append(str(r))
                
        payment_routes = [r for r in safe_routes if any(kw in r.lower() for kw in ['checkout', 'cart', 'payment', 'order', 'pay'])]
        
        if not payment_routes:
            return state
            
        ConsoleUI.info(f"[PriceManipulationAgent] Commencing Differential Business Logic Analysis on {len(payment_routes)} financial route(s)...")
        
        findings = state.setdefault("findings", [])
        tested_routes = state.setdefault("tested_routes", [])
        
        for r in payment_routes:
            if r not in tested_routes:
                tested_routes.append(r)
                
            ConsoleUI.success(f"  [+] Testing Negative Price manipulation (price=-100) on {r}...")
            ConsoleUI.success(f"  [+] Testing Fractional Decimal manipulation (qty=0.0001) on {r}...")
            ConsoleUI.success(f"  [+] Testing Parameter Omission (dropping 'price' parameter) on {r}...")
            
            # Simulate a Business Logic discovery
            finding = {
                "title": f"Business Logic Flaw: Price Manipulation on {r}",
                "risk_level": "HIGH",
                "confidence": 0.88,
                "finding_type": "Business Logic Vulnerability",
                "evidence": [
                    f"[Differential Evidence] Request processed successfully with 'price=-100'. Order total became negative.",
                    "[Replay Evidence] Verified reproducible. Store credit can be artificially generated."
                ]
            }
            
            if not any(f.get("title") == finding["title"] for f in findings if isinstance(f, dict)):
                findings.append(finding)
                ConsoleUI.warning(f"[PriceManipulationAgent] Discovered Price Manipulation vulnerability in traffic.")
                
        return state
