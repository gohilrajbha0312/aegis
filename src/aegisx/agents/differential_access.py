from typing import Dict, Any, List
from pydantic import BaseModel
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI
from aegisx.analysis.vulnscan.differential_engine import differential_engine
from aegisx.governance.auth.session import TargetSessionManager

class DifferentialEvidence(BaseModel):
    endpoint: str
    guest_response: Dict[str, Any]
    user_response: Dict[str, Any]
    admin_response: Dict[str, Any]
    ownership_violation: bool
    privilege_violation: bool
    confidence_score: float
    evidence: str

class DifferentialAccessAgent(BaseAgent):
    """
    Compares responses across trust contexts (guest vs user vs admin) 
    to validate broken access control, IDOR, and BOLA hypotheses.
    """
    def __init__(self):
        super().__init__("DifferentialAccessAgent")
        self.session_manager = TargetSessionManager()

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("AI Differential Access Validation")
        routes = state.get("routes", [])
        findings = state.get("findings", [])
        target = state.get("target")

        if not routes:
            ConsoleUI.warning("No routes available for differential validation.")
            return state
            
        sessions = state.get("sessions", [])
        if not sessions:
            ConsoleUI.warning("DifferentialAccessAgent skipped: No sessions discovered (evidence_count=0).")
            return state

        if not target.startswith("http"):
            target = f"http://{target}"

        tested = 0
        vulnerable = 0

        # We will test up to 5 routes to limit noise
        for route in routes[:5]:
            # if route is a dict from discovered_routes, extract the path
            if isinstance(route, dict):
                path = route.get("path", route.get("endpoint", ""))
                method = route.get("method", "GET")
            else:
                path = str(route)
                method = "GET"
                
            if not path:
                continue

            url = f"{target}{path}"
            ConsoleUI.info(f"Testing differential access on: {method} {url}")
            
            # Use http_client directly to simulate contexts
            from aegisx.core import http_client
            
            headers_guest = {}
            headers_user = {"Authorization": "Bearer mock_user_token"}
            headers_admin = {"Authorization": "Bearer mock_admin_token"}
            
            try:
                if method.upper() == "GET":
                    guest_resp = http_client.get(url, headers=headers_guest)
                    user_resp = http_client.get(url, headers=headers_user)
                    admin_resp = http_client.get(url, headers=headers_admin)
                else:
                    guest_resp = http_client.post(url, headers=headers_guest, json={})
                    user_resp = http_client.post(url, headers=headers_user, json={})
                    admin_resp = http_client.post(url, headers=headers_admin, json={})
                    
                guest_data = {"status": guest_resp.status_code, "length": len(guest_resp.content)}
                user_data = {"status": user_resp.status_code, "length": len(user_resp.content)}
                admin_data = {"status": admin_resp.status_code, "length": len(admin_resp.content)}
                
                # Heuristic: If admin is successful (200), and others get same success and similar length
                admin_success = admin_data["status"] in [200, 201]
                
                # If user gets exactly what admin gets (vertical escalation / ownership violation)
                ownership_violation = admin_success and user_data["status"] == admin_data["status"] and abs(user_data["length"] - admin_data["length"]) < 50
                
                # If guest gets exactly what admin gets (privilege violation)
                privilege_violation = admin_success and guest_data["status"] == admin_data["status"] and abs(guest_data["length"] - admin_data["length"]) < 50
                
                confidence = 0.0
                if privilege_violation:
                    confidence = 0.95
                elif ownership_violation:
                    confidence = 0.85
                    
                diff = f"Request: {method} {url}\nGuest: {guest_data['status']} ({guest_data['length']}b)\nUser: {user_data['status']} ({user_data['length']}b)\nAdmin: {admin_data['status']} ({admin_data['length']}b)"

            except Exception as e:
                ConsoleUI.warning(f"Differential test failed on {url}: {e}")
                continue
            
            # Construct DifferentialEvidence
            evidence_obj = DifferentialEvidence(
                endpoint=path,
                guest_response=guest_data,
                user_response=user_data,
                admin_response=admin_data,
                ownership_violation=ownership_violation,
                privilege_violation=privilege_violation,
                confidence_score=confidence,
                evidence=diff
            )
            
            tested += 1
            if evidence_obj.ownership_violation or evidence_obj.privilege_violation:
                ConsoleUI.success(f"[!] Vulnerable path discovered! Access control violation on {path} (Confidence: {confidence})")
                finding = {
                    "title": f"Broken Access Control on {path}",
                    "risk_level": "HIGH",
                    "finding_type": "BOLA/IDOR",
                    "base_confidence": confidence,
                    "consensus_score": confidence,
                    "governance_class": "ACTIVE_VALIDATION",
                    "evidence": evidence_obj.model_dump_json(),
                    "nodes": [
                        {"node_id": f"bola_{path}", "node_type": "Vulnerability"},
                        {"node_id": f"route_{path}", "node_type": "Route"}
                    ],
                    "edges": [
                        {"source_id": f"bola_{path}", "target_id": f"route_{path}", "edge_type": "EXPLOITS"}
                    ]
                }
                findings.append(finding)
                vulnerable += 1
            else:
                ConsoleUI.info(f"[-] Access control enforced on {path}")

        ConsoleUI.success(f"Differential validation complete. Tested {tested} routes, found {vulnerable} BOLA vulnerabilities.")
        state["findings"] = findings
        return state
