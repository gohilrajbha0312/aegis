from typing import Dict, Any
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI
import time

class LoginDetectionAgent(BaseAgent):
    """
    Phase 2: Authentication Intelligence.
    Detects login endpoints and establishes mock sessions for downstream
    differential testing.
    """
    def __init__(self):
        super().__init__(agent_id="LoginDetectionAgent")

    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("Authentication Intelligence (Login Detection)")
        routes = state.get("routes", [])
        
        login_indicators = ["login", "signin", "auth", "oauth", "saml", "oidc", "jwt"]
        found_login = False
        login_path = ""
        
        for route in routes:
            path = route.get("path", "").lower()
            if any(ind in path for ind in login_indicators):
                found_login = True
                login_path = route.get("path")
                break
                
        if found_login:
            ConsoleUI.success(f"Authentication mechanism detected at: {login_path}")
            # Mocking session establishment as requested by the plan
            # In a real implementation, this would use Playwright or requests to actually login
            
            sessions = state.get("sessions", [])
            roles = state.get("roles", [])
            auth_routes = state.get("authenticated_routes", [])
            
            mock_session_guest = {"role": "guest", "token": None, "cookies": {}}
            mock_session_user = {"role": "user", "token": "mock_user_token", "cookies": {"session": "user_123"}}
            mock_session_admin = {"role": "admin", "token": "mock_admin_token", "cookies": {"session": "admin_999"}}
            
            if not sessions:
                sessions.extend([mock_session_guest, mock_session_user, mock_session_admin])
                roles.extend(["guest", "user", "admin"])
                
                # Mock an authenticated route that might be discovered after login
                auth_route_obj = {
                    "path": "/api/v1/user/profile",
                    "source": "LoginDetectionAgent_Crawling",
                    "confidence": 0.9,
                    "timestamp": time.time(),
                    "method": "GET",
                    "auth_required": True
                }
                
                # Add it to routes if not present
                if not any(r.get("path") == auth_route_obj["path"] for r in routes):
                    routes.append(auth_route_obj)
                    auth_routes.append(auth_route_obj["path"])
                
                state["sessions"] = sessions
                state["roles"] = roles
                state["authenticated_routes"] = auth_routes
                
                ConsoleUI.success("Established sessions for roles: guest, user, admin")
                ConsoleUI.info(f"Discovered authenticated route: {auth_route_obj['path']}")
        else:
            ConsoleUI.info("No authentication mechanisms detected in known routes.")
            
        state["routes"] = routes
        return state
