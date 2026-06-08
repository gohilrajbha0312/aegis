"""
Skill 12: SessionCorrelationSkill
===================================
Track cookies, JWTs, refresh tokens, CSRF tokens, session identifiers.
Builds the state.sessions inventory.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 12: Session Correlation")
    sessions = list(state.sessions)
    
    # 1. Analyze Auth Surface for session mechanisms
    for auth in state.auth_surface:
        if auth.get("type") == "session_cookie":
            if not any(s.get("identifier") == auth.get("cookie") for s in sessions):
                sessions.append({
                    "identifier": auth.get("cookie"),
                    "type": "cookie",
                    "source": "auth_surface",
                    "confidence": 0.9
                })
        elif auth.get("type") in ["jwt_cookie", "jwt_token"]:
            val = auth.get("cookie") or auth.get("evidence")
            if not any(s.get("identifier") == val for s in sessions):
                sessions.append({
                    "identifier": val,
                    "type": "jwt",
                    "source": "auth_surface",
                    "confidence": 0.95
                })

    # 2. Extract CSRF tokens from parameters or headers
    for param in state.parameters:
        if "csrf" in param.get("name", "").lower():
            if not any(s.get("type") == "csrf_token" for s in sessions):
                sessions.append({
                    "identifier": param.get("name"),
                    "type": "csrf_token",
                    "source": "parameter_discovery",
                    "confidence": 0.8
                })

    # 3. Analyze headers for tokens
    for key, val in state.discovered_headers.items():
        if key.lower() in ["authorization", "x-csrf-token", "x-xsrf-token"]:
            if not any(s.get("identifier") == val for s in sessions):
                sessions.append({
                    "identifier": f"{key}: {val[:20]}...",
                    "type": "header_token",
                    "source": "header_analysis",
                    "confidence": 0.9
                })

    state.sessions = sessions
    if "session_correlation" not in state.explored_paths:
        state.explored_paths.append("session_correlation")
    state.evidence_ledger.append({
        "stage": "RECON_SESSION_CORRELATION", "timestamp": time.time(),
        "action": "session_tracking",
        "result": {"sessions_tracked": len(sessions)}
    })
    ConsoleUI.success(f"Session Correlation: {len(sessions)} session identifiers tracked")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_session_correlation", name="Session Correlation",
        description="Tracks cookies, JWTs, refresh tokens, CSRF tokens, session identifiers",
        category="recon_intelligence", noise_score=0, required_inputs=["auth_surface", "parameters"],
        produced_outputs=["sessions"],
        supported_phases=["Reconnaissance"],
        requires_evidence=True, execute_fn=_execute
    ))
