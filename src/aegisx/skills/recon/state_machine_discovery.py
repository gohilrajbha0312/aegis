"""
Skill 10: StateMachineDiscoverySkill
======================================
Build workflow graphs: Login→Profile→Cart→Checkout→Payment.
Purely passive — analyzes discovered routes and auth surface.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

FLOW_TEMPLATES = {
    "authentication": {"steps": ["login", "register", "verify", "profile", "dashboard"], "priority": 1},
    "shopping": {"steps": ["products", "search", "product", "basket", "cart", "checkout", "payment", "order"], "priority": 2},
    "account": {"steps": ["profile", "settings", "password", "address", "privacy", "data-export"], "priority": 3},
    "support": {"steps": ["contact", "feedback", "complaint", "support", "ticket"], "priority": 4},
    "admin": {"steps": ["admin", "administration", "users", "management", "dashboard"], "priority": 5},
}


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 10: State Machine Discovery")
    transitions = []
    flows = []

    all_routes = []
    for r in state.routes:
        route_str = r if isinstance(r, str) else r.get("route", str(r))
        all_routes.append(route_str.lower())

    # Match routes against flow templates
    for flow_name, template in FLOW_TEMPLATES.items():
        matched_steps = []
        for step in template["steps"]:
            matching_routes = [r for r in all_routes if step in r]
            if matching_routes:
                matched_steps.append({"step": step, "routes": matching_routes[:3]})

        if len(matched_steps) >= 2:
            flow = {
                "flow_name": flow_name, "steps": matched_steps,
                "completeness": len(matched_steps) / len(template["steps"]),
                "source": "route_pattern_analysis", "confidence": 0.7
            }
            flows.append(flow)

            # Build transitions between consecutive matched steps
            for i in range(len(matched_steps) - 1):
                transitions.append({
                    "from": matched_steps[i]["step"],
                    "to": matched_steps[i + 1]["step"],
                    "flow": flow_name,
                    "source": "inferred_sequence"
                })

    state.state_transitions = transitions
    state.business_flows = flows
    if "state_machine_discovery" not in state.explored_paths:
        state.explored_paths.append("state_machine_discovery")
    state.evidence_ledger.append({
        "stage": "RECON_STATE_MACHINE", "timestamp": time.time(),
        "action": "workflow_graph_build",
        "result": {"flows": len(flows), "transitions": len(transitions)}
    })
    ConsoleUI.success(f"State Machine: {len(flows)} business flows, {len(transitions)} transitions")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_state_machine_discovery", name="State Machine Discovery",
        description="Builds workflow graphs and business flow maps from discovered routes",
        category="recon_intelligence", noise_score=0, required_inputs=["routes"],
        produced_outputs=["state_transitions", "business_flows"],
        supported_phases=["Reconnaissance"],
        requires_evidence=True, execute_fn=_execute
    ))
