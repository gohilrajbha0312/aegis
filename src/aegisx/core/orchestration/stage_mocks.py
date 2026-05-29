import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI

def create_mock_stage(stage_name: str, stage_desc: str):
    """Creates a generic placeholder stage function."""
    def _stage(state: WorkflowState) -> WorkflowState:
        ConsoleUI.info(f"[{stage_name}] Executing: {stage_desc}")
        state.evidence_ledger.append({
            "stage": stage_name,
            "timestamp": time.time(),
            "action": "mock_execution",
            "result": "Placeholder executed successfully."
        })
        time.sleep(0.1)
        return state
    return _stage

# Missing 13-Phase Model Mocks
phase_2_asset_discovery = create_mock_stage("PHASE_2_ASSET_DISCOVERY", "Amass/Subfinder integration.")
phase_4_http_intelligence = create_mock_stage("PHASE_4_HTTP_INTELLIGENCE", "httpx metadata extraction.")
phase_5_tech_fingerprinting = create_mock_stage("PHASE_5_TECH_FINGERPRINTING", "whatweb / wafw00f integration.")
phase_6_route_discovery = create_mock_stage("PHASE_6_ROUTE_DISCOVERY", "feroxbuster route enumeration.")
phase_7_js_intelligence = create_mock_stage("PHASE_7_JS_INTELLIGENCE", "JavaScript AST & Linkfinder analysis.")
phase_8_auth_boundary = create_mock_stage("PHASE_8_AUTH_BOUNDARY", "Authentication boundary mapping.")
phase_9_cloud_intelligence = create_mock_stage("PHASE_9_CLOUD_INTELLIGENCE", "Cloud exposure & telemetry leaks.")
phase_13_reporting = create_mock_stage("PHASE_13_REPORTING", "Generating Enterprise Output Report.")
