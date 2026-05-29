"""
AEGIS-X Web Vulnerability Scanner Orchestrator
Master phase that invokes all 15 dedicated vulnerability scanner engines.
"""
import time
from typing import Dict, Any, List

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client
from aegisx.core.runtime_governor import RuntimeGovernor, ScanMode
import concurrent.futures

# Import all scanner engines
from aegisx.analysis.vulnscan.bruteforce_scanner import BruteForceScanner
from aegisx.analysis.vulnscan.command_injection_scanner import CommandInjectionScanner
from aegisx.analysis.vulnscan.csrf_scanner import CSRFScanner
from aegisx.analysis.vulnscan.file_inclusion_scanner import FileInclusionScanner
from aegisx.analysis.vulnscan.file_upload_scanner import FileUploadScanner
from aegisx.analysis.vulnscan.insecure_captcha_scanner import InsecureCaptchaScanner
from aegisx.analysis.vulnscan.sqli_scanner import SQLInjectionScanner
from aegisx.analysis.vulnscan.sqli_blind_scanner import BlindSQLInjectionScanner
from aegisx.analysis.vulnscan.weak_session_scanner import WeakSessionScanner
from aegisx.analysis.vulnscan.xss_dom_scanner import XSSDomScanner
from aegisx.analysis.vulnscan.xss_reflected_scanner import XSSReflectedScanner
from aegisx.analysis.vulnscan.xss_stored_scanner import XSSStoredScanner
from aegisx.analysis.vulnscan.csp_bypass_scanner import CSPBypassScanner
from aegisx.analysis.vulnscan.js_weakness_scanner import JSWeaknessScanner
from aegisx.analysis.vulnscan.open_redirect_scanner import OpenRedirectScanner

# Import AI Agents for Redesigned Architecture
from aegisx.agents.semantic_discovery import SemanticDiscoveryAgent
from aegisx.agents.adaptive_validation import AdaptiveValidationEngine
import asyncio


# Scanner registry: (name, class, requires_routes)
SCANNER_REGISTRY = [
    ("Brute Force",          BruteForceScanner,          True),
    ("Command Injection",    CommandInjectionScanner,     True),
    ("CSRF",                 CSRFScanner,                 True),
    ("File Inclusion",       FileInclusionScanner,        True),
    ("File Upload",          FileUploadScanner,           True),
    ("Insecure CAPTCHA",     InsecureCaptchaScanner,      True),
    ("SQL Injection",        SQLInjectionScanner,         True),
    ("SQL Injection (Blind)",BlindSQLInjectionScanner,    True),
    ("Weak Session IDs",     WeakSessionScanner,          True),
    ("XSS (DOM)",            XSSDomScanner,               True),
    ("XSS (Reflected)",      XSSReflectedScanner,         True),
    ("XSS (Stored)",         XSSStoredScanner,            True),
    ("CSP Bypass",           CSPBypassScanner,            True),
    ("JavaScript",           JSWeaknessScanner,           True),
    ("Open HTTP Redirect",   OpenRedirectScanner,         True),
]


def _extract_routes(state: WorkflowState) -> List[str]:
    """Extract discovered routes/endpoints from the evidence ledger."""
    routes = set()

    for item in state.evidence_ledger:
        stage = item.get("stage", "")
        result = item.get("result", {})

        # Phase 6: Route Discovery (feroxbuster/ffuf)
        if stage == "PHASE_6_ROUTE_DISCOVERY":
            if isinstance(result, dict):
                raw = result.get("raw_output", [])
                for r in raw:
                    if isinstance(r, dict):
                        url = r.get("url", "")
                        if url:
                            # Extract path only
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            routes.add(parsed.path or "/")
                    elif isinstance(r, str):
                        if r.startswith("http"):
                            from urllib.parse import urlparse
                            parsed = urlparse(r)
                            routes.add(parsed.path or "/")
                        else:
                            routes.add(r)

        # Phase 7: JS Intelligence (discovered endpoints)
        elif stage == "PHASE_7_JS_INTELLIGENCE":
            if isinstance(result, dict):
                for ep in result.get("discovered_endpoints", []):
                    if isinstance(ep, str) and ep.startswith("/"):
                        routes.add(ep)

        # Phase 8: API Boundary
        elif stage == "PHASE_8_API_BOUNDARY":
            if isinstance(result, dict):
                if result.get("graphql_detected"):
                    routes.add("/graphql")
                if result.get("swagger_detected"):
                    routes.add("/swagger/v1/swagger.json")

    # Always include common routes as fallback
    default_routes = [
        "/", "/login", "/admin", 
        "/api/v1/health", "/upload", "/search", "/register",
    ]
    for dr in default_routes:
        routes.add(dr)

    # Filter out known paths that cause unhandled exceptions (e.g., Juice Shop crash on /api, /rest, /redirect)
    # Using prefix filtering as an alternative method to avoid fuzzing sensitive endpoints.
    bad_prefixes = ("/api", "/rest", "/redirect")
    return [r for r in list(routes) if not r.startswith(bad_prefixes) or r == "/api/v1/health"]


def phase_12b_web_vuln_suite(state: WorkflowState) -> WorkflowState:
    """
    PHASE 12B: Enterprise AI-Native Web Validation Suite
    Executes Semantic Discovery and Adaptive Validation.
    Legacy brute-force engines are only invoked under DEEP_ANALYSIS mode.
    """
    ConsoleUI.header("PHASE 12B: ENTERPRISE AI-NATIVE VALIDATION ENGINE")
    ConsoleUI.info(f"Target: {state.normalized_target}")

    # Extract discovered routes
    routes = _extract_routes(state)
    ConsoleUI.info(f"Operating on {len(routes)} discovered routes/endpoints")

    # Reset global request counter for this scan phase
    http_client.reset_request_counter()
    gov = RuntimeGovernor.instance()
    
    if gov.mode == ScanMode.PASSIVE:
        ConsoleUI.info("Skipping active scanning (PASSIVE mode).")
        return state

    ConsoleUI.info(f"Rate limiter active: {gov.profile.max_rps} req/s, budget: {gov.profile.max_requests} requests")
    
    # 1. Semantic Discovery
    ConsoleUI.header("Step 1: Semantic Discovery")
    semantic_agent = SemanticDiscoveryAgent()
    try:
        # Wrap the async call in a synchronous run
        semantic_result = asyncio.run(semantic_agent.process({
            "target": state.normalized_target,
            "evidence_ledger": state.evidence_ledger
        }))
        state.evidence_ledger.append({
            "stage": "PHASE_12B_SEMANTIC_DISCOVERY",
            "timestamp": time.time(),
            "result": semantic_result
        })
        ConsoleUI.success("Semantic discovery completed.")
    except Exception as e:
        ConsoleUI.warning(f"Semantic discovery failed: {e}")
        semantic_result = {}

    # 2. Adaptive Validation
    ConsoleUI.header("Step 2: Adaptive Validation")
    validation_agent = AdaptiveValidationEngine()
    try:
        # Pass the semantic inferences into the validation agent
        val_state = {
            "target": state.normalized_target,
            "frameworks": semantic_result.get("frameworks", []),
            "api_style": semantic_result.get("api_style", "Unknown"),
            "inferred_endpoints": semantic_result.get("inferred_endpoints", []),
            "trust_boundaries": semantic_result.get("trust_boundaries", [])
        }
        validation_result = asyncio.run(validation_agent.process(val_state))
        
        # Inject the AI's execution plan into the global DAG state
        if "tool_execution_plan" in validation_result:
            state.tool_execution_plan = validation_result["tool_execution_plan"]
            
        state.evidence_ledger.append({
            "stage": "PHASE_12B_ADAPTIVE_VALIDATION",
            "timestamp": time.time(),
            "result": validation_result
        })
        ConsoleUI.success("Adaptive validation generated.")
    except Exception as e:
        ConsoleUI.warning(f"Adaptive validation failed: {e}")

    # 3. Legacy Brute-Force Scanners (Only if DEEP_ANALYSIS)
    if gov.mode == ScanMode.DEEP_ANALYSIS:
        ConsoleUI.header("Step 3: Legacy Brute-Force Scanning (DEEP_ANALYSIS mode active)")
        active_registry = SCANNER_REGISTRY
        total_findings = 0
        scanner_results = {}

        for scanner_name, scanner_class, needs_routes in active_registry:
            if gov.is_paused:
                ConsoleUI.warning(f"Scanner suite paused by governor: {gov.pause_reason}")
                break

            ConsoleUI.header(f"Scanner: {scanner_name}")

            try:
                scanner = scanner_class()
                start_time = time.time()

                def run_scanner():
                    if needs_routes:
                        return scanner.scan(state.normalized_target, routes)
                    else:
                        return scanner.scan(state.normalized_target, [])

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(run_scanner)
                    try:
                        findings = future.result(timeout=30)
                    except concurrent.futures.TimeoutError:
                        ConsoleUI.warning(f"[{scanner_name}] Scanner timed out after 30s.")
                        findings = []

                duration = time.time() - start_time

                if findings:
                    ConsoleUI.success(
                        f"[{scanner_name}] Discovered {len(findings)} finding(s) in {duration:.1f}s"
                    )
                    state.findings.extend(findings)
                    total_findings += len(findings)
                    scanner_results[scanner_name] = len(findings)
                else:
                    ConsoleUI.info(f"[{scanner_name}] No findings ({duration:.1f}s)")
                    scanner_results[scanner_name] = 0

            except http_client.BudgetExhaustedError:
                ConsoleUI.warning(f"[{scanner_name}] Request budget exhausted — stopping scan to protect target.")
                scanner_results[scanner_name] = "BUDGET_EXHAUSTED"
                break
            except Exception as e:
                ConsoleUI.warning(f"[{scanner_name}] Scanner error: {str(e)[:200]}")
                scanner_results[scanner_name] = f"ERROR: {str(e)[:100]}"

        # Summary
        ConsoleUI.header("WEB VULN SUITE SUMMARY")
        ConsoleUI.success(f"Total new findings: {total_findings}")
        for name, count in scanner_results.items():
            if isinstance(count, int) and count > 0:
                ConsoleUI.success(f"  ✓ {name}: {count} finding(s)")
            elif isinstance(count, int):
                ConsoleUI.info(f"  ○ {name}: clean")
            else:
                ConsoleUI.warning(f"  ✗ {name}: {count}")

        # Log to evidence ledger
        state.evidence_ledger.append({
            "stage": "PHASE_12B_LEGACY_VULN_SUITE",
            "timestamp": time.time(),
            "action": "web_vuln_scanner_suite",
            "result": {
                "total_findings": total_findings,
                "scanner_results": scanner_results,
                "routes_tested": len(routes),
            },
        })
    else:
        ConsoleUI.info("Legacy brute-force scanning skipped. (Enable DEEP_ANALYSIS for full fuzzing).")

    return state
