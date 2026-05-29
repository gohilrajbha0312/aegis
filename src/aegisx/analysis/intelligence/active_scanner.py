import json
import time
from typing import Dict, Any, List

from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI
from aegisx.core.runtime_governor import RuntimeGovernor, ScanMode

class ActiveScanner:
    """
    Enterprise Active Vulnerability Scanner using Nuclei and Nikto.
    """
    
    def run_nuclei(self, target: str, mode: ScanMode, execution_plan: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """Runs Nuclei dynamically driven by the AI execution plan."""
        execution_plan = execution_plan or {}
        
        # Ensure we use HTTP or HTTPS depending on port, assuming HTTP for simplicity if not 443
        url = f"http://{target}"
        if target.endswith(":443"):
            url = f"https://{target}"
            
        cmd = ["nuclei", "-u", url, "-j", "-silent", "-timeout", "5", "-c", "50"]
        
        # AI-Driven Pre-Plan execution
        prescribed_tags = execution_plan.get("nuclei_tags", [])
        
        if mode == ScanMode.DEEP_ANALYSIS:
            # Full suite
            pass
        elif prescribed_tags:
            # Use EXACTLY what the AI determined is safe and relevant
            cmd.extend(["-tags", ",".join(prescribed_tags)])
            # Always exclude purely destructive/noisy payloads unless in deep analysis
            cmd.extend(["-etags", "fuzz,dast,sqli,xss,injection"])
            ConsoleUI.info(f"Executing Nuclei using AI-prescribed pre-plan tags: {prescribed_tags}")
        else:
            # Fallback if no pre-plan was generated (or AI couldn't determine anything)
            cmd.extend(["-tags", "cve,exposure,tech,misconfig"])
            cmd.extend(["-etags", "fuzz,dast,sqli,xss,injection"])
            ConsoleUI.info("Executing Nuclei with static safe-fallback tags (No AI pre-plan found).")
            
        result = CommandGateway.execute(cmd, timeout=300, description="Enterprise Vulnerability Scanning (Nuclei)")
        
        findings = []
        if not result["success"]:
            ConsoleUI.warning(f"Nuclei execution failed or was denied: {result.get('stderr')}")
            return findings
            
        raw_out = result.get("stdout", "")
        for line in raw_out.strip().split('\n'):
            if line:
                try:
                    data = json.loads(line)
                    # Mapping Nuclei info to AEGIS-X format
                    severity = data.get("info", {}).get("severity", "info").upper()
                    
                    # Skip informational/low findings to focus on actionable exploits
                    if severity in ["INFO"]:
                        continue
                        
                    name = data.get("info", {}).get("name", "Unknown Nuclei Finding")
                    template_id = data.get("template-id", "unknown")
                    description = data.get("info", {}).get("description", "")
                    remediation = data.get("info", {}).get("remediation", "Review and patch the affected component.")
                    matched = data.get("matched-at", url)
                    
                    risk_level = "LOW"
                    if severity in ["CRITICAL", "HIGH"]:
                        risk_level = severity
                    elif severity == "MEDIUM":
                        risk_level = "MEDIUM"
                        
                    findings.append({
                        "finding_type": f"Nuclei [{template_id}] - {name}",
                        "base_confidence": 0.95, # Nuclei is typically high confidence
                        "consensus_score": 0.95,
                        "score_conflict": False,
                        "risk_level": risk_level,
                        "governance_class": "ACTIVE_VALIDATION",
                        "requires_human_approval": False,
                        "recommended_validation": [remediation],
                        "reasoning": [description, f"Matched at: {matched}"],
                        "nodes": [],
                        "edges": []
                    })
                except json.JSONDecodeError:
                    pass
                    
        return findings

    def run_nikto(self, target: str) -> List[Dict[str, Any]]:
        """Runs Nikto for legacy web server flaws."""
        url = f"http://{target}"
        if target.endswith(":443"):
            url = f"https://{target}"
            
        cmd = ["nikto", "-h", url, "-Tuning", "12389", "-maxtime", "60s"]
        
        result = CommandGateway.execute(cmd, timeout=120, description="Legacy Web Server Scanning (Nikto)")
        
        findings = []
        if not result["success"]:
            ConsoleUI.warning(f"Nikto execution failed or was denied: {result.get('stderr')}")
            return findings
            
        # Parse basic Nikto output
        raw_out = result.get("stdout", "")
        # Nikto output is plain text, we look for lines starting with +
        nikto_issues = []
        for line in raw_out.strip().split('\n'):
            if line.startswith("+ ") and "OSVDB" in line or "CVE-" in line or "Directory indexing found" in line:
                clean_line = line[2:].strip()
                nikto_issues.append(clean_line)
                
        if nikto_issues:
            findings.append({
                "finding_type": "Nikto Web Server Flaws",
                "base_confidence": 0.70,
                "consensus_score": 0.75,
                "score_conflict": False,
                "risk_level": "MEDIUM",
                "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": ["Review legacy configurations and patch server components."],
                "reasoning": nikto_issues[:5], # Limit to top 5
                "nodes": [],
                "edges": []
            })
            
        return findings

    def run_sqlmap(self, target: str) -> List[Dict[str, Any]]:
        """Runs SQLMap for active injection scanning."""
        url = f"http://{target}"
        if target.endswith(":443"):
            url = f"https://{target}"
            
        cmd = ["sqlmap", "-u", url, "--crawl=1", "--batch", "--random-agent", "--level", "1", "--risk", "1", "-v", "0"]
        
        result = CommandGateway.execute(cmd, timeout=300, description="Active Injection Scanning (SQLMap)")
        
        findings = []
        if not result["success"]:
            ConsoleUI.warning(f"SQLMap execution failed or was denied: {result.get('stderr')}")
            return findings
            
        raw_out = result.get("stdout", "") or ""
        # Very basic grep for vulnerability confirmation from sqlmap
        if "is vulnerable" in raw_out or "identified the following injection point" in raw_out:
            findings.append({
                "finding_type": "SQL Injection Discovered",
                "base_confidence": 0.99,
                "consensus_score": 0.99,
                "score_conflict": False,
                "risk_level": "CRITICAL",
                "governance_class": "ACTIVE_VALIDATION",
                "requires_human_approval": False,
                "recommended_validation": ["Sanitize inputs and use parameterized queries."],
                "reasoning": ["SQLMap actively confirmed injection payload execution."],
                "nodes": [],
                "edges": []
            })
            
        return findings

def phase_12_active_scanning(state: WorkflowState) -> WorkflowState:
    """
    PHASE 12: Active Vulnerability Scanning
    Executes enterprise scanners (Nuclei, Nikto) to discover advanced flaws.
    """
    ConsoleUI.info(f"Executing Phase 12 Active Scanning against: {state.normalized_target}")
    
    gov = RuntimeGovernor.instance()
    if gov.mode == ScanMode.PASSIVE:
        ConsoleUI.info("Skipping active scanning (PASSIVE mode).")
        return state

    scanner = ActiveScanner()
    
    # Run Nuclei (Respecting governor mode and AI pre-plan)
    nuclei_findings = scanner.run_nuclei(state.normalized_target, gov.mode, state.tool_execution_plan)
    if nuclei_findings:
        ConsoleUI.success(f"Nuclei discovered {len(nuclei_findings)} vulnerabilities.")
        state.findings.extend(nuclei_findings)
        
    nikto_findings = []
    sqlmap_findings = []
    
    # Only run extremely noisy/legacy scanners in DEEP_ANALYSIS
    if gov.mode == ScanMode.DEEP_ANALYSIS:
        # Run Nikto
        nikto_findings = scanner.run_nikto(state.normalized_target)
        if nikto_findings:
            ConsoleUI.success(f"Nikto discovered web server flaws.")
            state.findings.extend(nikto_findings)
            
        # Run SQLMap
        sqlmap_findings = scanner.run_sqlmap(state.normalized_target)
        if sqlmap_findings:
            ConsoleUI.success(f"SQLMap discovered injection vulnerabilities.")
            state.findings.extend(sqlmap_findings)
    else:
        ConsoleUI.info("Skipping legacy Nikto/SQLMap scanning. (Enable DEEP_ANALYSIS for full active exploitation).")
        
    state.evidence_ledger.append({
        "stage": "PHASE_12_ACTIVE_SCANNING",
        "timestamp": time.time(),
        "action": "enterprise_scanners",
        "result": f"Nuclei: {len(nuclei_findings)} | Nikto: {len(nikto_findings)} | SQLMap: {len(sqlmap_findings)}"
    })
    
    return state
