import json
from typing import Dict, Any, List

class StaticAnalysisBridge:
    """
    Ingests Semgrep / CodeQL output to correlate static findings with runtime evidence.
    Reduces hallucinations by validating API discoveries against source code AST.
    """
    def __init__(self):
        pass
        
    def parse_semgrep_json(self, filepath: str) -> List[Dict[str, Any]]:
        """Parses a Semgrep JSON report to extract findings."""
        findings = []
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                
            for result in data.get("results", []):
                findings.append({
                    "rule_id": result.get("check_id"),
                    "path": result.get("path"),
                    "line": result.get("start", {}).get("line"),
                    "message": result.get("extra", {}).get("message"),
                    "severity": result.get("extra", {}).get("severity"),
                    "source": "semgrep"
                })
        except Exception as e:
            pass
            
        return findings

    def correlate_runtime_findings(self, runtime_routes: List[str], sast_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlates discovered runtime routes with SAST findings to increase confidence.
        """
        correlated = []
        
        # Very simple correlation logic for demonstration
        for route in runtime_routes:
            route_endpoint = route.split("?")[0].split("/")[-1]
            
            for finding in sast_findings:
                # If the SAST finding mentions the endpoint path or a parameter
                if route_endpoint in finding["path"] or route_endpoint in finding["message"]:
                    correlated.append({
                        "runtime_route": route,
                        "static_finding": finding,
                        "confidence_boost": 0.2,
                        "correlation_type": "Static-to-Runtime"
                    })
                    
        return correlated
