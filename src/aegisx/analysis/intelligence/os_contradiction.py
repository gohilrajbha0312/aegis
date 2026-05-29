from typing import Dict, Any, List

class OSContradictionDetector:
    """
    Multi-source OS verification.
    Detects contradictions between lower-level network scanning and application-level banners.
    """
    def evaluate(self, network_evidence: Dict[str, Any], app_evidence: Dict[str, Any]) -> Dict[str, Any]:
        """
        Takes Nmap OS detection and compares it against HTTP/Service banners.
        """
        nmap_os = network_evidence.get("os_match", "Unknown")
        app_server = app_evidence.get("server_header", "Unknown")
        
        contradiction = False
        details = []
        
        # Simple heuristic check
        if "Linux" in nmap_os and "IIS" in app_server:
            contradiction = True
            details.append("Network signature claims Linux, but HTTP banner claims IIS (Windows).")
            
        if "Windows" in nmap_os and "Ubuntu" in app_server:
            contradiction = True
            details.append("Network signature claims Windows, but HTTP banner claims Ubuntu (Linux).")
            
        return {
            "contradiction_detected": contradiction,
            "details": details,
            "confidence_penalty": 0.3 if contradiction else 0.0,
            "signal": "CONTRADICTORY_OS_SIGNAL" if contradiction else "OS_VERIFIED"
        }
