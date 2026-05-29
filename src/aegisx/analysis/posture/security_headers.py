from typing import Dict, Any, List

class SecurityHeaderAnalyzer:
    """
    HTTP Security Posture Analysis.
    Evaluates policy completeness scoring and header misconfigurations.
    """
    REQUIRED_HEADERS = {
        "Content-Security-Policy": 20,
        "Strict-Transport-Security": 20,
        "X-Frame-Options": 10,
        "X-Content-Type-Options": 10,
        "Referrer-Policy": 10,
        "Permissions-Policy": 10
    }

    def analyze(self, headers: Dict[str, str]) -> Dict[str, Any]:
        score = 100
        missing = []
        
        # Headers are usually case-insensitive, normalize them
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        
        for header, penalty in self.REQUIRED_HEADERS.items():
            if header.lower() not in normalized_headers:
                score -= penalty
                missing.append(header)
                
        # Specific check for weak CSP
        csp = normalized_headers.get("content-security-policy", "")
        if csp and "unsafe-inline" in csp:
            score -= 10
            missing.append("CSP contains unsafe-inline")
            
        return {
            "hardening_score": max(0, score),
            "missing_policies": missing,
            "remediation_recommended": score < 80
        }
