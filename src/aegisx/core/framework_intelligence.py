from typing import Dict, Any, List

class FrameworkIntelligence:
    """
    Analyzes target headers, cookies, and passive data to infer the underlying
    technology stack. Provides tailored validation profiles to avoid unhandled
    framework exceptions (e.g., Express.js crashing on unexpected path patterns).
    """
    
    @staticmethod
    def infer_framework(headers: Dict[str, str], passive_data: List[Any]) -> str:
        """Heuristic inference of the target framework."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        # Check explicit headers
        powered_by = headers_lower.get("x-powered-by", "")
        if "express" in powered_by:
            return "Express.js"
        if "next" in powered_by or "next.js" in powered_by:
            return "Next.js"
        
        # Check cookies
        cookies = headers_lower.get("set-cookie", "")
        if "connect.sid" in cookies:
            return "Express.js"
        if "sessionid" in cookies and "csrftoken" in cookies:
            return "Django"
            
        # Check passive data signatures
        for data in passive_data:
            data_str = str(data).lower()
            if "_next/static" in data_str:
                return "Next.js"
            if "angular" in data_str:
                return "Angular"
            if "wp-content" in data_str:
                return "WordPress"
                
        return "Unknown"
        
    @staticmethod
    def get_safe_payloads(framework: str, intent: str) -> List[str]:
        """
        Returns payloads tailored to not crash the specific framework.
        E.g., Express router fails on certain wildcards or malformed URIs.
        """
        if framework == "Express.js":
            if intent == "SQLi":
                return ["' OR 1=1--", "1; SLEEP(0)--"] # Safe SQLi that won't break URI routing
            elif intent == "IDOR":
                return ["9999", "admin"] # Avoid passing objects/arrays if string expected
        elif framework == "Next.js":
            if intent == "XSS":
                # React sanitizes well, focus on dangerous props
                return ["javascript:alert(1)"]
                
        # Default generic safe payloads
        if intent == "SQLi":
            return ["'"]
        if intent == "IDOR":
            return ["0", "1"]
        return []
