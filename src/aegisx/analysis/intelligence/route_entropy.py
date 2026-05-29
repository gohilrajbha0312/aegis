import math
from typing import Dict, Any, List

class RouteEntropyEngine:
    """
    Analyzes discovered routes to identify high-risk endpoints using Shannon Entropy 
    and Token Risk Weighting.
    """
    
    HIGH_RISK_TOKENS = {
        "debug", "internal", "metrics", "admin", "graphql", 
        "actuator", "backup", "private", "test", "v2-beta"
    }

    def _shannon_entropy(self, data: str) -> float:
        """Calculates Shannon entropy of a string (useful for detecting UUIDs/Hashes)."""
        if not data:
            return 0
        entropy = 0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy += - p_x * math.log(p_x, 2)
        return entropy

    def score_route(self, route: str) -> Dict[str, Any]:
        """
        Scores a single route.
        """
        score = 0.0
        flags = []
        
        # Token Risk Weighting
        route_lower = route.lower()
        for token in self.HIGH_RISK_TOKENS:
            if token in route_lower:
                score += 0.4
                flags.append(f"High-Risk Token: {token}")
                
        # Entropy check on route segments (e.g. IDOR endpoints)
        segments = route.split('/')
        has_high_entropy_segment = False
        for segment in segments:
            if len(segment) > 10:
                ent = self._shannon_entropy(segment)
                if ent > 3.5:
                    has_high_entropy_segment = True
                    flags.append("High-Entropy Segment (Potential Token/UUID)")
                    break
                    
        if has_high_entropy_segment:
            score += 0.3
            
        return {
            "route": route,
            "risk_score": min(1.0, score),
            "flags": flags,
            "investigation_recommended": score >= 0.5
        }
