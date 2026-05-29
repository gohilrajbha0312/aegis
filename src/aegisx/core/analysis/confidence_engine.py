from typing import List, Dict, Any

class ConfidenceEngine:
    """Calculates finding confidence based on evidence and logic."""
    
    @staticmethod
    def calculate_confidence(
        evidence_count: int, 
        independent_sources: int, 
        similarity_score: float,
        ownership_proven: bool,
        authorization_proven: bool
    ) -> float:
        """
        Scales from 0.0 to 1.0.
        """
        base_score = 0.2
        
        # Evidence volume
        base_score += min(0.3, evidence_count * 0.1)
        
        # Independent validation sources
        base_score += min(0.3, independent_sources * 0.15)
        
        # High similarity indicates lack of access control changes
        if similarity_score > 0.95:
            base_score += 0.1
            
        if ownership_proven:
            base_score += 0.2
            
        if authorization_proven:
            base_score += 0.2
            
        return min(1.0, base_score)
