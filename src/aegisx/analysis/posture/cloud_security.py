from typing import Dict, Any, List

class CloudSecurityPostureEngine:
    """
    Cloud Configuration Analysis.
    Detects public storage exposure, weak IAM posture, and metadata leakage.
    """
    
    def analyze_cloud_exposure(self, discovered_routes: List[str], header_data: Dict[str, str]) -> Dict[str, Any]:
        flags = []
        score = 100
        
        # 1. Cloud Metadata Exposure Detection
        metadata_indicators = ["169.254.169.254", "/latest/meta-data/"]
        for route in discovered_routes:
            for ind in metadata_indicators:
                if ind in route:
                    flags.append(f"CRITICAL: Potential Cloud Metadata SSRF route detected: {route}")
                    score -= 50
                    
        # 2. Public Storage Exposure Detection
        storage_indicators = ["s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net"]
        for route in discovered_routes:
            for ind in storage_indicators:
                if ind in route:
                    flags.append(f"WARNING: Public cloud storage bucket referenced: {route}")
                    score -= 20
                    
        return {
            "cloud_posture_score": max(0, score),
            "flags": flags,
            "least_privilege_review_recommended": score < 100
        }
