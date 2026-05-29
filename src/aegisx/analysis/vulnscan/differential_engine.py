import httpx
import json
from typing import Dict, Any, Tuple
from aegisx.analysis.auth.session_intelligence import session_manager

class DifferentialEngine:
    """Enterprise-grade differential analysis for semantic comparison of responses."""
    
    def __init__(self):
        self.session_manager = session_manager

    def compare_responses(self, resp_a: httpx.Response, resp_b: httpx.Response) -> Dict[str, Any]:
        """Compute the deterministic difference between two HTTP responses."""
        
        status_match = resp_a.status_code == resp_b.status_code
        len_a = len(resp_a.text)
        len_b = len(resp_b.text)
        
        # Calculate size difference percentage
        if max(len_a, len_b) > 0:
            size_similarity = 1.0 - (abs(len_a - len_b) / max(len_a, len_b))
        else:
            size_similarity = 1.0

        # Try JSON schema comparison
        json_similarity = 0.0
        field_delta = []
        try:
            json_a = resp_a.json()
            json_b = resp_b.json()
            
            if isinstance(json_a, dict) and isinstance(json_b, dict):
                keys_a = set(json_a.keys())
                keys_b = set(json_b.keys())
                
                shared_keys = keys_a.intersection(keys_b)
                all_keys = keys_a.union(keys_b)
                
                if all_keys:
                    json_similarity = len(shared_keys) / len(all_keys)
                
                # Fields in A but not B
                for k in keys_a - keys_b:
                    field_delta.append(f"Field '{k}' only in A")
                # Fields in B but not A
                for k in keys_b - keys_a:
                    field_delta.append(f"Field '{k}' only in B")
        except json.JSONDecodeError:
            json_similarity = -1.0 # Not JSON
            
        return {
            "status_match": status_match,
            "status_a": resp_a.status_code,
            "status_b": resp_b.status_code,
            "size_similarity": round(size_similarity, 2),
            "json_similarity": round(json_similarity, 2),
            "field_delta": field_delta
        }

    def test_idor_hypothesis(self, method: str, url: str, base_context: str = "admin", test_context: str = "user") -> Tuple[float, Dict[str, Any]]:
        """
        Executes a differential test to validate an IDOR hypothesis.
        Returns (confidence_score, analysis_dict)
        """
        try:
            resp_base = self.session_manager.execute_in_context(base_context, method, url)
            resp_test = self.session_manager.execute_in_context(test_context, method, url)
            
            diff = self.compare_responses(resp_base, resp_test)
            
            confidence = 0.0
            
            # If a lower-privileged user gets the exact same 200 OK success response as the admin
            if diff["status_a"] == 200 and diff["status_match"]:
                if diff["json_similarity"] > 0.90 or diff["size_similarity"] > 0.95:
                    confidence = 0.95 # High confidence IDOR / BOLA
                elif diff["json_similarity"] > 0.50:
                    confidence = 0.70 # Partial data exposure
            
            # If lower privileged user gets a 403/401, it's blocked correctly
            elif diff["status_test"] in [401, 403]:
                confidence = 0.0
                
            return confidence, diff
            
        except Exception as e:
            return 0.0, {"error": str(e)}

differential_engine = DifferentialEngine()
