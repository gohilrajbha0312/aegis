from aegisx.core import http_client as requests
from typing import Dict, Any, List
from aegisx.core.ui.console import ConsoleUI

class DirectoryVulnerabilityEngine:
    """
    Actively checks for Path Traversal and Open Directory Listing vulnerabilities.
    """
    
    def check_vulnerabilities(self, target: str, discovered_routes: List[str]) -> Dict[str, Any]:
        ConsoleUI.info(f"Scanning for Directory Vulnerabilities on {target}...")
        
        flags = []
        score = 100
        
        # 1. Check Path Traversal
        traversal_payloads = [
            "../../../../../../../../../etc/passwd",
            "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"
        ]
        
        for route in discovered_routes[:5]: # Limit to avoid aggressive scanning
            for payload in traversal_payloads:
                test_url = f"http://{target}{route}/{payload}"
                try:
                    resp = requests.get(test_url, timeout=3)
                    if "root:x:0:0:" in resp.text:
                        flags.append(f"CRITICAL: Path Traversal Vulnerability detected on {route}")
                        score -= 50
                        break
                except:
                    pass
                    
        # 2. Check Directory Listing
        dir_listing_signatures = ["Index of /", "Parent Directory"]
        for route in discovered_routes:
            # Often directories end with /
            if not route.endswith("/"):
                test_url = f"http://{target}{route}/"
            else:
                test_url = f"http://{target}{route}"
                
            try:
                resp = requests.get(test_url, timeout=3)
                for sig in dir_listing_signatures:
                    if sig in resp.text:
                        flags.append(f"WARNING: Open Directory Listing detected on {test_url}")
                        score -= 20
                        break
            except:
                pass
                
        if flags:
            for flag in flags:
                ConsoleUI.warning(flag)
        else:
            ConsoleUI.success("No obvious directory vulnerabilities found.")
            
        return {
            "directory_vuln_score": max(0, score),
            "flags": flags,
            "requires_remediation": score < 100
        }
