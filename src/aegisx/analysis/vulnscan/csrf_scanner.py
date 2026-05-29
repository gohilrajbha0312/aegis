"""
AEGIS-X CSRF Scanner
Algorithm: Token presence/absence analysis + SameSite cookie checking + Referer enforcement.
"""
import re
from aegisx.core import http_client as requests
from typing import Dict, Any, List
from urllib.parse import urljoin

from aegisx.core.ui.console import ConsoleUI

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False


class CSRFScanner:

    TOKEN_NAMES = ["csrf", "_token", "authenticity_token", "csrfmiddlewaretoken",
                   "__RequestVerificationToken", "csrf_token", "token", "_csrf"]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Check SameSite cookie attribute
        cookie_finding = self._check_samesite_cookies(base_url)
        if cookie_finding:
            findings.append(cookie_finding)

        # Check forms for CSRF tokens
        form_findings = self._check_forms(base_url, routes)
        findings.extend(form_findings)

        # Check Referer/Origin enforcement
        referer_finding = self._check_referer_enforcement(base_url, routes)
        if referer_finding:
            findings.append(referer_finding)

        return findings

    def _check_samesite_cookies(self, base_url: str) -> Dict[str, Any] | None:
        try:
            resp = requests.get(base_url, timeout=5)
            cookies_raw = resp.headers.get("Set-Cookie", "")
            if cookies_raw and "samesite" not in cookies_raw.lower():
                return {
                    "finding_type": "CSRF - Missing SameSite Cookie Attribute",
                    "base_confidence": 0.80, "consensus_score": 0.80, "score_conflict": False,
                    "risk_level": "MEDIUM", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Set SameSite=Strict or SameSite=Lax on all session cookies",
                        "Implement anti-CSRF tokens on all state-changing forms",
                    ],
                    "reasoning": [
                        "Session cookies lack SameSite attribute",
                        f"Cookie header: {cookies_raw[:200]}",
                    ],
                    "nodes": [], "edges": [],
                }
        except Exception:
            pass
        return None

    def _check_forms(self, base_url: str, routes: List[str]) -> List[Dict[str, Any]]:
        if not _BS4:
            return []
        findings = []
        checked = set()

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            if url in checked:
                continue
            checked.add(url)

            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 200:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                forms = soup.find_all("form", method=re.compile("post", re.I))

                for form in forms:
                    action = form.get("action", "")
                    has_token = False
                    for name in self.TOKEN_NAMES:
                        if form.find("input", {"name": re.compile(name, re.I)}):
                            has_token = True
                            break
                        hidden = form.find_all("input", {"type": "hidden"})
                        for h in hidden:
                            if h.get("name", "").lower() in [n.lower() for n in self.TOKEN_NAMES]:
                                has_token = True
                                break

                    if not has_token:
                        ConsoleUI.warning(f"[CSRF] No anti-CSRF token on form at {url} (action={action})")
                        findings.append({
                            "finding_type": "CSRF - Missing Anti-CSRF Token",
                            "base_confidence": 0.88, "consensus_score": 0.88, "score_conflict": False,
                            "risk_level": "HIGH", "governance_class": "PASSIVE_ANALYSIS",
                            "requires_human_approval": False,
                            "recommended_validation": [
                                "Add anti-CSRF tokens to all state-changing forms",
                                "Use framework-provided CSRF protection (Django, Rails, etc.)",
                            ],
                            "reasoning": [
                                f"POST form at {url} (action='{action}') has no CSRF token",
                                "Attacker can forge cross-site requests to perform actions",
                            ],
                            "nodes": [], "edges": [],
                        })
            except Exception:
                pass

        return findings

    def _check_referer_enforcement(self, base_url: str, routes: List[str]) -> Dict[str, Any] | None:
        """Check if server enforces Referer/Origin headers."""
        post_routes = [r for r in routes if any(
            kw in r.lower() for kw in ["login", "submit", "update", "delete", "create", "admin"]
        )]
        if not post_routes:
            post_routes = ["/login"]

        for route in post_routes[:2]:
            url = f"{base_url}{route}" if route.startswith("/") else route
            try:
                # Send POST without Referer/Origin
                resp_no_ref = requests.post(url, data={"test": "1"}, timeout=5,
                                            headers={"Referer": "", "Origin": ""}, allow_redirects=False)
                # Send POST with evil Referer
                resp_evil = requests.post(url, data={"test": "1"}, timeout=5,
                                          headers={"Referer": "https://evil.com", "Origin": "https://evil.com"},
                                          allow_redirects=False)

                if resp_no_ref.status_code not in [403, 401] and resp_evil.status_code not in [403, 401]:
                    return {
                        "finding_type": "CSRF - No Referer/Origin Validation",
                        "base_confidence": 0.75, "consensus_score": 0.75, "score_conflict": False,
                        "risk_level": "MEDIUM", "governance_class": "PASSIVE_ANALYSIS",
                        "requires_human_approval": False,
                        "recommended_validation": [
                            "Validate Referer and Origin headers on state-changing requests",
                            "Combine with anti-CSRF tokens for defense-in-depth",
                        ],
                        "reasoning": [
                            f"Endpoint {url} accepts requests without valid Referer/Origin",
                            "Cross-origin requests are not blocked",
                        ],
                        "nodes": [], "edges": [],
                    }
            except Exception:
                pass
        return None
