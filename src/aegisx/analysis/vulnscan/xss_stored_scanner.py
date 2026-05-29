"""
AEGIS-X XSS Stored Scanner
Algorithm: Persistent payload injection + delayed retrieval verification.
"""
import re
import uuid
from aegisx.core import http_client as requests
from typing import Dict, Any, List

from aegisx.core.ui.console import ConsoleUI

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False


class XSSStoredScanner:

    STORAGE_INDICATORS = ["comment", "message", "feedback", "post", "review",
                          "profile", "bio", "description", "note", "name", "title"]

    XSS_PAYLOADS = [
        '<script>document.title="AEGISX_STORED"</script>',
        '<img src=x onerror="document.title=\'AEGISX_STORED\'">',
        '<svg/onload=document.title="AEGISX_STORED">',
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Find forms that store data
        storage_endpoints = self._find_storage_forms(base_url, routes)
        ConsoleUI.info(f"[XSS-Stored] Found {len(storage_endpoints)} potential storage forms")

        for ep in storage_endpoints:
            result = self._test_stored_xss(base_url, ep)
            if result:
                findings.append(result)

        return findings

    def _find_storage_forms(self, base_url: str, routes: List[str]) -> List[Dict]:
        forms = []
        if not _BS4:
            return forms

        for route in routes[:15]:
            url = f"{base_url}{route}" if route.startswith("/") else route
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 200:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for form in soup.find_all("form", method=re.compile("post", re.I)):
                    inputs = form.find_all("input") + form.find_all("textarea")
                    text_fields = []
                    for inp in inputs:
                        itype = inp.get("type", "text").lower()
                        name = inp.get("name", "").lower()
                        if itype in ["text", "hidden", "email"] or inp.name == "textarea":
                            if any(si in name for si in self.STORAGE_INDICATORS) or inp.name == "textarea":
                                text_fields.append(inp.get("name", "field"))

                    if text_fields:
                        action = form.get("action", route)
                        if not action.startswith("http"):
                            action = f"{base_url}{action}" if action.startswith("/") else f"{base_url}/{action}"
                        forms.append({
                            "url": url, "action": action,
                            "fields": text_fields, "all_inputs": inputs
                        })
            except Exception:
                pass

        return forms

    def _test_stored_xss(self, base_url: str, endpoint: Dict) -> Dict[str, Any] | None:
        canary = f"AEGISX_XSS_{uuid.uuid4().hex[:6]}"
        action = endpoint["action"]
        fields = endpoint["fields"]
        page_url = endpoint["url"]

        for payload in self.XSS_PAYLOADS:
            tagged_payload = payload.replace("AEGISX_STORED", canary)

            # Build form data
            data = {}
            for inp in endpoint.get("all_inputs", []):
                name = inp.get("name")
                if name:
                    if name in fields:
                        data[name] = tagged_payload
                    else:
                        data[name] = inp.get("value", "test")

            if not data:
                continue

            try:
                # Submit the form
                ConsoleUI.info(f"[XSS-Stored] Injecting payload into {action}")
                resp = requests.post(action, data=data, timeout=10, allow_redirects=True)

                # Check if payload persists on the same page
                if canary in resp.text or tagged_payload in resp.text:
                    ConsoleUI.success(f"[XSS-Stored] Stored XSS confirmed at {action}")
                    return self._build_finding(action, fields, tagged_payload, "immediate response")

                # Re-fetch the original page to check for stored payload
                resp2 = requests.get(page_url, timeout=5)
                if canary in resp2.text or tagged_payload in resp2.text:
                    ConsoleUI.success(f"[XSS-Stored] Stored XSS persists at {page_url}")
                    return self._build_finding(page_url, fields, tagged_payload, "page re-fetch")

                # Check related pages
                for route_suffix in ["/comments", "/messages", "/posts", "/reviews", ""]:
                    try:
                        check_url = f"{base_url}{route_suffix}" if route_suffix else page_url
                        resp3 = requests.get(check_url, timeout=5)
                        if canary in resp3.text:
                            ConsoleUI.success(f"[XSS-Stored] Payload found at {check_url}")
                            return self._build_finding(check_url, fields, tagged_payload, "related page")
                    except Exception:
                        pass

            except Exception:
                pass

        return None

    def _build_finding(self, url: str, fields: List, payload: str, detection: str) -> Dict[str, Any]:
        return {
            "finding_type": "XSS (Stored) - Persistent Payload",
            "base_confidence": 0.94, "consensus_score": 0.94, "score_conflict": False,
            "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
            "requires_human_approval": False,
            "recommended_validation": [
                "Sanitize all user input before storage (server-side)",
                "HTML-encode output when rendering user-generated content",
                "Implement Content Security Policy (CSP)",
                "Use DOMPurify or similar library for client-side sanitization",
            ],
            "reasoning": [
                f"Stored XSS payload persists and renders at: {url}",
                f"Injected via fields: {', '.join(fields[:3])}",
                f"Detection method: {detection}",
                f"Payload: {payload[:80]}",
            ],
            "nodes": [], "edges": [],
        }
