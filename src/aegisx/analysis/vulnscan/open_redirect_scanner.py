"""
AEGIS-X Open HTTP Redirect Scanner
Algorithm: Parameter-based redirect injection + response Location header validation.
"""
import json
from aegisx.core import http_client as requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode

from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI


class OpenRedirectScanner:

    REDIRECT_PARAMS = ["url", "redirect", "next", "return", "goto", "dest",
                       "destination", "redir", "redirect_uri", "redirect_url",
                       "return_to", "returnTo", "continue", "target", "link",
                       "forward", "out", "view", "ref", "callback"]

    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "\\/\\/evil.com",
        "https://evil.com%23",
        "https://evil.com%2F%2F",
        "/\\evil.com",
        "https:evil.com",
        "http://evil.com@legitimate.com",
        "////evil.com",
        "https://evil.com/legitimate.com",
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []

        # Nuclei redirect scan
        nuclei_findings = self._run_nuclei_redirect(target)
        findings.extend(nuclei_findings)

        # Custom parameter injection
        custom_findings = self._custom_redirect_scan(target, routes)
        findings.extend(custom_findings)

        return findings

    def _run_nuclei_redirect(self, target: str) -> List[Dict[str, Any]]:
        findings = []
        url = f"http://{target}"
        cmd = ["nuclei", "-u", url, "-tags", "redirect", "-j", "-silent", "-timeout", "5"]
        result = CommandGateway.execute(cmd, timeout=120, description="Open Redirect Scan (Nuclei)")

        if result["success"]:
            for line in result.get("stdout", "").strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        sev = data.get("info", {}).get("severity", "info").upper()
                        if sev == "INFO":
                            continue
                        findings.append({
                            "finding_type": f"Open HTTP Redirect [{data.get('template-id', '')}]",
                            "base_confidence": 0.90, "consensus_score": 0.90, "score_conflict": False,
                            "risk_level": "MEDIUM", "governance_class": "ACTIVE_VALIDATION",
                            "requires_human_approval": False,
                            "recommended_validation": ["Validate redirect URLs against allowlist"],
                            "reasoning": [data.get("info", {}).get("name", ""), f"Matched: {data.get('matched-at', '')}"],
                            "nodes": [], "edges": [],
                        })
                    except Exception:
                        pass
        return findings

    def _custom_redirect_scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"
        tested = set()

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Test existing redirect-like params
            for pname in params:
                if pname.lower() in self.REDIRECT_PARAMS:
                    key = f"{parsed.path}:{pname}"
                    if key in tested:
                        continue
                    tested.add(key)
                    result = self._test_redirect(url, pname, params)
                    if result:
                        findings.append(result)
                        break

            # Try adding common redirect params
            if not params:
                for rp in self.REDIRECT_PARAMS[:5]:
                    result = self._test_redirect(url + f"?{rp}=test", rp, {rp: ["test"]})
                    if result:
                        findings.append(result)
                        break

        return findings

    def _test_redirect(self, url: str, param: str, params: dict) -> Dict[str, Any] | None:
        parsed = urlparse(url)
        burl = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload in self.REDIRECT_PAYLOADS[:5]:
            tp = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
            tp[param] = payload
            try:
                resp = requests.get(f"{burl}?{urlencode(tp)}", timeout=5, allow_redirects=False)

                # Check for redirect in Location header
                if resp.status_code in [301, 302, 303, 307, 308]:
                    location = resp.headers.get("Location", "")
                    if "evil.com" in location:
                        ConsoleUI.success(f"[OpenRedirect] Confirmed: {param} -> {location}")
                        return {
                            "finding_type": "Open HTTP Redirect",
                            "base_confidence": 0.93, "consensus_score": 0.93, "score_conflict": False,
                            "risk_level": "MEDIUM", "governance_class": "ACTIVE_VALIDATION",
                            "requires_human_approval": False,
                            "recommended_validation": [
                                "Validate redirect URLs against a strict allowlist",
                                "Use relative paths for internal redirects",
                                "Never use user input directly in Location headers",
                            ],
                            "reasoning": [
                                f"Open redirect via parameter '{param}'",
                                f"Payload: {payload}",
                                f"Redirects to: {location}",
                                f"URL: {burl}",
                            ],
                            "nodes": [], "edges": [],
                        }

                # Check for meta refresh redirect
                if resp.status_code == 200 and "evil.com" in resp.text.lower():
                    if "meta http-equiv" in resp.text.lower() or "window.location" in resp.text.lower():
                        return {
                            "finding_type": "Open HTTP Redirect (Client-Side)",
                            "base_confidence": 0.80, "consensus_score": 0.80, "score_conflict": False,
                            "risk_level": "LOW", "governance_class": "PASSIVE_ANALYSIS",
                            "requires_human_approval": False,
                            "recommended_validation": ["Validate redirect targets server-side"],
                            "reasoning": [
                                f"Client-side redirect via '{param}'",
                                f"Payload: {payload}",
                            ],
                            "nodes": [], "edges": [],
                        }
            except Exception:
                pass
        return None
