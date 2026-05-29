"""
AEGIS-X Command Injection Scanner
Algorithm: Payload injection with time-based and output-based confirmation.
Tools: commix (primary), custom Python payloads (fallback)
"""
import time
from aegisx.core import http_client as requests
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode

from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI


class CommandInjectionScanner:

    BLIND_PAYLOADS = [";sleep 5", "|sleep 5", "$(sleep 5)", "`sleep 5`", "& sleep 5 &", "|| sleep 5"]
    OUTPUT_PAYLOADS = [";id", "|id", "$(id)", "`id`", ";whoami", "|whoami"]
    CONFIRM_MARKERS = ["uid=", "gid=", "root:", "/bin/bash", "/bin/sh", "www-data"]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        commix_findings = self._run_commix(target, routes)
        findings.extend(commix_findings)
        custom_findings = self._custom_scan(target, routes)
        findings.extend(custom_findings)
        return findings

    def _run_commix(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"
        test_urls = []
        for r in routes:
            full = f"{base_url}{r}" if r.startswith("/") else r
            if "?" in full:
                test_urls.append(full)
            else:
                test_urls.append(f"{full}?cmd=test")

        for url in test_urls[:3]:
            cmd = ["commix", "--url", url, "--batch", "--level", "2", "--timeout", "10"]
            ConsoleUI.info(f"[CmdInjection] commix scanning: {url}")
            result = CommandGateway.execute(cmd, timeout=120, description="Command Injection Scan (commix)")
            stdout = result.get("stdout", "")
            if result["success"] and ("is vulnerable" in stdout.lower() or "injection point" in stdout.lower()):
                findings.append({
                    "finding_type": "Command Injection (OS) - commix confirmed",
                    "base_confidence": 0.98, "consensus_score": 0.98, "score_conflict": False,
                    "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Sanitize all user inputs", "Use parameterized APIs, not shell=True",
                        "Apply allowlist-based input validation",
                    ],
                    "reasoning": [f"commix confirmed injection at: {url}", stdout[:500]],
                    "nodes": [], "edges": [],
                })
        return findings

    def _custom_scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"
        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue
            for pname in params:
                r = self._test_time_based(url, pname, params)
                if r:
                    findings.append(r)
                    break
                r = self._test_output_based(url, pname, params)
                if r:
                    findings.append(r)
                    break
        return findings

    def _test_time_based(self, url, pname, base_params):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        try:
            start = time.time()
            requests.get(url, timeout=10)
            baseline = time.time() - start
        except Exception:
            return None
        for payload in self.BLIND_PAYLOADS:
            tp = {k: v[0] if isinstance(v, list) else v for k, v in base_params.items()}
            tp[pname] = str(tp.get(pname, "")) + payload
            try:
                start = time.time()
                requests.get(f"{base_url}?{urlencode(tp)}", timeout=15)
                elapsed = time.time() - start
                if elapsed - baseline > 4.0:
                    return {
                        "finding_type": "Command Injection (Blind Time-Based)",
                        "base_confidence": 0.92, "consensus_score": 0.92, "score_conflict": False,
                        "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                        "requires_human_approval": False,
                        "recommended_validation": ["Sanitize input", "Use subprocess with arg lists"],
                        "reasoning": [f"Time-based injection via '{pname}'", f"Payload: {payload} +{elapsed-baseline:.1f}s"],
                        "nodes": [], "edges": [],
                    }
            except Exception:
                pass
        return None

    def _test_output_based(self, url, pname, base_params):
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        try:
            baseline_text = requests.get(url, timeout=5).text
        except Exception:
            return None
        for payload in self.OUTPUT_PAYLOADS:
            tp = {k: v[0] if isinstance(v, list) else v for k, v in base_params.items()}
            tp[pname] = str(tp.get(pname, "")) + payload
            try:
                resp = requests.get(f"{base_url}?{urlencode(tp)}", timeout=10)
                for marker in self.CONFIRM_MARKERS:
                    if marker in resp.text and marker not in baseline_text:
                        return {
                            "finding_type": "Command Injection (Output-Based)",
                            "base_confidence": 0.97, "consensus_score": 0.97, "score_conflict": False,
                            "risk_level": "CRITICAL", "governance_class": "ACTIVE_VALIDATION",
                            "requires_human_approval": False,
                            "recommended_validation": ["Immediately patch — OS command execution confirmed"],
                            "reasoning": [f"Output injection via '{pname}'", f"Payload: {payload}, marker: {marker}"],
                            "nodes": [], "edges": [],
                        }
            except Exception:
                pass
        return None
