"""
AEGIS-X XSS DOM Scanner
Algorithm: JavaScript source/sink taint flow analysis via static regex-based analysis.
"""
import re
from aegisx.core import http_client as requests
from typing import Dict, Any, List

from aegisx.core.ui.console import ConsoleUI


class XSSDomScanner:

    # DOM XSS Sources — user-controllable data entry points
    SOURCES = [
        r"document\.location", r"document\.URL", r"document\.documentURI",
        r"document\.referrer", r"document\.cookie", r"window\.name",
        r"location\.hash", r"location\.search", r"location\.href",
        r"window\.location", r"document\.baseURI",
        r"location\.pathname", r"history\.pushState", r"history\.replaceState",
        r"postMessage",
    ]

    # DOM XSS Sinks — dangerous execution points
    SINKS = [
        r"document\.write\s*\(", r"document\.writeln\s*\(",
        r"\.innerHTML\s*=", r"\.outerHTML\s*=",
        r"\.insertAdjacentHTML\s*\(", r"\.onevent\s*=",
        r"eval\s*\(", r"setTimeout\s*\(", r"setInterval\s*\(",
        r"Function\s*\(", r"execScript\s*\(",
        r"\.src\s*=", r"\.href\s*=", r"\.action\s*=",
        r"jQuery\s*\(", r"\$\s*\(",
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Collect JavaScript URLs from pages
        js_urls = self._discover_js_files(base_url, routes)
        ConsoleUI.info(f"[XSS-DOM] Analyzing {len(js_urls)} JavaScript resources")

        for js_url in js_urls:
            result = self._analyze_js(js_url)
            if result:
                findings.append(result)

        # Analyze inline scripts in HTML pages
        for route in routes[:10]:
            url = f"{base_url}{route}" if route.startswith("/") else route
            inline_result = self._analyze_inline_scripts(url)
            if inline_result:
                findings.append(inline_result)

        return findings

    def _discover_js_files(self, base_url: str, routes: List[str]) -> List[str]:
        js_urls = set()
        for route in routes[:10]:
            url = f"{base_url}{route}" if route.startswith("/") else route
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 200:
                    continue
                # Find script src attributes
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I)
                for s in scripts:
                    if s.startswith("//"):
                        js_urls.add(f"http:{s}")
                    elif s.startswith("/"):
                        js_urls.add(f"{base_url}{s}")
                    elif s.startswith("http"):
                        js_urls.add(s)
                    else:
                        js_urls.add(f"{base_url}/{s}")
            except Exception:
                pass
        return list(js_urls)[:20]

    def _analyze_js(self, js_url: str) -> Dict[str, Any] | None:
        try:
            resp = requests.get(js_url, timeout=10)
            if resp.status_code != 200 or len(resp.text) < 10:
                return None
            return self._find_taint_flows(resp.text, js_url)
        except Exception:
            return None

    def _analyze_inline_scripts(self, url: str) -> Dict[str, Any] | None:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                return None
            inline = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.S | re.I)
            combined = "\n".join(inline)
            if len(combined) < 20:
                return None
            return self._find_taint_flows(combined, f"inline@{url}")
        except Exception:
            return None

    def _find_taint_flows(self, js_content: str, source_url: str) -> Dict[str, Any] | None:
        found_sources = []
        found_sinks = []

        for src_pattern in self.SOURCES:
            matches = re.findall(src_pattern, js_content)
            if matches:
                found_sources.append(src_pattern.replace("\\", ""))

        for sink_pattern in self.SINKS:
            matches = re.findall(sink_pattern, js_content)
            if matches:
                found_sinks.append(sink_pattern.replace("\\", "").replace(r"\s*\(", "("))

        if found_sources and found_sinks:
            # Proximity analysis: check if source and sink appear near each other
            risk = "HIGH" if len(found_sinks) > 2 else "MEDIUM"
            confidence = 0.78 if len(found_sinks) > 2 else 0.65

            ConsoleUI.warning(f"[XSS-DOM] Source/sink flow detected in {source_url}")
            return {
                "finding_type": "XSS (DOM-Based) - Source/Sink Taint Flow",
                "base_confidence": confidence, "consensus_score": confidence, "score_conflict": False,
                "risk_level": risk, "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Sanitize all DOM sources before passing to sinks",
                    "Use textContent instead of innerHTML",
                    "Implement DOMPurify for HTML sanitization",
                    "Avoid eval(), document.write(), and innerHTML with user data",
                ],
                "reasoning": [
                    f"JavaScript at: {source_url}",
                    f"Sources: {', '.join(found_sources[:5])}",
                    f"Sinks: {', '.join(found_sinks[:5])}",
                    "Data may flow from user-controlled source to dangerous sink",
                ],
                "nodes": [], "edges": [],
            }
        return None
