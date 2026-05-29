"""
AEGIS-X JavaScript Weakness Scanner
Algorithm: Static analysis for security anti-patterns in JavaScript resources.
"""
import re
from aegisx.core import http_client as requests
from typing import Dict, Any, List

from aegisx.core.ui.console import ConsoleUI


class JSWeaknessScanner:

    # Dangerous patterns in JavaScript
    PATTERNS = {
        "eval_usage": {
            "regex": r'\beval\s*\([^)]+\)',
            "risk": "eval() usage — potential code injection",
            "severity": "HIGH",
        },
        "innerhtml_assignment": {
            "regex": r'\.innerHTML\s*=\s*[^;]+',
            "risk": "innerHTML assignment — DOM XSS risk",
            "severity": "MEDIUM",
        },
        "document_write": {
            "regex": r'document\.write\s*\([^)]+\)',
            "risk": "document.write() — DOM manipulation risk",
            "severity": "MEDIUM",
        },
        "postmessage_no_origin": {
            "regex": r'addEventListener\s*\(\s*["\']message["\']\s*,\s*function\s*\([^)]*\)\s*\{(?:(?!origin).)*\}',
            "risk": "postMessage listener without origin check",
            "severity": "HIGH",
        },
        "hardcoded_api_key": {
            "regex": r'(?:api[_-]?key|apikey|api_secret|secret_key|access_token)\s*[:=]\s*["\'][a-zA-Z0-9_\-]{20,}["\']',
            "risk": "Hardcoded API key/secret in JavaScript",
            "severity": "CRITICAL",
        },
        "hardcoded_password": {
            "regex": r'(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']',
            "risk": "Hardcoded password in JavaScript",
            "severity": "CRITICAL",
        },
        "aws_key": {
            "regex": r'AKIA[0-9A-Z]{16}',
            "risk": "AWS Access Key ID exposed in JavaScript",
            "severity": "CRITICAL",
        },
        "jwt_token": {
            "regex": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+',
            "risk": "JWT token hardcoded in JavaScript",
            "severity": "HIGH",
        },
        "prototype_pollution": {
            "regex": r'(?:__proto__|constructor\s*\[\s*["\']prototype["\']\s*\]|Object\.assign\s*\(\s*\{\})',
            "risk": "Potential prototype pollution pattern",
            "severity": "MEDIUM",
        },
        "insecure_random": {
            "regex": r'Math\.random\s*\(\)',
            "risk": "Math.random() used — not cryptographically secure",
            "severity": "LOW",
        },
    }

    # Known vulnerable JS library patterns
    VULNERABLE_LIBS = {
        r'jquery[.-]1\.\d+': "jQuery 1.x — multiple known XSS vulnerabilities",
        r'jquery[.-]2\.[0-2]': "jQuery 2.0-2.2 — known XSS vulnerabilities",
        r'angular[.-]1\.[0-5]': "AngularJS 1.0-1.5 — known sandbox escapes",
        r'lodash[.-][0-3]\.': "Lodash < 4.0 — prototype pollution CVE",
        r'bootstrap[.-][23]\.': "Bootstrap 2.x/3.x — known XSS in tooltip/popover",
        r'moment[.-]2\.[0-9]\.': "Moment.js < 2.10 — ReDoS vulnerability",
    }

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Discover and analyze JS files
        js_urls = self._discover_js(base_url, routes)
        ConsoleUI.info(f"[JS-Weakness] Analyzing {len(js_urls)} JavaScript resources")

        all_issues = []
        for js_url in js_urls:
            issues = self._analyze_js(js_url)
            all_issues.extend(issues)

        # Analyze inline scripts
        for route in routes[:10]:
            url = f"{base_url}{route}" if route.startswith("/") else route
            inline_issues = self._analyze_inline(url)
            all_issues.extend(inline_issues)

        # Group by severity
        if all_issues:
            critical = [i for i in all_issues if i["severity"] == "CRITICAL"]
            high = [i for i in all_issues if i["severity"] == "HIGH"]
            medium_low = [i for i in all_issues if i["severity"] in ["MEDIUM", "LOW"]]

            if critical:
                findings.append({
                    "finding_type": "JavaScript Weakness - Critical Secrets Exposure",
                    "base_confidence": 0.92, "consensus_score": 0.92, "score_conflict": False,
                    "risk_level": "CRITICAL", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Remove all hardcoded secrets from JavaScript",
                        "Rotate all exposed API keys and tokens immediately",
                        "Use environment variables or server-side config for secrets",
                    ],
                    "reasoning": [i["detail"] for i in critical[:5]],
                    "nodes": [], "edges": [],
                })

            if high:
                findings.append({
                    "finding_type": "JavaScript Weakness - Dangerous Code Patterns",
                    "base_confidence": 0.80, "consensus_score": 0.80, "score_conflict": False,
                    "risk_level": "HIGH", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Avoid eval(), innerHTML, document.write() with user data",
                        "Validate postMessage origin in event listeners",
                    ],
                    "reasoning": [i["detail"] for i in high[:5]],
                    "nodes": [], "edges": [],
                })

            if medium_low:
                findings.append({
                    "finding_type": "JavaScript Weakness - Code Quality Issues",
                    "base_confidence": 0.65, "consensus_score": 0.65, "score_conflict": False,
                    "risk_level": "LOW", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": ["Review JavaScript code quality and security patterns"],
                    "reasoning": [i["detail"] for i in medium_low[:5]],
                    "nodes": [], "edges": [],
                })

        # Check for vulnerable libraries
        lib_findings = self._check_vulnerable_libs(js_urls)
        findings.extend(lib_findings)

        return findings

    def _discover_js(self, base_url: str, routes: List[str]) -> List[str]:
        js_urls = set()
        for route in routes[:10]:
            url = f"{base_url}{route}" if route.startswith("/") else route
            try:
                resp = requests.get(url, timeout=5)
                if resp.status_code != 200:
                    continue
                scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I)
                for s in scripts:
                    if s.startswith("//"):
                        js_urls.add(f"http:{s}")
                    elif s.startswith("/"):
                        js_urls.add(f"{base_url}{s}")
                    elif s.startswith("http"):
                        js_urls.add(s)
            except Exception:
                pass
        return list(js_urls)[:20]

    def _analyze_js(self, js_url: str) -> List[Dict]:
        issues = []
        try:
            resp = requests.get(js_url, timeout=10)
            if resp.status_code != 200:
                return issues
            content = resp.text
            for name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern["regex"], content, re.I)
                if matches:
                    issues.append({
                        "severity": pattern["severity"],
                        "detail": f"{pattern['risk']} in {js_url} ({len(matches)} occurrence(s))",
                    })
        except Exception:
            pass
        return issues

    def _analyze_inline(self, url: str) -> List[Dict]:
        issues = []
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                return issues
            inline = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.S | re.I)
            combined = "\n".join(inline)
            if len(combined) < 20:
                return issues
            for name, pattern in self.PATTERNS.items():
                matches = re.findall(pattern["regex"], combined, re.I)
                if matches:
                    issues.append({
                        "severity": pattern["severity"],
                        "detail": f"{pattern['risk']} in inline script at {url}",
                    })
        except Exception:
            pass
        return issues

    def _check_vulnerable_libs(self, js_urls: List[str]) -> List[Dict[str, Any]]:
        findings = []
        for js_url in js_urls:
            for pattern, risk in self.VULNERABLE_LIBS.items():
                if re.search(pattern, js_url, re.I):
                    findings.append({
                        "finding_type": "JavaScript Weakness - Vulnerable Library",
                        "base_confidence": 0.80, "consensus_score": 0.80, "score_conflict": False,
                        "risk_level": "MEDIUM", "governance_class": "PASSIVE_ANALYSIS",
                        "requires_human_approval": False,
                        "recommended_validation": ["Update library to latest version"],
                        "reasoning": [f"{risk}", f"URL: {js_url}"],
                        "nodes": [], "edges": [],
                    })
        return findings
