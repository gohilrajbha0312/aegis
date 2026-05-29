"""
AEGIS-X CSP Bypass Scanner
Algorithm: Content Security Policy header parsing + bypass vector identification.
"""
import re
from aegisx.core import http_client as requests
from typing import Dict, Any, List

from aegisx.core.ui.console import ConsoleUI


class CSPBypassScanner:

    DANGEROUS_DIRECTIVES = {
        "unsafe-inline": "Allows inline scripts/styles — XSS via inline injection",
        "unsafe-eval": "Allows eval() — code injection via eval",
        "data:": "Allows data: URIs — XSS via data:text/html",
        "*": "Wildcard source — any domain can serve scripts/styles",
    }

    MISSING_DIRECTIVES = {
        "default-src": "No default fallback policy",
        "script-src": "No script source restriction",
        "object-src": "Allows Flash/Java plugins — potential XSS bypass",
        "base-uri": "Allows base tag injection — relative URL hijacking",
        "form-action": "No form submission restrictions — data exfiltration risk",
        "frame-ancestors": "No clickjacking protection via CSP",
    }

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Analyze CSP headers
        csp_finding = self._analyze_csp(base_url)
        if csp_finding:
            findings.append(csp_finding)

        # Check for X-Content-Type-Options
        mime_finding = self._check_mime_sniffing(base_url)
        if mime_finding:
            findings.append(mime_finding)

        # Check for missing security headers
        header_finding = self._check_security_headers(base_url)
        if header_finding:
            findings.append(header_finding)

        return findings

    def _analyze_csp(self, base_url: str) -> Dict[str, Any] | None:
        try:
            resp = requests.get(base_url, timeout=5)
        except Exception:
            return None

        csp = resp.headers.get("Content-Security-Policy", "")
        csp_ro = resp.headers.get("Content-Security-Policy-Report-Only", "")

        if not csp and not csp_ro:
            return {
                "finding_type": "CSP Bypass - No Content Security Policy",
                "base_confidence": 0.85, "consensus_score": 0.85, "score_conflict": False,
                "risk_level": "MEDIUM", "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Implement a strict Content Security Policy",
                    "Start with: default-src 'self'; script-src 'self'; object-src 'none'",
                    "Use CSP nonces or hashes instead of unsafe-inline",
                ],
                "reasoning": [
                    "No Content-Security-Policy header present",
                    "Application is vulnerable to XSS payload execution",
                ],
                "nodes": [], "edges": [],
            }

        # Parse CSP directives
        policy = csp or csp_ro
        directives = {}
        for part in policy.split(";"):
            part = part.strip()
            if part:
                tokens = part.split()
                if tokens:
                    directives[tokens[0]] = tokens[1:] if len(tokens) > 1 else []

        issues = []

        # Check for dangerous values
        for directive, values in directives.items():
            for val in values:
                val_lower = val.lower().strip("'")
                if val_lower in self.DANGEROUS_DIRECTIVES:
                    issues.append(f"{directive} contains '{val}': {self.DANGEROUS_DIRECTIVES[val_lower]}")

        # Check for missing critical directives
        for directive, risk in self.MISSING_DIRECTIVES.items():
            if directive not in directives:
                # default-src covers missing directives
                if directive != "default-src" and "default-src" in directives:
                    continue
                issues.append(f"Missing '{directive}': {risk}")

        # Check for JSONP bypass potential
        for directive, values in directives.items():
            if directive in ["script-src", "default-src"]:
                for val in values:
                    if "googleapis.com" in val or "cdnjs.cloudflare.com" in val:
                        issues.append(f"'{val}' whitelisted in {directive} — potential JSONP/Angular bypass")
                    if "*.google.com" in val or "*.googleapis.com" in val:
                        issues.append(f"Broad domain wildcard '{val}' — JSONP endpoints may bypass CSP")

        if issues:
            risk = "HIGH" if any("unsafe-inline" in i or "unsafe-eval" in i or "Wildcard" in i for i in issues) else "MEDIUM"
            return {
                "finding_type": "CSP Bypass - Weak Content Security Policy",
                "base_confidence": 0.82, "consensus_score": 0.82, "score_conflict": False,
                "risk_level": risk, "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Remove unsafe-inline and unsafe-eval from CSP",
                    "Use nonce-based or hash-based CSP for inline scripts",
                    "Restrict script-src to specific trusted domains",
                    "Add object-src 'none' and base-uri 'self'",
                ],
                "reasoning": [f"CSP: {policy[:200]}"] + issues,
                "nodes": [], "edges": [],
            }
        return None

    def _check_mime_sniffing(self, base_url: str) -> Dict[str, Any] | None:
        try:
            resp = requests.get(base_url, timeout=5)
            xcto = resp.headers.get("X-Content-Type-Options", "")
            if xcto.lower() != "nosniff":
                return {
                    "finding_type": "CSP Bypass - Missing X-Content-Type-Options",
                    "base_confidence": 0.70, "consensus_score": 0.70, "score_conflict": False,
                    "risk_level": "LOW", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": ["Add header: X-Content-Type-Options: nosniff"],
                    "reasoning": ["Missing X-Content-Type-Options: nosniff", "Browser may MIME-sniff responses"],
                    "nodes": [], "edges": [],
                }
        except Exception:
            pass
        return None

    def _check_security_headers(self, base_url: str) -> Dict[str, Any] | None:
        try:
            resp = requests.get(base_url, timeout=5)
            missing = []
            if "X-Frame-Options" not in resp.headers:
                missing.append("X-Frame-Options (clickjacking protection)")
            if "Strict-Transport-Security" not in resp.headers:
                missing.append("Strict-Transport-Security (HSTS)")
            if "X-XSS-Protection" not in resp.headers:
                missing.append("X-XSS-Protection (legacy XSS filter)")
            if "Referrer-Policy" not in resp.headers:
                missing.append("Referrer-Policy")

            if missing:
                return {
                    "finding_type": "CSP Bypass - Missing Security Headers",
                    "base_confidence": 0.75, "consensus_score": 0.75, "score_conflict": False,
                    "risk_level": "LOW", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": ["Add all recommended security headers"],
                    "reasoning": ["Missing security headers:"] + missing,
                    "nodes": [], "edges": [],
                }
        except Exception:
            pass
        return None
