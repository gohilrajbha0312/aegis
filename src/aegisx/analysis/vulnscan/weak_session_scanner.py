"""
AEGIS-X Weak Session ID Scanner
Algorithm: Shannon entropy analysis + predictability testing + cookie attribute analysis.
"""
import math
import time
from aegisx.core import http_client as requests
import hashlib
from typing import Dict, Any, List
from collections import Counter

from aegisx.core.ui.console import ConsoleUI


class WeakSessionScanner:

    SESSION_COOKIE_NAMES = [
        "sessionid", "session_id", "sessid", "sid", "phpsessid",
        "jsessionid", "asp.net_sessionid", "connect.sid", "token",
        "auth_token", "access_token", "_session", "session",
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        # Collect session tokens
        tokens = self._collect_tokens(base_url)
        if not tokens:
            ConsoleUI.info("[WeakSession] No session cookies detected")
            return findings

        ConsoleUI.info(f"[WeakSession] Collected {len(tokens)} session tokens for analysis")

        # Entropy analysis
        entropy_finding = self._analyze_entropy(tokens, base_url)
        if entropy_finding:
            findings.append(entropy_finding)

        # Predictability / sequential analysis
        seq_finding = self._check_sequential(tokens, base_url)
        if seq_finding:
            findings.append(seq_finding)

        # Cookie attribute analysis
        attr_finding = self._check_cookie_attributes(base_url)
        if attr_finding:
            findings.append(attr_finding)

        return findings

    def _collect_tokens(self, base_url: str) -> List[Dict]:
        """Collect multiple session tokens by making repeated requests."""
        tokens = []
        for _ in range(10):
            try:
                session = requests.Session()
                resp = session.get(base_url, timeout=5)
                for cookie in session.cookies:
                    if cookie.name.lower() in self.SESSION_COOKIE_NAMES:
                        tokens.append({
                            "name": cookie.name,
                            "value": cookie.value,
                            "secure": cookie.secure,
                            "httponly": cookie.has_nonstandard_attr("HttpOnly") or "httponly" in str(cookie).lower(),
                            "path": cookie.path,
                        })
                time.sleep(0.5)
            except Exception:
                pass
        return tokens

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _analyze_entropy(self, tokens: List[Dict], base_url: str) -> Dict[str, Any] | None:
        if not tokens:
            return None

        values = [t["value"] for t in tokens]
        entropies = [self._shannon_entropy(v) for v in values]
        avg_entropy = sum(entropies) / len(entropies)
        avg_length = sum(len(v) for v in values) / len(values)

        # Total entropy bits = entropy_per_char * length
        total_bits = avg_entropy * avg_length

        ConsoleUI.info(f"[WeakSession] Avg entropy: {avg_entropy:.2f} bits/char, total: {total_bits:.0f} bits")

        # Flag if below NIST minimum (64 bits for session IDs)
        if total_bits < 64:
            return {
                "finding_type": "Weak Session IDs - Low Entropy",
                "base_confidence": 0.90, "consensus_score": 0.90, "score_conflict": False,
                "risk_level": "HIGH", "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Use cryptographically secure random generators for session IDs",
                    "Ensure minimum 128-bit entropy (NIST SP 800-63B)",
                    "Use framework-provided session management",
                ],
                "reasoning": [
                    f"Session token entropy: {avg_entropy:.2f} bits/char",
                    f"Total bits: {total_bits:.0f} (minimum recommended: 64)",
                    f"Token name: {tokens[0]['name']}, avg length: {avg_length:.0f} chars",
                    f"Sample values: {values[0]}, {values[1] if len(values) > 1 else 'N/A'}",
                ],
                "nodes": [], "edges": [],
            }

        # Flag if entropy is suspiciously low per character
        if avg_entropy < 3.5:
            return {
                "finding_type": "Weak Session IDs - Potentially Predictable",
                "base_confidence": 0.75, "consensus_score": 0.75, "score_conflict": False,
                "risk_level": "MEDIUM", "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Investigate session ID generation algorithm",
                    "Use cryptographically secure PRNG",
                ],
                "reasoning": [
                    f"Low per-character entropy: {avg_entropy:.2f} bits/char (< 3.5 threshold)",
                    f"Token name: {tokens[0]['name']}",
                ],
                "nodes": [], "edges": [],
            }
        return None

    def _check_sequential(self, tokens: List[Dict], base_url: str) -> Dict[str, Any] | None:
        """Check for sequential or predictable patterns."""
        values = [t["value"] for t in tokens]
        if len(values) < 5:
            return None

        # Check if tokens are numeric and sequential
        try:
            nums = [int(v) for v in values]
            diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
            if len(set(diffs)) <= 2:  # Nearly constant increment
                return {
                    "finding_type": "Weak Session IDs - Sequential/Predictable",
                    "base_confidence": 0.95, "consensus_score": 0.95, "score_conflict": False,
                    "risk_level": "CRITICAL", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Session IDs must not be sequential or predictable",
                        "Use cryptographically secure random generation",
                    ],
                    "reasoning": [
                        "Session IDs are sequential integers",
                        f"Increments: {diffs[:5]}",
                        "Attacker can predict and hijack sessions",
                    ],
                    "nodes": [], "edges": [],
                }
        except (ValueError, TypeError):
            pass

        # Check for timestamp-based tokens
        unique_ratio = len(set(values)) / len(values)
        if unique_ratio < 0.5:
            return {
                "finding_type": "Weak Session IDs - Low Uniqueness",
                "base_confidence": 0.80, "consensus_score": 0.80, "score_conflict": False,
                "risk_level": "HIGH", "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": ["Session tokens should be unique per session"],
                "reasoning": [f"Only {unique_ratio:.0%} of collected tokens are unique"],
                "nodes": [], "edges": [],
            }
        return None

    def _check_cookie_attributes(self, base_url: str) -> Dict[str, Any] | None:
        """Check cookie security attributes."""
        try:
            resp = requests.get(base_url, timeout=5)
            set_cookie = resp.headers.get("Set-Cookie", "")
            if not set_cookie:
                return None

            issues = []
            sc_lower = set_cookie.lower()

            if "httponly" not in sc_lower:
                issues.append("Missing HttpOnly flag — vulnerable to XSS cookie theft")
            if "secure" not in sc_lower:
                issues.append("Missing Secure flag — cookie sent over unencrypted connections")
            if "samesite" not in sc_lower:
                issues.append("Missing SameSite attribute — vulnerable to CSRF")

            if issues:
                return {
                    "finding_type": "Weak Session IDs - Insecure Cookie Attributes",
                    "base_confidence": 0.85, "consensus_score": 0.85, "score_conflict": False,
                    "risk_level": "MEDIUM", "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Set HttpOnly, Secure, and SameSite attributes on session cookies",
                    ],
                    "reasoning": issues + [f"Set-Cookie: {set_cookie[:200]}"],
                    "nodes": [], "edges": [],
                }
        except Exception:
            pass
        return None
