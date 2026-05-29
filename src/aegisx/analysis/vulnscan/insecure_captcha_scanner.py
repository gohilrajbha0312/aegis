"""
AEGIS-X Insecure CAPTCHA Scanner
Algorithm: CAPTCHA implementation analysis + bypass testing.
"""
import re
from aegisx.core import http_client as requests
from typing import Dict, Any, List

from aegisx.core.ui.console import ConsoleUI

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False


class InsecureCaptchaScanner:

    CAPTCHA_INDICATORS = [
        "recaptcha", "hcaptcha", "captcha", "g-recaptcha", "h-captcha",
        "captcha_code", "captcha_image", "security_code", "verification_code",
    ]

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"

        for route in routes:
            url = f"{base_url}{route}" if route.startswith("/") else route
            result = self._analyze_captcha(url)
            if result:
                findings.append(result)

        return findings

    def _analyze_captcha(self, url: str) -> Dict[str, Any] | None:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code != 200:
                return None
        except Exception:
            return None

        html = resp.text.lower()
        has_captcha = any(c in html for c in self.CAPTCHA_INDICATORS)
        if not has_captcha:
            return None

        ConsoleUI.info(f"[CAPTCHA] CAPTCHA detected at {url}, testing bypasses...")
        issues = []

        # Test 1: Client-side only validation
        if _BS4:
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                captcha_field = None
                for name in self.CAPTCHA_INDICATORS:
                    field = form.find("input", {"name": re.compile(name, re.I)})
                    if field:
                        captcha_field = field
                        break

                if captcha_field:
                    # Test 2: Submit form without CAPTCHA
                    bypass = self._test_captcha_omission(url, form, captcha_field)
                    if bypass:
                        issues.append("CAPTCHA field can be omitted from submission")

                    # Test 3: Submit with empty CAPTCHA
                    bypass = self._test_empty_captcha(url, form, captcha_field)
                    if bypass:
                        issues.append("Empty CAPTCHA value accepted")

        # Test 4: Check for static CAPTCHA values in HTML
        if re.search(r'captcha.*?value\s*=\s*["\']([^"\']+)', html):
            issues.append("Static CAPTCHA value exposed in HTML source")

        # Test 5: Check for CAPTCHA in client-side JS only
        if "captcha" in html and "grecaptcha" not in html and "hcaptcha" not in html:
            if re.search(r'captcha.*?==|captcha.*?===|verify.*?captcha', html):
                issues.append("CAPTCHA validation appears to be client-side only")

        if issues:
            return {
                "finding_type": "Insecure CAPTCHA Implementation",
                "base_confidence": 0.82, "consensus_score": 0.82, "score_conflict": False,
                "risk_level": "MEDIUM", "governance_class": "PASSIVE_ANALYSIS",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Use server-side CAPTCHA validation (reCAPTCHA v3, hCaptcha)",
                    "Never validate CAPTCHA in client-side JavaScript only",
                    "Ensure CAPTCHA tokens are single-use and time-limited",
                    "Make CAPTCHA field mandatory server-side",
                ],
                "reasoning": [f"CAPTCHA issues at {url}"] + issues,
                "nodes": [], "edges": [],
            }
        return None

    def _test_captcha_omission(self, url: str, form, captcha_field) -> bool:
        action = form.get("action", "")
        if not action.startswith("http"):
            from urllib.parse import urljoin
            action = urljoin(url, action) if action else url

        data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name and name != captcha_field.get("name"):
                data[name] = inp.get("value", "test")

        try:
            resp = requests.post(action, data=data, timeout=5, allow_redirects=False)
            if resp.status_code in [200, 301, 302]:
                error_words = ["captcha", "verification", "security code", "required"]
                if not any(w in resp.text.lower() for w in error_words):
                    return True
        except Exception:
            pass
        return False

    def _test_empty_captcha(self, url: str, form, captcha_field) -> bool:
        action = form.get("action", "")
        if not action.startswith("http"):
            from urllib.parse import urljoin
            action = urljoin(url, action) if action else url

        data = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                data[name] = inp.get("value", "test")
        data[captcha_field.get("name", "captcha")] = ""

        try:
            resp = requests.post(action, data=data, timeout=5, allow_redirects=False)
            if resp.status_code in [200, 301, 302]:
                error_words = ["captcha", "invalid", "incorrect", "wrong"]
                if not any(w in resp.text.lower() for w in error_words):
                    return True
        except Exception:
            pass
        return False
