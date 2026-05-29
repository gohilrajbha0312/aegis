"""
AEGIS-X Brute Force Scanner
Algorithm: Dictionary-based credential stuffing with adaptive response differential analysis.
Tools: hydra (primary), Python requests (fallback)
Wordlists: github.com/jeanphorn/wordlist (cloned to PROJECT_ROOT/wordlists/)
"""
import os
import time
from aegisx.core import http_client as requests
from typing import Dict, Any, List, Optional

from aegisx.core.orchestration.command_gateway import CommandGateway
from aegisx.core.ui.console import ConsoleUI

# ── Wordlist paths (jeanphorn/wordlist repo) ────────────────────────
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
WORDLIST_DIR = os.path.join(_PROJECT_ROOT, "wordlists")

# Primary wordlists
USERNAME_LIST = os.path.join(WORDLIST_DIR, "usernames", "admin.txt")       # 79 admin variants
PASSWORD_WEB = os.path.join(WORDLIST_DIR, "passwords", "web.txt")          # 456 web passwords
PASSWORD_SMALL = os.path.join(WORDLIST_DIR, "passwords", "common_small.txt")  # 1319 common
PASSWORD_SSH = os.path.join(WORDLIST_DIR, "passwords", "ssh.txt")          # SSH passwords
PASSWORD_FTP = os.path.join(WORDLIST_DIR, "passwords", "ftp.txt")          # FTP passwords
PASSWORD_COMMON = os.path.join(WORDLIST_DIR, "passwords", "common.txt")    # 11M large list
USERNAME_COMMON = os.path.join(WORDLIST_DIR, "usernames", "common.txt")    # 745K usernames
USERNAME_GLOBAL = os.path.join(WORDLIST_DIR, "usernames.txt")              # 719K global list


def _load_wordlist(path: str, max_entries: int = 500) -> List[str]:
    """Load a wordlist file, skipping comments and empty lines."""
    words = []
    if not os.path.isfile(path):
        ConsoleUI.warning(f"[BruteForce] Wordlist not found: {path}")
        return words
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    words.append(line)
                    if len(words) >= max_entries:
                        break
    except Exception as e:
        ConsoleUI.warning(f"[BruteForce] Error reading {path}: {e}")
    return words


class BruteForceScanner:
    """
    Brute-force authentication endpoints using dictionary attacks.
    Uses wordlists from github.com/jeanphorn/wordlist.
    Response differential analysis detects successful logins.
    """

    def __init__(self):
        try:
            from aegisx.core.runtime_governor import RuntimeGovernor
            gov = RuntimeGovernor.instance()
            max_entries = gov.profile.max_wordlist_entries
        except Exception:
            max_entries = 50

        # Load wordlists from the cloned jeanphorn/wordlist repository
        self.usernames = _load_wordlist(USERNAME_LIST, max_entries=min(20, max_entries))
        self.passwords = _load_wordlist(PASSWORD_WEB, max_entries=max_entries)

        # If web.txt is small, supplement with common_small.txt
        if len(self.passwords) < 100:
            self.passwords.extend(_load_wordlist(PASSWORD_SMALL, max_entries=500))

        # Deduplicate
        self.usernames = list(dict.fromkeys(self.usernames))
        self.passwords = list(dict.fromkeys(self.passwords))

        ConsoleUI.info(
            f"[BruteForce] Loaded {len(self.usernames)} usernames, "
            f"{len(self.passwords)} passwords from jeanphorn/wordlist"
        )

    def scan(self, target: str, routes: List[str]) -> List[Dict[str, Any]]:
        findings = []

        # Filter routes to auth-related endpoints
        auth_routes = [r for r in routes if any(
            kw in r.lower() for kw in ["login", "signin", "auth", "admin", "session"]
        )]

        if not auth_routes:
            auth_routes = ["/login", "/admin/login"]

        for route in auth_routes:
            result = self._attack_endpoint(target, route)
            if result:
                findings.extend(result)

        return findings

    def _attack_endpoint(self, target: str, route: str) -> List[Dict[str, Any]]:
        findings = []
        base_url = f"http://{target}"
        url = f"{base_url}{route}" if route.startswith("/") else route

        ConsoleUI.info(f"[BruteForce] Probing authentication endpoint: {url}")

        # Step 1: Try hydra with the wordlist files (fastest)
        hydra_result = self._try_hydra(target, route)
        if hydra_result:
            findings.append(hydra_result)
            return findings

        # Step 2: Fallback to Python-based brute force with response differential
        baseline = self._get_baseline(url)
        if not baseline:
            ConsoleUI.warning(f"[BruteForce] Could not establish baseline for {url}")
            return findings

        compromised = []
        total_attempts = 0
        for user in self.usernames:
            for pwd in self.passwords:
                total_attempts += 1
                try:
                    resp = requests.post(
                        url,
                        data={"username": user, "password": pwd},
                        timeout=5,
                        allow_redirects=False,
                    )

                    # Response differential analysis
                    if self._is_login_success(resp, baseline):
                        compromised.append({"username": user, "password": pwd})
                        ConsoleUI.success(f"[BruteForce] CREDENTIAL FOUND: {user}:{pwd}")
                        break  # Stop testing passwords for this user
                    time.sleep(0.2)
                except Exception:
                    pass

        if compromised:
            cred_str = ", ".join(c["username"] + ":" + c["password"] for c in compromised[:3])
            findings.append({
                "finding_type": "Brute Force - Weak Credentials Discovered",
                "base_confidence": 0.99,
                "consensus_score": 0.99,
                "score_conflict": False,
                "risk_level": "CRITICAL",
                "governance_class": "ACTIVE_VALIDATION",
                "requires_human_approval": False,
                "recommended_validation": [
                    "Implement account lockout after 5 failed attempts",
                    "Enable multi-factor authentication (MFA)",
                    "Enforce strong password policy (min 12 chars, complexity)",
                    "Implement rate limiting on authentication endpoints",
                ],
                "reasoning": [
                    f"Compromised {len(compromised)} credential pair(s) via dictionary attack",
                    f"Endpoint: {url}",
                    f"Credentials: {cred_str}",
                    f"Wordlist: jeanphorn/wordlist (usernames/admin.txt + passwords/web.txt)",
                    f"Total attempts: {total_attempts}",
                ],
                "nodes": [],
                "edges": [],
            })
        else:
            # Check if endpoint lacks rate limiting
            if self._check_no_rate_limiting(url):
                findings.append({
                    "finding_type": "Brute Force - No Rate Limiting on Auth Endpoint",
                    "base_confidence": 0.85,
                    "consensus_score": 0.85,
                    "score_conflict": False,
                    "risk_level": "MEDIUM",
                    "governance_class": "PASSIVE_ANALYSIS",
                    "requires_human_approval": False,
                    "recommended_validation": [
                        "Implement rate limiting (e.g. 5 attempts per minute)",
                        "Add CAPTCHA after 3 failed attempts",
                        "Implement progressive delays on failed login",
                    ],
                    "reasoning": [
                        f"Authentication endpoint {url} allows unlimited login attempts",
                        f"No account lockout or rate limiting detected after {total_attempts}+ attempts",
                    ],
                    "nodes": [],
                    "edges": [],
                })

        return findings

    def _try_hydra(self, target: str, route: str) -> Optional[Dict[str, Any]]:
        """Attempt brute force using hydra with jeanphorn/wordlist files."""
        host = target.split(":")[0]
        port = target.split(":")[1] if ":" in target else "80"

        # Use the actual wordlist files for hydra
        user_file = USERNAME_LIST
        pass_file = PASSWORD_WEB

        if not os.path.isfile(user_file) or not os.path.isfile(pass_file):
            ConsoleUI.warning("[BruteForce] Wordlist files not found, skipping hydra")
            return None

        cmd = [
            "hydra",
            "-L", user_file,        # Username list from jeanphorn/wordlist
            "-P", pass_file,         # Password list from jeanphorn/wordlist
            "-s", port, host,
            "http-post-form",
            f"{route}:username=^USER^&password=^PASS^:F=invalid:F=incorrect:F=error:F=failed",
            "-t", "4", "-w", "3", "-f",
        ]

        ConsoleUI.info(f"[BruteForce] Running hydra with jeanphorn/wordlist ({user_file}, {pass_file})")
        result = CommandGateway.execute(cmd, timeout=120, description="Brute Force Attack (Hydra + jeanphorn/wordlist)")

        if result["success"] and "login:" in result.get("stdout", "").lower():
            return {
                "finding_type": "Brute Force - Hydra Credential Discovery",
                "base_confidence": 0.99,
                "consensus_score": 0.99,
                "score_conflict": False,
                "risk_level": "CRITICAL",
                "governance_class": "ACTIVE_VALIDATION",
                "requires_human_approval": False,
                "recommended_validation": ["Enforce strong passwords and account lockout policies"],
                "reasoning": [
                    f"Hydra discovered valid credentials on {route}",
                    f"Wordlist: jeanphorn/wordlist (usernames/admin.txt + passwords/web.txt)",
                    result.get("stdout", "")[:500],
                ],
                "nodes": [],
                "edges": [],
            }
        return None

    def _get_baseline(self, url: str) -> Optional[Dict[str, Any]]:
        """Get baseline response for a failed login attempt."""
        try:
            resp = requests.post(
                url,
                data={"username": "nonexistent_x7q", "password": "invalid_z9k"},
                timeout=5,
                allow_redirects=False,
            )
            return {
                "status_code": resp.status_code,
                "content_length": len(resp.text),
                "has_set_cookie": "Set-Cookie" in resp.headers,
                "location": resp.headers.get("Location", ""),
            }
        except Exception:
            return None

    def _is_login_success(self, resp, baseline: Dict) -> bool:
        """Determine if response indicates successful login via differential analysis."""
        # Redirect to non-login page = success
        if resp.status_code in [301, 302, 303]:
            loc = resp.headers.get("Location", "").lower()
            if loc and "login" not in loc and "error" not in loc and "fail" not in loc:
                return True

        # Different status code than baseline
        if resp.status_code != baseline["status_code"]:
            if resp.status_code == 200 and baseline["status_code"] != 200:
                return True

        # Significant content length difference (> 20%) with session cookie
        if baseline["content_length"] > 0:
            diff_ratio = abs(len(resp.text) - baseline["content_length"]) / baseline["content_length"]
            if diff_ratio > 0.2 and "Set-Cookie" in resp.headers:
                # Verify it's not just an error message
                if "invalid" not in resp.text.lower() and "incorrect" not in resp.text.lower():
                    return True

        return False

    def _check_no_rate_limiting(self, url: str) -> bool:
        """Check if endpoint has rate limiting by sending rapid requests."""
        try:
            for _ in range(5):
                resp = requests.post(
                    url,
                    data={"username": "ratetest", "password": "ratetest"},
                    timeout=3,
                    allow_redirects=False,
                )
                if resp.status_code == 429:
                    return False  # Rate limiting is active
            return True  # No rate limiting detected
        except Exception:
            return False
