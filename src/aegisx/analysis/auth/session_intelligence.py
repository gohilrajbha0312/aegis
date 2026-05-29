import httpx
from typing import Dict, Any, Optional

class TokenVault:
    def __init__(self):
        self.tokens: Dict[str, str] = {}
        self.cookies: Dict[str, Dict[str, str]] = {}

    def store_token(self, context: str, token: str):
        self.tokens[context] = token

    def store_cookie(self, context: str, cookie_name: str, cookie_value: str):
        if context not in self.cookies:
            self.cookies[context] = {}
        self.cookies[context][cookie_name] = cookie_value

    def get_token(self, context: str) -> Optional[str]:
        return self.tokens.get(context)

    def get_cookies(self, context: str) -> Dict[str, str]:
        return self.cookies.get(context, {})

class CookieIsolationEngine:
    def __init__(self, vault: TokenVault):
        self.vault = vault

    def get_client(self, context: str) -> httpx.Client:
        headers = {}
        token = self.vault.get_token(context)
        if token:
            headers["Authorization"] = f"Bearer {token}"
            
        cookies = self.vault.get_cookies(context)
        
        return httpx.Client(headers=headers, cookies=cookies, verify=False)

class ReplayEngine:
    def __init__(self, isolation_engine: CookieIsolationEngine):
        self.isolation_engine = isolation_engine

    def replay_request(self, context: str, method: str, url: str, **kwargs) -> httpx.Response:
        with self.isolation_engine.get_client(context) as client:
            return client.request(method, url, **kwargs)

class SessionContextManager:
    def __init__(self):
        self.vault = TokenVault()
        self.isolation = CookieIsolationEngine(self.vault)
        self.replay = ReplayEngine(self.isolation)
        
        # Hardcode some dummy tokens for testing if none exist
        # In a real scenario, the AI would capture these dynamically
        self.vault.store_token("admin", "admin-jwt-token-mock")
        self.vault.store_token("user", "user-jwt-token-mock")
        self.vault.store_token("guest", "")
        self.vault.store_token("expired", "expired-jwt-token-mock")
        self.vault.store_token("tampered", "tampered-jwt-token-mock")

    def execute_in_context(self, context: str, method: str, url: str, **kwargs) -> httpx.Response:
        return self.replay.replay_request(context, method, url, **kwargs)

# Global instance for easy access
session_manager = SessionContextManager()
