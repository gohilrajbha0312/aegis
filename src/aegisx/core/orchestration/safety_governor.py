import time
from typing import Dict, Any, List

class RuntimeSafetyGovernor:
    """
    Adaptive reconnaissance throttling engine.
    Implements PID-style rate control and concurrency adaptation based on WAF reactions.
    """
    def __init__(self, max_concurrency: int = 50):
        self.max_concurrency = max_concurrency
        self.current_concurrency = max_concurrency
        self.consecutive_errors = 0
        self.state_blocked = False

    def evaluate_response(self, response_code: int, latency_ms: float, response_body: str) -> Dict[str, Any]:
        """
        Monitors for bans, WAFs, CAPTCHAs, and latency spikes.
        Dynamically adjusts allowed concurrency.
        """
        flags = []
        action = "CONTINUE"
        
        # Detect WAF Blocks or Bans
        if response_code in [403, 429]:
            self.consecutive_errors += 1
            if self.consecutive_errors > 3:
                self.current_concurrency = max(1, self.current_concurrency // 2)
                action = "REDUCE_CONCURRENCY"
                flags.append(f"Rate Limiting Detected (HTTP {response_code})")
        else:
            # Recovery
            self.consecutive_errors = max(0, self.consecutive_errors - 1)
            if self.consecutive_errors == 0 and self.current_concurrency < self.max_concurrency:
                self.current_concurrency += 1

        # Detect Captchas
        body_lower = response_body.lower()
        if "captcha" in body_lower or "cf-browser-verification" in body_lower:
            self.state_blocked = True
            action = "PAUSE_AGGRESSIVE_STAGES"
            flags.append("CAPTCHA/WAF Challenge Detected")
            
        # Detect Latency Spikes
        if latency_ms > 2000:
            self.current_concurrency = max(1, int(self.current_concurrency * 0.75))
            action = "SLOW_REQUESTS"
            flags.append("Latency Spike Detected")
            
        return {
            "action": action,
            "new_concurrency_limit": self.current_concurrency,
            "flags": flags,
            "is_blocked": self.state_blocked
        }

    def get_allowed_threads(self) -> int:
        """Returns the current dynamically calculated thread limit."""
        return self.current_concurrency

    def pause_all_agents(self, reason: str):
        """Globally pause all agents via the RuntimeGovernor."""
        self.state_blocked = True
        try:
            from aegisx.core.runtime_governor import RuntimeGovernor
            gov = RuntimeGovernor.instance()
            gov._paused = True
            gov._pause_reason = reason
        except ImportError:
            pass

    def check_system_health(self) -> Dict[str, Any]:
        """Proxy to RuntimeGovernor's system health check."""
        try:
            from aegisx.core.runtime_governor import RuntimeGovernor
            gov = RuntimeGovernor.instance()
            return gov.check_system_health()
        except ImportError:
            return {"action": "CONTINUE"}
