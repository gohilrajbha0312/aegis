"""
AEGIS-X Production-Safe HTTP Client
====================================
Centralized rate-limited HTTP client with adaptive throttling, response
truncation, deduplication, and target health feedback.

Every scanner and agent in the platform uses this instead of raw `requests`.
"""
import time
import hashlib
import threading
import requests as _requests
from typing import Optional, Dict, Any, Set


# ══════════════════════════════════════════════════════════════════════
# Token-Bucket Rate Limiter
# ══════════════════════════════════════════════════════════════════════

class _RateLimiter:
    """Global token-bucket rate limiter with adaptive latency feedback."""

    def __init__(self, rps: float = 5.0, burst: int = 3):
        self._rps = rps
        self._base_rps = rps
        self._burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        """Block until a request token is available."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(self._burst, self._tokens + elapsed * self._rps)
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            time.sleep(0.05)

    def set_rate(self, rps: float, burst: int = 3):
        with self._lock:
            self._rps = rps
            self._base_rps = rps
            self._burst = burst

    def adapt_to_latency(self, avg_latency_ms: float):
        """Dynamically slow down or recover based on target latency."""
        with self._lock:
            if avg_latency_ms > 2000:
                # Target stressed — halve rate
                self._rps = max(0.5, self._rps * 0.5)
            elif avg_latency_ms > 1000:
                # Slow — reduce gently
                self._rps = max(0.5, self._rps * 0.75)
            elif avg_latency_ms < 500 and self._rps < self._base_rps:
                # Healthy — slowly recover
                self._rps = min(self._base_rps, self._rps + 0.5)

    @property
    def current_rps(self) -> float:
        return self._rps


# ══════════════════════════════════════════════════════════════════════
# Global State
# ══════════════════════════════════════════════════════════════════════

_global_limiter = _RateLimiter(rps=5.0, burst=3)
_request_count = 0
_count_lock = threading.Lock()
_MAX_REQUESTS_PER_SCAN = 500
_MAX_RESPONSE_BYTES = 524_288  # 512 KB default
_response_hashes: Set[str] = set()
_response_hash_lock = threading.Lock()


def configure_from_governor():
    """Read budget limits from RuntimeGovernor if available."""
    global _MAX_REQUESTS_PER_SCAN, _MAX_RESPONSE_BYTES
    try:
        from aegisx.core.runtime_governor import RuntimeGovernor
        gov = RuntimeGovernor.instance()
        profile = gov.profile
        _MAX_REQUESTS_PER_SCAN = profile.max_requests
        _MAX_RESPONSE_BYTES = profile.max_response_bytes
        _global_limiter.set_rate(profile.max_rps, profile.burst)
    except Exception:
        pass  # Governor not yet initialized — use defaults


def set_rate_limit(rps: float = 5.0, burst: int = 3):
    _global_limiter.set_rate(rps, burst)


def reset_request_counter():
    global _request_count, _response_hashes
    with _count_lock:
        _request_count = 0
    with _response_hash_lock:
        _response_hashes = set()
    configure_from_governor()


def get_request_count() -> int:
    return _request_count


def _check_budget() -> bool:
    global _request_count
    with _count_lock:
        if _request_count >= _MAX_REQUESTS_PER_SCAN:
            return False
        _request_count += 1
        return True


def _record_health(response: _requests.Response, elapsed_ms: float):
    """Feed response data back to RuntimeGovernor and adaptive limiter."""
    try:
        from aegisx.core.runtime_governor import RuntimeGovernor
        gov = RuntimeGovernor.instance()
        gov.target_health.record(elapsed_ms, response.status_code)
        _global_limiter.adapt_to_latency(gov.target_health.avg_latency_ms)
    except Exception:
        pass


def _truncate_response(response: _requests.Response):
    """Truncate response content if it exceeds the max size."""
    if len(response.content) > _MAX_RESPONSE_BYTES:
        response._content = response.content[:_MAX_RESPONSE_BYTES]


def _handle_backoff(response: _requests.Response):
    """Handle 429 and 5xx responses with backoff."""
    if response.status_code == 429:
        retry_after = int(response.headers.get("Retry-After", 10))
        retry_after = min(retry_after, 30)  # Cap at 30s
        time.sleep(retry_after)
    elif response.status_code >= 500:
        time.sleep(2)  # Simple backoff on server errors


def is_duplicate_response(response: _requests.Response) -> bool:
    """Check if we've already seen this exact response body."""
    body_hash = hashlib.md5(response.content).hexdigest()
    with _response_hash_lock:
        if body_hash in _response_hashes:
            return True
        # Cap the set at 1000 to avoid unbounded growth
        if len(_response_hashes) < 1000:
            _response_hashes.add(body_hash)
        return False


# ══════════════════════════════════════════════════════════════════════
# Safe Request Wrapper
# ══════════════════════════════════════════════════════════════════════

def _safe_request(method: str, url: str, **kwargs) -> _requests.Response:
    """Unified request handler with all safety controls."""
    if not _check_budget():
        raise BudgetExhaustedError(f"Request budget exhausted ({_MAX_REQUESTS_PER_SCAN} max)")

    # Check governor pause state and request safety
    try:
        from aegisx.core.runtime_governor import RuntimeGovernor
        gov = RuntimeGovernor.instance()
        if gov.is_paused:
            raise ScanPausedError(f"Scan paused: {gov.pause_reason}")
            
        # Enforce Request Safety Engine
        safety_eval = gov.safety_engine.evaluate_request(
            url=url,
            method=method,
            target_unstable=gov.target_health.is_unstable,
            payloads=kwargs.get("params", []) # very basic payload extraction for scoring
        )
        if safety_eval["action"] == "SKIP":
            raise RequestSafetyError(f"Request skipped by Safety Engine: {safety_eval['reason']}")
        elif safety_eval["action"] == "HITL_REQUIRED":
            raise RequestSafetyError(f"HITL required by Safety Engine: {safety_eval['reason']}")
            
    except ImportError:
        pass

    kwargs.setdefault("timeout", 8)
    _global_limiter.acquire()

    start = time.monotonic()
    response = getattr(_requests, method)(url, **kwargs)
    elapsed_ms = (time.monotonic() - start) * 1000

    _record_health(response, elapsed_ms)
    _truncate_response(response)
    _handle_backoff(response)

    return response


# ══════════════════════════════════════════════════════════════════════
# Drop-in Replacement API
# ══════════════════════════════════════════════════════════════════════

def get(url: str, **kwargs) -> _requests.Response:
    return _safe_request("get", url, **kwargs)

def post(url: str, **kwargs) -> _requests.Response:
    return _safe_request("post", url, **kwargs)

def put(url: str, **kwargs) -> _requests.Response:
    return _safe_request("put", url, **kwargs)

def delete(url: str, **kwargs) -> _requests.Response:
    return _safe_request("delete", url, **kwargs)

def head(url: str, **kwargs) -> _requests.Response:
    return _safe_request("head", url, **kwargs)


class Session(_requests.Session):
    """Rate-limited requests.Session replacement."""
    def request(self, method, url, **kwargs):
        if not _check_budget():
            raise BudgetExhaustedError(f"Request budget exhausted ({_MAX_REQUESTS_PER_SCAN} max)")
        try:
            from aegisx.core.runtime_governor import RuntimeGovernor
            gov = RuntimeGovernor.instance()
            if gov.is_paused:
                raise ScanPausedError(f"Scan paused: {gov.pause_reason}")
                
            # Enforce Request Safety Engine
            safety_eval = gov.safety_engine.evaluate_request(
                url=url,
                method=method,
                target_unstable=gov.target_health.is_unstable,
                payloads=kwargs.get("params", [])
            )
            if safety_eval["action"] == "SKIP":
                raise RequestSafetyError(f"Request skipped by Safety Engine: {safety_eval['reason']}")
            elif safety_eval["action"] == "HITL_REQUIRED":
                raise RequestSafetyError(f"HITL required by Safety Engine: {safety_eval['reason']}")
                
        except ImportError:
            pass
        kwargs.setdefault("timeout", 8)
        _global_limiter.acquire()

        start = time.monotonic()
        response = super().request(method, url, **kwargs)
        elapsed_ms = (time.monotonic() - start) * 1000

        _record_health(response, elapsed_ms)
        _truncate_response(response)
        _handle_backoff(response)
        return response


# ══════════════════════════════════════════════════════════════════════
# Exceptions
# ══════════════════════════════════════════════════════════════════════

class BudgetExhaustedError(Exception):
    """Raised when the scan request budget is exceeded."""
    pass

class ScanPausedError(Exception):
    """Raised when the RuntimeGovernor has paused all scanning."""
    pass

class RequestSafetyError(Exception):
    """Raised when a request is blocked by the RequestSafetyEngine."""
    pass
