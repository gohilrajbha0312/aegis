"""
AEGIS-X Runtime Resource Governor
==================================
Central brain that monitors system health, enforces scan modes, and prevents
Docker crashes, heap exhaustion, recursive scan explosions, and unbounded fuzzing.

This is the highest-authority runtime component in AEGIS-X.
"""
import os
import time
import threading
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from collections import deque


# ══════════════════════════════════════════════════════════════════════
# Scan Mode Definitions
# ══════════════════════════════════════════════════════════════════════

class ScanMode(str, Enum):
    """Enterprise scanning intensity modes."""
    PASSIVE = "passive"                       # OSINT only, zero target interaction
    SAFE_RECON = "safe_recon"                 # Lightweight fingerprinting, minimal requests
    ADAPTIVE_VALIDATION = "adaptive"          # AI-guided, bounded concurrency (DEFAULT)
    DEEP_ANALYSIS = "deep"                    # Full suite, strict governance
    HIGH_INTENSITY = "high_intensity"         # Requires HITL approval, strict monitoring


@dataclass
class ScanModeProfile:
    """Resource budget for a specific scan mode."""
    max_requests: int               # Hard ceiling on total HTTP requests
    max_rps: float                  # Max requests per second
    burst: int                      # Token bucket burst
    max_response_bytes: int         # Truncate responses beyond this
    phase_timeout_seconds: int      # Max time per DAG phase
    max_scanners: int               # How many vuln scanners to run
    max_payloads_per_param: int     # Max fuzzing payloads per parameter
    max_wordlist_entries: int       # Max brute-force wordlist entries
    max_evidence_entries: int       # Max evidence ledger items in memory
    max_findings: int               # Max findings in memory
    max_workflow_depth: int         # AI recursion depth limit
    requires_hitl_start: bool       # Require HITL before scan starts


# Pre-configured profiles for each mode
SCAN_PROFILES: Dict[ScanMode, ScanModeProfile] = {
    ScanMode.PASSIVE: ScanModeProfile(
        max_requests=50,      max_rps=2.0,  burst=2,
        max_response_bytes=65_536,      phase_timeout_seconds=60,
        max_scanners=0,       max_payloads_per_param=0,
        max_wordlist_entries=0,  max_evidence_entries=50,
        max_findings=100,     max_workflow_depth=2,
        requires_hitl_start=False,
    ),
    ScanMode.SAFE_RECON: ScanModeProfile(
        max_requests=150,     max_rps=3.0,  burst=2,
        max_response_bytes=131_072,     phase_timeout_seconds=90,
        max_scanners=4,       max_payloads_per_param=3,
        max_wordlist_entries=20,  max_evidence_entries=100,
        max_findings=200,     max_workflow_depth=3,
        requires_hitl_start=False,
    ),
    ScanMode.ADAPTIVE_VALIDATION: ScanModeProfile(
        max_requests=400,     max_rps=5.0,  burst=3,
        max_response_bytes=524_288,     phase_timeout_seconds=120,
        max_scanners=15,      max_payloads_per_param=10,
        max_wordlist_entries=50,  max_evidence_entries=200,
        max_findings=500,     max_workflow_depth=5,
        requires_hitl_start=False,
    ),
    ScanMode.DEEP_ANALYSIS: ScanModeProfile(
        max_requests=800,     max_rps=8.0,  burst=5,
        max_response_bytes=1_048_576,   phase_timeout_seconds=180,
        max_scanners=15,      max_payloads_per_param=50,
        max_wordlist_entries=200,  max_evidence_entries=300,
        max_findings=1000,    max_workflow_depth=8,
        requires_hitl_start=False,
    ),
    ScanMode.HIGH_INTENSITY: ScanModeProfile(
        max_requests=2000,    max_rps=15.0, burst=10,
        max_response_bytes=2_097_152,   phase_timeout_seconds=300,
        max_scanners=15,      max_payloads_per_param=100,
        max_wordlist_entries=500,  max_evidence_entries=500,
        max_findings=2000,    max_workflow_depth=10,
        requires_hitl_start=True,
    ),
}


# ══════════════════════════════════════════════════════════════════════
# Target Health Tracker
# ══════════════════════════════════════════════════════════════════════

class TargetHealthTracker:
    """
    Continuously monitors target stability via response latency,
    error rates, and timeout rates. Triggers auto-downgrade if
    the target is under stress.
    """

    def __init__(self, window_size: int = 50):
        self._latencies: deque = deque(maxlen=window_size)
        self._errors: deque = deque(maxlen=window_size)     # True = error
        self._lock = threading.Lock()

    def record(self, latency_ms: float, status_code: int):
        """Record a single HTTP response observation."""
        with self._lock:
            self._latencies.append(latency_ms)
            self._errors.append(status_code >= 500 or status_code == 429)

    @property
    def avg_latency_ms(self) -> float:
        with self._lock:
            if not self._latencies:
                return 0.0
            return sum(self._latencies) / len(self._latencies)

    @property
    def error_rate(self) -> float:
        """Fraction of recent responses that were 5xx or 429."""
        with self._lock:
            if not self._errors:
                return 0.0
            return sum(1 for e in self._errors if e) / len(self._errors)

    @property
    def is_unstable(self) -> bool:
        """Target is considered unstable if avg latency > 3s or error rate > 30%."""
        return self.avg_latency_ms > 3000 or self.error_rate > 0.30


# ══════════════════════════════════════════════════════════════════════
# Runtime Governor (Singleton)
# ══════════════════════════════════════════════════════════════════════

class RequestSafetyEngine:
    """
    Evaluates every outgoing request for noise, anomaly, and risk of causing target instability.
    """
    def __init__(self):
        self.noise_threshold = 0.8
        self.anomaly_threshold = 0.9

    def calculate_noise_score(self, url: str, method: str, payloads: List[str]) -> float:
        """Calculate how noisy/disruptive a request is likely to be."""
        score = 0.1
        if len(payloads) > 5:
            score += 0.3 # High payload count
        
        # Heavy wildcards or known bad patterns
        if "*" in url or "sleep" in str(payloads).lower() or "benchmark" in str(payloads).lower():
            score += 0.4
            
        return min(1.0, score)
        
    def evaluate_request(self, url: str, method: str, target_unstable: bool, payloads: List[str] = None) -> Dict[str, Any]:
        payloads = payloads or []
        noise = self.calculate_noise_score(url, method, payloads)
        
        if target_unstable and noise > 0.4:
            return {"action": "SKIP", "reason": "Target unstable, request too noisy"}
            
        if noise >= self.noise_threshold:
            return {"action": "HITL_REQUIRED", "reason": f"High noise score ({noise})"}
            
        return {"action": "ALLOW", "noise_score": noise}

class RuntimeGovernor:
    """
    Global runtime governance engine. Enforces resource budgets, monitors
    system health, and auto-downgrades scan intensity to protect both
    the AEGIS-X process and the target. Includes RequestSafetyEngine.

    Usage:
        gov = RuntimeGovernor.instance()
        gov.set_mode(ScanMode.ADAPTIVE_VALIDATION)
        profile = gov.profile  # Access current budget limits
    """

    _instance: Optional["RuntimeGovernor"] = None
    _lock = threading.Lock()

    def __init__(self):
        self._mode = ScanMode.ADAPTIVE_VALIDATION
        self._profile = SCAN_PROFILES[self._mode]
        self._target_health = TargetHealthTracker()
        self._safety_engine = RequestSafetyEngine()
        self._paused = False
        self._pause_reason = ""
        self._workflow_depth = 0
        self._start_time = time.monotonic()

    @property
    def safety_engine(self) -> RequestSafetyEngine:
        return self._safety_engine

    @classmethod
    def instance(cls) -> "RuntimeGovernor":
        """Thread-safe singleton accessor."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        """Reset the singleton (for testing)."""
        with cls._lock:
            cls._instance = None

    # ── Mode Management ─────────────────────────────────────────────

    def set_mode(self, mode: ScanMode):
        """Set the scan intensity mode and apply the corresponding profile."""
        self._mode = mode
        self._profile = SCAN_PROFILES[mode]

    @property
    def mode(self) -> ScanMode:
        return self._mode

    @property
    def profile(self) -> ScanModeProfile:
        return self._profile

    # ── Target Health ───────────────────────────────────────────────

    @property
    def target_health(self) -> TargetHealthTracker:
        return self._target_health

    def check_target_health(self) -> Dict[str, Any]:
        """
        Evaluate target health and auto-downgrade if unstable.
        Returns status dict.
        """
        health = self._target_health
        result = {
            "avg_latency_ms": health.avg_latency_ms,
            "error_rate": health.error_rate,
            "is_unstable": health.is_unstable,
            "action": "CONTINUE",
        }

        if health.is_unstable:
            # Auto-downgrade scan mode
            mode_order = [
                ScanMode.HIGH_INTENSITY,
                ScanMode.DEEP_ANALYSIS,
                ScanMode.ADAPTIVE_VALIDATION,
                ScanMode.SAFE_RECON,
                ScanMode.PASSIVE,
            ]
            current_idx = mode_order.index(self._mode) if self._mode in mode_order else 2
            if current_idx < len(mode_order) - 1:
                new_mode = mode_order[current_idx + 1]
                self.set_mode(new_mode)
                result["action"] = f"DOWNGRADED to {new_mode.value}"
            else:
                self._paused = True
                self._pause_reason = "Target critically unstable — all modes exhausted"
                result["action"] = "PAUSED"

        return result

    # ── System Health ───────────────────────────────────────────────

    def get_process_memory_mb(self) -> float:
        """Get current process RSS in MB."""
        try:
            import resource
            # getrusage returns max RSS in KB on Linux
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return usage.ru_maxrss / 1024.0
        except Exception:
            return 0.0

    def check_system_health(self) -> Dict[str, Any]:
        """
        Check if the AEGIS-X process itself is under memory pressure.
        Returns status dict.
        """
        rss_mb = self.get_process_memory_mb()
        result = {
            "rss_mb": rss_mb,
            "action": "CONTINUE",
        }

        # Hard limit: if RSS > 1.5 GB, pause everything
        if rss_mb > 1536:
            self._paused = True
            self._pause_reason = f"Process memory critical: {rss_mb:.0f} MB"
            result["action"] = "PAUSED"
        elif rss_mb > 1024:
            result["action"] = "WARNING"

        return result

    # ── Pause Management ────────────────────────────────────────────

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def pause_reason(self) -> str:
        return self._pause_reason

    def resume(self):
        """Manually resume after a pause (HITL override)."""
        self._paused = False
        self._pause_reason = ""

    # ── Workflow Depth ──────────────────────────────────────────────

    def increment_workflow_depth(self) -> bool:
        """
        Increment depth counter. Returns False if max depth exceeded.
        """
        self._workflow_depth += 1
        return self._workflow_depth <= self._profile.max_workflow_depth

    def reset_workflow_depth(self):
        self._workflow_depth = 0

    @property
    def workflow_depth(self) -> int:
        return self._workflow_depth

    # ── Elapsed Time ────────────────────────────────────────────────

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self._start_time

    # ── Summary ─────────────────────────────────────────────────────

    def status_summary(self) -> Dict[str, Any]:
        """Full governor status for logging and UI display."""
        return {
            "scan_mode": self._mode.value,
            "max_requests": self._profile.max_requests,
            "max_rps": self._profile.max_rps,
            "phase_timeout": self._profile.phase_timeout_seconds,
            "max_scanners": self._profile.max_scanners,
            "workflow_depth": f"{self._workflow_depth}/{self._profile.max_workflow_depth}",
            "target_latency_ms": f"{self._target_health.avg_latency_ms:.0f}",
            "target_error_rate": f"{self._target_health.error_rate:.1%}",
            "target_unstable": self._target_health.is_unstable,
            "paused": self._paused,
            "pause_reason": self._pause_reason,
            "rss_mb": f"{self.get_process_memory_mb():.0f}",
            "elapsed_s": f"{self.elapsed_seconds:.0f}",
        }
