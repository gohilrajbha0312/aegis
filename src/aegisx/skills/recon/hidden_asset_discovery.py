"""
Skill 8: HiddenAssetDiscoverySkill
====================================
Search for backup, old, dev, beta, internal, test, staging, debug assets.
"""
import time
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client

HIDDEN_PREFIXES = [
    "/backup", "/old", "/dev", "/beta", "/internal", "/test", "/staging", "/debug",
    "/.env", "/.git", "/.svn", "/config", "/.htaccess", "/web.config",
    "/wp-admin", "/phpmyadmin", "/adminer", "/console", "/actuator",
    "/trace", "/heapdump", "/env", "/info", "/health",
]


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 8: Hidden Asset Discovery")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    assets = []

    for path in HIDDEN_PREFIXES:
        # Skip if already in known routes
        known = any((r if isinstance(r, str) else r.get("route", "")) == path for r in state.routes)
        if known:
            assets.append({"path": path, "status": "already_known", "source": "route_inventory", "confidence": 0.9})
            continue
        try:
            resp = http_client.get(f"{base}{path}", timeout=3, allow_redirects=False)
            if resp.status_code in [200, 301, 302, 403]:
                assets.append({
                    "path": path, "status": resp.status_code,
                    "content_length": len(resp.text),
                    "source": "active_probe", "confidence": 0.85
                })
                if resp.status_code == 200:
                    ConsoleUI.warning(f"  [Hidden] {path} → {resp.status_code} ({len(resp.text)} bytes)")
                elif resp.status_code == 403:
                    ConsoleUI.info(f"  [Hidden] {path} → 403 Forbidden (exists but protected)")
        except Exception:
            pass

    state.hidden_assets = assets
    if "hidden_asset_discovery" not in state.explored_paths:
        state.explored_paths.append("hidden_asset_discovery")
    state.evidence_ledger.append({
        "stage": "RECON_HIDDEN_ASSETS", "timestamp": time.time(),
        "action": "hidden_asset_scan",
        "result": {"assets_found": len(assets)}
    })
    ConsoleUI.success(f"Hidden Assets: {len(assets)} discovered")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_hidden_asset_discovery", name="Hidden Asset Discovery",
        description="Probes for backup, dev, staging, debug, config files and directories",
        category="recon_intelligence", noise_score=3, required_inputs=[],
        produced_outputs=["hidden_assets"],
        supported_phases=["Reconnaissance"],
        requires_evidence=False, execute_fn=_execute
    ))
