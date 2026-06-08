"""
Skill 1: RouteDiscoverySkill
==============================
Build a complete route inventory from HTML, JS, robots.txt, sitemap, OpenAPI.
Evidence-only: every route must have a source.
"""
import time
import re
from aegisx.core.orchestration.dag_engine import WorkflowState
from aegisx.core.ui.console import ConsoleUI
from aegisx.core import http_client


def _execute(state: WorkflowState) -> WorkflowState:
    ConsoleUI.header("RECON SKILL 1: Route Discovery")
    target = state.normalized_target or state.target
    base = f"http://{target}"
    inventory = []

    # 1. Collect routes already discovered by other agents
    for r in state.routes:
        route_str = r if isinstance(r, str) else r.get("path", r.get("route", str(r)))
        if route_str and not any(i.get("route") == route_str for i in inventory):
            inventory.append({"route": route_str, "source": "prior_discovery", "confidence": 0.9})

    for r in state.discovered_js_routes:
        if not any(i.get("route") == r for i in inventory):
            inventory.append({"route": r, "source": "javascript_analysis", "confidence": 0.85})

    for r in state.api_endpoints:
        if not any(i.get("route") == r for i in inventory):
            inventory.append({"route": r, "source": "api_endpoint", "confidence": 0.9})

    # 2. Fetch robots.txt (1 request)
    try:
        resp = http_client.get(f"{base}/robots.txt", timeout=5)
        if resp.status_code == 200 and "user-agent" in resp.text.lower():
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                    path = line.split(":", 1)[1].strip()
                    if path and path != "/" and not any(i.get("route") == path for i in inventory):
                        inventory.append({"route": path, "source": "robots.txt", "confidence": 0.95})
            ConsoleUI.info(f"  [robots.txt] Parsed successfully")
    except Exception:
        pass

    # 3. Fetch sitemap.xml (1 request)
    try:
        resp = http_client.get(f"{base}/sitemap.xml", timeout=5)
        if resp.status_code == 200 and "<url" in resp.text.lower():
            urls = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
            for url in urls[:50]:
                path = url.replace(base, "").replace(f"https://{target}", "")
                if path and not any(i.get("route") == path for i in inventory):
                    inventory.append({"route": path, "source": "sitemap.xml", "confidence": 0.95})
            ConsoleUI.info(f"  [sitemap.xml] {len(urls)} URLs found")
    except Exception:
        pass

    # 4. Parse HTML links from root page (1 request)
    try:
        resp = http_client.get(base, timeout=5)
        if resp.status_code == 200:
            hrefs = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
            for href in hrefs:
                if href.startswith("/") and not href.startswith("//"):
                    clean = href.split("?")[0].split("#")[0]
                    if clean and len(clean) < 200 and not any(i.get("route") == clean for i in inventory):
                        inventory.append({"route": clean, "source": "html_link", "confidence": 0.9})
            # Extract form actions
            actions = re.findall(r'action=["\']([^"\']+)["\']', resp.text)
            for action in actions:
                if action.startswith("/") and not any(i.get("route") == action for i in inventory):
                    inventory.append({"route": action, "source": "html_form", "confidence": 0.9})
    except Exception:
        pass

    # Store
    state.routes = inventory  # Replace with enriched inventory
    if "route_discovery" not in state.explored_paths:
        state.explored_paths.append("route_discovery")
    state.evidence_ledger.append({
        "stage": "RECON_ROUTE_DISCOVERY", "timestamp": time.time(),
        "action": "route_inventory_build",
        "result": {"routes_discovered": len(inventory)}
    })
    ConsoleUI.success(f"Route Discovery: {len(inventory)} routes in inventory")
    return state


def register(registry):
    from aegisx.skills.registry import SkillCapability
    registry.register(SkillCapability(
        skill_id="recon_route_discovery", name="Route Discovery",
        description="Builds complete route inventory from HTML, JS, robots.txt, sitemap, OpenAPI",
        category="recon_intelligence", noise_score=2, required_inputs=[],
        produced_outputs=["routes"],
        supported_phases=["Reconnaissance"],
        requires_evidence=False, execute_fn=_execute
    ))
