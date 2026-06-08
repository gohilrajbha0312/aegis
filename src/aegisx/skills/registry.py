"""
AEGIS-X Skill Registry
======================

Central registry for all AI vulnerability reasoning skills.
Each skill is a self-contained analysis module with:
  - A defined capability description
  - Required inputs (what state fields it needs)
  - Produced outputs (what it populates in the state)
  - A noise score (how many requests it generates)
  - A confidence contribution method
"""

from typing import Dict, Any, List, Callable, Optional
from dataclasses import dataclass, field
from aegisx.core.orchestration.dag_engine import WorkflowState


@dataclass
class SkillCapability:
    """Describes a single reasoning skill's metadata."""
    skill_id: str
    name: str
    description: str
    category: str  # e.g., "authorization", "authentication", "client_side", "api", "config"
    noise_score: int  # 0 (passive) to 10 (aggressive)
    required_inputs: List[str]  # WorkflowState fields this skill reads
    produced_outputs: List[str]  # WorkflowState fields this skill populates
    supported_phases: List[str]  # Workflow phases where this skill is relevant
    requires_evidence: bool = False  # If True, requires prior findings before execution
    execute_fn: Optional[Callable] = None


class SkillRegistry:
    """
    Central registry for all AI reasoning skills.
    The AI Commander can query this to understand available capabilities
    and select skills dynamically based on context.
    """

    def __init__(self):
        self._skills: Dict[str, SkillCapability] = {}

    def register(self, skill: SkillCapability):
        """Register a new skill."""
        self._skills[skill.skill_id] = skill

    def get(self, skill_id: str) -> Optional[SkillCapability]:
        return self._skills.get(skill_id)

    def list_by_category(self, category: str) -> List[SkillCapability]:
        return [s for s in self._skills.values() if s.category == category]

    def list_by_phase(self, phase: str) -> List[SkillCapability]:
        return [s for s in self._skills.values() if phase in s.supported_phases]

    def list_low_noise(self, max_noise: int = 3) -> List[SkillCapability]:
        return [s for s in self._skills.values() if s.noise_score <= max_noise]

    def get_capabilities_summary(self) -> str:
        """Returns a text summary for injection into the AI Commander prompt."""
        lines = ["\n=== AI VULNERABILITY REASONING SKILLS ===\n"]
        categories = sorted(set(s.category for s in self._skills.values()))
        for cat in categories:
            lines.append(f"\n## {cat.upper().replace('_', ' ')}")
            for skill in self.list_by_category(cat):
                noise_label = "🟢" if skill.noise_score <= 2 else ("🟡" if skill.noise_score <= 5 else "🔴")
                lines.append(f"  {noise_label} {skill.name} (noise:{skill.noise_score}) — {skill.description}")
        return "\n".join(lines)

    def list_by_tag(self, tag: str) -> List[SkillCapability]:
        """Filter skills whose description or category contains the given tag."""
        tag_lower = tag.lower()
        return [s for s in self._skills.values()
                if tag_lower in s.description.lower() or tag_lower in s.category.lower()]

    def all(self) -> List[SkillCapability]:
        return list(self._skills.values())

    def execute_skill(self, skill_id: str, state: WorkflowState) -> WorkflowState:
        """Execute a registered skill against the current WorkflowState."""
        skill = self._skills.get(skill_id)
        if not skill:
            from aegisx.core.ui.console import ConsoleUI
            ConsoleUI.warning(f"Skill '{skill_id}' not found in registry.")
            return state
        if skill.execute_fn:
            return skill.execute_fn(state)
        return state


# ── Global Singleton ─────────────────────────────────────────────
_global_registry: Optional[SkillRegistry] = None


def get_skill_registry() -> SkillRegistry:
    """Returns the global skill registry, initializing it on first call."""
    global _global_registry
    if _global_registry is None:
        _global_registry = SkillRegistry()
        _register_all_skills(_global_registry)
    return _global_registry


def _register_all_skills(registry: SkillRegistry):
    """Registers all built-in reasoning skills."""
    from aegisx.skills.authorization_reasoning import register as reg_authz
    from aegisx.skills.authentication_reasoning import register as reg_authn
    from aegisx.skills.client_side_reasoning import register as reg_client
    from aegisx.skills.api_intelligence import register as reg_api
    from aegisx.skills.security_config_reasoning import register as reg_config
    from aegisx.skills.data_exposure_reasoning import register as reg_data
    from aegisx.skills.error_analysis_reasoning import register as reg_error
    from aegisx.skills.juice_shop_reasoning import register as reg_juice_shop
    # ── Juice Shop Challenge Skills ──────────────────────────────────
    from aegisx.skills.injection_reasoning import register as reg_injection
    from aegisx.skills.xss_reasoning import register as reg_xss
    from aegisx.skills.broken_access_reasoning import register as reg_bac
    from aegisx.skills.broken_auth_reasoning import register as reg_bauth
    from aegisx.skills.sensitive_data_reasoning import register as reg_sde
    from aegisx.skills.improper_input_reasoning import register as reg_input
    from aegisx.skills.vulnerable_components_reasoning import register as reg_vc
    from aegisx.skills.crypto_deser_xxe_reasoning import register as reg_crypto

    reg_authz(registry)
    reg_authn(registry)
    reg_client(registry)
    reg_api(registry)
    reg_config(registry)
    reg_data(registry)
    reg_error(registry)
    reg_juice_shop(registry)
    # ── Juice Shop Challenge Skills ──────────────────────────────────
    reg_injection(registry)
    reg_xss(registry)
    reg_bac(registry)
    reg_bauth(registry)
    reg_sde(registry)
    reg_input(registry)
    reg_vc(registry)
    reg_crypto(registry)

    # ── Enterprise Recon Intelligence Skills ─────────────────────────
    from aegisx.skills.recon.route_discovery import register as reg_route
    from aegisx.skills.recon.parameter_discovery import register as reg_param
    from aegisx.skills.recon.auth_discovery import register as reg_auth_disc
    from aegisx.skills.recon.authz_surface import register as reg_authz_surf
    from aegisx.skills.recon.js_intelligence import register as reg_js
    from aegisx.skills.recon.openapi_intelligence import register as reg_openapi
    from aegisx.skills.recon.graphql_intelligence import register as reg_graphql
    from aegisx.skills.recon.hidden_asset_discovery import register as reg_hidden
    from aegisx.skills.recon.security_header_intel import register as reg_headers
    from aegisx.skills.recon.state_machine_discovery import register as reg_state
    from aegisx.skills.recon.api_inventory import register as reg_api_inv
    from aegisx.skills.recon.session_correlation import register as reg_session
    from aegisx.skills.recon.evidence_integrity import register as reg_evidence
    from aegisx.skills.recon.hallucination_detector import register as reg_hallucination
    from aegisx.skills.recon.recon_completeness import register as reg_completeness

    reg_route(registry)
    reg_param(registry)
    reg_auth_disc(registry)
    reg_authz_surf(registry)
    reg_js(registry)
    reg_openapi(registry)
    reg_graphql(registry)
    reg_hidden(registry)
    reg_headers(registry)
    reg_state(registry)
    reg_api_inv(registry)
    reg_session(registry)
    reg_evidence(registry)
    reg_hallucination(registry)
    reg_completeness(registry)

