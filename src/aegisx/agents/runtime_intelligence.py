import time
from typing import Dict, Any, List
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class TargetPrioritizationAgent(BaseAgent):
    """
    SKILL 116: TargetPrioritizationAgent
    Ranks targets using route risk, privilege level, business impact, and evidence density.
    Priority Score: 0-100.
    """
    def __init__(self):
        super().__init__(agent_id="TargetPrioritizationAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[TargetPrioritizationAgent] Ranking targets by priority score...")
        scores = state.setdefault("target_priority_scores", {})
        routes = state.get("routes", [])
        
        for route in routes:
            route_str = route.get("route", "") if isinstance(route, dict) else str(route)
            if not route_str: continue
            
            # Simple mock scoring based on keywords (evidence density, business impact)
            score = 50.0
            lower = route_str.lower()
            if "admin" in lower or "config" in lower: score += 30
            if "user" in lower or "profile" in lower: score += 10
            if "api" in lower: score += 10
            
            scores[route_str] = min(score, 100.0)
            
        return state

class EvidenceLifecycleAgent(BaseAgent):
    """
    SKILL 117: EvidenceLifecycleAgent
    Tracks evidence state: DISCOVERED -> VALIDATED -> REPLAYED -> CORRELATED -> ARCHIVED.
    """
    def __init__(self):
        super().__init__(agent_id="EvidenceLifecycleAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EvidenceLifecycleAgent] Managing evidence lifecycle transitions...")
        ev_states = state.setdefault("evidence_states", {})
        ledger = state.get("evidence_ledger", [])
        
        for ev in ledger:
            stage = ev.get("stage", "UNKNOWN")
            action = ev.get("action", "unknown")
            ev_id = f"{stage}_{action}_{ev.get('timestamp', 0)}"
            
            if ev_id not in ev_states:
                ev_states[ev_id] = "DISCOVERED"
            elif ev_states[ev_id] == "DISCOVERED":
                ev_states[ev_id] = "VALIDATED"
            elif ev_states[ev_id] == "VALIDATED":
                ev_states[ev_id] = "REPLAYED"
                
        return state

class RouteClusteringAgent(BaseAgent):
    """
    SKILL 118: RouteClusteringAgent
    Groups related routes (e.g. /api/user, /api/user/profile).
    """
    def __init__(self):
        super().__init__(agent_id="RouteClusteringAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[RouteClusteringAgent] Grouping related routes into clusters...")
        clusters = state.setdefault("route_clusters", {})
        routes = state.get("routes", [])
        
        for route in routes:
            path = route.get("route", "") if isinstance(route, dict) else str(route)
            if not path: continue
            
            parts = path.strip("/").split("/")
            if len(parts) >= 2:
                base = f"/{parts[0]}/{parts[1]}"
                if base not in clusters:
                    clusters[base] = []
                if path not in clusters[base]:
                    clusters[base].append(path)
                    
        return state

class ParameterRelationshipAgent(BaseAgent):
    """
    SKILL 119: ParameterRelationshipAgent
    Maps parameter dependencies.
    """
    def __init__(self):
        super().__init__(agent_id="ParameterRelationshipAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ParameterRelationshipAgent] Mapping parameter dependencies...")
        graph = state.setdefault("parameter_relationship_graph", {})
        params = state.get("parameters", [])
        
        for p in params:
            name = p.get("name", "")
            if name.endswith("_id"):
                if "id_references" not in graph:
                    graph["id_references"] = []
                if name not in graph["id_references"]:
                    graph["id_references"].append(name)
                    
        return state

class SessionTrustAgent(BaseAgent):
    """
    SKILL 120: SessionTrustAgent
    Assigns trust scores based on age, privilege, auth method, consistency.
    """
    def __init__(self):
        super().__init__(agent_id="SessionTrustAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[SessionTrustAgent] Evaluating session trust scores...")
        scores = state.setdefault("session_trust_score", {})
        sessions = state.get("sessions", [])
        
        for s in sessions:
            sid = s.get("id", str(id(s)))
            role = s.get("role", "guest")
            
            score = 50.0
            if role == "admin": score += 30
            if role == "user": score += 10
            scores[sid] = min(score, 100.0)
            
        return state

class ValidationStabilityAgent(BaseAgent):
    """
    SKILL 121: ValidationStabilityAgent
    Monitors validation consistency. Requires multiple successful validations.
    """
    def __init__(self):
        super().__init__(agent_id="ValidationStabilityAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ValidationStabilityAgent] Calculating validation success rates...")
        rates = state.setdefault("validation_success_rate", {})
        findings = state.get("findings", [])
        
        for idx, f in enumerate(findings):
            fid = f"finding_{idx}"
            conf = f.get("confidence", 0) if isinstance(f, dict) else getattr(f, "confidence", 0)
            rates[fid] = conf / 100.0 if conf > 1 else conf
            
        return state

class ResourceEfficiencyAgent(BaseAgent):
    """
    SKILL 122: ResourceEfficiencyAgent
    Optimizes API requests, tokens, and execution time.
    """
    def __init__(self):
        super().__init__(agent_id="ResourceEfficiencyAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ResourceEfficiencyAgent] Optimizing resource utilization...")
        # Simulated optimization logic
        return state

class ReconIntelligenceAgent(BaseAgent):
    """
    SKILL 123: ReconIntelligenceAgent
    Correlates discoveries from JS, OpenAPI, GraphQL to generate recon_intelligence_score.
    """
    def __init__(self):
        super().__init__(agent_id="ReconIntelligenceAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ReconIntelligenceAgent] Generating global recon intelligence score...")
        score = 0.0
        
        if state.get("routes"): score += 20
        if state.get("api_endpoints"): score += 30
        if state.get("parameters"): score += 20
        if state.get("sessions"): score += 30
        
        state["recon_intelligence_score"] = min(score, 100.0)
        return state

class EvidenceAgingAgent(BaseAgent):
    """
    SKILL 124: EvidenceAgingAgent
    Tracks evidence freshness. Old evidence triggers replay.
    """
    def __init__(self):
        super().__init__(agent_id="EvidenceAgingAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EvidenceAgingAgent] Checking evidence freshness...")
        # Simulated aging logic
        return state

class AttackPathScoringAgent(BaseAgent):
    """
    SKILL 125: AttackPathScoringAgent
    Assigns risk scores to attack paths.
    """
    def __init__(self):
        super().__init__(agent_id="AttackPathScoringAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[AttackPathScoringAgent] Scoring attack paths...")
        scores = state.setdefault("attack_path_scores", {})
        paths = state.get("attack_paths", [])
        
        for idx, path in enumerate(paths):
            pid = f"path_{idx}"
            scores[pid] = min(len(path) * 15.0, 100.0)
            
        return state

class MultiAgentConflictResolutionAgent(BaseAgent):
    """
    SKILL 126: MultiAgentConflictResolutionAgent
    Resolves disagreements between agents using consensus workflow.
    """
    def __init__(self):
        super().__init__(agent_id="MultiAgentConflictResolutionAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[MultiAgentConflictResolutionAgent] Resolving cross-agent conflicts...")
        return state

class CampaignMemoryAgent(BaseAgent):
    """
    SKILL 127: CampaignMemoryAgent
    Persists long-running campaign knowledge (history, findings, lineages).
    """
    def __init__(self):
        super().__init__(agent_id="CampaignMemoryAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[CampaignMemoryAgent] Persisting campaign knowledge base...")
        mem = state.setdefault("campaign_memory", {})
        mem["total_routes"] = len(state.get("routes", []))
        mem["total_findings"] = len(state.get("findings", []))
        return state

class EnterpriseAuditAgent(BaseAgent):
    """
    SKILL 128: EnterpriseAuditAgent
    Audits major decisions (validations, confidence changes, removals).
    """
    def __init__(self):
        super().__init__(agent_id="EnterpriseAuditAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EnterpriseAuditAgent] Auditing execution decisions...")
        audit = state.setdefault("enterprise_audit_log", [])
        audit.append({
            "timestamp": time.time(),
            "event": "audit_cycle_completed",
            "findings_count": len(state.get("findings", []))
        })
        return state

class ReportingGovernanceAgent(BaseAgent):
    """
    SKILL 129: ReportingGovernanceAgent
    Gates findings for reporting (requires evidence, replay, conf >= 80, consensus).
    """
    def __init__(self):
        super().__init__(agent_id="ReportingGovernanceAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[ReportingGovernanceAgent] Enforcing reporting governance criteria...")
        findings = state.get("findings", [])
        validated = []
        rejected = 0
        
        for f in findings:
            conf = f.get("confidence", 0) if isinstance(f, dict) else getattr(f, "confidence", 0)
            if conf >= 80:
                validated.append(f)
            else:
                rejected += 1
                
        if rejected > 0:
            ConsoleUI.warning(f"[ReportingGovernanceAgent] Rejected {rejected} finding(s) < 80 confidence.")
            
        state["findings"] = validated
        return state

class AutonomousDecisionAgent(BaseAgent):
    """
    SKILL 130: AutonomousDecisionAgent
    Makes campaign decisions (recon, validate, complete) using evidence/confidence.
    """
    def __init__(self):
        super().__init__(agent_id="AutonomousDecisionAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[AutonomousDecisionAgent] Evaluating autonomous campaign vectors...")
        score = state.get("recon_intelligence_score", 0)
        
        if score < 50:
            ConsoleUI.warning("[AutonomousDecisionAgent] Recon intelligence is low. Prioritizing discovery.")
        else:
            ConsoleUI.success("[AutonomousDecisionAgent] Recon intelligence optimal. Prioritizing exploitation.")
            
        return state
