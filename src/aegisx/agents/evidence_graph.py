from typing import Dict, Any
import hashlib
import json
from aegisx.agents.base import BaseAgent
from aegisx.core.ui.console import ConsoleUI

class EvidenceGraphAgent(BaseAgent):
    """
    SKILL 81: EvidenceGraphAgent
    Maps routes, params, sessions, and findings into a strict evidence graph.
    """
    def __init__(self):
        super().__init__(agent_id="EvidenceGraphAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EvidenceGraphAgent] Building strict Evidence Graph...")
        
        graph = {
            "nodes": [],
            "edges": []
        }
        
        routes = state.get("routes", [])
        params = state.get("parameters", [])
        sessions = state.get("sessions", [])
        findings = state.get("findings", [])
        
        # Build Base Nodes
        for r in routes: 
            r_name = r.get('path', str(r)) if isinstance(r, dict) else str(r)
            graph["nodes"].append({"id": f"route:{r_name}", "type": "Route"})
        for p in params: 
            p_name = p.get('name', str(p)) if isinstance(p, dict) else str(p)
            graph["nodes"].append({"id": f"param:{p_name}", "type": "Parameter"})
        for s in sessions: 
            s_id = s.get('id', str(s)) if isinstance(s, dict) else str(s)
            graph["nodes"].append({"id": f"session:{s_id}", "type": "Session"})
            
        valid_findings = []
        rejected = 0
        
        for f in findings:
            title = f.get('title', 'Unknown')
            finding_id = f"finding:{title}"
            has_connection = False
            evidence_str = str(f.get("evidence", [])).lower()
            
            # Map edges based on evidence overlap
            for r in routes:
                r_name = r.get('path', str(r)) if isinstance(r, dict) else str(r)
                if r_name.lower() in evidence_str:
                    graph["edges"].append({"source": finding_id, "target": f"route:{r_name}", "relation": "correlates_to"})
                    has_connection = True
                    
            for p in params:
                p_name = p.get('name', str(p)) if isinstance(p, dict) else str(p)
                if p_name.lower() in evidence_str:
                    graph["edges"].append({"source": finding_id, "target": f"param:{p_name}", "relation": "manipulates"})
                    has_connection = True
                    
            if has_connection:
                graph["nodes"].append({"id": finding_id, "type": "Finding"})
                valid_findings.append(f)
            else:
                rejected += 1
                
        if rejected > 0:
            ConsoleUI.warning(f"[EvidenceGraphAgent] Rejected {rejected} finding(s) due to lack of graph connectivity (No Evidence = No Hypothesis).")
            
        state["findings"] = valid_findings
        state["evidence_graph"] = graph
        return state

class AttackPathCorrelationAgent(BaseAgent):
    """
    SKILL 98: AttackPathCorrelationAgent
    Builds attack chains by correlating multiple findings (e.g., IDOR -> Account Takeover).
    """
    def __init__(self):
        super().__init__(agent_id="AttackPathCorrelationAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[AttackPathCorrelationAgent] Correlating findings into macro-attack chains...")
        findings = state.get("findings", [])
        graph = state.get("evidence_graph", {"nodes": [], "edges": []})
        attack_paths = state.get("attack_paths", [])
        
        # Simple heuristic correlation for simulation
        high_risk = [f for f in findings if isinstance(f, dict) and f.get("confidence", 0) >= 0.8]
        if len(high_risk) >= 2:
            path_id = f"AP-{len(attack_paths)+1}"
            titles = [f.get("title", "Unknown") for f in high_risk[:2]]
            chain = " -> ".join(titles)
            
            if chain not in attack_paths:
                attack_paths.append(chain)
                ConsoleUI.success(f"[AttackPathCorrelationAgent] Correlated Attack Path: {chain}")
                
                # Map into evidence graph
                graph["nodes"].append({"id": path_id, "type": "AttackPath"})
                for title in titles:
                    graph["edges"].append({"source": path_id, "target": f"finding:{title}", "relation": "comprises"})
                
        state["attack_paths"] = attack_paths
        state["evidence_graph"] = graph
        return state

class EvidenceChainIntegrityAgent(BaseAgent):
    """
    SKILL 95: EvidenceChainIntegrityAgent
    Hashes evidence to create an immutable evidence chain and reject modified evidence.
    """
    def __init__(self):
        super().__init__(agent_id="EvidenceChainIntegrityAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EvidenceChainIntegrityAgent] Validating evidence chain integrity...")
        findings = state.get("findings", [])
        evidence_chain = state.get("evidence_chain", {})
        
        valid_findings = []
        rejected = 0
        for f in findings:
            if isinstance(f, dict):
                title = f.get("title", "Unknown")
                evidence = f.get("evidence", [])
                
                # Create a deterministic hash of the evidence
                evidence_str = json.dumps(evidence, sort_keys=True)
                current_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
                
                stored_hash = evidence_chain.get(title)
                if stored_hash and stored_hash != current_hash:
                    ConsoleUI.error(f"[EvidenceChainIntegrityAgent] Integrity failure! Evidence for '{title}' was modified.")
                    rejected += 1
                else:
                    evidence_chain[title] = current_hash
                    valid_findings.append(f)
            else:
                valid_findings.append(f)
                    
        if rejected > 0:
            ConsoleUI.warning(f"[EvidenceChainIntegrityAgent] Rejected {rejected} finding(s) due to evidence tampering.")
            
        state["findings"] = valid_findings
        state["evidence_chain"] = evidence_chain
        return state

class AttackPathExpansionAgent(BaseAgent):
    """
    SKILL 109: AttackPathExpansionAgent
    Forces new route/parameter discovery after a validated finding.
    """
    def __init__(self):
        super().__init__(agent_id="AttackPathExpansionAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[AttackPathExpansionAgent] Scanning for validated findings requiring expansion...")
        findings = state.get("findings", [])
        validated = [f for f in findings if isinstance(f, dict) and f.get("confidence", 0) >= 80]
        
        if validated:
            ConsoleUI.warning(f"[AttackPathExpansionAgent] Detected {len(validated)} validated finding(s). Forcing attack surface expansion.")
            state["force_expansion"] = True
            
        return state
