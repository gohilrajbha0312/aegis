from typing import Dict, Any, List
from aegisx.core.analysis.confidence_engine import ConfidenceEngine
from aegisx.core.ui.console import ConsoleUI

class EvidenceCorrelationEngine:
    """Aggregates evidence across different stages and agents to update finding confidence."""
    
    @staticmethod
    def correlate(state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.header("Evidence Correlation Engine")
        findings = state.get("findings", [])
        evidence_ledger = state.get("evidence_ledger", [])
        
        if not findings:
            return state
            
        ConsoleUI.info(f"Correlating evidence for {len(findings)} findings...")
        
        validated_findings = []

        for finding in findings:
            title = finding.get("title", "")
            
            # Evidence Requirement Layer (Hallucination Prevention)
            # 1. Finding must have an evidence block
            # 2. Evidence must not be empty
            evidence = finding.get("evidence")
            if not evidence or (isinstance(evidence, (str, dict, list)) and len(evidence) == 0):
                ConsoleUI.warning(f"Rejecting finding '{title}' due to missing evidence block. (Hallucination Prevention)")
                continue

            # Check if evidence contains request/response hints
            evidence_str = str(evidence).lower()
            has_request = "request" in evidence_str or "method" in evidence_str or "url" in evidence_str
            has_response = "response" in evidence_str or "status" in evidence_str
            
            if not (has_request or has_response):
                ConsoleUI.warning(f"Rejecting finding '{title}' due to invalid evidence structure (missing request/response).")
                continue
            
            # Calculate Scores
            related_evidence_count = sum(1 for e in evidence_ledger if e.get("stage") != "STAGE_1_NORMALIZATION")
            independent_sources = len(set(e.get("stage") for e in evidence_ledger if e.get("stage") != "STAGE_1_NORMALIZATION"))
            
            ownership_proven = "DifferentialEvidence" in str(finding.get("evidence", ""))
            authorization_proven = "StateTransitionFinding" in str(finding.get("evidence", ""))
            
            # Sub-scores for the formula
            evidence_score = min(0.3, related_evidence_count * 0.05)
            correlation_score = min(0.3, independent_sources * 0.1)
            attack_graph_score = 0.2 if ownership_proven else 0.0
            validation_score = 0.2 if authorization_proven else 0.0
            
            # confidence = evidence_score + correlation_score + attack_graph_score + validation_score
            new_confidence = evidence_score + correlation_score + attack_graph_score + validation_score
            
            # Ensure at least base confidence if it came with one
            base_confidence = finding.get("base_confidence", 0.0)
            if base_confidence > new_confidence:
                new_confidence = base_confidence

            old_confidence = finding.get("consensus_score", 0.0)
            if new_confidence > old_confidence:
                finding["consensus_score"] = new_confidence
                ConsoleUI.success(f"Increased confidence for '{title}' to {new_confidence:.2f}")
                
            # Evidence Count Requirement
            # Calculate evidence points based on routes, parameters, differential response
            evidence_count = 1  # Base for having passed the request/response check
            
            # Check if it references a route
            if any(r.get("path") in evidence_str for r in state.get("routes", [])):
                evidence_count += 1
                
            # Check if it references a parameter
            if any(p.get("name") in evidence_str for p in state.get("parameters", [])):
                evidence_count += 1
                
            # Check if it has differential response or ownership validation
            if ownership_proven or authorization_proven:
                evidence_count += 1
                
            finding["evidence_count"] = evidence_count
            
            if evidence_count >= 3:
                finding["status"] = "VERIFIED"
                ConsoleUI.success(f"Finding '{title}' VERIFIED (Evidence Count: {evidence_count})")
            else:
                finding["status"] = "HYPOTHESIS"
                ConsoleUI.info(f"Finding '{title}' remains HYPOTHESIS (Evidence Count: {evidence_count})")
                
            validated_findings.append(finding)
                
        state["findings"] = validated_findings
        return state
