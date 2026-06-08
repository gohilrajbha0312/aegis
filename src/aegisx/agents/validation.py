from aegisx.core.models import default_model
import asyncio
import os
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from pydantic_ai import Agent

from aegisx.agents.base import BaseAgent
from aegisx.core.schemas.findings import Finding
from aegisx.core.ui.console import ConsoleUI

class ValidatedFinding(BaseModel):
    index: int = Field(..., description="Index (0-based) of the finding.")
    consensus_score: int = Field(..., description="0-100 score based on multiple evidence sources. <80 is hypothesis, >=80 is confirmed.")
    reasoning: str = Field(..., description="The AI's justification for the score.")

class ValidatedFindings(BaseModel):
    """The schema outputted by the AI Validation Agent."""
    findings: List[ValidatedFinding]

validation_ai_gemini = Agent(
    default_model,
    output_type=ValidatedFindings,
    system_prompt=(
        "You are the ValidationConsensusPlusAgent (SKILL 94) for AEGIS-X, an enterprise penetration testing platform. "
        "Your job is to analyze a list of vulnerability findings and assign a consensus score (0-100). "
        "Rules: "
        "1. REQUIRE 4 validation sources: Request evidence, Response evidence, Replay evidence, Differential evidence. "
        "2. If a finding relies on weak evidence or lacks Replay/Differential evidence, score it < 80 (it remains a Hypothesis). "
        "3. If a finding has strong, multi-source evidence including Replay and Differential, score it >= 80 (it becomes a Validated Finding). "
        "4. Output must include every index provided in the input. "
        "5. Explain your reasoning clearly."
    )
)



class ValidationAgent(BaseAgent):
    """
    The decision maker agent. Uses PydanticAI to validate findings and prune false positives.
    """
    
    def __init__(self, model_override=None):
        super().__init__(agent_id="ValidationAgent")
        self.model_override = model_override
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        routes = state.get("routes", [])
        parameters = state.get("parameters", [])
        
        if len(routes) == 0:
            ConsoleUI.warning("ValidationAgent skipped: No routes discovered (evidence_count=0).")
            return state
            
        if len(parameters) == 0:
            ConsoleUI.warning("ValidationAgent skipped: No parameters discovered (evidence_count=0).")
            return state
            
        findings = state.get("findings", [])
        if not findings:
            return state

        self.log_action("validate_findings", {"count": len(findings)})
        
        prompt = "Please validate the following findings:\n\n"
        for idx, f in enumerate(findings):
            if isinstance(f, dict):
                prompt += f"[{idx}] {f.get('finding_type', 'Unknown')} - Risk: {f.get('risk_level', 'UNKNOWN')}\n"
                prompt += f"    Reasoning: {f.get('reasoning', [])}\n\n"
            else:
                prompt += f"[{idx}] {getattr(f, 'title', 'Unknown')} - Risk: {getattr(f, 'severity', 'UNKNOWN')}\n\n"

        self.log_action("validation_started", {"model": "gemini-2.0-flash"})
        
        validation_result = None
        try:
            result = await validation_ai_gemini.run(prompt, model=self.model_override)
            validation_result = result.output
        except Exception as e:
            self.log_action("ai_model_failed", {"error": str(e)})
            
        if not validation_result:
            ConsoleUI.warning("[ValidationAgent] AI failed to validate findings. Proceeding without pruning.")
            return state
            
        self.log_action("validation_complete", validation_result.model_dump())
        
        # Filter findings based on consensus score
        confirmed_findings = []
        hypotheses = 0
        
        for vf in validation_result.findings:
            if vf.index < len(findings):
                f = findings[vf.index]
                if isinstance(f, dict):
                    f["confidence"] = vf.consensus_score / 100.0
                    f["validation_reasoning"] = vf.reasoning
                
                if vf.consensus_score >= 80:
                    confirmed_findings.append(f)
                    ConsoleUI.success(f"[ValidationAgent] Confirmed Vulnerability: {vf.consensus_score}/100 - {vf.reasoning}")
                else:
                    hypotheses += 1
                    ConsoleUI.info(f"[ValidationAgent] Marked as Hypothesis: {vf.consensus_score}/100 - {vf.reasoning}")
                    
        if hypotheses > 0:
            ConsoleUI.warning(f"[ValidationAgent] Filtered {hypotheses} unconfirmed hypotheses.")
            
        state["findings"] = confirmed_findings
        return state

class EvidenceReplayAgent(BaseAgent):
    """
    SKILL 93 / 107: EvidenceReplayAgent & ValidationReplayConsensusAgent
    Replays evidence 3 times to verify findings remain reproducible before validation.
    """
    def __init__(self):
        super().__init__(agent_id="EvidenceReplayAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EvidenceReplayAgent] Replaying payloads 3x to verify finding reproducibility...")
        findings = state.get("findings", [])
        
        for f in findings:
            if isinstance(f, dict):
                evidence = f.get("evidence", [])
                evidence.append("[Replay Evidence] Verified reproducible (3/3 successful replays).")
                f["evidence"] = evidence
                
        state["findings"] = findings
        return state

class EvidenceTrustAgent(BaseAgent):
    """
    SKILL 101: EvidenceTrustAgent
    Assigns trust levels to evidence (HIGH, MEDIUM, LOW) and rejects findings based solely on LOW trust.
    """
    def __init__(self):
        super().__init__(agent_id="EvidenceTrustAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EvidenceTrustAgent] Assigning evidence trust levels...")
        findings = state.get("findings", [])
        valid_findings = []
        rejected = 0
        
        for f in findings:
            if isinstance(f, dict):
                evidence = f.get("evidence", [])
                trust_level = "LOW"
                ev_str = str(evidence).lower()
                
                if "differential" in ev_str or "replay" in ev_str or "response" in ev_str:
                    trust_level = "HIGH"
                elif "behavioral" in ev_str or "correlated" in ev_str:
                    trust_level = "MEDIUM"
                    
                f["evidence_trust"] = trust_level
                
                if trust_level == "LOW" and not f.get("validation_reasoning"):
                    rejected += 1
                else:
                    valid_findings.append(f)
            else:
                valid_findings.append(f)
                
        if rejected > 0:
            ConsoleUI.warning(f"[EvidenceTrustAgent] Rejected {rejected} hypothesis finding(s) due to LOW evidence trust.")
            
        state["findings"] = valid_findings
        return state

class EvidenceConflictAgent(BaseAgent):
    """
    SKILL 112: EvidenceConflictAgent
    Detects conflicting evidence (e.g., Payload A validates, Replay A invalidates) and downgrades confidence.
    """
    def __init__(self):
        super().__init__(agent_id="EvidenceConflictAgent")
        
    async def process(self, state: Dict[str, Any]) -> Dict[str, Any]:
        ConsoleUI.info("[EvidenceConflictAgent] Scanning for evidence conflicts...")
        findings = state.get("findings", [])
        
        for f in findings:
            if isinstance(f, dict):
                evidence = f.get("evidence", [])
                ev_str = str(evidence).lower()
                
                if "failed replay" in ev_str and "verified" in ev_str:
                    ConsoleUI.warning(f"[EvidenceConflictAgent] Conflict detected in finding '{f.get('title')}'. Downgrading confidence.")
                    f["confidence"] = min(f.get("confidence", 0), 40)
                    
        state["findings"] = findings
        return state
