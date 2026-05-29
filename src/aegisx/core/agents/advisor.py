from aegisx.core.models import default_model
import os
from typing import List
from google import genai
from pydantic import BaseModel, Field

from aegisx.core.agents.schemas import AIHypothesis, AIOutput
from aegisx.governance.policy.engine import RiskLevel
from aegisx.core.taxonomy.vulnerability_taxonomy import GovernanceClass
from aegisx.core.ui.console import ConsoleUI

class AdvisorResponse(BaseModel):
    risk_level: str = Field(description="One of: LOW, MEDIUM, HIGH, CRITICAL")
    governance_class: str = Field(description="One of: PASSIVE_ANALYSIS, ACTIVE_VALIDATION, INTRUSIVE_VALIDATION, EXPLOIT_SIMULATION")
    requires_human_approval: bool
    recommended_validation: List[str] = Field(description="3-5 step action plan for validating the vulnerability safely")

class AIGovernanceAdvisor:
    """
    Evaluates hypotheses and recommends Governance Classes and Risk Levels using an LLM.
    """
    def __init__(self, use_mock: bool = False):
        self.use_mock = use_mock
        
        api_key = os.getenv("OPENROUTER_API_KEY_2")
        
        if self.use_mock or not api_key:
            self.client = None
            if not self.use_mock:
                ConsoleUI.warning("No OPENROUTER_API_KEY_2 found, falling back to mock AIGovernanceAdvisor.")
                self.use_mock = True
        else:
            try:
                self.client = genai.Client(api_key=api_key)
            except Exception as e:
                ConsoleUI.warning(f"Failed to initialize google-genai in Advisor: {e}")
                self.use_mock = True
        
    def advise(self, hypothesis: AIHypothesis) -> AIOutput:
        """
        Translates a hypothesis into a fully structured AIOutput format using LLM.
        """
        if self.use_mock:
            return self._mock_advise(hypothesis)
            
        prompt = f"""
        Analyze this vulnerability hypothesis and classify its risk and governance class according to enterprise security standards.
        Hypothesis: {hypothesis.hypothesis}
        Reasoning: {hypothesis.reasoning}
        
        Classify RiskLevel (LOW, MEDIUM, HIGH, CRITICAL) and GovernanceClass (PASSIVE_ANALYSIS, ACTIVE_VALIDATION, INTRUSIVE_VALIDATION, EXPLOIT_SIMULATION).
        Also provide a safe validation plan.
        """
        
        try:
            response = self.client.models.generate_content(
                model=default_model,
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AdvisorResponse,
                    temperature=0.1
                )
            )
            
            res: AdvisorResponse = response.parsed
            
            return AIOutput(
                finding_type=hypothesis.hypothesis,
                confidence=hypothesis.confidence,
                risk_level=getattr(RiskLevel, res.risk_level, RiskLevel.LOW),
                governance_class=getattr(GovernanceClass, res.governance_class, GovernanceClass.PASSIVE_ANALYSIS),
                requires_human_approval=res.requires_human_approval,
                recommended_validation=res.recommended_validation,
                reasoning=hypothesis.reasoning,
                nodes=hypothesis.nodes,
                edges=hypothesis.edges
            )
        except Exception as e:
            ConsoleUI.warning(f"AIGovernanceAdvisor LLM failed: {e}. Falling back to mock.")
            return self._mock_advise(hypothesis)
            
    def _mock_advise(self, hypothesis: AIHypothesis) -> AIOutput:
        risk_level = RiskLevel.LOW
        gov_class = GovernanceClass.PASSIVE_ANALYSIS
        requires_human = False
        rec_val = ["Verify headers", "Check route enumeration"]
        
        if "SSRF" in hypothesis.hypothesis or "SQLi" in hypothesis.hypothesis:
            risk_level = RiskLevel.HIGH
            gov_class = GovernanceClass.INTRUSIVE_VALIDATION
            requires_human = True
            rec_val = ["Attempt safe SSRF to internal canary domain", "Monitor DNS out-of-band"]
        elif "Debug Exposure" in hypothesis.hypothesis:
            risk_level = RiskLevel.MEDIUM
            gov_class = GovernanceClass.ACTIVE_VALIDATION
            requires_human = True
            rec_val = ["Fetch debug route", "Analyze metadata response without modifying state"]
            
        return AIOutput(
            finding_type=hypothesis.hypothesis,
            confidence=hypothesis.confidence,
            risk_level=risk_level,
            governance_class=gov_class,
            requires_human_approval=requires_human,
            recommended_validation=rec_val,
            reasoning=hypothesis.reasoning,
            nodes=hypothesis.nodes,
            edges=hypothesis.edges
        )

class AIValidationPlanner:
    """
    Designs safe, sandbox-contained validation sequences for the findings.
    """
    def __init__(self, use_mock: bool = True):
        self.use_mock = use_mock
        
    def plan_workflow(self, output: AIOutput) -> List[str]:
        """
        Generates a step-by-step execution plan based on the Advisor's recommendations.
        """
        plan = []
        plan.append(f"INITIALIZE: Sandbox with network ACL restricting egress to {output.finding_type} canaries only.")
        
        for step in output.recommended_validation:
            plan.append(f"EXECUTE: {step}")
            
        plan.append("CAPTURE: Telemetry and rollback any state changes.")
        return plan
