import uuid
from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from aegisx.core.taxonomy.vulnerability_taxonomy import GovernanceClass

class RiskLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class GovernanceActionRequest(BaseModel):
    action_id: str
    risk: RiskLevel
    governance_class: GovernanceClass
    operator_signoff_required: bool = False
    sandbox_required: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)
    
    # Risk score inputs
    execution_impact: Optional[str] = None
    target_sensitivity: Optional[str] = None
    authentication_state: Optional[str] = None
    exploitability_confidence: Optional[float] = None
    network_exposure: Optional[str] = None
    data_sensitivity: Optional[str] = None
    blast_radius: Optional[str] = None
    rollback_capability: Optional[bool] = None


class GovernanceDecision(BaseModel):
    approved: bool
    reason: str
    risk_level: str
    governance_class: str
    approval_required: bool
    required_quorum: int
    sandbox_required: bool
    audit_id: str


class GovernancePolicyEngine:
    """
    Evaluates requested actions against enterprise security governance rules.
    Governance is the highest-authority component in AEGIS-X.
    """
    def __init__(self):
        # Classes that NEVER bypass human approval
        self.HARD_DENY_CLASSES = {
            GovernanceClass.ACTIVE_VALIDATION,
            GovernanceClass.INTRUSIVE_VALIDATION,
            GovernanceClass.EXPLOIT_SIMULATION,
            GovernanceClass.POST_VALIDATION,
            GovernanceClass.CREDENTIAL_ACCESS,
            GovernanceClass.CLOUD_VALIDATION,
            GovernanceClass.HIGH_IMPACT_ACTION,
        }

    def _calculate_quorum(self, risk: RiskLevel) -> int:
        if risk in {RiskLevel.INFO, RiskLevel.LOW}:
            return 1
        elif risk == RiskLevel.MEDIUM:
            return 2
        elif risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return 2 # Represents 2-of-3 quorum requirement conceptually
        return 1

    def evaluate_request(self, request: GovernanceActionRequest) -> GovernanceDecision:
        """
        Evaluate if an action can be auto-approved or requires human-in-the-loop oversight.
        """
        audit_id = f"AUD-{str(uuid.uuid4())[:8].upper()}"
        required_quorum = self._calculate_quorum(request.risk)

        # 1. Hard Deny Rules
        if request.governance_class in self.HARD_DENY_CLASSES:
            return GovernanceDecision(
                approved=False,
                reason=f"Governance class {request.governance_class.value} always requires explicit analyst approval.",
                risk_level=request.risk.value,
                governance_class=request.governance_class.value,
                approval_required=True,
                required_quorum=required_quorum,
                sandbox_required=request.sandbox_required,
                audit_id=audit_id
            )
            
        # 2. Check for explicit operator signoff requirements or sandbox requirements
        if request.operator_signoff_required:
            return GovernanceDecision(
                approved=False,
                reason="Explicit operator signoff is required for this action.",
                risk_level=request.risk.value,
                governance_class=request.governance_class.value,
                approval_required=True,
                required_quorum=required_quorum,
                sandbox_required=request.sandbox_required,
                audit_id=audit_id
            )
            
        # 3. Check for specific HITL enforcement overrides
        # Mandatory HITL required for: any MEDIUM+ risk action
        if request.risk in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return GovernanceDecision(
                approved=False,
                reason=f"Risk level {request.risk.value} mandates Human-In-The-Loop (HITL) approval.",
                risk_level=request.risk.value,
                governance_class=request.governance_class.value,
                approval_required=True,
                required_quorum=required_quorum,
                sandbox_required=request.sandbox_required,
                audit_id=audit_id
            )

        # 4. Check Auto-Approval Criteria
        # risk == LOW AND governance_class == PASSIVE_ANALYSIS AND operator_signoff_required == FALSE AND sandbox_required == FALSE
        if (request.risk in {RiskLevel.LOW, RiskLevel.INFO} and 
            request.governance_class == GovernanceClass.PASSIVE_ANALYSIS and
            not request.operator_signoff_required and
            not request.sandbox_required):
            
            return GovernanceDecision(
                approved=True,
                reason="Action satisfies deterministic auto-approval policy:\n* LOW risk\n* PASSIVE analysis\n* No intrusive validation\n* No credential interaction\n* No exploit simulation",
                risk_level=request.risk.value,
                governance_class=request.governance_class.value,
                approval_required=False,
                required_quorum=0,
                sandbox_required=False,
                audit_id=audit_id
            )
            
        # 5. Default Deny -> Require Human Approval
        return GovernanceDecision(
            approved=False,
            reason="Action did not meet strict auto-approval criteria. Human oversight required.",
            risk_level=request.risk.value,
            governance_class=request.governance_class.value,
            approval_required=True,
            required_quorum=required_quorum,
            sandbox_required=request.sandbox_required,
            audit_id=audit_id
        )
