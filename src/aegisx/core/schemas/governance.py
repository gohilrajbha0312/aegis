from pydantic import BaseModel, Field
from typing import Optional

class ApprovalGate(BaseModel):
    operation_id: str = Field(..., description="The operation this approval belongs to")
    phase: str = Field(..., description="The phase of execution (e.g., exploitation)")
    risk_level: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    requires_approval: bool = Field(True, description="Flag indicating if HITL is mandatory")
    approved_by: Optional[str] = Field(None, description="Operator ID if approved")

class ScopeValidator:
    def is_authorized(self, target: str) -> bool:
        """Validates if the target is within the authorized scope."""
        # TODO: Implement CIDR logic and boundary checks
        pass
